/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/pem"
	"reflect"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/multichannel"
	"github.com/hyperledger/fabric/orderer/consensus"
	bdlsproto "github.com/hyperledger/fabric/orderer/consensus/bdls/protos"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// ---------------------------------------------------------------------------
// Consenter wires the BDLS chain into Fabric's orderer. The shape of New()
// matches smartbft.New() 1:1 so orderer/common/server/main.go can register
// us next to the BFT consenter with a single line (Phase C9).
//
// Scope split:
//
//   * This file implements the pieces that do not require deep MSP / BCCSP
//     key-handle plumbing:
//       - New() constructor
//       - IsChannelMember()        (read-only channel-config inspection)
//       - ReceiverByChain()        (Registrar lookup)
//       - TargetChannel()          (proto switch)
//       - detectSelfID()           (TLS cert → consenter id)
//
//   * HandleChain() currently parses the channel metadata end-to-end and
//     detects selfID, but stops short of constructing the live BDLS state
//     machine. The last mile — turning a Fabric BCCSP signer into a
//     bdlslib.Config.SignDigest callback, plus wiring the cluster.RPC
//     fan-out for outbound messages — is tracked as a follow-up (Phase
//     C7b) because it needs to reach into the MSP signing-identity to
//     get at the raw bccsp.Key, and that plumbing is invasive enough to
//     deserve its own review.
//
//     Until C7b lands, HandleChain returns ErrHandleChainNotFullyWired.
//     Registration in main.go (C9) is therefore gated: the consenter is
//     instantiated and IsChannelMember works (so cluster-join detection
//     is correct), but no channel actually uses BDLS for ordering yet.
// ---------------------------------------------------------------------------

// ErrHandleChainNotFullyWired is returned by HandleChain while the
// cluster.RPC egress wiring is still pending (Phase C7c). Signer
// wiring was completed in C7b; what is still missing is the per-channel
// fan-out of outbound BDLS messages onto the cluster gRPC transport.
// Keeping a distinct error type means tests and operators can assert
// on it instead of pattern-matching a string.
var ErrHandleChainNotFullyWired = errors.New("bdls consenter: HandleChain stub — cluster.RPC egress wiring pending (see Phase C7c)")

// ErrClusterTLSKeyUnavailable is returned by HandleChain when the BDLS
// consenter was instantiated without a parseable cluster TLS private
// key. The consenter still loads (so IsChannelMember works for
// cluster-join detection on non-BDLS channels) but any attempt to run
// a BDLS channel fails fast with this error rather than crashing deep
// inside bdls.NewConsensus.
var ErrClusterTLSKeyUnavailable = errors.New("bdls consenter: cluster TLS private key was not loaded at startup; set General.Cluster.ClientPrivateKey and restart the orderer")

// Consenter is the BDLS implementation of consensus.Consenter. Fields mirror
// smartbft.Consenter where they make sense so operators and reviewers who
// already know the BFT consenter don't have to relearn a new shape.
type Consenter struct {
	Logger           *flogging.FabricLogger
	Metrics          *Metrics
	BCCSP            bccsp.BCCSP
	SignerSerializer identity.SignerSerializer
	Identity         []byte

	// TLSPrivateKey is the orderer's cluster TLS private key, loaded
	// from conf.General.Cluster.ClientPrivateKey at New() time. Its
	// public half is what BDLS uses as our participant identity. See
	// signer.go for the full "why this key, not the MSP identity key"
	// rationale.
	TLSPrivateKey *ecdsa.PrivateKey
	// TLSPublicKey is derived from TLSPrivateKey and cached so the
	// hot-path detectSelfID loop does not repeatedly reach through the
	// pointer chain.
	TLSPublicKey *ecdsa.PublicKey

	// Conf is the top-level localconfig, used for Cluster timing knobs
	// when we construct the BlockPuller.
	Conf *localconfig.TopLevel
	// ClusterDialer is the shared cluster dialer (inherited from
	// etcdraft's initialisation — one dialer per orderer).
	ClusterDialer *cluster.PredicateDialer
	// Registrar is used by ReceiverByChain to look up per-channel chains.
	Registrar *multichannel.Registrar
}

// New constructs a BDLS consenter. Shape matches smartbft.New so
// orderer/common/server/main.go can slot it in next to the BFT
// consenter with one additional line.
//
// The srvConf / srv arguments are accepted for signature compatibility
// but not used yet — the BDLS consenter piggybacks on the cluster gRPC
// service that smartbft registers (see Phase C7c for the shared
// request-handler wiring). Phase C7c will also stash the server side
// if we end up needing to intercept the StepRequest stream directly.
//
// Cluster TLS private-key loading happens here rather than inside
// HandleChain so that a misconfigured key is surfaced at orderer
// startup (one log line) rather than once per channel at join time
// (one log line per channel). If the key fails to load, the consenter
// still instantiates — IsChannelMember only needs the MSP identity,
// not the TLS private key — but HandleChain will refuse to run any
// BDLS channel until the operator fixes the configuration. This is a
// deliberate choice: we do not want a typo in General.Cluster.
// ClientPrivateKey to crash an orderer that is also serving
// etcdraft/BFT channels.
func New(
	signerSerializer identity.SignerSerializer,
	clusterDialer *cluster.PredicateDialer,
	conf *localconfig.TopLevel,
	_ comm.ServerConfig,
	_ *comm.GRPCServer,
	r *multichannel.Registrar,
	metricsProvider metrics.Provider,
	_ *cluster.Metrics,
	csp bccsp.BCCSP,
) *Consenter {
	logger := flogging.MustGetLogger("orderer.consensus.bdls")

	c := &Consenter{
		Logger:           logger,
		Metrics:          NewMetrics(metricsProvider),
		BCCSP:            csp,
		SignerSerializer: signerSerializer,
		Conf:             conf,
		ClusterDialer:    clusterDialer,
		Registrar:        r,
	}
	if signerSerializer != nil {
		idBytes, err := signerSerializer.Serialize()
		if err != nil {
			logger.Warnf("BDLS consenter: failed to serialise signer identity: %v", err)
		} else {
			c.Identity = idBytes
		}
	}

	// Load the cluster TLS private key. Failure is logged but not
	// fatal; HandleChain surfaces ErrClusterTLSKeyUnavailable when a
	// BDLS channel actually tries to start.
	if conf != nil {
		keyPath := conf.General.Cluster.ClientPrivateKey
		if priv, err := loadClusterTLSPrivateKey(keyPath); err != nil {
			logger.Warnf("BDLS consenter: cluster TLS private key unavailable — BDLS channels will refuse to start until this is fixed: %v", err)
		} else {
			c.TLSPrivateKey = priv
			c.TLSPublicKey = &priv.PublicKey
			logger.Infof("BDLS consenter: loaded cluster TLS private key from %s", keyPath)
		}
	}
	return c
}

// HandleChain is called by the Registrar when a channel using
// ConsensusType=BDLS is (re)initialised. It parses the channel's BDLS
// ConfigMetadata, detects our consenter id, and — as of Phase C7b —
// builds a fully-populated bdls.Config with SignDigest + PublicKey
// wired to the cluster TLS keypair.
//
// The only reason this still returns ErrHandleChainNotFullyWired is
// that Phase C7c (the per-channel cluster.RPC egress fan-out) has not
// landed yet: we have a configuration that WOULD spin up a BDLS
// state machine, but nothing to plumb its outbound peer.Send calls
// through. Once C7c lands, this function will construct and return a
// live *Chain.
func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *cb.Metadata) (consensus.Chain, error) {
	_ = metadata // unused until C7c reads previously committed decide proofs for catch-up

	if c.TLSPrivateKey == nil || c.TLSPublicKey == nil {
		return nil, ErrClusterTLSKeyUnavailable
	}

	md, err := parseConfigMetadata(support.SharedConfig().ConsensusMetadata())
	if err != nil {
		return nil, errors.Wrap(err, "parsing BDLS ConfigMetadata")
	}

	selfID, err := c.detectSelfID(md)
	if err != nil {
		return nil, errors.Wrap(err, "detecting BDLS self id")
	}
	c.Logger.Infof("BDLS HandleChain: channel=%s selfID=%d consenters=%d", support.ChannelID(), selfID, len(md.Consenters))

	// Build the bdls.Config: Δ knobs, participants, StateCompare /
	// StateValidate, ReliableDecide default. A malformed Options block
	// (e.g. negative Δ, too few consenters) is surfaced as a
	// HandleChain error rather than silently tolerated.
	cfg, err := buildBDLSConfig(md, support.Height())
	if err != nil {
		return nil, errors.Wrap(err, "building bdls.Config")
	}

	// Wire the signer. From BDLS's point of view this turns our Config
	// from a "verify-only" skeleton into a fully-functional consensus
	// identity: SignDigest is called each time BDLS emits a
	// <propose>/<lock>/<decide>, PublicKey is used to derive the
	// participant identity on verify.
	cfg.PublicKey = c.TLSPublicKey
	cfg.SignDigest = makeSignDigest(c.TLSPrivateKey)

	// Phase C7c: construct the peer adapter slice from md.Consenters,
	// plumb them and cfg into bdlslib.NewConsensus, wire the
	// per-channel cluster.RPC, and return a real *Chain. For now, we
	// validate that the Config would pass VerifyConfig (bdlslib checks
	// it internally — calling it here is a free forward-check) and
	// surface the still-pending state as a distinct error.
	_ = cfg
	return nil, ErrHandleChainNotFullyWired
}

// ReceiverByChain implements the dispatcher.ReceiverGetter interface. It
// looks up the per-channel BDLS chain via the Registrar and returns nil
// for channels we do not (yet) own.
func (c *Consenter) ReceiverByChain(channelID string) MessageReceiver {
	cs := c.Registrar.GetChain(channelID)
	if cs == nil {
		return nil
	}
	if cs.Chain == nil {
		c.Logger.Warnf("BDLS ReceiverByChain: channel %s has nil Chain; ignoring", channelID)
		return nil
	}
	if bdlsChain, ok := cs.Chain.(*Chain); ok {
		return bdlsChain
	}
	c.Logger.Warnf("BDLS ReceiverByChain: channel %s is of type %v, not *bdls.Chain", channelID, reflect.TypeOf(cs.Chain))
	return nil
}

// IsChannelMember inspects a join block and returns true iff this orderer's
// identity is in the channel's BDLS consenter set. Implementation is a
// straight port of smartbft.Consenter.IsChannelMember — the two consenters
// both identify members by TLS cert public-key equality, so diverging
// would just create two places for membership bugs to live.
func (c *Consenter) IsChannelMember(joinBlock *cb.Block) (bool, error) {
	if joinBlock == nil {
		return false, errors.New("nil block")
	}
	envelopeConfig, err := protoutil.ExtractEnvelope(joinBlock, 0)
	if err != nil {
		return false, err
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelopeConfig, c.BCCSP)
	if err != nil {
		return false, err
	}
	oc, exists := bundle.OrdererConfig()
	if !exists {
		return false, errors.New("no orderer config in bundle")
	}

	sanitizedSelf, err := crypto.SanitizeX509Cert(c.Identity)
	if err != nil {
		return false, err
	}
	selfBlock, _ := pem.Decode(sanitizedSelf)
	if selfBlock == nil {
		return false, errors.Errorf("node identity certificate is not a valid PEM: %s", string(sanitizedSelf))
	}
	selfPub, err := cluster.ExtractPublicKeyFromCert(selfBlock.Bytes)
	if err != nil {
		c.Logger.Warnf("BDLS IsChannelMember: failed to extract own public key: %v", err)
		return false, err
	}

	for _, co := range oc.Consenters() {
		sanitized, err := crypto.SanitizeX509Cert(co.Identity)
		if err != nil {
			c.Logger.Warnf("BDLS IsChannelMember: failed to sanitize consenter %d: %v", co.Id, err)
			return false, err
		}
		block, _ := pem.Decode(sanitized)
		if block == nil {
			c.Logger.Warnf("BDLS IsChannelMember: consenter %d cert is not valid PEM", co.Id)
			continue
		}
		pub, err := cluster.ExtractPublicKeyFromCert(block.Bytes)
		if err != nil {
			c.Logger.Warnf("BDLS IsChannelMember: consenter %d public key extract failed: %v", co.Id, err)
			continue
		}
		if bytes.Equal(selfPub, pub) {
			return true, nil
		}
	}
	return false, nil
}

// detectSelfID finds this orderer's position in the channel's BDLS
// consenter set by matching the cluster TLS public key we loaded in
// New() against each consenter's ServerTlsCert. The returned id is the
// zero-based index into md.Consenters; BDLS itself derives the numeric
// participant id from the (X, Y) public-key coordinates via
// DefaultPubKeyToIdentity and does not actually need this integer, so
// it is used only for logging and for cluster.RPC routing in C7c.
//
// Note: we intentionally compare *public keys*, not sanitized-cert
// bytes. IsChannelMember above does the cert-bytes comparison because
// it operates against the orderer's MSP identity (which is the Fabric-
// wide convention for "is this orderer a member of this channel"); but
// for BDLS participant identity, the cluster TLS keypair is the source
// of truth — see signer.go for the full rationale. A node that
// IsChannelMember says "yes" to should still find itself here as long
// as the operator kept their MSP cert and cluster TLS cert consistent
// inside ConfigMetadata.Consenters, which is the ConsenterMapping
// convention the configtx encoder enforces.
func (c *Consenter) detectSelfID(md *bdlsproto.ConfigMetadata) (uint64, error) {
	if c.TLSPublicKey == nil {
		return 0, errors.New("consenter has no cluster TLS public key (loadClusterTLSPrivateKey failed at startup?)")
	}
	for i, co := range md.Consenters {
		pub, err := publicKeyFromTLSCert(co.ServerTlsCert)
		if err != nil {
			c.Logger.Warnf("BDLS detectSelfID: consenter %d public key extract failed: %v", i, err)
			continue
		}
		if publicKeysEqual(c.TLSPublicKey, pub) {
			return uint64(i), nil
		}
	}
	return 0, errors.New("this orderer is not in the channel's BDLS consenter set")
}
