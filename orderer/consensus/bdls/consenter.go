/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"bytes"
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

// ErrHandleChainNotFullyWired is returned by HandleChain while the crypto /
// cluster.RPC wiring is still pending. It is deliberately distinct from a
// generic error so tests and operators can assert on it.
var ErrHandleChainNotFullyWired = errors.New("bdls consenter: HandleChain stub — BCCSP signer / cluster.RPC wiring pending (see Phase C7b)")

// Consenter is the BDLS implementation of consensus.Consenter. Fields mirror
// smartbft.Consenter where they make sense so operators and reviewers who
// already know the BFT consenter don't have to relearn a new shape.
type Consenter struct {
	Logger           *flogging.FabricLogger
	Metrics          *Metrics
	BCCSP            bccsp.BCCSP
	SignerSerializer identity.SignerSerializer
	Identity         []byte

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
// but not used yet — the BDLS consenter reuses the cluster gRPC service
// that etcdraft and smartbft already register, rather than opening its
// own listener. Phase C7b will stash them on the struct if we decide
// we need to intercept the StepRequest stream directly.
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
	return c
}

// HandleChain is called by the Registrar when a channel using
// ConsensusType=BDLS is (re)initialised. It parses the channel's BDLS
// ConfigMetadata and detects our consenter id, then — in Phase C7b —
// will go on to construct the live bdlslib.Consensus and return a Chain.
//
// Keeping the parse/detect side on `main` means registration is not a
// dangling dead code path: operator tooling that validates channel
// configs against the installed consenter gets real feedback for
// malformed ConfigMetadata, even before end-to-end ordering is
// available.
func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *cb.Metadata) (consensus.Chain, error) {
	_ = metadata // unused until C7b reads previously committed decide proofs for catch-up

	md, err := parseConfigMetadata(support.SharedConfig().ConsensusMetadata())
	if err != nil {
		return nil, errors.Wrap(err, "parsing BDLS ConfigMetadata")
	}

	selfID, err := c.detectSelfID(md)
	if err != nil {
		return nil, errors.Wrap(err, "detecting BDLS self id")
	}
	c.Logger.Infof("BDLS HandleChain: channel=%s selfID=%d consenters=%d", support.ChannelID(), selfID, len(md.Consenters))

	// Build the bdls.Config skeleton — Δ knobs, participants,
	// StateCompare / StateValidate, ReliableDecide default. Kept here
	// even though we don't hand it to NewConsensus yet so that a
	// malformed Options block (e.g. negative Δ, too few consenters) is
	// surfaced as a HandleChain error, not silently tolerated.
	if _, err := buildBDLSConfig(md, support.Height()); err != nil {
		return nil, errors.Wrap(err, "building bdls.Config")
	}

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
// consenter set by matching TLS cert public keys against our own identity.
// The returned id is the zero-based index into md.Consenters; BDLS itself
// derives the numeric participant id from the (X, Y) public-key coordinates
// via DefaultPubKeyToIdentity and does not actually need this integer, so
// it is used only for logging and for cluster.RPC routing in C7b.
//
// Membership matching uses sanitized-cert public-key equality, identical
// to IsChannelMember above and to smartbft's detectSelfID. Keeping the two
// helpers byte-for-byte consistent means a node that IsChannelMember says
// "yes" to will always find itself in detectSelfID, and vice versa.
func (c *Consenter) detectSelfID(md *bdlsproto.ConfigMetadata) (uint64, error) {
	if len(c.Identity) == 0 {
		return 0, errors.New("consenter has no serialised identity (New was called with nil SignerSerializer?)")
	}
	sanitizedSelf, err := crypto.SanitizeX509Cert(c.Identity)
	if err != nil {
		return 0, errors.Wrap(err, "sanitising own identity cert")
	}
	selfBlock, _ := pem.Decode(sanitizedSelf)
	if selfBlock == nil {
		return 0, errors.Errorf("own identity is not a valid PEM: %s", string(sanitizedSelf))
	}
	selfPub, err := cluster.ExtractPublicKeyFromCert(selfBlock.Bytes)
	if err != nil {
		return 0, errors.Wrap(err, "extracting own TLS public key")
	}

	for i, co := range md.Consenters {
		sanitized, err := crypto.SanitizeX509Cert(co.ServerTlsCert)
		if err != nil {
			c.Logger.Warnf("BDLS detectSelfID: consenter %d cert sanitize failed: %v", i, err)
			continue
		}
		block, _ := pem.Decode(sanitized)
		if block == nil {
			c.Logger.Warnf("BDLS detectSelfID: consenter %d cert is not valid PEM", i)
			continue
		}
		pub, err := cluster.ExtractPublicKeyFromCert(block.Bytes)
		if err != nil {
			c.Logger.Warnf("BDLS detectSelfID: consenter %d public key extract failed: %v", i, err)
			continue
		}
		if bytes.Equal(selfPub, pub) {
			return uint64(i), nil
		}
	}
	return 0, errors.New("this orderer is not in the channel's BDLS consenter set")
}
