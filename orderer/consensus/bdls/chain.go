/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"fmt"
	"sync"
	"time"

	bdlslib "github.com/BDLS-bft/bdls"
	gogoproto "github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"

	bdlsproto "github.com/hyperledger/fabric/orderer/consensus/bdls/protos"
)

// ---------------------------------------------------------------------------
// chain.go implements orderer/consensus.Chain on top of a bdlslib.Consensus.
//
// Lifecycle:
//
//   HandleChain (Phase C7)
//      └─ NewChain ──► constructor sets up the state machine, wires the
//                      peer adapters, and pulls ledger-head state forward
//                      into blockCreator. Returns a ready-but-not-started
//                      Chain.
//
//   multichannel.Registrar
//      └─ chain.Start() ──► spawns run() in a background goroutine and
//                           returns immediately.
//
//   run()
//      ├─ submitC    : a client envelope from Order() or a forwarded
//      │               SubmitRequest — feed into the block cutter, cut a
//      │               batch when full, propose the marshalled block to
//      │               BDLS as a new State.
//      ├─ configC    : a channel-config envelope from Configure() — cut
//      │               immediately, propose as a config block. Participant
//      │               set updates happen *after* the config block commits,
//      │               via a chain rebuild in Phase C7 (HandleChain is
//      │               called again by the Registrar post-commit).
//      ├─ tickC      : periodic Update(now) to drive BDLS timeouts.
//      ├─ decideC    : latency/4 poll of CurrentState / CurrentProof. On a
//      │               new height, unmarshal the state bytes back into a
//      │               Block, attach the CurrentProof bytes to
//      │               BlockMetadata[ORDERER] as our bdls_decide_proof,
//      │               and WriteBlockSync.
//      └─ haltC      : close everything, release the run goroutine.
//
// We poll for decide rather than use a callback because Phase A did not
// add a Config.OnDecide hook — the library keeps its polling contract
// unchanged. A latency/4 poll gives us up to ¼-latency of extra tail
// latency per committed block, which at realistic Fabric latencies
// (~100ms) is 25ms. Acceptable for v1; swap to a callback later if
// measurable pressure shows up.
// ---------------------------------------------------------------------------

// defaultTickInterval is used by Start when the channel's Options.LatencyMs
// is not set. 20ms matches IPCPeer.Update and gives BDLS's internal
// Section-8.2 timeouts enough granularity to fire on time.
const defaultTickInterval = 20 * time.Millisecond

// submitReq groups an envelope with its config sequence. Chain.Order uses
// configSeq to re-validate messages after a config update overtakes the
// message in-flight — same semantics etcdraft and smartbft use.
type submitReq struct {
	env       *cb.Envelope
	configSeq uint64
}

// Chain is the BDLS implementation of orderer/consensus.Chain. One Chain
// instance lives per channel per orderer.
type Chain struct {
	logger    *flogging.FabricLogger
	channelID string

	support consensus.ConsenterSupport
	metrics *Metrics

	// consensusMu guards concurrent use of the bdls.Consensus state
	// machine. BDLS's own API is not internally synchronised — the
	// embedder owns serialisation. We take this on every ReceiveMessage,
	// Propose, and Update call.
	consensusMu sync.Mutex
	bdls        *bdlslib.Consensus

	// peers are the N−1 adapters talking to remote consenters via the
	// existing cluster.RPC. Kept so Chain can observe sendErrs counters
	// for catch-up escalation heuristics.
	peers []*peerAdapter

	// blockCreator tracks the previous-block hash + number so run() can
	// assemble new blocks without re-reading the ledger every batch.
	blockCreator *blockCreator

	// tickInterval drives the Update(now) ticker. Pulled from
	// ConfigMetadata.Options.LatencyMs at constructor time, or
	// defaultTickInterval if unset.
	tickInterval time.Duration

	// decidePollInterval is the cadence at which run() polls
	// CurrentState / CurrentProof to detect newly finalised heights.
	// Set to tickInterval by default.
	decidePollInterval time.Duration

	// Queues for run()'s select loop. Buffered so that a brief run()
	// stall does not block incoming cluster traffic.
	submitC chan *submitReq
	configC chan *submitReq
	haltC   chan struct{}
	doneC   chan struct{}
	errC    chan error

	// lastCommittedHeight is the BDLS height of the most recent block we
	// have written to the ledger. Used by the decide poller to detect
	// height advance.
	lastCommittedHeight uint64

	// startOnce / haltOnce protect Start / Halt against being called
	// more than once by a buggy Registrar or a test harness.
	startOnce sync.Once
	haltOnce  sync.Once
}

// NewChain constructs a BDLS chain for the given channel. The caller —
// usually Consenter.HandleChain in Phase C7 — is responsible for:
//
//   1. Parsing the channel's ConsensusType.Metadata into a
//      *bdlsproto.ConfigMetadata (via parseConfigMetadata in util.go).
//   2. Calling buildBDLSConfig to build the bdlslib.Config skeleton.
//   3. Filling in Config.SignDigest + PublicKey from the orderer's BCCSP
//      signer so the private key never leaves the process.
//   4. Calling bdlslib.NewConsensus(config) to construct the state
//      machine.
//   5. Passing the resulting Consensus, the parsed metadata, and the
//      peer adapters into NewChain.
//
// NewChain then wires the pieces together, seeds the block creator from
// the ledger head, and returns a ready-but-not-started Chain.
func NewChain(
	support consensus.ConsenterSupport,
	bdlsConsensus *bdlslib.Consensus,
	md *bdlsproto.ConfigMetadata,
	peers []*peerAdapter,
	metrics *Metrics,
) (*Chain, error) {
	if support == nil {
		return nil, fmt.Errorf("bdls chain: ConsenterSupport is nil")
	}
	if bdlsConsensus == nil {
		return nil, fmt.Errorf("bdls chain: Consensus is nil")
	}
	if md == nil {
		return nil, fmt.Errorf("bdls chain: ConfigMetadata is nil")
	}

	logger := flogging.MustGetLogger("orderer.consensus.bdls").With("channel", support.ChannelID())

	// Seed blockCreator from ledger head so the next locally cut block
	// hashes back to the right place — even if this is a fresh restart
	// and the previous orderer lifecycle wrote blocks we are catching up
	// to via BlockPuller.
	bc := &blockCreator{logger: logger}
	if h := support.Height(); h > 0 {
		last := support.Block(h - 1)
		if last == nil {
			return nil, fmt.Errorf("bdls chain: ledger reports height %d but block %d is missing", h, h-1)
		}
		bc.advance(last)
	}

	tick := defaultTickInterval
	if md.Options != nil && md.Options.LatencyMs > 0 {
		tick = time.Duration(md.Options.LatencyMs) * time.Millisecond / 4
		if tick < time.Millisecond {
			tick = time.Millisecond
		}
	}

	ch := &Chain{
		logger:             logger,
		channelID:          support.ChannelID(),
		support:            support,
		metrics:            metrics,
		bdls:               bdlsConsensus,
		peers:              peers,
		blockCreator:       bc,
		tickInterval:       tick,
		decidePollInterval: tick,
		submitC:            make(chan *submitReq, 64),
		configC:            make(chan *submitReq, 4),
		haltC:              make(chan struct{}),
		doneC:              make(chan struct{}),
		errC:               make(chan error, 1),
	}
	if ch.metrics != nil {
		ch.metrics.ClusterSize.With("channel", ch.channelID).Set(float64(len(peers) + 1))
		ch.metrics.CommittedBlockNumber.With("channel", ch.channelID).Set(float64(bc.number))
	}
	ch.lastCommittedHeight = bc.number
	return ch, nil
}

// ------- consensus.Chain interface ----------------------------------------

// Order accepts a client envelope for ordering. It enqueues the envelope on
// submitC and returns immediately. Actual batching happens in run().
func (c *Chain) Order(env *cb.Envelope, configSeq uint64) error {
	c.logger.Debugf("bdls chain %s: Order received client transaction (configSeq %d)", c.channelID, configSeq)
	select {
	case c.submitC <- &submitReq{env: env, configSeq: configSeq}:
		return nil
	case <-c.haltC:
		return fmt.Errorf("bdls chain %s halted", c.channelID)
	}
}

// Configure accepts a config-block envelope. Config blocks bypass the
// block cutter and are proposed to BDLS as a single-envelope batch so
// the participant set / Options changes take effect at a well-defined
// height.
func (c *Chain) Configure(env *cb.Envelope, configSeq uint64) error {
	c.logger.Debugf("bdls chain %s: Configure received config transaction (configSeq %d)", c.channelID, configSeq)
	select {
	case c.configC <- &submitReq{env: env, configSeq: configSeq}:
		return nil
	case <-c.haltC:
		return fmt.Errorf("bdls chain %s halted", c.channelID)
	}
}

// WaitReady returns nil — BDLS is ready to accept Order() calls the
// moment NewChain returns. There is no leader-election blackout the way
// etcdraft has at startup.
func (c *Chain) WaitReady() error { return nil }

// Errored returns a channel closed when the chain has hit a fatal error.
// errC is buffered-1; run() writes once and closes doneC to signal the
// chain is dead.
func (c *Chain) Errored() <-chan struct{} { return c.doneC }

// Start launches the run-loop goroutine. Safe to call multiple times;
// subsequent calls are no-ops.
func (c *Chain) Start() {
	c.startOnce.Do(func() {
		c.logger.Infof("Starting BDLS chain %s (%d peers, tick=%s)",
			c.channelID, len(c.peers), c.tickInterval)
		go c.run()
	})
}

// Halt signals the run-loop to shut down and blocks until doneC closes.
// Safe to call multiple times.
func (c *Chain) Halt() {
	c.haltOnce.Do(func() {
		c.logger.Infof("Halting BDLS chain %s", c.channelID)
		close(c.haltC)
	})
	<-c.doneC
}

// ------- MessageReceiver (dispatcher.go) ----------------------------------

// Consensus delivers an inbound BDLS SignedProto (carried in the
// ConsensusRequest.Payload) to the state machine. Called from
// Dispatcher.OnConsensus.
func (c *Chain) Consensus(req *orderer.ConsensusRequest, sender uint64) error {
	if req == nil || len(req.Payload) == 0 {
		return fmt.Errorf("bdls chain %s: Consensus received empty payload from %d", c.channelID, sender)
	}
	c.logger.Debugf("bdls chain %s: Consensus received payload from %d, len %d", c.channelID, sender, len(req.Payload))
	c.consensusMu.Lock()
	defer c.consensusMu.Unlock()
	return c.bdls.ReceiveMessage(req.Payload, time.Now())
}

// Submit forwards a client envelope that a remote orderer has forwarded to
// us via SubmitRequest. We treat it exactly like a local Order() call.
func (c *Chain) Submit(req *orderer.SubmitRequest, sender uint64) error {
	if req == nil || req.Payload == nil {
		return fmt.Errorf("bdls chain %s: Submit received nil payload from %d", c.channelID, sender)
	}
	c.logger.Debugf("bdls chain %s: Submit received forwarded transaction from %d", c.channelID, sender)
	return c.Order(req.Payload, req.LastValidationSeq)
}

// ------- run-loop ---------------------------------------------------------

// run is the chain's main goroutine. Exits only on Halt() or a fatal error
// written to errC. The select order biases haltC so a halt that arrives
// while the chain is under load cannot be starved by a tight submit loop.
func (c *Chain) run() {
	defer close(c.doneC)

	tick := time.NewTicker(c.tickInterval)
	defer tick.Stop()

	decidePoll := time.NewTicker(c.decidePollInterval)
	defer decidePoll.Stop()

	ticking := false
	timer := time.NewTimer(time.Second)
	if !timer.Stop() {
		<-timer.C
	}

	startTimer := func() {
		if !ticking {
			ticking = true
			timer.Reset(c.support.SharedConfig().BatchTimeout())
		}
	}

	stopTimer := func() {
		if !timer.Stop() && ticking {
			<-timer.C
		}
		ticking = false
	}

	for {
		select {
		case <-c.haltC:
			return

		case req := <-c.submitC:
			c.handleSubmit(req, startTimer, stopTimer)

		case req := <-c.configC:
			stopTimer()
			c.handleConfig(req)

		case <-timer.C:
			ticking = false
			batch := c.support.BlockCutter().Cut()
			if len(batch) > 0 {
				c.logger.Debugf("Batch timer expired, creating block")
				if err := c.proposeBatch(batch); err != nil {
					c.fatalf("proposeBatch (timer) failed: %v", err)
					return
				}
			}

		case <-tick.C:
			c.tickBDLS()

		case <-decidePoll.C:
			c.checkDecide()
		}
	}
}

// handleSubmit runs the block cutter over an incoming envelope and, for
// each full batch the cutter emits, proposes the assembled block to BDLS.
// Messages whose configSeq is stale against the current support.Sequence
// are dropped — the support has already moved past them.
func (c *Chain) handleSubmit(req *submitReq, startTimer func(), stopTimer func()) {
	if c.support.Sequence() > req.configSeq {
		c.logger.Debugf("Dropping stale envelope (configSeq %d < current %d)", req.configSeq, c.support.Sequence())
		return
	}

	batches, pending := c.support.BlockCutter().Ordered(req.env)
	for _, batch := range batches {
		if err := c.proposeBatch(batch); err != nil {
			c.fatalf("proposeBatch failed: %v", err)
			return
		}
	}

	if len(batches) == 0 && pending {
		startTimer()
	} else if !pending {
		stopTimer()
	}
}

// handleConfig cuts immediately (config blocks bypass the batching knobs)
// and proposes a single-envelope block.
func (c *Chain) handleConfig(req *submitReq) {
	if c.support.Sequence() > req.configSeq {
		c.logger.Debugf("Dropping stale config envelope (configSeq %d < current %d)", req.configSeq, c.support.Sequence())
		return
	}
	// Drain any pending non-config envelopes first — they must commit at
	// lower heights than the config block so channel-config updates take
	// effect at a clean boundary.
	if pending := c.support.BlockCutter().Cut(); len(pending) > 0 {
		if err := c.proposeBatch(pending); err != nil {
			c.fatalf("proposeBatch (pre-config flush) failed: %v", err)
			return
		}
	}
	if err := c.proposeBatch([]*cb.Envelope{req.env}); err != nil {
		c.fatalf("proposeBatch (config) failed: %v", err)
	}
}

// proposeBatch assembles a block from the given envelopes and hands its
// marshalled bytes to BDLS as a proposed state. BDLS chooses which
// proposal to finalise inside the round; once CurrentState advances we
// pick up the finalised bytes in checkDecide and write them to the ledger.
func (c *Chain) proposeBatch(batch []*cb.Envelope) error {
	if len(batch) == 0 {
		return nil
	}
	block, err := c.blockCreator.createNextBlock(batch)
	if err != nil {
		if c.metrics != nil {
			c.metrics.ProposalFailures.With("channel", c.channelID).Add(1)
		}
		return fmt.Errorf("createNextBlock: %w", err)
	}
	stateBytes, err := proto.Marshal(block)
	if err != nil {
		if c.metrics != nil {
			c.metrics.ProposalFailures.With("channel", c.channelID).Add(1)
		}
		return fmt.Errorf("marshal proposed block: %w", err)
	}
	c.consensusMu.Lock()
	c.bdls.Propose(stateBytes)
	c.consensusMu.Unlock()
	c.logger.Debugf("Proposed block %d (%d envelopes, %d bytes)", block.Header.Number, len(batch), len(stateBytes))
	return nil
}

// tickBDLS drives the library's internal timeout machinery. BDLS owns all
// of its scheduling off this single call; chain.go never has to reach into
// Δ₀..Δ₃ itself.
func (c *Chain) tickBDLS() {
	c.consensusMu.Lock()
	err := c.bdls.Update(time.Now())
	c.consensusMu.Unlock()
	if err != nil {
		// Non-fatal: PR-A2 converted every former panic on the Update
		// path into a returned error. Log and keep the chain running —
		// the next tick will try again.
		c.logger.Warnf("bdls.Update returned %v (non-fatal, continuing)", err)
	}
}

// checkDecide polls the library for a new finalised height. On hit, it
// unmarshals the finalised state bytes back into a Block, attaches the
// current proof as BlockMetadata[ORDERER].Value via our BlockMetadata
// proto, and WriteBlockSync's the result. It also advances blockCreator
// so the next locally-cut block hashes back to the new head, and resets
// the peer adapters' sendErrs counters.
func (c *Chain) checkDecide() {
	c.consensusMu.Lock()
	height, round, state := c.bdls.CurrentState()
	proof := c.bdls.CurrentProof()
	c.consensusMu.Unlock()

	if height == 0 || height <= c.lastCommittedHeight {
		return
	}
	if len(state) == 0 {
		c.logger.Warnf("bdls reported decide at height %d but state is empty", height)
		return
	}

	block := &cb.Block{}
	if err := proto.Unmarshal(state, block); err != nil {
		c.fatalf("failed to unmarshal decided state at height %d: %v", height, err)
		return
	}

	// The BDLS SignedProto uses gogo/protobuf (the library has been on
	// gogo since before google.golang.org/protobuf existed), so we must
	// marshal it with the gogo runtime, not the modern proto package we
	// use for everything else in this file.
	var proofBytes []byte
	if proof != nil {
		var err error
		proofBytes, err = gogoproto.Marshal(proof)
		if err != nil {
			c.fatalf("failed to marshal decide proof at height %d: %v", height, err)
			return
		}
	}

	bm := &bdlsproto.BlockMetadata{
		BdlsHeight:      height,
		BdlsRound:       round,
		BdlsDecideProof: proofBytes,
	}
	encodedMetadata, err := proto.Marshal(bm)
	if err != nil {
		c.fatalf("failed to marshal bdls BlockMetadata at height %d: %v", height, err)
		return
	}

	if protoutil.IsConfigBlock(block) {
		c.support.WriteConfigBlock(block, encodedMetadata)
	} else {
		c.support.WriteBlockSync(block, encodedMetadata)
	}

	c.blockCreator.advance(block)
	c.lastCommittedHeight = height
	for _, p := range c.peers {
		p.resetSendErrs()
	}
	if c.metrics != nil {
		c.metrics.CommittedBlockNumber.With("channel", c.channelID).Set(float64(block.Header.Number))
	}
	c.logger.Debugf("Committed block %d at BDLS height %d round %d", block.Header.Number, height, round)
}

// fatalf writes a fatal error to errC (if nothing is there already) and
// closes doneC via the deferred close in run(). Callers should return
// immediately after invoking fatalf so the select loop exits cleanly.
func (c *Chain) fatalf(format string, args ...interface{}) {
	err := fmt.Errorf(format, args...)
	c.logger.Errorf("BDLS chain %s fatal: %v", c.channelID, err)
	select {
	case c.errC <- err:
	default:
	}
	// Signal halt so run() exits on the next iteration. We do NOT call
	// Halt() here because Halt blocks on doneC, which run() will close
	// on return — that would deadlock.
	c.haltOnce.Do(func() { close(c.haltC) })
}

// StatusReport returns the ConsensusRelation & Status
func (c *Chain) StatusReport() (types.ConsensusRelation, types.Status) {
	return types.ConsensusRelationConsenter, types.StatusActive
}

// Compile-time assertions keep interface drift honest.
var (
	_ consensus.Chain          = (*Chain)(nil)
	_ consensus.StatusReporter = (*Chain)(nil)
	_ MessageReceiver          = (*Chain)(nil)
)
