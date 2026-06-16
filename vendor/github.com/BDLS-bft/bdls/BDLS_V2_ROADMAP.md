# BDLS v2 Hardening Roadmap

Companion to `MISSING_PIECES.md`. Scopes out the production-grade work that is *not* required for the in-flight Fabric integration (which pins `v1.0.0-fabric` — see `/Users/saditya/.claude/plans/calm-finding-book.md`) but is needed before BDLS is credible as a general-purpose embeddable consensus library.

The Fabric integration is intentionally scoped to work around three of the four items below by leaning on Fabric primitives (blockcutter, ledger, BlockPuller). That works *for Fabric*, but locks BDLS out of other embedders. This roadmap is the plan for lifting those workarounds into the library itself.

---

## Mapping against existing work

| Missing piece (from `MISSING_PIECES.md`) | Status today | New library work needed |
|---|---|---|
| 1. Application-layer batching | Fabric-side: the blockcutter batches txs into a single block → one `State` per BDLS height. Works for Fabric, nothing for standalone embedders. | Mempool + Batcher wrapper as a **separate package** (`bdls/batcher`), opt-in — no changes to `consensus.go`. |
| 2. WAL / crash persistence | **Not handled anywhere.** Fabric's ledger persists committed blocks; BDLS in-flight vote state (locks, unconfirmed, roundchange) is lost on crash. On restart the chain re-runs the current height, which is a liveness hit but not a safety violation. | New in-library WAL + replay path. See §W below. |
| 3. State synchronization / catch-up | Fabric-side: `orderer/consensus/bdls/blockpuller.go` pulls committed blocks via Fabric's deliver service, verifies each block's `bdls_decide_proof` with `ValidateDecideMessage`. Sidesteps needing a BDLS-level protocol. | New in-library sync RPC as an **optional** helper for non-Fabric embedders; see §S below. |
| 4. Dynamic validator sets | Audit item **B3**. PR-A3 (in-flight) adds `(*Consensus).UpdateParticipants(next []Identity) error` callable between heights. Fabric side: C8's metadata_validator + Registrar re-instantiation on config-commit. | Already the A3 work. §D below is just the follow-on: a first-class "epoch boundary" so UpdateParticipants can be proposed *through* consensus, not as an out-of-band call. |

Items already done by Phase A (do not re-do):
- **B1** — de-panic hot path → PR-A2.
- **B2** — reliable decide broadcast → PR-A3.
- **G1** — `SignDigest` external signer → PR-A1 (merged).
- **G3** — Δ₀..Δ₃ tunables → PR-A3.

---

## §W. Write-Ahead Log

**Goal.** A crashed node restarts and resumes its current-height vote without violating safety (no double-vote, no reneging on a lock).

**Minimum viable WAL.**
- One append-only file per chain, default path `${embedder-provided}/bdls-wal/<chain-id>`. Segment size and fsync policy are embedder-configurable via `Config.WAL`.
- Records (variable length, `length || crc32 || type || payload`):
  - `ENTER_HEIGHT(h)` — written when a new height starts.
  - `SENT_VOTE(h, r, kind, digest, signedProto)` — written *before* the signed proto is handed to `PeerInterface.Send`. This is the single critical write: if it's on disk, the node has committed to its vote and can replay it on restart; if it's not on disk, the node has not voted and can vote freely after restart.
  - `LOCK(h, r, state)` — written when `LockRelease` / lock transitions fire.
  - `DECIDE(h, round, proof, state)` — written on local finalisation; used to skip replay on clean restart.
  - `TRUNCATE(h)` — written when height `h` commits, garbage-collects entries for heights `< h`.
- Replay on startup: seek to the last `DECIDE`, replay everything after it to rebuild `unconfirmed`, `locks`, `latestHeight`, `roundChangeStatus`. Re-assert `SENT_VOTE` records with the Consensus state machine so it knows what it has already signed.

**Non-goals.** Don't try to compete with `etcd/raft/wal`'s performance envelope. A simple `os.File` + `bufio.Writer` + per-write fsync (configurable) is enough; consensus correctness is the point, not µs-latency.

**Interaction with Fabric embedder.** Fabric orderers already have `General.Cluster.WALDir` and a per-channel WAL convention (smartbft uses it). BDLS consenter would set `Config.WAL = walpkg.New(filepath.Join(conf.General.Cluster.WALDir, "bdls", channelID))` in HandleChain.

**Sequencing.** Two PRs.
- **PR-W1**: the WAL package itself (`bdls/wal`) + unit tests, no integration with `Consensus`. Reviewed in isolation.
- **PR-W2**: wire it into `consensus.go` — add `Config.WAL`, call the writes at the right points, implement replay in `NewConsensus`.

**Test contract.** Kill-restart fault injection at every protocol state (pre-vote / post-vote / pre-commit / pre-decide) × every sender role (leader / follower / both). Assert: no fork, no double-vote, no stuck height.

---

## §B. Application-layer batching

**Goal.** Let non-Fabric embedders batch application transactions into a single BDLS `State` without re-inventing a mempool.

**Scope.** Pure wrapper package `bdls/batcher`. Never imported by `consensus.go`.

**API sketch.**
```go
type Batcher struct {
    MaxBytes  int
    MaxCount  int
    MaxWait   time.Duration
    OnBatch   func(batch []byte) error  // called with marshalled batch when cut
}
func (b *Batcher) Submit(tx []byte) error
func (b *Batcher) Drain() ([]byte, error)  // cut immediately
```
Wire format: `repeated bytes transactions` protobuf message (one .proto file in the package).

**Non-scope.** Anti-spam, fee markets, transaction validation — all embedder concerns.

**Why this is not on the Fabric critical path.** Fabric's blockcutter is already this, with better fee/validation policy. BDLS-on-Fabric will not use `bdls/batcher`. The reason to ship it is so the next embedder doesn't have to re-derive it.

**Sizing.** One small PR (~300 LoC + tests).

---

## §S. State synchronization

**Goal.** A node at height `h` can catch up to a live cluster at height `H` without human intervention.

**Design decision: library-level sync is optional.**

Embedders that already have a block-storage/sync layer (Fabric, any chain-style system) should *not* use this — they already have a canonical ordered log. The library-level sync path is aimed at embedders where BDLS *is* the log.

**API sketch (opt-in, gated on `Config.SyncEnabled bool`).**
```go
type SyncPeer interface {
    // Returns committed decides in [from, from+batch), each carrying its
    // State payload and the CurrentProof at that height.
    FetchDecides(ctx, from, batch uint64) ([]DecideRecord, error)
}
type DecideRecord struct {
    Height uint64
    Round  uint64
    State  []byte
    Proof  []byte  // marshalled SignedProto of the <decide>
}
func (c *Consensus) CatchUp(peer SyncPeer) error  // blocks until height matches
```

Verification uses the existing `ValidateDecideMessage(proof, state)` — no new crypto.

**Sequencing.** One PR, landing **after** §W (WAL) because catch-up must cooperate with the WAL replay path (don't replay an in-flight vote for a height that's already been proven via catch-up).

---

## §D. Dynamic validator sets — follow-on to PR-A3

**What PR-A3 delivers.** `UpdateParticipants(next []Identity)` is an *out-of-band* mutation: the embedder calls it between heights, and the library trusts the embedder to have reached consensus about the new set some other way. For Fabric that other way is Fabric's own channel-config commit path (which is itself a BDLS-decided block), which works but has a subtle race: a node that's lagging on height `h` might call `UpdateParticipants` for a set-change that was committed at height `h-1` before it finishes processing its own `h-1` decide.

**Follow-on.** A "reconfiguration record" embedded in the decide payload:
- The committed `State` for a reconfig height carries a marker (e.g., `State[0] == 0x01` for "this block changes participants"); `StateValidate` in the embedder validates the marker and decodes the new set.
- On `<decide>` receive, the library (a) installs the new set atomically at the `h → h+1` boundary, (b) persists it in the WAL as part of the `DECIDE` record, (c) re-derives the leader schedule for `h+1`.
- The out-of-band `UpdateParticipants` call is demoted to a test helper.

**Sequencing.** Depends on §W. Explicitly **not blocking** for the Fabric integration because Fabric's Registrar re-calls `HandleChain` on every config commit, which rebuilds the whole `*Consensus`. That's heavier than necessary but correct.

---

## Relationship to Fabric integration

Neither §W nor §B nor §S nor §D blocks `feature/bdls-consenter`. They are upstream library improvements that the Fabric consenter will pick up *for free* once they land, via a `go.mod` bump from `v1.0.0-fabric` to a future `v1.1.0-fabric`:

- §W: remove the "restart hits liveness, not safety" footnote from the Fabric README (Phase E).
- §B: no-op — Fabric will keep using blockcutter.
- §S: no-op — Fabric will keep using BlockPuller.
- §D: simplifies `orderer/consensus/bdls/consenter.go` HandleChain by letting us skip a full chain rebuild on every config commit.

---

## Proposed sequencing

1. **Finish the current Fabric integration milestone** (`feature/bdls-consenter` Phase D + E). This lands PR-A1/A2/A3 and `v1.0.0-fabric`, and gets the `BDLS` ConsensusType into a Fabric branch that runs end-to-end tests.
2. **PR-W1** — `bdls/wal` package in isolation.
3. **PR-W2** — wire WAL into `Consensus` + replay.
4. **PR-B1** — `bdls/batcher` package.
5. **PR-S1** — `CatchUp` + `SyncPeer`.
6. **PR-D1** — in-band reconfig records.

Steps 2–6 can be independently reviewed and landed. Cut `v1.1.0-fabric` once step 3 merges (the rest are additive).

---

## Out of scope for v2

- Threshold-BLS (paper's "linear authenticator complexity" headline). Revisit as v3.
- Chained BDLS analogue of chained HotStuff.
- Pipelined heights (proposing `h+1` before `h` finalises). Requires a correctness proof extension that is not in eprint 2019/1460.
- gRPC-native transport (currently embedder-supplied `PeerInterface`). Not worth the dependency churn for a library.
