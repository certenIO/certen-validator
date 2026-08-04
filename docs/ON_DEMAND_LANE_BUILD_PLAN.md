# On-demand: intent-keyed batches

**Design and implementation plan.** Supersedes the earlier period-lane draft (a second batch
period at 5 blocks with a member cap of 1); §9 records why that shape was abandoned. The
on_cadence findings from that draft survive in §8.

---

## 1. The core insight

An on-demand batch holds exactly one intent. Its entire on-chain identity is therefore a pure
function of that intent — there is nothing to wait for, and no window to define.

```
leaf             = ComputeBatchLeaf(chainID, {ADIURL, ExecutionCommitment, OperationID})
batchRoot        = leaf                                    // N=1: MerkleRoot returns the leaf
leafCount        = 1
batchOperationID = keccak("certen:batchopid:v1" || OperationID)
accumulateHeight = the intent's own CommitHeight
bundleId         = keccak("certen:batchbundle:v1" || chainId || root || 1 || batchOpID || height)
merkleProof      = []                                      // empty branch; root == leaf
```

Every input is a property of the intent. No period, no ordering, no member cap, no truncation.

**This is not a workaround — the contract designs for it.** `CertenAnchorV8_1.createBatchAnchor`:

> *N=1 is a legitimate batch: a one-leaf tree whose root equals the leaf. Callers need no
> special case, and single/batch cannot drift apart into two code paths.*

And `MerkleRoot` in `batch_tree.go`:

> *N=1 returns the leaf itself, which is why a single intent needs no special case anywhere:
> its root equals its leaf and its branch is empty.*

`accumulateBlockHeight` is **unconstrained** by the contract — it is bound into the bundleId
derivation and stored, with no requirement that it be a period boundary
(`CertenAnchorV8_1.sol:759-812`). Using the intent's own commit height is fully valid.

### Why the determinism is *stronger* than the window design

Window-based membership requires every validator to agree on a **set**. A peer holding some but
not all of a period's members derives a different bundleId — that is the 2026-08-02 2-of-7
failure, and it is the entire reason `DefaultBatchSettleGrace` exists.

Intent-keyed membership requires only that a validator **holds the intent**. The derivation
cannot be perturbed by what else that validator does or does not have. There is no set to agree
on, so there is nothing for a settle grace to wait for.

That single property is what collapses the latency and most of the complexity.

---

## 2. What this deletes

Against the period-lane draft:

| Hazard in that draft | Here |
|---|---|
| Lane-scoped selection filter | **Gone** — lookup by key, no window |
| `periodKey` grace-map collision (every multiple of 100 is a multiple of 5) | **Gone** — no periods, no shared cutoff space |
| Retention expressed in periods (50 × 5 blocks ≈ 6 min) | **Gone** — wall-clock TTL |
| `batchLeaderFailoverPeriods = 3` meaning 21s in a 5-block lane | **Gone** — wall-clock failover |
| Pool-wide `PruneOlderThan` deleting the other lane's members | **Gone** — separate store (§4.1) |
| Lane-less persisted members + the step-5 migration gate | **Gone** — §7 |
| Settle grace as a blind 30s guess | Replaced by readiness retry (§4.4) |

**The on_cadence path is not modified at all.** Every file the period path touches —
`selectForPeriodLocked`, `PendingPeriods`, `periodKey`, `PruneOlderThan`,
`IsBatchPeriodLeader`, `flushChainPeriods` — keeps its current behaviour byte for byte. That is
the single largest risk reduction in this plan: the working path is not on the table.

---

## 3. Invariants

**I1 — One member is one intent on one chain.** A multi-leg intent spanning N chains is already
split into N members at enqueue (`batch_quorum_prover.go:325-341`), and `BatchMempool.add`
rejects any leg whose `ChainID` differs from the member's (`batch_mempool.go:262`). A 3-chain
on_demand intent produces **three independent intent-keyed batches**, each with its own leader,
anchor and settlement.

**I2 — Multi-leg is orthogonal.** N legs on one chain remain **one** member carrying the
multi-leg batch commitment (`ExecutionCommitment`: 1 leg → `computeSingleCommitment`, N legs →
`computeBatchCommitment`). Both nest inside the same leaf and both reach
`CertenAccountV7._authorizeLeaf` identically. Nothing here constrains leg count.

**I3 — The key is `(chainID, operationID)`, not `operationID`.** The same intent on two chains
yields two members with the same operationID. The leaf binds `chainID` and the bundleId binds
`chainId`, so they cannot collide — but every map, election and lookup must use the pair.

**I4 — The attester never builds from proposer data.** It receives a key, looks up **its own**
member, rebuilds, and signs only if its own derived bundleId matches. This is the security
boundary from `batch_attestation.go` and it is preserved exactly. It is in fact tightened: with
no window on the wire there is no width for a proposer to name at all.

**I5 — Uniqueness is free.** Two different intents produce different operationIDs → different
leaves → different roots *and* different batchOperationIDs → different bundleIds, even at the
same commit height. No collision, no truncation, no stranding.

---

## 4. Design

### 4.1 Storage — a separate index

`BatchMempool` gains a parallel structure for on_demand members:

```go
onDemand map[int64]map[[32]byte]*PendingBatchIntent   // chainID -> operationID -> member
```

Deliberately **not** the same pool with a lane filter. Keeping them separate is what guarantees
`selectForPeriodLocked` and `PruneOlderThan` cannot see an on_demand member, so the on_cadence
path needs no changes and no lane-scoping. Duplication cost is small (add / lookup / remove /
prune / persist); the payoff is that the proven path is untouched.

New methods: `AddOnDemand`, `GetOnDemand(chainID, opID)`, `RemoveOnDemand`,
`PendingOnDemand(chainID)`, `PruneOnDemandOlderThan(ttl)`.

Prune is a **wall-clock TTL** on `EnqueuedAt` (suggest 2h, matching the on_cadence horizon in
wall-clock terms), not a period count.

### 4.2 Routing at enqueue

`enqueueForBatch` derives proofClass via `certenIntent.GetProofClass()` and routes:

- `on_cadence` → `EnqueueForBatch` (existing, unchanged)
- `on_demand` → `EnqueueOnDemand` (new)
- anything else → **refuse the enqueue**, caller falls back. Never default a lane.

`TestEnqueueIsNotGatedOnProofClass` must keep passing in spirit: proofClass selects the *path*,
never whether to enqueue at all. Routing on_demand off the batch mechanism entirely cannot
settle a `CertenAccountV7` account, because `_authorizeLeaf` only ever computes the batch-form
leaf (`CertenAccountV7.sol:436-449`).

### 4.3 Submission — event-driven

Enqueueing an on_demand member signals a channel; a dedicated worker wakes immediately. No
period wait and no 15s sub-tick.

Per member, the leader:

1. Screens the account (`memberAccountUsable`) — same predicate as the period path. A failure
   is deterministic across validators (on-chain state) and routes to fallback.
2. Builds the one-leaf tree via the **existing** `BuildBatchTree(chainID, []{input}, commitHeight)`.
   No new derivation code — that is the point.
3. Collects quorum (§4.4).
4. `createBatchAnchor` → `executeComprehensiveProof` → per-leaf settlement, via the existing
   orchestrator.
5. Removes the member and attests, or routes to fallback on terminal failure.

A slow safety ticker (~60s) re-scans `PendingOnDemand` so a member whose event was lost to a
restart is still picked up.

### 4.4 Readiness retry replaces the settle grace

There is no co-member risk, so the only failure mode is *"the peer has not enqueued it yet"* —
measured at a **4-second** spread across all seven validators on 2026-08-04. A fixed grace is a
pessimistic guess at that; a retry measures it.

The collector already surfaces per-peer reasons (`batch_quorum_attestor.go:164`). Classify the
refusal:

| Refusal | Meaning | Action |
|---|---|---|
| member not held | Peer has not seen the intent yet | **Not-ready** — retry on backoff, does not consume an attempt |
| bundleId mismatch | Genuine disagreement on the intent's own data | Consume an attempt; **log loudly** — for N=1 this indicates a real bug, not a race |
| unreachable / timeout | Transient | Retry, bounded separately |

The attester must return a **distinguishable, structured** reason — a `Code` field on
`BatchAttestationResponse`, not a string match on prose.

Bound the whole thing with a **wall-clock deadline** (suggest 3 min) rather than a fixed attempt
count. On expiry → fallback. Expected latency to quorum: **~4–10s**.

### 4.5 Leadership and failover

Leader = deterministic hash of `(chainID, operationID)` over the roster — same construction as
`IsBatchPeriodLeader`, new domain string (`certen:ondemand:v1`), spreading gas across the set.
Multi-chain intents naturally get a different leader per chain.

Failover is **wall-clock**: if no anchor for that bundleId is observed within T, the next node
in the roster takes over. Duplicate anchors are absorbed — `createBatchAnchor` reverts
`AnchorAlreadyExists`, which the submitter already treats as success, and an already-attested
anchor short-circuits. So failover can be aggressive; the cost of over-eagerness is an
occasional wasted gas attempt, and the cost of under-eagerness is a stalled urgent intent.

T needs a measurement (§10), not a derivation. It must exceed one quorum-plus-anchor cycle by a
healthy multiple.

### 4.6 Attestation protocol

```go
type OnDemandAttestationRequest struct {
    ChainID     int64  `json:"chain_id"`
    OperationID string `json:"operation_id"` // hex — the lookup key, NOT member data
    BundleID    string `json:"bundle_id"`    // for comparison ONLY
    ProposerID  string `json:"proposer_id"`
}
```

Handler:

1. Look up **our own** member by `(chainID, operationID)`. Absent → refuse with
   `CodeMemberNotHeld` (the not-ready signal).
2. Rebuild leaf, root, batchOperationID, bundleId from **our** copy, at **our** member's
   `CommitHeight`.
3. Compare to `req.BundleID`. Mismatch → refuse with `CodeBundleMismatch`.
4. Sign the same 6-field pre-exec message via `ComputeEvmMessageHashV6_1_Pre` — unchanged.

Note step 2: the height comes from *our* member, never the request. That is what makes the
proposer unable to influence the derivation at all.

**A new handler and route, alongside the period one.** The existing
`HandleBatchAttestationRequest` is untouched.

---

## 5. Measured baseline (2026-08-04)

Source: `certen_proofs.intent_lifecycle` and `anchor_batches` on the production host, 533
intents back to 2026-03-04. Not estimates.

### 5.1 on_demand gets no expedited treatment today

p50 seconds, by day, `authorized → in_process` (the flush wait) and `in_process → completed`
(execute, settle, write back):

| Day | Class | n | Flush wait | Exec+settle | **Total** |
|---|---|---|---|---|---|
| 08-04 | on_demand | 20 | 379.8 | 51.0 | **431.4** |
| 08-04 | on_cadence | 4 | 377.8 | 51.3 | **429.0** |
| 07-29 | on_demand | 13 | 123.2 | 150.1 | 272.2 |
| 07-26 | on_demand | 17 | 72.0 | 148.3 | 220.1 |

**on_demand and on_cadence are statistically identical today** — 431s vs 429s. The expedited
class is not expedited. Worse, on_demand has **regressed**: 220s on 07-26 → 431s on 08-04, as it
moved onto the batch path and inherited the full 4-minute grace.

### 5.2 The flush side dominates — the "chain inclusion floor" concern is refuted

Flush wait is **379.8s of 431.4s = 88%** of end-to-end. Execute-settle-writeback is only
**51.0s**, and it *improved* (150s → 51s) between July and August. There is no large downstream
term hiding behind the flush optimisation.

### 5.3 Projection

| | Flush wait | Exec+settle | Total |
|---|---|---|---|
| Measured 08-04 | 379.8s | 51.0s | **431s** |
| Currently deployed, est. (§5.5) | ~145s | 51s | **~196s** |
| Intent-keyed | ~5–15s | 51s | **~56–66s** |

**6.5× against the measured regime, ~3× against the currently-deployed estimate.**

### 5.4 N=1 is empirically universal — and multi-leg is untested

`anchor_batches`, 45 days: on_demand is **`max_members = 1` across all 62,296 rows** on every
chain. The invariant this design rests on is not an assumption; it is what production has always
done.

Separately: **every intent in the last 45 days is `leg_count=1, n_chains=1`** (304 rows, both
classes). Multi-leg and multi-chain are supported by I1/I2 and covered by tests, but have **zero
production traffic**. Treat that path as unexercised.

### 5.5 Live trace against the currently-deployed build

Intent `0d76afa7`, opID `0x31da7b66…`, Sepolia, submitted 2026-08-04 19:00:43Z. Settled clean:
`1 settled, 0 failed`, anchor `0x965f5f1d…`, gas 278,069, quorum 7/7 (700/700 voting power).

| At | Event | Δ |
|---|---|---|
| 19:00:52 | authorized (lifecycle) | — |
| 19:01:02–19:01:07 | **enqueued on all seven — 5s spread** | +12s |
| 19:02:36 | period 6379300 observed closed; `solo member — grace 1m0s instead of 4m0s` | +104s |
| 19:03:50 | past grace → flushing | +178s |
| 19:04:01 | anchor created (gas 278,069) | +189s |
| 19:04:02 | **quorum 7/7 collected in 0.53s** | +190s |
| 19:04:28 | anchor attested; root spendable | +216s |
| 19:04:37 | `1 settled, 0 failed` → `in_process` | +225s |
| 19:05:28 | complete | **+276s** |

**Three things this pins down:**

1. **The solo-grace commit is live and working** — 431s → 276s. The earlier ~145s estimate in
   this section was optimistic; the real figure is 276s.
2. **The 5s enqueue spread and the 0.53s quorum collection are the readiness-retry evidence.**
   Every peer held the member and answered in half a second. A retry loop would clear in
   single-digit seconds; the 60s grace is waiting for something that finished 55 seconds earlier.
3. **The decomposition corrects §5.3.** What the lifecycle calls "flush wait" contains both the
   period+grace *and* the anchor/quorum/attest/settle work:

| Segment | Measured | Intent-keyed |
|---|---|---|
| authorized → enqueued (discovery + proof pipeline) | 12s | unchanged |
| enqueued → period closed | **92s** | **0** — no period |
| grace + sub-tick | **74s** | **~5s** — readiness retry |
| flush → settled (tree, anchor mined, quorum, attest, TX3) | 47s | unchanged |
| settled → complete | 51s | unchanged |
| **Total** | **276s** | **~115s** |

So the honest projection is **276s → ~115s (2.4×)**, or 3.7× against the pre-solo-grace 431s
regime — not the ~60s §5.3 implied, because 47s of anchor-and-settle work sits inside the
"flush wait" column and is untouched by this design. §5.3's table is superseded by this one.

Still unmeasured: the failover T in §4.5, which needs a leader to actually fail.

### 5.6 VERIFIED LIVE — intent-keyed lane enabled, 2026-08-04 21:41Z

`ON_DEMAND_INTENT_KEYED=true` on all seven. Both lanes settled clean, end to end, with writeback
to Accumulate.

| Intent | Lane | Flush wait | Exec+settle | **Total** | Wrote back |
|---|---|---|---|---|---|
| `0d76afa7` | on_demand via PERIOD (baseline) | 225s | 51s | **276s** | ✓ |
| `db439b53` | on_demand **intent-keyed** | **64.9s** | 51.9s | **116.8s** | ✓ |
| `0fef33eb` | on_cadence (period, unchanged) | 140.3s | 51.2s | **191.5s** | ✓ |

**276s → 116.8s, a 2.4× improvement.** §5.5 projected ~115s; actual 116.8s.

The `db439b53` trace, on leader validator-7:

| At | Event |
|---|---|
| 21:40:19–21:40:27 | enqueued on all seven as `ON-DEMAND intent-keyed` (8s spread) |
| 21:40:25.855 | **one-member batch formed 0.5s after enqueue** — no period, no grace |
| 21:40:38.278 | anchor created, gas 278,081 |
| 21:40:38.905 | **quorum 7/7, 700/700 — all six peers attested on the FIRST attempt, zero retries** |
| 21:41:01.464 | anchor `0x5ce0e7bc…` attested; root `0x3d3833a0…` spendable |
| 21:41:13.665 | member settled, tx `0x87c04cb7…` |
| 21:41:13.668 | Phase 7-9 replay → complete, written back |

All nine phases confirmed: L1–L4 proof, G0/G1/G2 governance proofs, A+++ BLS signature (gov=G2),
canonical BFT consensus execution, Phase 7-9 cycle, Accumulate writeback.

**What the readiness retry actually did: nothing.** Every peer already held the member when the
leader asked, so the quorum formed on attempt one. That is the design working as intended — the
60s solo grace it replaced was pure dead time, exactly as §5.5's 5s-spread/0.53s-quorum
measurement predicted.

**Incidental validation of the persistence path.** `db439b53` was submitted while the flag was
still off and was mid-discovery when the containers were recreated. The discovery watermark
rewind re-derived it under the new binary, it routed to the on-demand lane, settled, and a later
re-discovery correctly logged `already completed, skipping`. The restart cost nothing.

---

## 6. Implementation — BUILT (commit `7184d7e`)

All five steps are implemented, formatted, vetted and green across the whole module. The lane is
**OFF by default** (`ON_DEMAND_INTENT_KEYED` unset), so the deploy is a no-op until the flag is
set. Files added: `batch_mempool_ondemand.go`, `batch_attestation_ondemand{,_client}.go`,
`batch_orchestrator_ondemand.go`, `batch_ondemand_submitter.go` (+ five test files).

Deviations from the plan as written, and why:

- **No `Lane` field on `PendingBatchIntent`.** The structure holding a member is the single
  authority on its lane; a second copy on the member could disagree with it. `BatchLane` exists
  only as the persistence discriminator and the routing vocabulary.
- **`SettleOnDemandMember` reuses FlushChain's primitives rather than extracting its body.** It
  calls the same `memberAccountUsable`, `anchorAlreadyAttested`, `verifyLeavesAgainstAccounts`,
  `createBatchAnchor`, `verifyLeavesAgainstAnchor`, `settleMember` in the same order, so the
  security-critical checks have one implementation. What it does not inherit is FlushChain's
  member-lifecycle logic (requeue-some-drop-others, per-period attempt counters, partial tree
  outcomes) — all of which is about sets and meaningless at N=1. **FlushChain itself is
  unmodified.**
- **`BatchQuorumAttestor.prove` was extracted** so both lanes share one aggregate-and-submit
  body. That is where a quorum forgery would have to get past (CRYPTO-007), and a second copy
  for on-demand would be a second place for the registry check to weaken.

### Step detail

**Step 1 — Storage.** `onDemand` index on `BatchMempool` + methods + TTL prune. Persist as a
sibling array in the snapshot. No behaviour change; nothing writes to it yet.
- `TestOnDemandIndexIsInvisibleToPeriodSelection`
- `TestOnDemandPruneDoesNotTouchPeriodPool`
- `TestOnDemandTTLIsWallClock`

**Step 2 — Derivation, pinned.** No new code — assert the existing primitives against the
contract for N=1.
- `TestSingleMemberRootEqualsLeaf`
- `TestSingleMemberBranchIsEmptyAndVerifies` — `VerifyBranch([], root, leaf)`
- `TestSingleMemberBundleIDMatchesSolidityVector` — extend the existing
  `CertenBatchTreeVector.t.sol` vectors to N=1
- `TestBundleIDIsPureFunctionOfIntent` — same intent, two mempool states, identical bundleId
- `TestDistinctIntentsAtSameHeightGetDistinctBundleIDs`
- `TestSameIntentOnTwoChainsGetsDistinctLeavesAndBundleIDs` (I3)

**Step 3 — Attestation handler + response codes.** Handler live on all seven; nobody proposes
this shape yet, so it is inert. Add `Code` to `BatchAttestationResponse` and populate it in the
**existing** period handler too, so the classifier has structured input on both paths.
- `TestHandlerRefusesUnheldMemberWithNotHeldCode`
- `TestHandlerRebuildsAtItsOwnCommitHeightNotTheRequests`
- `TestHandlerRefusesBundleMismatch`
- `TestPeriodHandlerStillBehavesIdentically` (regression)

**Step 4 — Proposer, worker, leader, readiness retry.** The first step that changes behaviour.
Ship behind `ON_DEMAND_INTENT_KEYED=false`.
- `TestNotHeldDoesNotConsumeAnAttempt`
- `TestBundleMismatchDoesConsumeAnAttempt`
- `TestDeadlineExpiryRoutesToFallback`
- `TestLeaderDiffersPerChainForOneMultiChainIntent`
- `TestFailoverTakesOverAfterT`
- `TestMultiLegSingleChainStaysOneMember` (I2)

**Step 5 — Routing.** `enqueueForBatch` routes on proofClass; unknown class refuses. Flip the
flag.
- `TestOnDemandRoutesToIntentKeyedPath`
- `TestOnCadenceStillRoutesToPeriodPath`
- `TestUnknownProofClassRefusesEnqueue`

---

## 7. Persistence — no migration needed

Add `lane` to `persistedMember`, absent ⇒ on_cadence, and persist on_demand members as a sibling
array. **Both directions are safe, which is why there is no migration gate here.**

- **Old file, new binary:** every member loads as on_cadence and takes the period path. Correct
  — that is exactly where on_demand intents go *today* (they are enqueued into the period
  mempool regardless of proofClass).
- **New file, old binary:** the unknown field is ignored by `encoding/json` and on_demand
  members are simply absent from the array the old binary reads. It recovers them through the
  discovery watermark rewind, which is its existing behaviour.

The earlier draft needed a "lane-less count = 0" gate because a lane-less member could default
into a lane that *behaved differently*. Here the default lands on the path that member would
have taken anyway, so the hazard does not arise.

`Load` already degrades to re-derivation on a corrupt or unreadable file
(`batch_mempool_store.go:205-212`); that backstop is unchanged.

---

## 8. On_cadence — two findings that still stand

Independent of this work, and worth their own investigation:

**`MinBatchSize` and `MaxAge` are dead config.** `FlushDueChains` is the only caller of
`DueChains`, and it is not invoked in production — `RunFlushLoop`'s flush closure iterates
`s.Resolver.Chains()` directly. The comment at `batch_assembly.go:606` claiming RunFlushLoop
drives FlushDueChains is stale. So "flush early once you have 16" does not exist in the live
path and `MaxAge` (5 min) never fires.

**on_cadence amortisation is real but thin — and absent on two of three chains.** Measured
(`anchor_batches`, 45 days):

| Chain | Batches | Avg members | Max | Solo |
|---|---|---|---|---|
| ethereum-sepolia | 246 | 2.25 | 8 | 57 (23%) |
| arbitrum-sepolia | 7 | 2.29 | 4 | 0 |
| base-sepolia | 19 | **1.00** | **1** | **19 (100%)** |

Sepolia averages 2.25 members — a genuine ~2.25× on the 81.2% of gas that `createAnchor` +
`executeComprehensiveProof` represent, trending flat (2.46 → 2.00 over the last two weeks). So
the earlier hypothesis that on_cadence amortises *nothing* was too strong and is withdrawn.

But **base-sepolia is 100% solo across every batch**: it pays 429s of latency for zero
amortisation. On that chain on_cadence is strictly worse than on_demand would be, and the
size-trigger fix applies directly.

---

## 9. Why not the period-lane approach

For the record, since it was the first proposal. A second period at 5 blocks with a member cap
of 1 reaches ~35–52s and requires: lane-scoped selection, a lane field in `periodKey`, a
lane-scoped `PruneOlderThan`, retention re-expressed in blocks, `batchLeaderFailoverPeriods`
re-expressed in blocks (with a measurement to pick it), a versioned leader-key change requiring
all seven to roll together, and a persisted-lane migration gated on a counter.

Every one of those is a modification to the **working on_cadence path**, and four of them fail
silently. The intent-keyed design reaches ~5–15s while touching none of it. The period was never
load-bearing for a one-member batch; it was inherited from a mechanism built for sets.

---

## 10. Open items

- **DONE — baseline measured** (§5). Flush wait is 88% of end-to-end; the chain-inclusion-floor
  concern is refuted. Proceed.
- **One intent through the current build** (§5.5). No traffic has run since the solo-grace
  deploy, so the ~145s current-baseline is derived, not observed — and the failover T in §4.5
  still has no data. One on_demand intent yields both. This gates step 4, not steps 1–3.
- **Gas.** Each on_demand intent pays a full `createAnchor` + `executeComprehensiveProof` —
  802,128 of 987,644 gas (81.2%) with nothing to amortise against. That is the deliberate
  on_demand trade, but confirm the multi-leg case against `gas_ceiling_test.go`: the ~$0.25/proof
  figure assumes one intent, not one intent with N legs across N targets.
- **Failover aggressiveness.** Duplicate anchors are absorbed, but each costs a reverted
  transaction's gas. Pick T from measured data.
- **`verifyProof` with an empty branch.** `VerifyBranch([], root, leaf)` reduces to
  `leaf == root` in Go; confirm `CertenAnchorV8_1._verifyMerkleProof` does the same for a
  zero-length array before step 4. Pin it with a Solidity vector.
