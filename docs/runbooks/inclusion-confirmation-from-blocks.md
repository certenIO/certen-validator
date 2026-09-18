# Runbook — decide a broadcast from committed blocks, not the tx index

> ## STATUS: IMPLEMENTED. §1 describes the defect as it was, not as it is.
>
> Steps 1–4 (the inclusion scan) and Step 5 (the strict `REQUIRE_BFT_COMMIT` default) are both written,
> and ship as **two separate releases** with a soak between them, as §3 and §5 require. §7 records what
> shipped, what differs, and what still needs a live fleet.
>
> §1's present tense is the state before this work. Nothing in it is a current defect.

Owner: validator (`pkg/consensus`). Base: `4fa751b` (origin/main).
Severity: medium. A committed ValidatorBlock can be reported as failed (false failure). Bundled with it:
an intent can today proceed **without** a proven commit, which is the more consequential default.

---

## 1. What is wrong

### 1a. The tx index can answer for the wrong copy (CONFIRMED, reproduced)

Verified against CometBFT v0.38.0 source:

- **A rejected tx leaves the mempool cache.** `mempool/clist_mempool.go:618-625`: a committed tx with a
  non-zero code is *removed* from the cache unless `KeepInvalidTxsInCache` is set; it defaults to false
  (`config/config.go:729,738-750`) and all three engine builders take `config.DefaultConfig()`
  (`bft_integration.go:1913, 2693, 3762`). So **identical bytes can be admitted again**.
- **The live indexer overwrites by hash.** The node's `IndexerService` calls `AddBatch`
  (`state/txindex/indexer_service.go:105`), and `AddBatch` (`kv.go:80-111`) always `Set(hash, …)`.
  **Last inclusion wins, in both directions.** (`TxIndex.Index` has a keep-the-success rule, but that path
  is not what the node uses — do not rely on it.)
- **Therefore:** inside one `submitValidatorBlock` call, copy 1 can be rejected at height H, copy 2 admitted
  and committed OK at H+1, while the poll reads copy 1's failure and returns
  `transaction failed in block: code=…`.

Realistic trigger: an entitlement **policy activation** between the two blocks
(`policy_update_apply.go:24-48`) — e.g. enforce→observe, or a new key added. Most other FinalizeBlock
rejections are deterministic and cannot flip.

**No false success is possible through the index:** an OK record can only exist if these exact bytes
committed OK, and each attempt's bytes are unique per second (`validator_block_builder.go:238` stamps
`Timestamp = time.Now()`).

### 1b. The real false-success risk (separate, worse)

`bft_integration.go:1389-1407`: when the inclusion poll times out (`Height == 0`), the intent **proceeds**
unless `REQUIRE_BFT_COMMIT=true`. Checked on the fleet: **not set on any validator**. So a
target-chain side effect can execute on a ValidatorBlock that was never proven committed.

---

## 2. Target design

**The committed blocks decide. The index is at most a hint.**

1. Record `h0 = Status().SyncInfo.LatestBlockHeight` **before** the first broadcast, and again before each
   attempt (`hAttempt`).
2. To resolve, scan committed blocks above `h0`: `BlockchainInfo` to skip empty ranges, then `Block` +
   `BlockResults` per candidate height; collect every inclusion of the hash, in order, with its code.
   (`rpcCommittedBlockSource` in `bft_broadcast_confirm.go` already reads blocks this way — share it.)
3. Decide:
   - **First OK inclusion → success** at that height, even if a later copy failed.
   - **Failure is final only if** no copy is still in the mempool **and** no attempt was admitted at or
     after that failure's height. Otherwise keep waiting inside the existing window.
   - **A block or result that cannot be read → `txLookupFailed`**, never "not found" (this repo already
     distinguishes those two; keep that).
4. Use it in both places: the lost-reply lookup and the Phase 2 inclusion poll.
5. Extend the `broadcastRPC` interface with `Status`, `BlockchainInfo`, `Block`, `BlockResults` — all
   present on `*cmthttp.HTTP`; keep the existing compile-time assertion
   (`TestCometHTTPClientSatisfiesTheBroadcastInterfaces`).
6. **Default `REQUIRE_BFT_COMMIT` to true** (fail closed, retryable). Keep an explicit opt-out.

Rejected alternatives:

| Alternative | Why not |
|---|---|
| Height floor on `rpc.Tx` alone | Both copies land above `h0`; last-write-wins still hides a success |
| Subscribe to the tx event | Subscriptions drop when buffers fill and do not survive a node restart; still needs the block scan behind it (worth adding later only to cut latency) |
| Nonce per attempt | Breaks the hash-identical dedup the lost-reply fix depends on, and lets two copies of one bundle commit |
| `KeepInvalidTxsInCache = true` | A transiently rejected block could never be resubmitted; combined with "already in cache" it becomes a false-success risk |
| Reject duplicate bundles in FinalizeBlock with a non-zero code | Changes a consensus rule (rules-version bump), and under `AddBatch` the failing duplicate would overwrite the OK index entry — making it worse |

---

## 3. Implementation

### Step 1 — extend the RPC seam

```go
type broadcastRPC interface {
    BroadcastTxSync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error)
    Tx(ctx context.Context, hash []byte, prove bool) (*coretypes.ResultTx, error)
    UnconfirmedTxs(ctx context.Context, limit *int) (*coretypes.ResultUnconfirmedTxs, error)
    Status(ctx context.Context) (*coretypes.ResultStatus, error)
    BlockchainInfo(ctx context.Context, minHeight, maxHeight int64) (*coretypes.ResultBlockchainInfo, error)
    Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error)
    BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error)
}
```

### Step 2 — `scanInclusions`

```go
type inclusion struct{ Height int64; Code uint32; Log string }

// scanInclusions returns every inclusion of hash in (fromHeight, tip], oldest first, and whether the
// scan was complete. An unreadable block or result makes complete=false; callers must not read absence
// from an incomplete scan.
func scanInclusions(ctx context.Context, rpc broadcastRPC, hash []byte, fromHeight int64,
    timing broadcastTiming) (found []inclusion, complete bool, err error)
```

- Bound the scan: at most `timing.maxScanBlocks` (default 200) and `timing.lookupTimeout` per RPC call.
- `BlockchainInfo` gives block metadata in ranges (max 20 per call); only fetch `Block`/`BlockResults`
  for heights whose `NumTxs > 0`.
- Match by `cmttypes.Tx(tx).Hash()` against the target hash, and read the code from
  `BlockResults.TxsResults[i]`.

### Step 3 — resolve

```go
func resolveOutcome(inc []inclusion, complete bool, admittedAt []int64, inMempool bool) outcome
```

- `outcome`: `committedOK(height)` | `failedFinal(height, code, log)` | `pending` | `unknown`.
- First OK wins. A failure is final only when `complete && !inMempool` and no `admittedAt >= failHeight`.
- `!complete` → `unknown` (caller keeps waiting or reports "admission could not be confirmed", which this
  repo already words correctly).

### Step 4 — wire into `submitValidatorBlock`

- Capture `h0` before the loop; capture `hAttempt` before each `BroadcastTxSync`.
- Lost-reply path: `scanInclusions` first; only fall back to `UnconfirmedTxs` for the "is it queued"
  question. Keep the existing `txLookupFailed` semantics (do not regress that fix).
- Phase 2: replace the `rpc.Tx` poll with `scanInclusions` + `resolveOutcome`. `rpc.Tx` may be used only
  to pick a starting height.
- Preserve today's return contract: `Height > 0` committed; `Height == 0` admitted/pending;
  `CheckTx failed: code=…` unchanged for rejections.

### Step 5 — strict commit by default

`bft_integration.go:1389`: invert to `os.Getenv("REQUIRE_BFT_COMMIT") != "false"`. Log once at startup
which mode is active. Update `docs/` and the compose/env templates.

**Note:** with §3 the pending window closes far more often, so the strict default should rarely trigger.
Deploy Steps 1–4 first, watch `Height == 0` frequency for 24 h, then flip Step 5.

---

## 4. Verification — proving it is 100% correct

Model the node with the **real** CometBFT pieces (`mempool.LRUTxCache`, `kv.TxIndex` on an in-memory DB)
plus a fake block store, so the tests encode CometBFT's actual semantics rather than assumptions.

### A. The defect and its neighbours

| # | Scenario | Expected |
|---|---|---|
| A1 | lost reply → copy 1 rejected at H → resend admitted → copy 2 OK at H+1 | success at H+1 (today: false failure) |
| A2 | both copies rejected | failure citing the later height |
| A3 | OK at H, then a failed duplicate at H+1 overwrites the index | **success at H** |
| A4 | inclusions at or below `h0` only | ignored (not this submission) |
| A5 | `BlockResults` pruned/unavailable mid-scan | `unknown` → "admission could not be confirmed", never "not in the mempool" |
| A6 | `Status` errors | treated as lookup failure, no crash, retry |
| A7 | empty blocks between inclusions | skipped without fetching them |
| A8 | scan cap reached | `unknown`, bounded time, no infinite loop |

### B. Regressions that must still hold (existing suite)

All 13 tests in `bft_broadcast_confirm_test.go` must pass unchanged, in particular:
`TestLostReplyForACommittedValidatorBlockIsSuccess`, `TestRetriesOutlastASlowCommit`,
`TestUnansweredLookupIsNotReportedAsAbsence`, `TestSlowCommitWithBlockedLookupsStillConfirmsInclusion`,
`TestHonoursTheCallersDeadline`, `TestCheckTxRejectionIsReportedWithoutRetry`.

### C. Mutation checks (each must fail a named test)

| Mutation | Must be caught by |
|---|---|
| Use `rpc.Tx` result directly as the verdict | A1, A3 |
| Treat `!complete` as "not found" | A5 |
| Drop the `h0` floor | A4 |
| First *failure* wins instead of first success | A1, A3 |
| Remove the scan cap | A8 (timing) |
| Revert `REQUIRE_BFT_COMMIT` to opt-in | E2 below |

### D. Timing

| # | Check | Gate |
|---|---|---|
| D1 | happy path, tx committed 1 block later | resolves in < 2 s, ≤ 3 RPC calls beyond the broadcast |
| D2 | 200-block scan | < `lookupTimeout` × cap, and inside the caller's 3-minute context |

### E. Live verification (Base Sepolia, FICTIONAL parties)

1. **Normal payment:** completes; validator logs show a committed height, no "admission could not be
   confirmed", no `[PERSIST]` warnings.
2. **Strict default:** with Step 5 deployed, grep 24 h of logs for
   `NOT committed within inclusion window` → each occurrence must be a genuine retry that later succeeded,
   never an executed side effect. `Height == 0` outcomes trend to ~0 after Steps 1–4.
3. **Induced slow commit** (staging only): add an artificial 20 s delay to a test build's Commit, run one
   intent, and confirm the broadcaster still resolves by inclusion and the intent completes.
4. **Policy-activation window** (staging): schedule an entitlement activation between two blocks, force a
   rejected-then-accepted pair, and confirm the intent is not failed.

---

## 5. Rollout and rollback

1. Steps 1–4 behind `INCLUSION_SCAN=on` (default on), one validator first, then the fleet.
2. Watch for 24 h: `Height == 0` counts, "admission could not be confirmed" counts, intent failure rate.
3. Then Step 5 (strict commit default) as its own small release.
4. **Rollback:** `INCLUSION_SCAN=off` restores the index-based path; `REQUIRE_BFT_COMMIT=false` restores
   the old permissive behaviour. No schema or consensus change is involved — nothing to migrate back.

**Consensus safety note:** none of this touches ABCI, the app hash, or FinalizeBlock. It changes only how
a node *observes* its own submission. A rolling deploy is safe and nodes may run mixed versions.

---

## 6. Sign-off checklist

- [x] A1–A8 green, using real `LRUTxCache` and `kv.TxIndex`.
- [x] All 13 existing broadcaster tests still green — the file is byte-for-byte unchanged.
- [x] Every mutation in C caught by its named test — each was applied and observed to fail.
- [x] D1–D2 within gates.
- [ ] E1 observed live; E3–E4 observed in staging. — **needs a fleet; see §7.3**
- [ ] 24 h of fleet logs reviewed before flipping `REQUIRE_BFT_COMMIT` (E2). — **the flip is a separate
      branch, deliberately unmerged until the soak is done**
- [x] Docs/env templates updated for the new default.

---

## 7. What actually shipped

### 7.1 Two releases, in order

| Release | Contents | Branch |
|---|---|---|
| 1 | Steps 1–4: the inclusion scan, behind `INCLUSION_SCAN` (default on) | `fix/inclusion-from-committed-blocks` |
| 2 | Step 5: `REQUIRE_BFT_COMMIT` defaults to required, startup log, env templates | `fix/require-bft-commit-by-default` |

They are deliberately separate. §3 says to deploy 1–4, watch the `Height == 0` rate for 24 h, and only
then flip the default — because the strict default is safe to the extent that the pending window has
already stopped closing spuriously. Merging both at once would skip that evidence.

### 7.2 The premise, checked rather than assumed

The whole change rests on two claims about CometBFT. Both are now asserted against the real types, not a
model of them:

- `TestRejectedTxLeavesTheRealMempoolCacheAndCanBeResubmitted` drives `mempool.LRUTxCache`: a rejected
  transaction is evicted and identical bytes are admitted again.
- `TestRealIndexerLetsAFailedDuplicateOverwriteASuccess` drives `kv.TxIndex` through `AddBatch`, the path
  the node's `IndexerService` actually uses, and observes the later FAILURE overwriting the earlier
  success. This test **passed** — it did not take its skip branch — so the false failure is real on
  CometBFT v0.38.0, not merely possible in principle.

### 7.3 Where the implementation differs from §3

**A rejection found during the submit loop is remembered, not returned.** §2.3 says a failure is final
only when nothing can still succeed. Applied literally at the moment of a lost reply, the first rejection
looks final — no later attempt has been made yet — and A1 would fail. But CometBFT evicted those bytes
from the cache *because* they were rejected, so a resend can still be admitted and commit. The rejection
is therefore held and reported only when the submit budget is out and no further copy can be offered.
That is what makes A1 (rejected at H, resend OK at H+1) resolve as a success while
`TestCommittedWithAFailureCodeIsReported` still reports `transaction failed in block: code=2`.

**The lost-reply path no longer consults the index at all.** §3 Step 4 says to fall back to
`UnconfirmedTxs` only for the "is it queued" question. The first implementation still fell through to
`lookupTxByHash`, which asks `rpc.Tx` first and treats a committed-with-failure-code as the verdict — the
original defect, reinstated one level down. `lookupMempoolOnly` now answers that question without the
index. This was caught by a test written specifically because mutation 1 escaped the first suite; see 7.4.

### 7.4 On the mutation table

All six mutations in §4.C were applied to the source and observed to fail their named tests.

Mutation 1 ("use the `rpc.Tx` result directly as the verdict") initially **escaped**: A1 and A3 are
scan-level tests, and the end-to-end fakes only ever had an index that answered "not found", so nothing
exercised an index that answered *wrongly* — which is the entire defect.
`TestTheIndexLyingAboutAFailureDoesNotOverrideTheBlocks` and its lost-reply twin were added to close that,
and they immediately failed against the then-current code, exposing the real bug described in 7.3. The
mutation is caught now in both the Phase 2 and lost-reply paths.

### 7.5 Not done

§4.E needs a live fleet: E1 (a normal payment), E3 (an induced slow commit in staging) and E4 (a policy
activation between two blocks in staging). E2 is the 24 h log review that gates merging release 2.

The race detector could not be run in the development environment (no C toolchain, `-race` requires cgo);
the suite was instead run repeatedly with `-count=5`.
