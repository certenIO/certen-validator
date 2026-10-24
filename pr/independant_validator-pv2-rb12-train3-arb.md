# RB12-INDEX-B: the Arbitrum batch index (Train 3), with the fixes the index exposed in the reference reader

Branch `pv2/rb12-train3-arb`, cut from `pv2/rb12-train3` @b6cfa549 (Base capture index, reviewed PASS by V-INDEX-3), merges into train3.
Every sentence below is backed by a test named in the table at the end or by a command that is quoted; nothing is claimed that is not run.

## 0. What the live defect really is (corrects the ledger text of F8)

The ledger said `capture.LoadBatches` reads the whole table per leg. Measured on the live table (read-only, 2026-10-23): 57,081 rows / 1,265 MB on
chain 421614, of which **9,181 blob rows = 1,204 MB** and **3,229 batch rows = 4.2 MB**. LoadBatches reads the 4.2 MB (it grows linearly and is small).
The starvation is `Builder.locate`: it loads and brotli-decodes **every batch whose time bounds hold the leg's timestamp** before it can say that
no batch holds the leg. Every batch of the table has the same bounds, `maxTs - minTs = 87,168 s`, so a timestamp is inside the bounds of 713 to 1,100
(median about 1,010) batches: about 3 blob rows (131,168 B) each = **about 390 MB read and 590 MB reserved (RowCost 1.5x) per ask of a leg that no
batch holds** (a leg posted before the capture started, a block with no signed standard transaction, a block not posted yet but old). The memory budget
(2 GiB, shared by all builds) refuses such asks: the 24 legs at `finality_pending` / refused-by-budget.

The index therefore replaces the candidate decode, not only the batch listing: each batch is decoded **once**, ever, and a lookup reads the entries
(a few KB) of its window and the rows of the **one** batch it locates.

## 1. Design (design/RB12_CAPTURE_INDEX.md section 8, established from the code and the spec)

* **No new table, no migration.** Index rows are rows of `proof_finality_capture` under `idx/g<G>/arb/...`, all insert-only, all a pure function of captured
  rows + pins digest + generation; a different row under an existing key is the named `finality.ErrIndexConflict`.
  `f/<T>` block digest (T = L1 timestamp of the block, in the name), written **last** (it says "block whole and processed"); `e/<minTs>/<maxTs>/<N>` entry
  per batch at the batch's own captured key; `q/<N>` self-check quarantine; `u` unreadable-block record; `cursor`. Entry: status, pins digest, N, L1 block/hash,
  T, time bounds, data location, parts, batch tx index/hash, **length and SHA-256 prefix of the batch row it was made from**, segments, message count
  (the covered message range 0..messages-1), delayed count, and the sorted 8-byte **fingerprints** of the messages' signed-standard-transaction lists; checksum.
* **How a batch is located (established, not assumed).** The verifier binds neither a time window nor an absolute message position
  (`verify.go` verifyState; research A6.4: poster-reported message counts are not evidence). The builder narrows candidates by the batch's own time
  bounds and serves the first candidate in (N, L1 block, hash) order whose payload has a message with the block's transactions. The index reproduces that rule:
  candidates = entries with `minTs <= ts <= maxTs`, same order; a candidate is tried only if the fingerprint of the leg's standard-transaction list is in its entry.
  The fingerprint is a **pre-filter**: the batch it points to is judged by `Builder.matchCandidate`, the same function the reference loop now calls, so a
  collision costs one decode and can never serve a wrong batch. (Block number = message index is informational and is not used.)
* **The window = the reference's rule.** A lookup finds the L1 blocks that can hold a candidate by the L1 timestamp T of a batch's block (the SequencerInbox
  derives the bounds from it: `minTs = T - delay`, `maxTs = T + future`): T is in `[ts - futureCap, ts + delayCap]`, with `delayCap = 100,000 s` and
  `futureCap = 4,000 s` (production: 86,400 and 768; both in the pins digest). The first and last block of that range come from a **bisect over the digest names**
  (T grows with the block number), starting a first-scan slack (512 blocks) below the capture's first cursor row. The writer refuses a batch beyond a cap
  by name (`index_block_unindexable{window_beyond_cap}`): it can never silently drop a candidate the reference would have served. Boundaries are pinned (N found, N+1 not).
* **Trust model identical to Base.** The index is a locator. A wrong or missing row yields a named state or a pending, never an addendum the reference would
  not also produce; a missing entry is pending; there is no fallback answer path. `CERTEN_FINALITY_ARB_INDEX=off` (or a bad setting) leaves the reference reader
  (LoadBatches + the window decode) as the *named, announced* operator mode, and an AST test proves `LoadBatches` and `locate` are reachable from a build **only**
  in the `else` of `if b.Index != nil`.
* **Authorization (the F19 analog), stated precisely.** `SequencerBatchDelivered` is emitted by the SequencerInbox only after its own `isBatchPoster` check (or by
  `forceInclusion`, data location NoData, which carries no batch data). No pin names the posters and the capture holds no `isBatchPoster` storage proof; the
  verifier's authority is the Bridge accumulator (`verify.go:210-227`, annex A6.3 O3: `keccak256(beforeAcc || dataHash || delayedAcc)` must equal the proven
  `Bridge.sequencerInboxAccs[N]`), which only the SequencerInbox can write, after that check. So **THE rule is `capture.AuthorizeBatch`**: a record is PROVEN when a captured
  proof (account and storage verified under the state root of a header row that hashes to its key, proof block >= the batch's block) shows the slot equal to its
  afterAcc, FOREIGN when such a proof shows another value or an empty slot (an orphan reorg twin, an invented event), UNPROVEN otherwise (kept: the leg's verifier decides, and
  a batch without a proof is `l1_proof_window_unavailable`). It is the verifier's own rule applied earlier, so skipping a foreign record changes no verdict. One function,
  four callers: `Capturer.proveAt` (counts and logs a foreign record when it stores the proof), the reference `locate`, the indexed reader, and the index writer.
  The authorization comes **before** the N-hole: a hole is claimed only between two records the Bridge holds, so an invented record (a huge batch number) cannot make
  a leg that is simply not posted yet look like a capture gap.
* **Holes and parts.** A blob batch whose blob rows are not all stored is not digested and has no entry; a leg whose window holds it is told
  `l1_blob_unavailable` exactly as the reference tells it. A batch number missing between two Bridge-proven neighbours is `l1_capture_gap{gap_state=unrecorded}`.
  An unreadable block (`batch_row_malformed`, `header_row_malformed`, `blob_row_malformed`, `window_beyond_cap`) is recorded once, the cursor passes it, and a leg that is not found
  is told by name (`index_block_unindexable`): the reference simply fails on such a row (`LoadBatches` returns an error for every leg).
* **Determinism (class 11).** Bytes depend only on captured rows + pins + generation; test: different step sizes, a shuffled arrival order of rows (units atomic, blobs later)
  and a late arrival below the cursor write identical rows (cursor rows compared by their highest block only).

## 2. BEHAVIOUR CHANGES in the production reference path (intended, each with a fail-before test)

1. **A record a verified Bridge proof contradicts is no longer served** (`Builder.locate` skips it). Fail-before at b6cfa549:
   `TestRB12ArbReferenceReaderDoesNotServeARecordTheBridgeDoesNotHold` -> "the reference reader serves the record 49ded2ec that the Bridge does not hold".
   Live relevance: the table holds one reorg twin (N under two blocks).
2. **BuildFor uses the first proof AT OR AFTER the batch's own block** (it used `proofs[0]`, the lowest proof block). The capturer tries the head and the two blocks under it,
   so a batch captured in the head block can get a proof taken one block BELOW its event block, where the slot is still empty; the verifier then refuses the build although a later proof exists.
   Live: the h2 shape check finds **1 proof row below its batch's block** (J9). Fail-before: `TestRB12ArbBuildSkipsAProofTakenBelowTheBatchBlock` -> l1_state_unavailable.
3. **Proof listings are bounded** (`capture.LoadProofsFrom`, `AuthorizeStored`): ranges `[E, E+64]`, then `+1024`, `+16384`, then the rest, never below E, stopping at the first range
   that has a proof (authorization stops at the first range that PROVES). `ListByRange` is `WHERE chain=$1 AND l1_block BETWEEN $2 AND $3 AND starts_with(item,$4)`: an Index Only Scan of the primary key
   `(chain, l1_block, l1_hash, item)` bounded by the block range (the item prefix is a filter on the last key column), so the common listing touches about 65 blocks of keys and returns 1-3 rows
   (shape check J14 shows the plan on the live table). Test: `TestRB12ProofListingIsBoundedAboveTheBatchBlockAndWidensOnlyWhenEmpty`.

## 3. Runtime

* `CERTEN_FINALITY_ARB_INDEX` (default on) and `CERTEN_FINALITY_ARB_INDEX_GENERATION` (1..2^32-1) are read **outside** `envvar.Check`: a bad value is
  `finality_index_disabled{chain=421614, variable, reason, refused}` (F14's closed reasons; the value is never printed), announced at wiring (log, gauge
  `certen_finality_index_disabled{family="arb"}`, `/health/detailed` `index_disabled_reason`), and the validator runs on with the reference reader. The two step bounds both indexes share
  (`CERTEN_FINALITY_INDEX_BLOCKS_PER_STEP`, `..._STEP_SECONDS`) switch both off, each with its own state.
* `wireArb` sets `Builder.Index` and registers a **separate loop**, `ArbIndexLoop` (`arbitrum-sepolia/batch-index`), that steps the indexer every capture interval towards the highest capture
  cursor row under the process memory budget (`finality.Hold`, released by `defer`; one block, about 33 MB, at a time; a refused reservation ends the step: the index lags, it does not fail) and records
  a named inconsistency in the status table. Unlike the Base index (which runs inside the capture goroutine, V-INDEX note 1) a backfill of the whole table can therefore never delay a capture tick.
  `ArbPostedLoop` only notes `Report.BlobBlocks` (blocks whose blobs arrived) to the indexer (`LateBlockNoter`). Index rows are written through `env.Durable` (not counted against the per-leg capture bound).
* `validator finality-arb-index-selfcheck [--sample N]`: exit 0 ok, 1 mismatch (the entry is quarantined by an insert-only record every reader checks), 2 index off, 3 incomplete (budget refused rows; nothing judged for them), 4 could not run, 5 usage.
* Registry (`states.json`): three new `index_block_unindexable` reasons (`batch_row_malformed`, `header_row_malformed`, `window_beyond_cap`). **The certen-sdk byte-identical mirror owes the same edit (BETA re-syncs at Train 3).**
  `index_inconsistent` reasons are the existing ones and the F17 reason-aware table needs no new row.
* Metrics (family `arb`): through, lag, open, digests, entries, late, rebuilds, mismatches, conflicts, lookups{result}, lookup_bytes, step_seconds, selfcheck_skipped, unindexable{reason}, notes_dropped, disabled; all non-zero at the moment they move (scrape test).

## 4. Post-deploy checklist

1. `pr/rb11-prod-shape-check.sh` section (h2) before (done, read-only: 14 PASS, J9 WARN = the live proofs-below-batch row, J13 WARN = no index rows yet) and after the backfill (J13 must PASS).
2. Backfill of the live 3,276 batches: one block per step reserved and released, `CERTEN_FINALITY_INDEX_BLOCKS_PER_STEP` default 128 and a 15 s step budget bound each tick; expect the cursor to advance 128 batches per step (about 8 steps of 12 s per 1,000 batches when a batch costs the 7 ms measured on an unloaded host; the 15 s step budget stops a slower host at a block boundary). Watch `certen_finality_index_lag_blocks{family="arb"}` and `certen_finality_index_step_seconds` (measure the wall once on the real table).
3. `validator finality-arb-index-selfcheck --sample 4` must exit 0; record the exit code.
4. Rollback = `CERTEN_FINALITY_ARB_INDEX=off` (named, announced); rebuild = a new generation.

## 5. Train-3 integration (read, not merged: pv2/rb12-archive-backfill @e46ef7cc)

The archive backfill's Arbitrum prefix scan stores batches **below** the capture's first cursor row through the same `captureBatch`. To connect: (1) its stored blocks must be noted
(`finality.LateBlockNoter`, the interface the Base gap backfill already uses); (2) set `IndexReader.Floor` to the lowest block of its coverage rows (otherwise the time search starts 512 blocks below the first cursor row;
`TestRB12ArbIndexFloorHookCoversBatchesBelowTheCaptureStart`); (3) its `coverage()` verdict (a window that predates the capture) is consulted before the index's miss states; (4) its `Report` fields are additive to `Foreign` and `BlobBlocks`.

## 6. Assumptions and limits (named, not hidden)

* L1 block timestamps grow with the block number (a consensus fact) and every captured batch lies within 512 blocks below the capture's first cursor row (shape check J12; the `Floor` hook is the extension point).
* The time caps (100,000 s / 4,000 s) hold for the live SequencerInbox (86,400 / 768); a raised time variation is named `window_beyond_cap`, loudly, and needs a new generation with new caps.
* A hole is claimed only between two Bridge-proven records, so a hole next to a batch without a captured proof stays a plain pending.
* The index does not capture `isBatchPoster` storage proofs (see section 1; it would need new capture rows and provider calls).
* The incomplete-batch outcome stays `l1_blob_unavailable` (reference-equal and more specific than a gap).

## 7. Tests (claim -> test)

| claim | test (package arbposted unless stated) |
|---|---|
| indexed == reference over a population (60 legs x 10 timestamps), order, twins, window boundaries, skips | `TestRB12ArbIndexLocatesExactlyWhatTheReferenceLocates`, `...KeepsTheReferenceOrderOfBatches`, `...WindowBoundariesAreExact`, `...SkipsWhatTheReferenceSkips`, `...AnswersABlockWithoutStandardTransactionsLikeTheReference`, `...WithoutRowsIsANamedPendingNotAnAnswer` |
| real vector 883,753: indexed build == reference == recorded evidence, byte for byte; a missing blob is named alike | `TestRB12ArbIndexRealVectorBuildIsByteIdenticalToTheReferenceAndTheRecordedEvidence`, `...RealVectorMissingBlobIsNamedLikeTheReference` |
| 22 damage cases are named and never a different accept; the self-check names a lying entry and quarantines it | `TestRB12ArbIndexCorruptionIsNamedAndNeverAcceptsAnotherBatch`, `...SelfCheckNamesAnEntryThatLiesAndQuarantinesIt` |
| determinism and the named conflict | `TestRB12ArbIndexBytesAreAFunctionOfTheCapturedRowsOnly`, `...ConflictingRowIsTheNamedError` |
| one authorization for every reader; a foreign twin never shadows the one the Bridge holds (both orders) | `TestRB12ArbAuthorizationIsOneRuleForEveryReader`, `TestRB12ArbForeignTwinNeverShadowsTheBatchTheBridgeHolds` |
| behaviour changes 1 and 2 (fail-before at b6cfa549) | `TestRB12ArbReferenceReaderDoesNotServeARecordTheBridgeDoesNotHold`, `TestRB12ArbBuildSkipsAProofTakenBelowTheBatchBlock` |
| bounded proof listing | capture: `TestRB12ProofListingIsBoundedAboveTheBatchBlockAndWidensOnlyWhenEmpty` |
| late data, notes, floor, unreadable row, holes, forged number (fail-before at dc91b1e6) | `TestRB12ArbIndexFindsABatchWhoseBlobsArriveAfterTheCursorPassedIt`, `...NoteLateIndexesTheBlockAtTheNextStep`, `...FloorHookCoversBatchesBelowTheCaptureStart`, `...UnreadableBatchRowIsRecordedAndDoesNotStall`, `...MissingBatchNumberIsANamedCaptureGap`, `...ForgedBatchNumberCannotMakeAFalseCaptureGap` |
| names fit the production table | `TestRB12ArbIndexLongestNamesFitTheProductionTable`; pkg/database `TestFinalityCaptureIndexArbRowsFitTheProductionTable` (PostgreSQL) |
| the window is found by time in a 300-batch history with a 3-day outage | `TestRB12ArbIndexTimeMapFindsTheWindowInALongHistoryAndOutages` |
| the reference reader is unreachable with the index on; an indexed lookup reads no other batch's blobs | `TestRB12ArbReferenceReaderIsReachableOnlyThroughTheOffSwitch`, `TestRB12ArbIndexedLookupReadsOnlyTheBlobsOfTheBatchItLocates` |
| metrics | `TestRB12ArbIndexMetricsAreSetWhereTheyShouldBe` |
| runtime: settings, wiring, loop, self-check | runtime `TestRTBadArbIndexSettingsAreANamedDisabledStateNotAFatalStartup`, `...IsAnnouncedAndWiresNoIndexWhileTheArbChainStillRuns`, `TestRTArbIndexOffLeavesNoIndexerAndNoReaderAndOnWiresBoth`, `TestRTArbIndexLoopStepsTheBatchIndexTowardsTheCaptureCursorUnderTheMemoryBudget`, `TestRTArbLoopNotesTheBlocksWhoseBlobsArrived`, `TestRTArbIndexSelfCheckOnDemandNamesItsResult`; root `TestFinalityArbIndexSelfCheckUsageIsExitCode5` |
| cost flat in the table, equivalence at scale | `TestRB12ArbIndexCostIsIndependentOfTheTableAndEqualsTheReference` (numbers below) |

## 8. Measured (lazy production-shaped store; real encodings; 3 blob rows per batch; CERTEN_RB12_ARB_SCALES)

SCALE_NUMBERS_PLACEHOLDER
