# Stages 1–3 — Implementation Runbook

**Companion prompt:** `PHASE7_L5_CLAUDE_PROMPT.md`
**Date:** 2026-08-25
**Depends on:** Phase 6 (`c0e7112`) + `proofverify` (`7fb8413`), both deployed to all 7 validators
**Estimated:** ~1 day (Stage 1) + ~3 days (Stage 2) + ~2 days (Stage 3)
**Blast radius:** `pkg/consensus/`, `pkg/execution/`, `pkg/proof/`, `pkg/database/`,
`accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/`

> ⚠️ **The one rule inherited from Phase 6: this work changes no hash.**
> `pkg/execution/contracts/phase6_invariant_test.go` pins all ten govRoot slots and six
> struct shapes to literals. If it goes red, an edit widened a canonical struct. Revert
> that edit. **Never re-baseline those constants to make a test pass** — they are what
> every already-signed TX2 on the fleet commits to.

---

## 0. What these three stages are, and why in this order

Phase 6 established a pattern that all three stages reuse: **the conclusion goes in the
hash; the evidence goes beside it, in storage, where it can be checked.** That is the only
idea here. Each stage applies it to a different layer that is still stuck at "conclusion
only."

| Stage | What is broken today | What it is worth |
|---|---|---|
| **1 — Confirm correctness** | `TargetChainConfirmed` is a `bool`, so *"not confirmed yet"* and *"confirmed failed"* are the same value. A pending settle is logged as a failure that never gets retracted. | Correctness and observability. **It changes nothing about what is provable.** Cheapest by an order of magnitude. |
| **2 — Governance results** | `governance_proof_levels` does not contain the governance proof. The real `G0Result`/`G1Result`/`G2Result` never reach the database at all. | The largest of the three. G1 — *did the right key page authorize this* — is the product's central claim and is currently unpersisted in any checkable form. |
| **3 — L5-lite** | The external anchor coordinates are stored but nothing verifies them, and nothing proves *this* proof is in *that* anchored batch. | Makes an existing protection checkable. **It does not add a security property** — CERTEN already anchors the govRoot externally on every intent. |

**Order is not arbitrary.** Stage 1 is independent and cheap; do it first so the fleet stops
crying wolf while the other two are built. Stage 3 anchors the govRoot, and the govRoot
commits to G0–G2 — so what a governance proof *contains* (Stage 2) has to settle before you
build the layer that attests to it.

### 0.1 What none of these fix — state this plainly to anyone who asks

`Layer4.VerifyOffline` checks that every signer appears in `validatorSet` and that
`publicKeyHash == sha256(publicKey)`. Both the signatures **and the roster they are checked
against** come from the same document. That is internal consistency, not independent
establishment of the signing set.

Closing it requires an Accumulate validator-set history rooted at genesis. **No stage in
this runbook touches it**, and Stage 3 in particular must not be described as though it
does — an external timestamp attests to *whatever was signed*, and says nothing about
whether the signers were the right ones.

CERTEN's own validator set is in a much better position and should not be conflated with
Accumulate's: its root is on-chain (`currentValidatorSetRoot`, read via
`getValidatorSetRoot`, `pkg/execution/contracts/anchor_v6_1.go:51,140`) and compared at
submission. Its open question is governance of that root's rotation, not cryptographic
self-reference.

---

## Non-negotiable rules

1. **BACKUP FIRST.** Phase 0 below, including the `pg_dump`, verified before any edit.
2. **NO HASH MOVES.** Do not add, remove, reorder or retag any field of `ConsensusProof`,
   `L4LegSummary`, `G0Result`, `G1Result`, `G2Result`, or `GovReceiptData`.
   `CanonicalJSONMarshal` is `json.Marshal`, so struct layout IS the wire format.
   **`GovReceiptData` is the trap in Stage 2** — it is nested inside `G0Result` and
   therefore inside the G0/G1/G2 canonical hash. Adding `Entries` to it moves the govRoot.
3. **IF A GATE SHOWS govROOT MOVING, STOP.** Revert the edit. Do not update the constant.
4. **GATES ARE BLOCKING.** Gate N green before step N+1. Do not batch and check at the end.
5. **STORING IS NOT VERIFYING.** Every stage that stores evidence must also prove a
   *mutation of the stored bytes is rejected*. A test asserting fields are present proves
   nothing and must not be presented as a passing gate.
6. **NEVER FABRICATE HISTORICAL EVIDENCE.** The 1,106 historical G-levels and the 402
   `summary_only` proofs cannot be reconstructed. Mark them. A synthesized record is worse
   than an absent one, because the absent one is honest about what it does not know.
7. **ONE HELPER, EVERY CALL SITE.** Both orchestrators, and both G-level writers in
   `unified_orchestrator.go`, must call the same construction function. Two copies drift;
   that is how L4 came to be missing from one path already.
8. **NO SILENT PARTIAL WRITES.** Log loudly and write nothing rather than half a record.
9. **REPORT FAITHFULLY.** If a gate fails, say so with the output. If you skipped
   something, say that. The gates are executable — execute them.
10. **DEPLOY IS NOT YOURS.** Commit and push to `main`; the user pulls and rebuilds. DB
    migrations and server `.env` edits ARE yours. Never run `docker compose`,
    `git pull`, or `git reset` on a server checkout.
11. **USE base-sepolia FOR e2e** ($0.35 flat vs ~$3.30 on ethereum-sepolia).
12. **WATCH THE ELECTED EXECUTOR.** Settlement happens on ONE validator chosen by
    BFT-DETERMINISTIC. Find it (`grep -iE "is ELECTED|Selected executor"`), then read that
    node. **Confirmation lags the consensus-complete log — measured at 51s on 2026-08-25.**
    Check `chain_execution_results` and the chain before calling anything a failure. This
    lag is the subject of Stage 1; do not let it fool you while you are fixing it.

---

## Phase 0 — Safety (MANDATORY, do first)

### 0.1 Source backup

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator/accumulate-lite-client-2/liteclient/proof"
TS=$(date +%Y%m%d_%H%M%S); BK="_PROOF_BACKUPS/$TS"
mkdir -p "$BK"
cp -r working-proof_do_not_edit     "$BK/"
cp -r consolidated_governance-proof "$BK/"
cp healing_proof.go                 "$BK/"
(cd "$BK" && find . \( -name "*.go" -o -name "*.md" -o -name "*.MD" \) | sort | xargs sha256sum > MANIFEST.sha256)
echo "BACKUP: $(pwd)/$BK"
```

### 0.2 Gate 0 — backup integrity

```bash
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256 | grep -v ': OK$'
```

✅ No output — every line `OK`. ❌ Otherwise stop; re-take the backup.

### 0.3 Database backup

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker exec certen-postgres pg_dump -U certen -d certen_proofs \
     -t governance_proof_levels -t chained_proof_layers -t proof_artifacts \
     -t batch_transactions -t certen_anchor_proofs -t chain_execution_results \
     | gzip > /root/certen_proofs_stage123_$(date +%Y%m%d_%H%M%S).sql.gz \
   && ls -la /root/certen_proofs_stage123_*.sql.gz'
```

✅ A non-empty `.sql.gz`. This is the only rollback for a bad backfill or marking.

### 0.4 The govRoot baseline — the value all three stages must preserve

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator"
go test ./pkg/execution/contracts/ -run TestP6_ -count=1 -v 2>&1 | grep "invariant holds"
go test ./pkg/proof/ -run TestP5_GovRootMovesVersusZeroL4 -count=1 -v 2>&1 | grep "govRoot moves"
```

Record both. Today:
- fixture govRoot `bb293c644b31c0c2361ebd79a10a4996af870f430c6fc88c6b91f57d48b8cb59`
- production baseline `d375630fb8c1f224 -> e23ce1074f59ce28`

**Both must be identical at the end of Stage 3.**

### 0.5 Measured starting state — re-measure, do not trust this table

Captured 2026-08-25 after Phase 6 deployed. Re-run these before starting; if a number
disagrees, find out why before writing code.

```sql
SELECT count(*) total, count(merkle_root) root, count(leaf_hash) leaf,
       count(leaf_index) idx, count(merkle_path) path, count(batch_id) batch,
       count(anchor_tx_hash) atx FROM proof_artifacts;
SELECT verification_status, count(*) FROM proof_artifacts GROUP BY 1;
SELECT gov_level, count(*), count(*) FILTER (WHERE level_json::text LIKE '%entries%') ent
  FROM governance_proof_levels GROUP BY 1 ORDER BY 1;
SELECT count(*) FROM certen_anchor_proofs;
SELECT count(*) bt, count(merkle_path) bt_path, count(tree_index) bt_idx FROM batch_transactions;
SELECT count(*) ab, count(anchor_tx_hash) ab_atx, count(merkle_root) ab_root FROM anchor_batches;
```

| Fact | Value |
|---|---|
| `proof_artifacts` | 418 total; `merkle_root` 418; `leaf_hash` 418; `leaf_index` 383; **`merkle_path` 0**; **`batch_id` 0**; `anchor_tx_hash` 410 |
| `proof_artifacts.verification_status` | 402 `summary_only`, 9 `failed`, 6 NULL, 1 `verified` (the Phase 6 e2e proof) |
| `governance_proof_levels` | 400 G0 / 365 G1 / 365 G2; **0 rows contain `entries`**; 9 mention `receipt` |
| `certen_anchor_proofs` | **0 rows** |
| `batch_transactions` | 70,253 rows; `merkle_path` 70,253; `tree_index` 70,253 |
| `anchor_batches` | 67,847 rows; `merkle_root` 67,847; **`anchor_tx_hash` 0** |

### 0.6 Rollback

```bash
cd ".../liteclient/proof"
rm -rf working-proof_do_not_edit consolidated_governance-proof
cp -r "_PROOF_BACKUPS/<TS>/working-proof_do_not_edit"     .
cp -r "_PROOF_BACKUPS/<TS>/consolidated_governance-proof" .
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
# database:
zcat /root/certen_proofs_stage123_<TS>.sql.gz | docker exec -i certen-postgres psql -U certen -d certen_proofs
```

### 0.7 A PostgreSQL with the live schema (needed by every round-trip gate)

```bash
docker rm -f certen-p6-test 2>/dev/null
docker run -d --name certen-p6-test -e POSTGRES_USER=certen -e POSTGRES_PASSWORD=certen \
  -e POSTGRES_DB=certen_proofs -p 15433:5432 postgres:16
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker exec certen-postgres pg_dump -U certen -d certen_proofs --schema-only' > /tmp/schema.sql
docker exec -i certen-p6-test psql -U certen -d certen_proofs -q < /tmp/schema.sql
export CERTEN_TEST_DB="postgres://certen:certen@localhost:15433/certen_proofs?sslmode=disable"
```

Load the **full** schema, not a subset: `batch_transactions.batch_id` and
`proof_artifacts.anchor_id` are real foreign keys, and a relaxed copy hides fixture bugs
that production will not.

To reach **production** Postgres (it is not published on the host):

```bash
CID=$(ssh -i ~/.ssh/certen_server root@116.202.214.38 \
      "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' certen-postgres")
ssh -i ~/.ssh/certen_server -N -L 15434:$CID:5432 root@116.202.214.38 &
# password: docker exec certen-postgres printenv POSTGRES_PASSWORD
```

**Read-only queries only.** Kill the tunnel when done.

---

# STAGE 1 — Make "did not confirm" mean what it says

**Est. 1 day.** No schema change to the proof tables. No hash change. Independent of
Stages 2 and 3.

## 1.0 The defect, measured

Observed on intent `1638327d-af2c-439c-a188-be53cdb5c854`, 2026-08-25:

```
07:33:41  ⚠️ [BFT-CANONICAL] Consensus committed but target-chain execution did NOT
          confirm: intent=1638327d… targetChainError="" — gas may have been spent on a
          reverted transaction
07:33:41  ✅ Intent 1638327d… processed successfully and marked complete
07:34:32  chain_execution_results: base-sepolia status=1 block=45937480
```

**51 seconds.** The transaction was fine. Three separate defects produced that output:

**(a) The state is a bool.** `pkg/consensus/bft_integration.go:479`:

```go
TargetChainConfirmed bool `json:"target_chain_confirmed"`
```

Set at `:1631` from `anchorRes.AllTransactionsConfirmed`, after a **60-second** context at
`:1621`. There is no value for *"submitted, not yet resolved."* Not-yet and failed collapse.

**(b) The message asserts a cause it has no evidence for.** `:860-865`. At that moment
`anchorRes != nil` (it had just logged `External audit completed: tx=…`) and
`targetChainErr == nil` — hence `targetChainError=""`. A tx hash and no error is the
textbook signature of *pending*. "Gas may have been spent on a reverted transaction" is
speculation printed as a finding, in precisely the case with no evidence of a revert.

**(c) Nobody retracts it.** `go bv.RunProofCycle(...)` at `:1651` learns the truth
asynchronously and writes `chain_execution_results`. The database ends up right. The log
keeps its warning forever, and `pkg/intent/discovery.go:958` has already called
`markCompleted` and logged success.

**The empty `targetChainError` is the tell, and it is machine-readable.** That is the whole
fix: never infer FAILED from a timeout.

> This is the same class of error the comment at `bft_integration.go:466-478` was written
> to fix, one level down. That comment correctly split *consensus success* from *execution
> success* after the 2026-08-09 incident. It left *execution unknown* collapsed into
> *execution failed*.

## 1.1 Design

Introduce a tri-state. Do **not** delete `TargetChainConfirmed` — other code and the JSON
tag `target_chain_confirmed` may be read elsewhere; keep it as a derived accessor.

```go
// TargetChainOutcome distinguishes the three answers a bool cannot hold.
type TargetChainOutcome string

const (
    // TargetChainConfirmedOutcome: a receipt was seen and it succeeded.
    TargetChainConfirmedOutcome TargetChainOutcome = "confirmed"

    // TargetChainPending: SUBMITTED, no terminal receipt yet. This is NOT a
    // failure and must never be reported as one. Measured lag on base-sepolia
    // is ~51s against a 60s submit window, so pending is the ORDINARY case,
    // not the exception.
    TargetChainPending TargetChainOutcome = "pending"

    // TargetChainFailed: a receipt was seen and it reverted, or submission
    // itself errored. Only this value justifies saying gas was spent on a
    // reverted transaction.
    TargetChainFailed TargetChainOutcome = "failed"
)
```

**The classification rule, and it is the whole stage:**

| Evidence in hand | Outcome |
|---|---|
| submission returned an error | `failed` |
| receipt seen, status 0 | `failed` |
| receipt seen, status 1 | `confirmed` |
| tx hash present, no error, no receipt yet | **`pending`** |
| no tx hash, no error (never submitted) | `pending`, and say so differently |

A timeout is **never** evidence of failure. `AllTransactionsConfirmed == false` alone means
*"I did not see a receipt within my window"* — nothing more.

## 1.2 Edits

| # | File:line | Change |
|---|---|---|
| 1.2.1 | `pkg/consensus/bft_integration.go:466-484` | Add `TargetChainOutcome` field to `ExecutionTaskResult`. Keep `TargetChainConfirmed bool` as `outcome == confirmed`. Comment WHY the bool was insufficient, citing the 51-second measurement. |
| 1.2.2 | `pkg/consensus/bft_integration.go:1555-1663` | Replace `var targetChainConfirmed bool` with outcome classification per the table above. `anchorRes != nil && anchorRes.AnchorTxID != "" && targetChainErr == nil && !AllTransactionsConfirmed` → `pending`. |
| 1.2.3 | `pkg/consensus/bft_integration.go:858-866` | Three branches, not two. Pending must print the tx hash and say the proof cycle will record the terminal status. **Delete the gas-speculation sentence from the pending branch**; keep it only under `failed`. |
| 1.2.4 | `pkg/intent/discovery.go:955-959` | Do not log "processed successfully and marked complete" when the outcome is `pending`. Say settlement is in flight and name the resolver. |
| 1.2.5 | `pkg/database/intent_lifecycle_types.go:19-34` | Add `IntentLifecycleSettling = "settling"` between `in_process` and `complete`. Existing states: `submitted`, `pending_signatures`, `authorized`, `in_process`, `complete`, `failed` — there is no state for "consensus done, chain write in flight", which is why `complete` was overloaded. |
| 1.2.6 | `pkg/consensus/async_attestation.go` (`RunProofCycle`) | On terminal resolution, log the outcome against the **same intent ID** so the resolution sits next to the warning, and advance the lifecycle `settling → complete` or `→ failed`. |
| 1.2.7 | `pkg/consensus/batch_quorum_prover.go:239,434` and `pkg/consensus/async_attestation.go:619` | These construct `AnchorExecutionResult{AllTransactionsConfirmed: false}` for genuine failures. Make them carry `failed` explicitly so a real failure is never downgraded to `pending` by the new default. **This is the dangerous direction of the change — check each site individually.** |

> ⚠️ **1.2.7 is where this stage can do harm.** Making everything default to `pending` would
> mask a real revert. Each of those three sites is a *known* failure and must classify as
> `failed`. Read them; do not pattern-match.

**Do not touch** `pkg/verification/target_chain_executor.go:131-149`
(`AnchorExecutionResult`) or `pkg/execution/executor.go:228`. They report what the executor
observed, which is correct — the misinterpretation is downstream.

## 1.3 Migration `014_intent_lifecycle_settling.sql`

Only if `intent_lifecycle.status` has a CHECK constraint. Verify first:

```sql
SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid = 'intent_lifecycle'::regclass AND contype = 'c';
```

If a constraint enumerates the states, extend it to include `settling`. If none exists, no
migration is needed — write the file anyway to record intent, as `013` did, with the
version key matching the filename stem (the runner derives it that way,
`pkg/database/client.go:277`).

## Gate 1 — BLOCKING

**1a. Unit — the classification table, exhaustively.** New
`pkg/consensus/stage1_outcome_test.go`. Every row of §1.1 as a case. Explicitly:

```
tx hash + no error + no receipt  →  pending   (NOT failed)
submission error                 →  failed
receipt status 0                 →  failed
```

**1b. The gas sentence appears only under `failed`.** Assert on the rendered log string.
This is a real regression risk and a one-line test.

**1c. No lifecycle skips `settling`.** An intent may not go `in_process → complete` without
passing through `settling` on the on-demand path.

**1d. Existing suites unchanged:**

```bash
go build ./... && go test ./pkg/... -count=1
go test ./pkg/execution/contracts/ -run TestP6_ -count=1 -v   # govRoot must still hold
```

**1e. Live.** After deploy, run one base-sepolia e2e and read the elected executor:

```bash
node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'for i in 1 2 3 4 5 6 7; do docker logs --since 15m certen-validator-$i 2>&1 \
     | grep -iE "is ELECTED|Selected executor"; done'
```

✅ The pending line appears **with a tx hash**, and is followed within ~2 minutes by a
terminal line for the same intent ID.
❌ If the old "did NOT confirm … gas may have been spent" text appears for a transaction
that later reports `status=1`, the stage has failed.

---

# STAGE 2 — Persist the governance results, not a summary of something adjacent

**Est. 3 days.** This is the stage with the largest gap and the largest payoff.

## 2.0 The defect, measured — and why the earlier scoping was wrong

`docs/l4/PHASE6_RUNBOOK.md` Phase 7 says *"`ReceiptData.Entries` already exists and is
already populated in memory. Persist it into `level_json`."*

**That premise does not hold, and following it would polish a pipe that is not connected.**

Three measurements:

1. **The real G-results never reach the database.**
   `ComprehensiveData["g0Proof"]` is *read* at `pkg/execution/proof_cycle_orchestrator.go:1995,1998,2001`
   and **written nowhere** — grep the tree for a writer and it returns nothing. So
   `g0Data`/`g1Data`/`g2Data` are always `""` and that function always takes its stub
   fallback.

2. **The production writer never had them either.** The rows you actually see come from
   `pkg/execution/unified_orchestrator.go:2537-2545` (and a second writer at `~3395`),
   which builds `level_json` from `result.ObservationResults[0]` — **EVM observation data** —
   plus `txGovData` key-page thresholds. Confirmed by the stored key set:

   ```
   threshold_m, threshold_n, authority_url, confirmations,
   finality_achieved, inclusion_verified
   ```

   Those are verdict flags about an EVM settlement. **`governance_proof_levels` does not
   contain the governance proof.**

3. **0 of 400 G0 rows contain `entries`**; 9 of 400 mention `receipt` at all.

**The real G-results do exist upstream** — `pkg/consensus/async_attestation.go:66-68`:

```go
G0Proof *proof.G0Result
G1Proof *proof.G1Result
G2Proof *proof.G2Result
```

on `PendingAttestation`, populated at `bft_integration.go:1051,1066,…` from
`governanceProofGen.GenerateG0/G1/G2`, and carried into `RunProofCycle`.

**The structural break:** `ProofCycleCompletion`
(`pkg/execution/synthetic_transaction.go:920`) carries `Commitment`, `ExecutionResult`,
`Attestation` and the three anchor tx hashes — and **not** `CertenProof`, and **not** the
G-results. So they die at the boundary between the attestation and the persistence path.

**And separately, the merkle path is discarded at the source.**
`pkg/proof/governance_library.go:196` and `:234`:

```go
result.Receipt = GovReceiptData{
    Start:      hex.EncodeToString(txRecord.SourceReceipt.Start),
    Anchor:     hex.EncodeToString(txRecord.SourceReceipt.Anchor),
    LocalBlock: int64(txRecord.Received),
}
```

`txRecord.SourceReceipt` is a `*merkle.Receipt` that **has `.Entries`**. The path is in
memory and is dropped one line from where it is needed. Nothing needs re-querying.

## 2.1 The trap — read this before writing any code

`GovReceiptData` (`pkg/proof/governance_types.go:58-65`) is the `Receipt` field of
`G0Result` (`:215`). `G0Result` is embedded in `G1Result`, which is embedded in `G2Result`.
All three are hashed:

```go
// pkg/consensus/v6_1_signing.go:272-274, 439-441, 769-771
gb.SetG0FromJSON(certenProof.G0Result).
   SetG1FromJSON(certenProof.G1Result).
   SetG2FromJSON(certenProof.G2Result)
```

**Adding `Entries` to `GovReceiptData` moves the govRoot.** `TestP6_CanonicalShapesUnchanged`
blocks it, correctly. Do not "fix" that test.

**What is NOT hashed**, and is therefore where evidence goes:

- the `GovernanceProof` wrapper (`governance_types.go`, fields `Level`, `SpecVersion`,
  `GeneratedAt`, `G0`, `G1`, `G2`)
- `CertenProof` itself (`pkg/proof/certen_proof.go:44`)
- `LiteClientProofData`, `CompleteProof` — Phase 6 already hung `Layer4BVN`/`Layer4DN` here

This is the "non-hashed sibling": **a field on a struct that is not part of any canonical
hash, carrying the evidence next to the conclusion that is.** Phase 6 proved it works —
`layer4Bvn`/`layer4Dn` went onto `CompleteProof` and `e23ce107…` did not move.

## 2.2 Design

**2.2.1 A new evidence type, structurally separate from the hashed one.**

```go
// GovReceiptEvidence is the merkle path for a governance receipt.
//
// It is deliberately NOT a field of GovReceiptData: that struct is inside
// G0Result and therefore inside the G0/G1/G2 canonical hash, so widening it
// would move every govRoot ever signed. This type lives beside the hashed
// summary, never inside it — the same shape Phase 6 used for the L4 legs.
//
// Start/Anchor/LocalBlock are restated so the evidence is self-contained and a
// verifier never has to trust that it was paired with the right receipt.
type GovReceiptEvidence struct {
    Level      string       `json:"level"`      // "G0" | "G1" | "G2"
    Start      string       `json:"start"`      // hex32, the leaf
    Anchor     string       `json:"anchor"`     // hex32, the root
    LocalBlock int64        `json:"localBlock"`
    Entries    []ReceiptStep `json:"entries"`   // the merkle path
}
```

Reuse the `{hash, right}` step shape already used by `chained_proof.ReceiptStep` and the
consolidated `ReceiptData` (`consolidated_governance-proof/types.go:226-250`), so a stored
governance receipt and a fixture are the same document. **`right` is omitted when false**,
matching Accumulate's encoding — do not add `omitempty` semantics of your own.

**2.2.2 Carry it on the wrapper.** Add `Receipts []GovReceiptEvidence` to `GovernanceProof`
and/or `CertenProof`. Populate at `governance_library.go:196` and `:234` from
`txRecord.SourceReceipt.Entries` / `entry.Receipt.Entries`.

**2.2.3 Close the plumbing break.** Add `CertenProof *proof.CertenProof` (or the three
G-results plus the evidence) to `ProofCycleCompletion`, populated where the cycle is built
from `PendingAttestation`. **This is the actual fix** — everything else is downstream of it.

**2.2.4 Write the real results into `level_json`.** Both writers
(`proof_cycle_orchestrator.go:1982+` and `unified_orchestrator.go:2537,~3395`) must call
**one shared helper**, exactly as `WriteLayer4Rows` is shared:

```go
// pkg/execution/governance_levels.go
func BuildGovernanceLevelJSON(level string, g interface{}, ev *GovReceiptEvidence,
    existing map[string]interface{}) json.RawMessage
```

**Additive.** Keep every existing key (`inclusion_verified`, `finality_achieved`,
`threshold_m/n`, `authority_url`, `confirmations`) so the evidence report and approval
console keep working. Add `result` (the real `G*Result`) and `receipt` (the evidence).

**2.2.5 Make `VerifyReceiptMerkle` importable.** It lives at
`consolidated_governance-proof/receipt_merkle.go:76` in **`package main`** — not importable
by the validator. Move it to a real package. It only delegates to
`chained_proof.NewReceiptVerifier().ValidateIntegrity`, so the move also serves its own
stated goal of one receipt-recomputation implementation in the tree. **Keep the
single-leaf rule intact**: empty path is valid *only* when `start == anchor`; any other
empty path is an error, or every receipt verifies vacuously.

**2.2.6 Read path.** Extend `pkg/proof/chained_proof_storage.go` with
`GovernanceLevelsFromStorage(ctx, store, proofID)` returning the stored levels plus
evidence, and a typed `ErrGovernanceSummaryOnly` for rows that carry no `receipt` key —
mirroring `ErrSummaryOnly`. Wire it into `cmd/proofverify` as a `--governance` flag.

## 2.3 Migration `015_governance_receipt_evidence.sql`

`level_json` is already `jsonb`, so **no schema change is strictly required.** Write the
migration anyway to record intent and add the query projections:

```sql
ALTER TABLE governance_proof_levels
  ADD COLUMN IF NOT EXISTS receipt_entry_count integer,
  ADD COLUMN IF NOT EXISTS receipt_anchor      bytea;

COMMENT ON COLUMN governance_proof_levels.level_json IS
  'Verdict flags, PLUS the real G0/G1/G2 result under "result" and its merkle path under '
  '"receipt". Rows written before stage 2 have the flags only and are summary_only: their '
  'evidence was never captured and CANNOT be reconstructed.';
```

Same rule as `013`: the projections are for querying, `level_json` is authoritative.

## 2.4 Honest marking of the 1,106 historical G-levels

`docs/l4/mark_summary_only_proofs.sql` is the precedent. Count first, then mark:

```sql
SELECT count(*) FROM governance_proof_levels WHERE NOT (level_json ? 'receipt');
```

**Measured 2026-08-25: 1,106 rows.** Note that 400 + 365 + 365 = 1,130, so roughly 24 rows
already carry a `receipt` key from some other path — which is exactly why the rule is count
first and reconcile, not assume. Mark them; do **not** re-query
Accumulate to synthesize a receipt. The receipt fetched today is not necessarily the one
the proof was built on, and re-coupling a stored artifact to a live network is the
governance-layer version of reconstructing a historical validator set. Rule 6.

## Gate 2 — BLOCKING

**2a. govRoot unchanged.** `go test ./pkg/execution/contracts/ -run TestP6_ -count=1 -v` —
`bb293c64…`. **Run this after EVERY edit in this stage**, not just at the end.
`GovReceiptData` is one careless keystroke from moving it.

**2b. Shape test extended.** Add `GovReceiptEvidence` and the `GovernanceProof` wrapper to
`TestP6_CanonicalShapesUnchanged` as **explicitly NOT-hashed** types, with a comment saying
so, so a future reader cannot mistake which side of the line they are on.

**2c. Round trip, real Postgres, network disabled.** Modelled on
`pkg/execution/phase6_roundtrip_test.go`. Write a proof with G-levels, read back, recompute
each receipt from `level_json` alone.

**2d. Mutations — mandatory, not optional.** Each must be **rejected**:

| Mutation | Expected |
|---|---|
| flip a byte of a stored `entries[i].hash` | reject |
| flip `entries[i].right` | reject |
| drop one entry from the path | reject |
| empty the path while `start != anchor` | reject |
| alter the stored `anchor` | reject |
| graft another proof's G1 receipt | reject |

❌ If verification passes but a mutation is *not* rejected, the verifier is not running.
Do not proceed.

**2e. Historical rows read summary-only**, not `verified`, and not "failed."

**2f. Full suite:** `go build ./... && go test ./pkg/... -count=1`, plus
`go test ./proof/working-proof_do_not_edit/ -count=1` in the liteclient module.
The three pre-existing `consolidated_governance-proof` failures (`TestURLUtils`,
`TestG0Layer`, `TestCompleteWorkflow`) must fail **identically** — confirm, do not fix.
**If you move `VerifyReceiptMerkle` out of `package main`, re-confirm those three are
unchanged**, since you have touched that package.

---

# STAGE 3 — L5-lite: prove this proof is in the batch that was anchored

**Est. 2 days.** Build the lite version. **Do not build a light client.**

## 3.0 What this is and is not

**Accumulate does not anchor into Bitcoin or Ethereum.** Verified: every anchor type in
`accumulate-core/protocol/types_gen.go` is internal (`BlockValidatorAnchor:203`,
`DirectoryAnchor:322`, `PartitionAnchor:666`, `AnchorLedger:95`), and there is no
external-anchoring service in that tree. `AnchorLedger.MajorBlockIndex/MajorBlockTime` is
Accumulate's own periodic checkpoint, not a publication elsewhere. **Do not build this
stage waiting for that, and do not describe L5 as consuming it.**

**CERTEN already anchors externally** — `createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256)`
on base-sepolia, every intent. So the immutability/timestamp property **already exists**.
L5-lite does not add it; it makes it *checkable*, and closes the gap between "we have a tx
hash somewhere" and "here is the path proving this proof is in that anchored batch."

**Scope boundary, and hold it:** offline verification covers **leaf → batch root**. The
step from batch root → external chain is reported as *coordinates plus an optional online
check*, never claimed as offline. A trustless inclusion proof against an external block
header needs a light client, and "offline" becomes meaningless once you must trust a header
from somewhere. **Out of scope. Say so in the code comments.**

## 3.1 Measured state — the pieces mostly exist and are unjoined

| Piece | Where | State |
|---|---|---|
| leaf → batch-root merkle path | `batch_transactions.merkle_path` | ✅ **70,253 / 70,253** |
| leaf index | `batch_transactions.tree_index` | ✅ 70,253 / 70,253 |
| batch root | `anchor_batches.merkle_root` | ✅ 67,847 / 67,847 |
| external tx coordinates | `proof_artifacts.anchor_chain` / `anchor_tx_hash` / `anchor_block_number` | ✅ 410 / 418 |
| external tx + block + status | `chain_execution_results` | ✅ populated |
| proof → batch join | `proof_artifacts.batch_id` | ❌ **0 / 418** |
| batch → external tx | `anchor_batches.anchor_tx_hash` | ❌ **0 / 67,847** |
| per-proof merkle path | `proof_artifacts.merkle_path` | ❌ **0 / 418** (migration `006` added it; never written) |
| the assembled artifact | `certen_anchor_proofs` | ❌ **0 rows** (17 cols, incl. `anchor_ref_json`, `merkle_proof_json`) |

`certen_anchor_proofs` is the L5 slot, empty — exactly the state `chained_proof_layers`
layer 4 was in before Phase 6.

`merkle_path` is `[]database.MerklePathNode{Hash string, Position "left"|"right"}`
(`pkg/database/types.go:72-75`). Recomputation uses `pkg/merkle` (`hashPair`, `tree.go:158`;
`ComputeRoot`, `receipt.go:110`). **An empty path is legitimate for a single-transaction
batch** — the leaf is the root, as on the Phase 6 e2e proof, whose stored path is `[]`.
Handle it with the same rule as `VerifyReceiptMerkle`: empty is valid **only** when
`leaf == root`.

## 3.2 Design

**3.2.1 The layer type** — in the lite client, beside `Layer4`, in the same file style:

```go
// Layer5 binds a verified L1-L4 proof to its publication on an external chain.
//
// L4 ends at "a threshold quorum of Accumulate validators signed this state
// root." That is a CONSENSUS claim. It carries no evidence that the claim was
// published anywhere it cannot later be retracted, so it cannot by itself
// answer "was this history rewritten afterwards".
//
// L5 answers the part of that question CERTEN can answer: this proof's leaf is
// under a batch root, and that batch root was written to an external chain at a
// stated block. The leaf->root half verifies OFFLINE. The root->chain half is
// COORDINATES plus an optional online check — proving it offline would require
// a light client for the target chain, which is deliberately out of scope.
//
// It does NOT establish that the Accumulate validator set which signed L4 is
// the legitimate one. Nothing here does. See PHASE7_L5_RUNBOOK §0.1.
type Layer5 struct {
    ChainID     int64  `json:"chainId"`
    Network     string `json:"network"`
    AnchorTx    string `json:"anchorTx"`
    BlockNumber uint64 `json:"blockNumber"`
    BlockHash   string `json:"blockHash,omitempty"`

    BatchRoot string `json:"batchRoot"` // hex32 - what was anchored
    LeafHash  string `json:"leafHash"`  // hex32 - this proof's leaf
    LeafIndex uint64 `json:"leafIndex"`
    Path      []MerkleStep `json:"path"` // leaf -> batchRoot; empty iff leaf == root
}
```

**3.2.2 `VerifyOffline()`** — fail-closed, mirroring `Layer4.VerifyOffline`:

1. `leafHash` and `batchRoot` are 32-byte hex.
2. Empty `path` ⇒ require `leafHash == batchRoot`; otherwise reject.
3. Recompute leaf→root through `pkg/merkle`'s `hashPair`. **One implementation** — do not
   write a second.
4. Recomputed root must equal `batchRoot`.
5. `anchorTx` non-empty and `blockNumber > 0`, or the coordinates are not actionable.

It must **not** perform network access — same `deadDialer` harness.

**3.2.3 Storage.** Persist as `layer_number = 5`, `layer_name = "L5 - External Anchor"`,
through the **same** `WriteLayer4Rows`-style helper family in
`pkg/execution/layer4_rows.go`. Migration `013` deliberately added no CHECK on
`layer_number` precisely so a future L5 would not be rejected — that is this.

Also populate the joins that are currently NULL: `proof_artifacts.batch_id`,
`proof_artifacts.merkle_path`, `anchor_batches.anchor_tx_hash`. **These are the actual
plumbing defect** and are worth more than the new layer on its own.

**3.2.4 Do NOT add L5 to the govRoot.** `ComputeAccumulateGovRoot` is a fixed 10-slot,
352-byte preimage (`pkg/execution/contracts/v6_1_binding.go:264-284`) and the EVM contract
agrees with it. Adding a slot is a contract change and an atomic fleet upgrade. **Out of
scope.** L5 is storage and read-path only — and note the ordering problem that makes this
structural, not merely conservative: L5 describes the anchoring of a govRoot that must
already exist before the anchor is written. It cannot be inside what it describes.

**3.2.5 `proofverify --l5`.** Extend `cmd/proofverify`. Keep the exit-code discipline:
`0` verified, `3` summary-only, `1` failed. Add a **distinct** message for "L1-L4 verified,
L5 absent" — that is `summary_only` for L5, not a failure.

## 3.3 Migration `016_layer5_external_anchor.sql`

```sql
COMMENT ON COLUMN chained_proof_layers.layer_number IS
  '1..3 state layers; 4 = quorum signature leg (one per partition); 5 = external anchor '
  'binding (leaf -> batch root -> external chain tx). 0 records a failed L1-L3 attempt. '
  'No CHECK constraint: a future L6 must not be rejected by this table.';

CREATE INDEX IF NOT EXISTS idx_pa_batch_id ON proof_artifacts (batch_id)
  WHERE batch_id IS NOT NULL;
```

## Gate 3 — BLOCKING

**3a.** `Layer5.VerifyOffline` recomputes leaf→root, network disabled.
**3b. Single-leaf case**: empty path with `leaf == root` **passes**; empty path with
`leaf != root` **rejects**. Both directions — this is where a vacuous pass hides.
**3c. Mutations rejected**: flip a path hash; flip a position; drop a step; alter
`batchRoot`; alter `leafHash`; graft another proof's path.
**3d.** Six rows per new proof: 1, 2, 3, 4-BVN, 4-DN, 5.
**3e.** `proofverify --l5` on a live proof: leaf→root verifies and the external coordinates
match `chain_execution_results` for that proof.
**3f. govRoot unchanged** — `bb293c64…` and `e23ce107…`.

---

## Final gate — all three stages

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator"
go build ./... && go test ./pkg/... -count=1
go test ./pkg/execution/contracts/ -run TestP6_ -count=1 -v      # govRoot
CERTEN_TEST_DB=... go test ./pkg/execution/ -run 'TestP6_|TestS1_|TestS2_|TestS3_' -count=1 -v
cd accumulate-lite-client-2/liteclient && go test ./proof/working-proof_do_not_edit/ -count=1
```

✅ All green, except the three pre-existing `consolidated_governance-proof` failures, which
must fail **identically** to baseline.

| Definition of done | |
|---|---|
| A pending settle is never reported as a failure, and is resolved by a later line | Stage 1 |
| The real `G0Result`/`G1Result`/`G2Result` are in `level_json` | Stage 2 |
| Each stored G-level receipt recomputes from `level_json` alone; all six mutations rejected | Stage 2 |
| Historical G-levels read summary-only, not verified | Stage 2 |
| Six layer rows per new proof, `Layer5.VerifyOffline` green, all six mutations rejected | Stage 3 |
| `proof_artifacts.batch_id` / `merkle_path` and `anchor_batches.anchor_tx_hash` populated | Stage 3 |
| **govRoot byte-identical: `bb293c64…` and `e23ce107…`** | **all** |
| `ConsensusProof` / `L4LegSummary` / `G*Result` / `GovReceiptData` shapes unchanged | **all** |
| A live e2e on base-sepolia settles with `status = 1` | all |

---

## Deploy

Storage and read-path only. No govRoot move, therefore **no atomic-fleet requirement** —
which is exactly why the govRoot gate must be green before you believe that sentence.

1. Apply migrations `014`/`015`/`016` to production (**assistant's job**).
2. Commit and push to `main`. **Stop there.** The user pulls and rebuilds.
3. Verify the roll landed before running any live gate:
   ```bash
   ssh -i ~/.ssh/certen_server root@116.202.214.38 \
     'git -C /root/certen-validators log -1 --oneline;
      for i in 1 2 3 4 5 6 7; do printf "v%s: " $i;
        docker exec certen-validator-$i strings /app/validator | grep -c "<new-marker>"; done'
   ```
4. Run the historical marking (Stage 2), count first.
5. Run the live e2e and confirm Gates 1e, 3e.

---

## Explicitly out of scope

- **Adding an 11th govRoot slot.** Contract change + atomic fleet upgrade.
- **A light client for any external chain.** §3.0.
- **Accumulate validator-set history / genesis chain.** §0.1 — the largest remaining gap,
  and none of these stages touch it. Do not imply otherwise in code comments or reports.
- **Reconstructing historical evidence** of any kind. Rule 6.
- **Changing `layer4_verify.go`, `layer4_types.go`, or `ProofVerifier`.** The L1-L4
  verifier is correct and tested. Feed it; do not touch it.
- **The `ProofType: "chained_l1_l2_l3"` label** — inaccurate, persisted, filterable, and a
  separate decision.
