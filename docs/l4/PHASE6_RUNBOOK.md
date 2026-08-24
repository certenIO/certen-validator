# Phase 6 — Implementation Runbook

**Companion to:** `PHASE6_PERSISTENCE_PLAN.md`
**Date:** 2026-08-24
**Estimated:** 6.5 working days (6.5 / step 5 is the largest single item)
**Blast radius:** `pkg/database/`, `pkg/execution/{proof_cycle,unified}_orchestrator.go`, `pkg/proof/liteclient_adapter.go`, `consolidated_governance-proof/`

> ⚠️ Every step is gated. Do not proceed past a failed gate — roll back and diagnose.
>
> ⚠️ **The one rule of Phase 6: it changes no hash.** If any gate shows govRoot
> moving, you have widened a canonical struct. Stop and revert that edit — do
> not "re-baseline" the expected value.

---

## Phase 0 — Safety (MANDATORY, do first)

### 0.1 Backup

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator/accumulate-lite-client-2/liteclient/proof"
TS=$(date +%Y%m%d_%H%M%S); BK="_PROOF_BACKUPS/$TS"
mkdir -p "$BK"
cp -r working-proof_do_not_edit     "$BK/"
cp -r consolidated_governance-proof "$BK/"
cp healing_proof.go                 "$BK/"
(cd "$BK" && find . -name "*.go" -o -name "*.md" -o -name "*.MD" | sort | xargs sha256sum > MANIFEST.sha256)
echo "BACKUP: $(pwd)/$BK"
```

### 0.2 Gate 0 — backup integrity

```bash
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
```

✅ Every line reports `OK`. ❌ Otherwise stop; re-take the backup.

### 0.3 Database backup — this phase writes to PostgreSQL

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker exec certen-postgres pg_dump -U certen -d certen_proofs \
     -t chained_proof_layers -t proof_artifacts -t batch_transactions \
     | gzip > /root/certen_proofs_phase6_$(date +%Y%m%d_%H%M%S).sql.gz && ls -la /root/certen_proofs_phase6_*.sql.gz'
```

✅ A non-empty `.sql.gz`. This is the only rollback for a bad backfill.

### 0.4 Capture the govRoot baseline — the value the whole phase must preserve

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator"
go test ./pkg/proof/ -run TestP5_GovRootMovesVersusZeroL4 -v 2>&1 | grep "govRoot moves"
```

Record both values. Today: `d375630f… -> e23ce107…`. **The right-hand value must
be identical at the end of Phase 6.**

### 0.5 Rollback procedure (keep visible)

```bash
cd ".../liteclient/proof"
rm -rf working-proof_do_not_edit consolidated_governance-proof
cp -r "_PROOF_BACKUPS/<TS>/working-proof_do_not_edit"     .
cp -r "_PROOF_BACKUPS/<TS>/consolidated_governance-proof" .
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
# database:
zcat /root/certen_proofs_phase6_<TS>.sql.gz | docker exec -i certen-postgres psql -U certen -d certen_proofs
```

---

## Phase 1 — Characterization (before any edit)

Write tests that pass against the **current** code. They are the regression net.

### 1.1 The govRoot invariant test

`pkg/execution/contracts/phase6_invariant_test.go`:

- Build `AccumulateGovRootInputs` from a fixed, hardcoded proof fixture.
- Assert each of the 10 slots equals a golden hex constant.
- Assert `ComputeAccumulateGovRoot` equals a golden root.

Hardcode the goldens as literals. Do **not** compute the expected value from
the same code path under test — that would pass no matter what moved.

### 1.2 The canonical-shape test

Reflect over `ConsensusProof`, `L4LegSummary`, `G0Result`, `G1Result`,
`G2Result`, `ReceiptData`. Assert field **names, order and json tags** against a
golden slice. Any widening fails here with a readable diff.

### 1.3 The current-storage test

Pin today's behaviour so the change is visible: exactly 3 layer rows written,
`layer_json` keys as they are now, blob keys as they are now.

### Gate 1

```bash
go test ./pkg/execution/contracts/ ./pkg/proof/ ./pkg/database/ -count=1
```

✅ All pass against unmodified code. ❌ If 1.1 fails now, the baseline is wrong —
fix the test, not the product.

---

## Phase 2 — Migration and repository (step 6.2)

### 2.1 Write `pkg/database/migrations/013_layer4_persistence.sql`

Exactly as `PHASE6_PERSISTENCE_PLAN.md` §4. `ADD COLUMN IF NOT EXISTS`
throughout so re-running is safe.

### 2.2 Extend the repository

`NewChainedProofLayer` gains `SignatureCount`, `Threshold`, `SignedHash`.
`CreateChainedProofLayer` writes them. The read side gains
`GetChainedProofLayers(proofID)` returning all rows ordered by `layer_number`.

### 2.3 Apply to a scratch database first

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker exec certen-postgres psql -U certen -d certen_proofs -c "CREATE DATABASE certen_proofs_p6 TEMPLATE certen_proofs;"'
```

Apply 013 there, confirm, then apply to the real database.

### Gate 2

```sql
\d chained_proof_layers
SELECT count(*) FROM chained_proof_layers;   -- unchanged from Phase 0
```

✅ Three new columns present, all NULL, row count unchanged.
✅ `go test ./pkg/database/ -count=1` passes.

---

## Phase 3 — Write the L4 rows (step 6.3)

### 3.1 `proof_cycle_orchestrator.go`

Replace the hardcoded `for layer := 1; layer <= 3` (≈line 1930) so that after
L1–L3 it writes two more rows from `chainedProof.Layer4BVN` / `Layer4DN`:

- `LayerNumber: 4`
- `LayerName: "L4-BVN - Quorum Signature"` / `"L4-DN - Quorum Signature"`
- `BVNPartition: leg.Partition`
- `LayerJSON:` the full `Layer4`, marshalled with its own tags
- `SignatureCount`, `Threshold`, `SignedHash` for querying

**Nil legs are not "skip".** If a leg is nil at this point the proof should not
exist — `RequireL4Committed` rejects it upstream. Log loudly and write no row;
never write a half row.

### 3.2 `unified_orchestrator.go`

Same, at the L1/L2/L3 block (≈2779–2844).

### 3.3 Both paths, one helper

Put the row construction in ONE function used by both orchestrators. Two
copies will drift, which is how L4 came to be missing from one of them.

### Gate 3

Live run: submit one intent (see Phase 6 below) and

```sql
SELECT layer_number, layer_name, bvn_partition, signature_count, threshold
FROM chained_proof_layers
WHERE proof_id = '<new>' ORDER BY layer_number;
```

✅ Five rows: 1, 2, 3, 4 (BVN1), 4 (Directory).
✅ Gate 1 still green — **especially 1.1**.

---

## Phase 4 — Complete the travelling blob (step 6.4)

### 4.1 Add the legs to `complete_proof`

In `pkg/proof/liteclient_adapter.go` (`ChainedProofToCompleteProof`), carry
`Layer4BVN` / `Layer4DN` through as `layer4Bvn` / `layer4Dn`, matching the
testdata fixtures exactly.

> **Do not touch `BuildL4ConsensusProof` or `summarizeL4Leg`.** They produce the
> govRoot payload. This step adds a sibling field on a different struct.

### 4.2 Confirm the blob is what travels

`batch_transactions.chained_proof` is written by the batch assembly path;
confirm the new fields survive that serialization rather than assuming it.

### Gate 4

```sql
SELECT (chained_proof::text LIKE '%sequencedMessage%') AS seq,
       (chained_proof::text LIKE '%validatorSet%')     AS vset,
       (chained_proof::text LIKE '%publicKeyHash%')    AS pkh,
       length(chained_proof::text)                     AS bytes
FROM batch_transactions ORDER BY created_at DESC LIMIT 1;
```

✅ `t | t | t | ~18000`.
✅ Gate 1.1 still green.

---

## Phase 5 — Read it back and verify offline (step 6.5) — THE PHASE

### 5.1 `ChainedProofFromStorage`

In `pkg/proof/`, reassemble a `chained_proof.ChainedProof` from the stored rows
and blob. Prefer the blob when both are present; fall back to the rows;
return a typed `ErrSummaryOnly` when layer-4 evidence is absent.

### 5.2 Verify with the network disabled

Feed the result to the **unmodified** `ProofVerifier`, in the same
network-disabled harness `offline_verify_test.go` already uses.

### 5.3 Negative tests — mandatory, not optional

Storing evidence and checking evidence are different claims. Prove the second:

| Mutation | Expected |
|---|---|
| flip one byte of a stored signature | reject |
| drop a signature below threshold | reject |
| substitute a validator not in the set | reject |
| alter stored `stateTreeAnchor` | reject |
| alter stored `sequencedMessage` | reject |
| graft another proof's stored DN leg | reject |

### Gate 5 — the gate the phase exists for

```bash
go test ./pkg/proof/ -run 'TestP6_StoredProofVerifiesOffline|TestP6_StoredProofRejects' -count=1 -v
```

✅ A proof read from PostgreSQL verifies with no network access, and every
mutation above is rejected.
❌ If verification passes but a mutation is *not* rejected, the verifier is not
actually running — do not proceed.

---

## Phase 6 — Honest marking and live e2e (steps 6.6, 6.8)

### 6.1 Mark the historical proofs

```sql
UPDATE proof_artifacts SET verification_status = 'summary_only'
WHERE proof_id NOT IN (SELECT DISTINCT proof_id FROM chained_proof_layers WHERE layer_number = 4)
  AND verification_status = 'verified';
```

Run the `SELECT` form first and record the count. Expected: **365**.

> Never reconstruct historical L4 evidence. See plan §3.5.

### 6.2 Live end-to-end

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator"
node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand
```

Use **base-sepolia** ($0.35 flat vs ~$3.30 on ethereum-sepolia). Watch the
elected executor, not just validator-1:

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs --since 15m certen-validator-1 2>&1 | grep -E "DETERMINISTIC|Selected executor"'
```

then read that validator's logs for the settlement.

### 6.3 Verify the new proof end to end

```bash
go run ./cmd/proofverify --proof-id <new> --offline
```

### Gate 6

| Check | Expected |
|---|---|
| settlement on-chain | `status = 1` |
| layer rows | 5 (1,2,3,4-BVN,4-DN) |
| offline verification of the NEW proof | passes |
| historical proofs | `summary_only`, count 365 |
| **govRoot (Gate 1.1)** | **unchanged** |

---

## Phase 7 — Governance receipts (step 6.7, separable)

`governance_proof_levels.level_json` stores verdict flags
(`inclusion_verified`, `finality_achieved`, `threshold_m/n`) but not the
receipt entries, so a G-level cannot be recomputed from storage either.

`ReceiptData.Entries` already exists and is already populated in memory (it was
added in Phase 4C, and its lack of `omitempty` is what moves G0 unconditionally
— see `PHASE5_PLAN.md` §1.2). Persist it into `level_json`.

> **`ReceiptData` is inside the G0/G1/G2 canonical hash.** Adding a field to the
> struct moves the govRoot. Persisting the field that already exists does not.
> Gate 1.1 and 1.2 both apply here.

### Gate 7

`VerifyReceiptMerkle` recomputes each stored G-level receipt from `level_json`
alone, and the seven Phase-4C mutations are all rejected.

---

## Phase 8 — Deploy

Storage-only. No govRoot move, therefore **no atomic-fleet requirement** —
which is exactly why Gate 1.1 must be green before you believe that sentence.

1. Apply migration 013 to production.
2. Roll the fleet (rolling restart is acceptable this time; confirm with a
   `git log -1` on `/root/certen-validators` that every node is on the same
   commit afterwards).
3. Run 6.1 marking.
4. Re-run 6.2 and confirm Gate 6.

### Final gate

```bash
go build ./... && go test ./pkg/... -count=1
cd accumulate-lite-client-2/liteclient && go test ./proof/working-proof_do_not_edit/ -count=1
```

✅ All green, except the three pre-existing failures in
`consolidated_governance-proof` (`TestURLUtils`, `TestG0Layer`,
`TestCompleteWorkflow`) which fail identically at baseline `adb5cae` and are
stub tests pointing at a literal `"test"` endpoint.
