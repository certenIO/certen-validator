# Phase 6 — Persist the L4 evidence, so a stored proof verifies offline

**Status:** SCOPED, not started
**Date:** 2026-08-24
**Depends on:** Phase 5 (`1b9b7fa`) + the typed-nil fix (`4356344`), both deployed
**Blast radius:** storage and read paths only. **This phase must not move govRoot.**

---

## 0. The one-line summary

L4 is built, verified in flight, and committed into the governance root — but
what lands in PostgreSQL is the *conclusion* of the quorum check, not the
evidence for it. A verifier reading the database can recompute L1→L2→L3 and
read what L4 concluded, and cannot independently re-verify that a validator
quorum ever signed anything. Spec §4 ("A governance proof MUST be verifiable
offline") is therefore still unmet for L4 on the persisted artifact.

---

## 1. What is actually stored — measured, not assumed

Measured against proof `b7a48634-733a-4999-84eb-06d2c84db112`
(intent `8347416f…`, the P5.7 run that settled on ethereum-sepolia).

| Location | Carries | Recomputable offline? |
|---|---|---|
| `chained_proof_layers` rows 1/2/3 | `receipt_entries` = **17 / 24 / 25** merkle siblings | **yes** |
| `chained_proof_layers` row 4 | **does not exist** | — |
| `batch_transactions.chained_proof.complete_proof` | `main_chain_proof`, `bpt_proof`, `bvn_anchor_proof`, `dn_anchor_proof`, `combined_receipt` | yes |
| `batch_transactions.chained_proof.consensus_proof` | `v: certen:l4gov:v1`, both legs: partition, threshold, sorted signers, `signedHash`, `rootChainAnchor`, `stateTreeAnchor`, `minorBlockIndex` | **no — conclusions only** |
| `governance_proof_levels.level_json` | `threshold_m/n`, `authority_url`, `inclusion_verified`, `finality_achieved` | **no — verdict flags** |
| `proof_artifacts.artifact_json` | 188 bytes of settlement metadata | n/a |
| `proof_artifacts.merkle_path` | **NULL** | n/a |
| `certen_anchor_proofs` | **0 rows** | n/a |

Absent from every one of them, verified by direct substring test over the
stored blob (`signature=f, validatorSet=f, publicKeyHash=f`):

- `Layer4.Signatures` — the ed25519 signatures themselves
- `Layer4.ValidatorSet` — who was eligible, and on which partition
- `Layer4.SequencedMessage` — the canonical signed bytes
- `Layer4.AcceptThreshold` / `NetworkVersion` — the network's own rational

Those five are exactly what `layer4_verify.go` consumes. Without them the
stored proof cannot be checked; it can only be believed.

### 1.1 Why the summary is not the evidence, by design

`healing_proof.go` says so itself, and is right to:

> Only the conclusions: the legs themselves hold ~2KB of canonical signed bytes
> plus the full validator set, **which a verifier needs** but which would couple
> this hash to incidental encoding.

That reasoning is correct **for the govRoot payload** and must not be revisited
— widening `ConsensusProof` would move every govRoot again. The error is having
no *second* home for the evidence the same comment says a verifier needs.

### 1.2 The capability exists and is tested — it is only unreachable from storage

`testdata/proof_bvn1.json` and `proof_bvn3.json` DO carry signatures and
validator set, and the offline verifier passes against them: network disabled,
**34** targeted mutations rejected, **4** cross-bind grafts rejected.

Phase 6 is plumbing, not cryptography. Nothing in
`working-proof_do_not_edit/layer4_verify.go` needs to change.

---

## 2. Size — measured from the fixtures

| Component | proof_bvn1 | proof_bvn3 |
|---|---|---|
| layer1 / layer2 / layer3 | 1,484 / 3,497 / 4,219 B | 1,574 / 4,666 / 3,860 B |
| **layer4Bvn** | **1,899 B** (1 sig, 3 validators, 352 B seqMsg) | **1,896 B** |
| **layer4Dn** | **4,100 B** (3 sigs, 3 validators, 1,940 B seqMsg) | **4,392 B** |

**~6 KB of L4 evidence per proof.** Today's stored blob is 12,681 B; complete
it and it becomes ~18.7 KB — a 47% increase on a jsonb column, at 365 G2 proofs
to date. This is not a capacity problem. Do not compress, do not truncate, do
not sample: a partially stored leg is unverifiable, which is the state we are
leaving.

`SequencedMessage` and `ValidatorSet` dominate and both grow with the validator
set, so size scales with the network, not with traffic.

---

## 3. Design

### 3.1 The invariant that governs this whole phase

> **Phase 6 changes what is written and read. It changes no hash.**

`ConsensusProof` / `L4LegSummary` is the govRoot preimage
(`CanonicalJSONMarshal` is `json.Marshal`, so struct layout IS the wire format).
Any field added to it moves `L4ConsensusProofH`, moves govRoot, and forces a
second atomic fleet upgrade. Phase 6 must therefore:

- **not** add, remove, reorder or retag a single field of `ConsensusProof`,
  `L4LegSummary`, `G0Result`, `G1Result`, `G2Result`, `ReceiptData`
- store the evidence **beside** the summary, never inside it

This is pinned by a blocking gate (§6, P6.1) that computes govRoot before and
after and requires byte equality.

### 3.2 Where the evidence goes

Two candidate homes. **Recommendation: both, for different readers.**

**(a) `chained_proof_layers` rows for layer 4 — the queryable home.**

The table already has `receipt_anchor`, `bvn_partition`, `layer_json` and
`verified`. Two rows per proof: `layer_number = 4`, `layer_name =
"L4-BVN - Quorum Signature"` / `"L4-DN - Quorum Signature"`, `bvn_partition`
set to the signing partition, full `Layer4` JSON in `layer_json`.

The blocker is a hardcoded loop, not a schema limit:

```go
// pkg/execution/proof_cycle_orchestrator.go:1930
for layer := 1; layer <= 3; layer++ {
    names := []string{"", "L1 - Transaction to BVN", "L2 - BVN to DN", "L3 - DN to Consensus"}
```

`LayerNumber: 4` appears nowhere in the codebase. `unified_orchestrator.go`
(~2779–2844) has the same 1/2/3 shape and needs the same extension.

`layer_number` is `integer` with no CHECK constraint and `layer_json` is
`jsonb`, so **no migration is strictly required for (a)** — add one anyway to
record intent (§4).

**(b) `batch_transactions.chained_proof.complete_proof.layer4Bvn` / `layer4Dn`
— the self-contained home.**

This blob is what actually travels; `chained_proof_valid` is already computed
over it. A verifier handed this one column should be able to finish the job
with no second query.

Doing only (a) leaves the travelling artifact incomplete. Doing only (b) leaves
L4 unqueryable and keeps `chained_proof_layers` claiming a three-layer proof.

### 3.3 Serialization

Reuse `chained_proof.Layer4`'s existing JSON tags verbatim — the same shape the
offline verifier and the testdata fixtures already use. Write the fixtures'
exact field names (`layer4Bvn` / `layer4Dn`) so a stored proof and a fixture are
the same document, and the existing verifier runs on both with no shim.

### 3.4 Read path

`ChainedProofFromStorage(proofID) (*chained_proof.ChainedProof, error)` —
reassemble L1–L4 from storage and hand it to the **unmodified** `ProofVerifier`.

This is the function that converts "we store more" into "we can prove it", and
it is what P6.5 exercises.

### 3.5 Backfill

365 G2 proofs predate this. Their L4 evidence was never persisted and **cannot
be reconstructed**: `SequencedMessage` and the historical validator set are not
recoverable from what was kept, and re-querying Accumulate returns *today's*
validator set, not the one that signed.

Do not fabricate it. Mark them honestly instead —
`verification_status = 'summary_only'` for proofs whose layer-4 rows are absent.
A verifier must be able to tell "not verifiable from storage" from "verified".

---

## 4. Migration

```sql
-- 013_layer4_persistence.sql
ALTER TABLE chained_proof_layers
  ADD COLUMN IF NOT EXISTS signature_count integer,
  ADD COLUMN IF NOT EXISTS threshold       integer,
  ADD COLUMN IF NOT EXISTS signed_hash     bytea;

COMMENT ON COLUMN chained_proof_layers.layer_number IS
  '1..3 state layers; 4 = quorum signature leg (one row per partition, BVN and DN)';

CREATE INDEX IF NOT EXISTS idx_cpl_proof_layer
  ON chained_proof_layers (proof_id, layer_number);
```

The three columns exist for querying ("show me proofs whose DN leg had fewer
than 3 signers"); the authoritative evidence is `layer_json`. No CHECK
constraint on `layer_number` exists today — do not add one that would reject a
future L5.

---

## 5. Work breakdown

| # | Item | Files | Est. |
|---|---|---|---|
| 6.1 | Characterization tests: pin current govRoot + current stored shape | new `_test.go` | 0.5 d |
| 6.2 | Migration 013 + repository support for layer 4 | `pkg/database/` | 0.5 d |
| 6.3 | Write L4 rows in both orchestrators | `proof_cycle_orchestrator.go`, `unified_orchestrator.go` | 1 d |
| 6.4 | Add `layer4Bvn`/`layer4Dn` to the `complete_proof` blob | `pkg/proof/liteclient_adapter.go`, batch assembly | 1 d |
| 6.5 | `ChainedProofFromStorage` + round-trip offline verification | `pkg/proof/` | 1.5 d |
| 6.6 | `summary_only` marking + backfill script | `pkg/database/`, `scripts/` | 0.5 d |
| 6.7 | Governance receipts: store `ReceiptData.Entries` in `level_json` | `consolidated_governance-proof/` | 1 d |
| 6.8 | Live e2e + gates | — | 0.5 d |

**~6.5 working days.** 6.7 is separable and may ship after 6.1–6.6.

### 5.1 Ordering

1. **6.1 first, always.** The govRoot equality gate must exist before any edit.
2. 6.2 → 6.3 → 6.4 are storage-only and safe to land incrementally; nothing
   reads the new data yet, so none of them changes behaviour.
3. 6.5 is the payoff and the proof the phase worked.
4. 6.6 must land before anyone treats `verification_status = verified` as
   meaning "offline-verifiable".

---

## 6. Verification plan

| # | Gate | Method |
|---|---|---|
| **P6.1** | **govRoot byte-identical before and after the phase** | build inputs from one fixed proof pre/post; assert equality on all 10 slots AND the root. **Blocking.** |
| P6.2 | `ConsensusProof` / `L4LegSummary` shape unchanged | reflect over the struct; assert field names, order and tags against a golden list |
| P6.3 | Two layer-4 rows written per proof | live run; assert `layer_number = 4` count = 2, partitions distinct |
| P6.4 | Stored blob carries full L4 | assert `signature`, `validatorSet`, `publicKeyHash`, `sequencedMessage` all present |
| **P6.5** | **A proof read back from storage verifies offline** | `ChainedProofFromStorage` → `ProofVerifier`, **network disabled**. This is the phase. |
| P6.6 | A tampered stored proof is rejected | mutate a stored signature byte, a validator key, `stateTreeAnchor`; each must fail |
| P6.7 | Cross-bind still rejected from storage | graft another proof's stored DN leg; must fail |
| P6.8 | Pre-Phase-6 proofs read `summary_only` | assert the 365 historical proofs are not reported as offline-verifiable |
| P6.9 | Size within budget | assert stored blob < 32 KB |

P6.1 and P6.5 are the two that matter. P6.1 says we broke nothing; P6.5 says we
fixed the thing we set out to fix.

---

## 7. Risks

| Risk | Severity | Handling |
|---|---|---|
| A field is added to `ConsensusProof` "while we're in there" | **critical** — moves govRoot, reverts every TX2 on a mixed fleet | P6.1 + P6.2, both blocking |
| Storing evidence is mistaken for verifying it | high | P6.5 must run the real verifier, not a field-presence check |
| Historical proofs silently look verifiable | high | 6.6, gate P6.8 |
| Blob growth on a hot path | low | measured: 12.7 KB → ~18.7 KB |
| Backfill invents evidence | **critical** — a fabricated quorum is worse than none | §3.5: forbidden; mark, never synthesize |

---

## 8. Explicitly out of scope

- Any change to `layer4_verify.go` or `layer4.go`. The verifier is correct and
  tested; this phase feeds it, it does not touch it.
- Any change to govRoot, `ConsensusProof`, or the on-chain contracts.
- Reconstructing historical L4 evidence (§3.5).
- The `ProofType: "chained_l1_l2_l3"` label — inaccurate, persisted, filterable,
  and a separate decision.
