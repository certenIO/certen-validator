# Claude Code Prompt — Phase 6 Execution (L4 Persistence)

Paste the block below into a fresh Claude Code session rooted at
`C:\Accumulate_Stuff\certen`.

**End state:** a governance proof read back out of PostgreSQL verifies offline,
end to end, L1 through L4 — with govRoot byte-identical to what it is today.

---

```
You are completing CERTEN's proof persistence. One defect:

  L4 is built, verified in flight, and committed into the governance root, but
  only its CONCLUSIONS are persisted. The signatures, validator set and signed
  bytes that a verifier needs are written nowhere. A stored proof can be
  believed but not checked, which fails governance spec §4 ("A governance proof
  MUST be verifiable offline").

  This was measured, not inferred. On proof b7a48634-733a-4999-84eb-06d2c84db112
  the stored blob tests: signature=f, validatorSet=f, publicKeyHash=f.

AUTHORITATIVE DOCUMENTS — read both in full before any edit:
  independant_validator/docs/l4/PHASE6_PERSISTENCE_PLAN.md
  independant_validator/docs/l4/PHASE6_RUNBOOK.md

Background, for context on how L4 got here (read if anything surprises you):
  independant_validator/docs/l4/L4_DESIGN.md
  independant_validator/docs/l4/PHASE5_PLAN.md          (esp. §1.2 and §8)
  .../proof/consolidated_governance-proof/docs/CERTEN_GOVERANCE_PROOF_SPEC.MD

CODE IN SCOPE — read each file COMPLETELY, not in fragments:
  A. pkg/database/proof_artifact_repository.go
     pkg/database/proof_artifact_types.go
     pkg/database/migrations/            (add 013)
  B. pkg/execution/proof_cycle_orchestrator.go   (the 1..3 loop, ~line 1930)
     pkg/execution/unified_orchestrator.go       (the L1/L2/L3 block, ~2779-2844)
  C. pkg/proof/liteclient_adapter.go             (ChainedProofToCompleteProof)
     pkg/proof/certen_proof.go
  D. accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/
       layer4_types.go  layer4_verify.go  offline_verify_test.go  types.go
     READ ONLY — the verifier is correct and tested. Feed it; do not touch it.
  E. accumulate-lite-client-2/liteclient/proof/healing_proof.go
     READ ONLY unless a gate proves otherwise — ConsensusProof is the govRoot
     preimage.

LIVE RESOURCES
  Accumulate v3 : https://kermit.accumulatenetwork.io/v3
  CERTEN host   : ssh -i ~/.ssh/certen_server root@116.202.214.38
  Proof DB      : docker exec certen-postgres psql -U certen -d certen_proofs
                  (governance_proof_levels, chained_proof_layers,
                   proof_artifacts, batch_transactions)
  Validators    : certen-validator-1..7, source at /root/certen-validators
  E2E           : node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. BACKUP FIRST. Execute Runbook Phase 0 — including the pg_dump — and verify
   the SHA-256 manifest before touching anything.

2. THIS PHASE CHANGES NO HASH. Do not add, remove, reorder or retag any field
   of ConsensusProof, L4LegSummary, G0Result, G1Result, G2Result or
   ReceiptData. CanonicalJSONMarshal is json.Marshal, so struct layout IS the
   wire format: one added field moves govRoot and reverts every TX2 on a mixed
   fleet. Store evidence BESIDE the summary, never inside it.

3. IF A GATE SHOWS govROOT MOVING, STOP. Revert the edit that moved it. Do NOT
   update the expected value to match. The golden constants in the Phase 1
   characterization tests are the specification, not a snapshot.

4. GATES ARE BLOCKING. Runbook Gate N must be green before step N+1. Do not
   batch steps and check at the end.

5. STORING IS NOT VERIFYING. Gate 5 must run the real ProofVerifier with the
   network disabled AND show every listed mutation being rejected. A test that
   only asserts fields are present proves nothing and must not be presented as
   passing Gate 5.

6. NEVER FABRICATE HISTORICAL EVIDENCE. The 365 pre-existing proofs cannot have
   their L4 reconstructed — re-querying Accumulate returns today's validator
   set, not the one that signed. Mark them 'summary_only'. A synthesized quorum
   is worse than an absent one.

7. ONE HELPER, BOTH ORCHESTRATORS. proof_cycle_orchestrator and
   unified_orchestrator must call the SAME row-construction function. Two
   copies drift; that is how L4 came to be missing from one path already.

8. NO SILENT PARTIAL WRITES. A nil L4 leg at write time means the plumbing
   broke — RequireL4Committed rejects such a proof upstream. Log loudly and
   write no row. Never write a half row.

9. REPORT FAITHFULLY. If a gate fails, say so with the output. If you skipped
   something, say that. Do not describe a step as done because the code looks
   right — the runbook gates are all executable, so execute them.

10. USE base-sepolia FOR e2e ($0.35 flat). ethereum-sepolia is ~$3.30/proof and
    its cost-basis gate goes stale after 48h of no traffic
    (api-gateway/scripts/refresh-chain-cost-basis.mjs).

11. WATCH THE ELECTED EXECUTOR. Settlement happens on ONE validator chosen by
    BFT-DETERMINISTIC, not on validator-1. Find it in the logs, then read that
    node. Confirmation can lag the consensus-complete log by ~90s — check
    chain_execution_results and the chain itself before calling it a failure.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0  Safety + govRoot baseline        -> Gate 0
  Runbook Phase 1  Characterization tests           -> Gate 1   (1.1 is the spec)
  Runbook Phase 2  Migration 013 + repository       -> Gate 2
  Runbook Phase 3  Write layer-4 rows               -> Gate 3
  Runbook Phase 4  Complete the travelling blob     -> Gate 4
  Runbook Phase 5  ChainedProofFromStorage + verify -> Gate 5   <- THE PHASE
  Runbook Phase 6  summary_only + live e2e          -> Gate 6
  Runbook Phase 7  Governance receipts (separable)  -> Gate 7
  Runbook Phase 8  Deploy                           -> final gate

═══════════════════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════════════════

  [ ] A proof written today is read back from PostgreSQL and verified with the
      network disabled, L1 through L4.
  [ ] Every mutation in Runbook 5.3 is rejected from storage.
  [ ] govRoot is byte-identical to the Phase 0 baseline (e23ce107...).
  [ ] ConsensusProof / L4LegSummary / G*Result / ReceiptData shapes unchanged.
  [ ] Five layer rows per new proof: 1, 2, 3, 4-BVN, 4-DN.
  [ ] The 365 historical proofs read 'summary_only', not 'verified'.
  [ ] A live e2e on base-sepolia settles with status 1.
  [ ] go build ./... clean; go test ./pkg/... green; working-proof green.
      (The three consolidated_governance-proof failures — TestURLUtils,
      TestG0Layer, TestCompleteWorkflow — are pre-existing and fail identically
      at baseline adb5cae. Confirm they are unchanged; do not "fix" them as
      part of this phase.)

Begin with Runbook Phase 0. Do not skip the pg_dump.
```
