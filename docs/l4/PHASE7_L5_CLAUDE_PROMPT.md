# Claude Code Prompt — Stages 1–3 Execution (Confirm correctness, Governance results, L5-lite)

Paste the block below into a fresh Claude Code session rooted at
**`C:\Accumulate_Stuff\certen\independant_validator`**.

That is the git repository every edit lands in, so `git status`, `git diff` and rollback all
work without a `cd`. `C:\Accumulate_Stuff\certen` is *not* a repository, and
`accumulate-core` is a **sibling of `certen`**, not inside it — referenced below by absolute
path and read-only.

**End state:** a pending settlement is never reported as a failure; a governance level read
back out of PostgreSQL recomputes its own receipt; and a stored proof carries the merkle
path proving it is in the batch that was anchored on an external chain. govRoot byte-identical
throughout.

---

```
You are completing three things Phase 6 left. Phase 6 established the pattern all three
reuse: THE CONCLUSION GOES IN THE HASH, THE EVIDENCE GOES BESIDE IT, IN STORAGE, WHERE IT
CAN BE CHECKED. That is the only idea here.

  STAGE 1 — "did not confirm" reports a failure that did not happen.
    TargetChainConfirmed is a bool, so "not confirmed YET" and "confirmed FAILED" are the
    same value. Measured on intent 1638327d-af2c-439c-a188-be53cdb5c854 (2026-08-25): the
    fleet logged "did NOT confirm ... gas may have been spent on a reverted transaction"
    with targetChainError="" at 07:33:41, and the transaction confirmed status=1 at
    07:34:32. Fifty-one seconds. It also called markCompleted while the write was in
    flight. This is correctness and observability; it changes NOTHING about what is
    provable, and it is the cheapest of the three by an order of magnitude.

  STAGE 2 — governance_proof_levels does not contain the governance proof.
    The runbook you may have read from Phase 6 says "ReceiptData.Entries already exists and
    is populated; persist it into level_json." THAT PREMISE IS FALSE and following it would
    polish a pipe that is not connected. Measured: ComprehensiveData["g0Proof"] is read in
    exactly one place and WRITTEN IN ZERO. The rows you actually see are built from EVM
    observation results plus key-page thresholds. 0 of 400 G0 rows contain "entries". The
    real G0Result/G1Result/G2Result exist on PendingAttestation and die at the boundary
    with ProofCycleCompletion, which does not carry them. This is the largest gap and the
    largest payoff: G1 is "did the right key page authorize this", which is the product's
    central claim, and it is unpersisted in any checkable form.

  STAGE 3 — L5-lite. certen_anchor_proofs has 0 rows.
    Accumulate does NOT anchor into Bitcoin or Ethereum — verified, every anchor type in
    accumulate-core/protocol/types_gen.go is internal. Do not build this waiting for that.
    CERTEN already anchors the govRoot externally on every intent, so the immutability
    property ALREADY EXISTS; L5-lite does not add it, it makes it checkable. Offline
    verification covers leaf -> batch root only. Root -> external chain is coordinates plus
    an optional online check. A light client is OUT OF SCOPE and "offline" would stop
    meaning anything if you built one.

AUTHORITATIVE DOCUMENT — read it in full before any edit:
  docs/l4/PHASE7_L5_RUNBOOK.md

Background, for how the pattern was established (read if anything surprises you):
  docs/l4/PHASE6_PERSISTENCE_PLAN.md      (esp. §1.2 and §3.1)
  docs/l4/PHASE6_RUNBOOK.md               (its Phase 7 premise is WRONG — see Stage 2)
  docs/l4/mark_summary_only_proofs.sql    (the precedent for honest marking)
  pkg/execution/layer4_rows.go            (the one-helper-both-orchestrators pattern)
  pkg/proof/chained_proof_storage.go      (the read path + ErrSummaryOnly)
  pkg/execution/phase6_roundtrip_test.go  (what a real round-trip gate looks like)

CODE IN SCOPE — read each file COMPLETELY, not in fragments:
  STAGE 1
    pkg/consensus/bft_integration.go        (466-484 struct, 858-866 log, 1555-1663 assign)
    pkg/consensus/batch_quorum_prover.go    (239, 434 — genuine failures)
    pkg/consensus/async_attestation.go      (619; RunProofCycle)
    pkg/intent/discovery.go                 (930-960 markCompleted)
    pkg/database/intent_lifecycle_types.go  (19-34 — no state for "settling")
  STAGE 2
    pkg/proof/governance_types.go           (58-65 GovReceiptData — THE TRAP; 205-255 G*Result)
    pkg/proof/governance_library.go         (196, 234 — .Entries dropped here)
    pkg/consensus/async_attestation.go      (47-75 PendingAttestation carries the real results)
    pkg/execution/synthetic_transaction.go  (920+ ProofCycleCompletion — the break)
    pkg/execution/proof_cycle_orchestrator.go (1982+ storeGovernanceLevels)
    pkg/execution/unified_orchestrator.go   (2478-2560 and ~3395 — TWO writers)
    pkg/consensus/v6_1_signing.go           (272-274 — what is actually hashed)
    accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/
        receipt_merkle.go (76 VerifyReceiptMerkle — package main, must move), types.go (226)
  STAGE 3
    pkg/database/types.go                   (72-75 MerklePathNode)
    pkg/merkle/tree.go (158 hashPair), pkg/merkle/receipt.go (110 ComputeRoot)
    pkg/execution/contracts/v6_1_binding.go (229-284 — the FIXED 10-slot govRoot)
    cmd/proofverify/main.go
  READ ONLY — the L1-L4 verifier is correct and tested. Feed it; do not touch it:
    accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/
        layer4_types.go  layer4_verify.go  proof_verifier.go  offline_verify_test.go

LIVE RESOURCES
  Accumulate v3 : https://kermit.accumulatenetwork.io/v3
  CERTEN host   : ssh -i ~/.ssh/certen_server root@116.202.214.38
  Proof DB      : docker exec certen-postgres psql -U certen -d certen_proofs
                  (governance_proof_levels, chained_proof_layers, proof_artifacts,
                   batch_transactions, anchor_batches, certen_anchor_proofs,
                   chain_execution_results, intent_lifecycle)
                  NOT published on the host — tunnel it, see Runbook §0.7. READ ONLY.
  Validators    : certen-validator-1..7, source at /root/certen-validators
  E2E           : node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. BACKUP FIRST. Runbook Phase 0, including the pg_dump, verified before touching anything.

2. THESE STAGES CHANGE NO HASH. Do not add, remove, reorder or retag any field of
   ConsensusProof, L4LegSummary, G0Result, G1Result, G2Result or GovReceiptData.
   CanonicalJSONMarshal is json.Marshal, so struct layout IS the wire format.
   GovReceiptData IS THE TRAP: it is nested inside G0Result and therefore inside the
   G0/G1/G2 canonical hash. Putting Entries there is the obvious move and it is wrong.
   Run `go test ./pkg/execution/contracts/ -run TestP6_ -count=1 -v` after EVERY edit in
   Stage 2, not just at the end.

3. IF A GATE SHOWS govROOT MOVING, STOP. Revert the edit that moved it. Do NOT update the
   expected value. The golden constants in phase6_invariant_test.go are the specification,
   not a snapshot — they are what every already-signed TX2 on the fleet commits to.

4. GATES ARE BLOCKING. Gate N green before step N+1. Do not batch and check at the end.

5. STORING IS NOT VERIFYING. Every stage that stores evidence must show a MUTATION OF THE
   STORED BYTES being rejected, with the real verifier and the network disabled. A test
   that asserts fields are present proves nothing and must not be presented as a pass.

6. NEVER FABRICATE HISTORICAL EVIDENCE. The 1,106 historical G-levels cannot have their
   receipts reconstructed — the receipt fetched today is not necessarily the one the proof
   was built on. Mark them, exactly as the 402 proofs were marked. A synthesized record is
   worse than an absent one.

7. ONE HELPER, EVERY CALL SITE. Stage 2 has THREE G-level writers (proof_cycle_orchestrator
   plus TWO in unified_orchestrator). They must call the same construction function. Two
   copies drift; that is how L4 came to be missing from one path already.

8. STAGE 1 CAN DO HARM — 1.2.7 IS THE DANGEROUS EDIT. Making everything default to
   "pending" would mask a real revert. batch_quorum_prover.go:239,434 and
   async_attestation.go:619 are GENUINE failures and must classify as failed. Read each
   site individually; do not pattern-match.

9. ADDITIVE ONLY on level_json and the stored blob. Keep every existing key — the evidence
   report and approval console read them. Add beside; never rename, retype or remove.

10. DEPLOY IS NOT YOURS. Commit and push to main; the user pulls and rebuilds. DB
    migrations and server .env edits ARE yours. Never run docker compose, git pull or
    git reset on a server checkout. When a live gate needs deployed code, say so and stop.

11. USE base-sepolia FOR e2e ($0.35 flat; ethereum-sepolia is ~$3.30).

12. WATCH THE ELECTED EXECUTOR. Settlement happens on ONE validator chosen by
    BFT-DETERMINISTIC, not validator-1. Find it, then read that node. CONFIRMATION LAGS
    THE CONSENSUS-COMPLETE LOG — measured at 51s. Check chain_execution_results and the
    chain before calling anything a failure. That lag is the subject of Stage 1; do not let
    it fool you while you are fixing it.

13. DO NOT ADD AN 11th govROOT SLOT. ComputeAccumulateGovRoot is a fixed 352-byte preimage
    and the EVM contract agrees with it. L5 is storage and read-path only. It also cannot
    be inside the govRoot it describes: the govRoot must exist before the anchor is written.

14. DO NOT OVERCLAIM WHAT L5 PROVES. It does not establish that the Accumulate validator
    set which signed L4 is the legitimate one. Nothing in these three stages does. Say so
    in the code comments and in the final report — an external timestamp attests to
    whatever was signed, not to whether the signers were the right ones.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0   Safety + govRoot + measured baselines   -> Gate 0
  Runbook Stage 1   Tri-state outcome + lifecycle           -> Gate 1   (cheapest, do first)
  Runbook Stage 2   Real G-results + receipt evidence       -> Gate 2   <- THE BIG ONE
  Runbook Stage 3   L5-lite external anchor binding         -> Gate 3
  Final gate        build + full suite + govRoot            -> deploy handoff

Stage 1 is independent — land it first so the fleet stops crying wolf while the rest is
built. Stage 3 comes last on purpose: it attests to a govRoot that commits to G0-G2, so
what a governance proof CONTAINS has to settle before you build the layer attesting to it.

═══════════════════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════════════════

  [ ] A pending settlement is reported as pending, WITH its tx hash, and is followed by a
      terminal line for the same intent ID. The gas-spent sentence appears only for a real
      status-0 receipt.
  [ ] No intent reaches lifecycle 'complete' while its chain write is still in flight.
  [ ] The real G0Result/G1Result/G2Result are in governance_proof_levels.level_json.
  [ ] Every stored G-level receipt recomputes from level_json ALONE, and all six Stage 2
      mutations are rejected.
  [ ] The 1,106 historical G-levels read summary-only — not verified, not failed.
  [ ] Six layer rows per new proof: 1, 2, 3, 4-BVN, 4-DN, 5.
  [ ] Layer5.VerifyOffline recomputes leaf->batchRoot with the network disabled, accepts
      the single-leaf case (empty path, leaf == root) and REJECTS empty-path-with-mismatch.
  [ ] proof_artifacts.batch_id, proof_artifacts.merkle_path and
      anchor_batches.anchor_tx_hash are populated for new proofs.
  [ ] govRoot byte-identical: fixture bb293c644b31c0c2361ebd79a10a4996af870f430c6fc88c6b91f57d48b8cb59
      and production d375630fb8c1f224 -> e23ce1074f59ce28.
  [ ] ConsensusProof / L4LegSummary / G*Result / GovReceiptData shapes unchanged.
  [ ] A live e2e on base-sepolia settles with status 1.
  [ ] go build ./... clean; go test ./pkg/... green; working-proof green.
      (The three consolidated_governance-proof failures — TestURLUtils, TestG0Layer,
      TestCompleteWorkflow — are pre-existing. Confirm they fail IDENTICALLY; do not
      "fix" them. Re-confirm after moving VerifyReceiptMerkle out of package main, since
      that touches their package.)

Begin with Runbook Phase 0. Do not skip the pg_dump. Re-measure §0.5 rather than trusting
the table — if a number disagrees, find out why before writing code.
```
