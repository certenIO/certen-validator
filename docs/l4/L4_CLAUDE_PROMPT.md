# Claude Code Prompt — Exhaustive L4 + G2 Execution & Full-Scope Verification

Paste the block below into a fresh Claude Code session rooted at
`C:\Accumulate_Stuff\certen`.

**End state:** L1–L4 and G0–G2 all real, complete, correct, offline-verifiable,
and engine-independent — no stubs, no tautologies, no silent degradation.

---

```
You are completing CERTEN's end-to-end cryptographic proof system. Four
defects, all of the same class — a proof succeeding with less evidence than the
spec requires:

  D1  L4 is not a layer. Two live CometBFT RPC assertions that store nothing,
      verify no signatures, cannot verify offline, and will not compile once
      Accumulate removes CometBFT.
  D2  G1 signature evidence: a stub returning success with zero signatures, and
      a live path that silently drops signatures on transient errors. THIS is
      what actually costs G2 proofs (9 of 399).
  D3  G2 outcome binding — G2's defining claim over G1 — is verified with
      non-empty string tests over flags set by earlier stages.
  D4  G2 payload verification has a dormant fail-open keyed on an error string.

AUTHORITATIVE DOCUMENTS — read all three in full before any edit:
  independant_validator/docs/l4/L4_DESIGN.md
  independant_validator/docs/l4/L4_RUNBOOK.md
  independant_validator/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/docs/CERTEN_GOVERANCE_PROOF_SPEC.MD

CODE IN SCOPE — read each file COMPLETELY, not in fragments:
  A. accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/
       types.go  proof_builder.go  proof_verifier.go  receipt_verifier.go
       layer1.go layer2.go layer3.go chained_proof.go
  B. accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/
       g0_layer.go g1_layer.go g2_layer.go signature_verifier.go
       go_verifier.go authority_builder.go common.go types.go main.go
  C. pkg/proof/liteclient_adapter.go
     pkg/proof/governance_adapter.go
     pkg/execution/contracts/v6_1_binding.go
     pkg/consensus/liteclient_binding.go
  D. Accumulate core (reference, DO NOT MODIFY):
       C:\Accumulate_Stuff\accumulate-core   (branch: origin/dagbft-integration)
       internal/core/execute/v2/block/msg_block_anchor.go
       internal/core/signer.go
       pkg/types/network/validators.go
       protocol/types_gen.go   (PartitionAnchor, NetworkDefinition, ValidatorInfo)

LIVE RESOURCES
  Accumulate v3 : https://kermit.accumulatenetwork.io/v3
  CERTEN host   : ssh -i ~/.ssh/certen_server root@116.202.214.38
  Proof DB      : docker exec certen-postgres psql -U certen -d certen_proofs
                  (tables: governance_proof_levels, chained_proof_layers,
                           proof_artifacts)

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. BACKUP FIRST. Execute Runbook Phase 0 and verify the SHA-256 manifest before
   reading further. Re-verify at the end. An existing backup is at
   proof/_PROOF_BACKUPS/20260824_053303 (32 files).

2. VERIFY EMPIRICALLY, NOT BY READING. Any claim about runtime behaviour must be
   proven by executing something — a live query, a compiled test, a decoded
   transaction, a SQL result. "The code appears to..." is not a finding. State
   assumptions you could not execute as assumptions.

3. NO STUBS. NO TAUTOLOGIES. NO PLACEHOLDERS AS AN END STATE. A function that
   returns empty-with-nil-error, or verifies by testing a string is non-empty,
   or trusts a flag an earlier stage set, is not an implementation. If a
   temporary guard is needed while building the real thing, it must fail loudly
   and must be deleted before the phase gate closes.

4. FAIL CLOSED, ALWAYS. Every ambiguity resolves toward rejection. Never add a
   branch letting a proof succeed with less evidence. No boolean may default to
   true; prefer tri-state (NotRun / Failed / Verified) so "never executed"
   cannot read as "passed".

5. DISTINGUISH "INVALID" FROM "UNAVAILABLE". An infrastructure failure must
   never be recorded as a governance verdict. This single confusion is the root
   of D2 and cost 9 proofs.

6. DO NOT SHAPE THE DESIGN AROUND CURRENT INFRASTRUCTURE. Kermit BVNs have one
   validator each today; that is a deployment parameter, not an invariant. Both
   the BVN and DN L4 legs are required and symmetric. Never drop or weaken
   either.

7. NEVER WEAKEN A CHECK TO MAKE A TEST PASS. If verification fails, assume your
   implementation is wrong, not the check. Diagnose.

8. PRESERVE L1–L3 EXACTLY. Capture the baseline in Phase 0.4; any change means
   you broke something — roll back.

9. REUSE EXISTING VERIFIED CODE. Signature digests: ComputeAccumulateDigest +
   VerifyEd25519 (signature_verifier.go). Merkle recomputation:
   ReceiptVerifier.ValidateIntegrity (receipt_verifier.go). Do not write second
   copies of either.

10. GATES ARE BLOCKING. Report each gate result explicitly before proceeding.

═══════════════════════════════════════════════════════════════════
KNOWN-GOOD FIXTURE — your L4 implementation MUST reproduce this
═══════════════════════════════════════════════════════════════════

  txHash        e6dd1988102e29aa5206cc1c5fcb0f3ff5b4cac0b4580928029d03ed93035572
  pubkey        40e6e8b96de7e7ed4c38815448abe22ab555236418d813b3a02cb6a7bc42871b
  signature     f9b81b4634ab6280ef423aa70133962a41a6b70985ef9703778868a9f3a298fb
                5f3c7626e376e19173d34e12b4721ec3dde77b696ee94954f6d8b18b5423500b
  signer        acc://dn.acme/network
  timestamp     1787562303142
  signerVersion 0
  digest        sha256( ED25519Signature{pubkey,signer,signerVersion,timestamp}
                        .Metadata().Hash()  ||  txHash )
  EXPECT        ed25519.Verify == true

Anchor context: directoryAnchor, source acc://dn.acme, minorBlock 7671708,
stateTreeAnchor e59fe47dc1e7ce6a73080f823a05fc9502b007f5d1f04845ad9518f949ca7395,
at index 169156 of acc://bvn-BVN1.acme/anchors, carrying 3 of 3 DN validator
signatures. Directory threshold = 2 (validatorAcceptThreshold 2/3 over 3 active).

Baseline G2 funnel (2026-08-24): 399 G0 / 364 G1 / 355 G2.
Target after Phase 4A.5 backfill: 399 / 399 / 399.

═══════════════════════════════════════════════════════════════════
EXECUTION
═══════════════════════════════════════════════════════════════════

Work Runbook phases 0 → 6 in order:
  0  Safety + baseline          4A Signature evidence  (D2 — do first)
  1  Characterization tests     4B Payload fail-open   (D4)
  2  Add Layer4 (additive)      4C Outcome binding     (D3)
  3  Retire the CometBFT bind   5  Propagate L4 into govRoot
                                6  Acceptance

4B and 4C are ONE correctness item — 4B's bypass is guarded by checks 4C proves
to be tautologies. Do not ship either alone.

At each gate report:
  GATE n: PASS | FAIL
  evidence: <command run and its ACTUAL output>
  if FAIL: diagnosis, and whether you are rolling back

Core deliverables — a passing negative test is a CRITICAL DEFECT, stop and
report:
  • Phase 2.5 — eight L4 mutations, all must reject
  • Phase 4A.6 — fault injection: an RPC error must yield
    SignatureEvidenceIncomplete, NEVER threshold_met:false
  • Phase 4C.4 — mutated outcome receipt, foreign receipt, ENTRY_HASH mismatch,
    and failed/pending outcome must all reject

═══════════════════════════════════════════════════════════════════
FULL-SCOPE VERIFICATION — run after Phase 6, report as a table
═══════════════════════════════════════════════════════════════════

Trust / merkle chain
  V1   L1 receipt recomputes to its anchor (offline)
  V2   L2 root+bpt receipts recompute; pairing invariants hold
  V3   L3 root+bpt receipts recompute; DN-self pairing holds
  V4   L4-BVN: every signature verifies; signers ∈ set active on that BVN;
       unique count ≥ BVN threshold
  V5   L4-DN: same, against Directory
  V6   Layer4BVN.StateTreeAnchor == Layer2.BVNStateTreeAnchor
  V7   Layer4DN.StateTreeAnchor  == Layer3.DNStateTreeAnchor
  V8   Ordering invariants (DN_FINAL_MBI ≥ DN_MBI; consensusHeight == DN_MBI+1)

Governance chain
  V9   G0 inclusion + finality; execution witness derived
  V10  G1 KPSW-EXEC: key page state at execution time; signerVersion matches;
       every counted key ∈ State_exec(P).keys
  V11  G1 threshold: unique valid member keys ≥ page threshold
  V12  G1 timing: every counted signature has receipt.localBlock ≤ EXEC_MBI
  V13  G1 evidence completeness: no signature silently dropped; unavailable ⇒
       SignatureEvidenceIncomplete, never a threshold verdict
  V14  G1 enumeration artifact produced (spec §4.1 item 5) — enumeration AND
       single-entry resolution
  V15  G1 both routes run and agree; disagreement fails closed
  V16  G2 outcome leaf exists, is success-only, and its receipt MERKLE-
       RECOMPUTES to the anchor (not a non-empty check)
  V17  G2 outcome leaf bound to EXEC_WITNESS; ENTRY_HASH == receipt-proven leaf
  V18  G2 payload verification ran for real; no config bypass path exists
  V19  g2Hash == 0 whenever G2 was not fully achieved; no "partial G2" state

Cross-cutting
  V20  Whole proof verifies with network access DISABLED
  V21  No cometbft/tendermint import anywhere in the proof tree
  V22  No stub, tautology, or boolean-defaulting-true remains:
       grep -rn "not yet implemented\|If we reached this point" returns nothing
  V23  L1–L3 byte-identical to the Phase 0.4 baseline
  V24  Backup manifest verifies
  V25  Signer/verifier govRoot agreement (v6_1_signing.go vs
       ethereum_contracts.go) — bit-for-bit
  V26  G2 coverage 399/399 after backfill (SQL funnel query)
  V27  Load test at 3× the 2026-08-03 peak: zero threshold_met:false with
       attestation_count > 0
  V28  One full CERTEN cycle succeeds on Sepolia

For each: PASS / FAIL / NOT VERIFIED, with evidence. "NOT VERIFIED" is an
acceptable and expected answer for anything you could not execute. An
UNSUPPORTED PASS IS NOT.

═══════════════════════════════════════════════════════════════════
REPORT
═══════════════════════════════════════════════════════════════════

1. Gate results, in order, with evidence.
2. The V1–V28 table.
3. Every assumption you could not verify, stated plainly.
4. Any OTHER place where a proof can succeed with less evidence than the spec
   requires. Four such defects motivated this work; finding a fifth is a better
   outcome than a clean run. Look especially for: nil errors on failure paths,
   `continue` on infrastructure errors, verification by non-empty check,
   booleans that default true, and fallbacks that mask a broken primary.
5. Diffs applied, and the backup path for rollback.

Do not claim completion until every gate is green, or you have explicitly
reported which are not and why.
```

---

## Notes for whoever runs this

- **4A is the largest item and the one that pays.** It is the sole cause of the
  nine observed G2 failures. 4B alone changes nothing on the current fleet.
- **Expect the G2 count to drop during 4C** before the backfill restores it.
  Proofs accepted by the old tautologies may not survive real outcome binding.
  That is a correction, not a regression — but plan for it, and diff which
  proofs change verdict.
- **Phase 5 is the risky one.** Changing `ComputeAccumulateGovRoot` inputs
  changes the BLS message hash; signer and verifier must move atomically or
  every on-chain TX2 reverts. Stage it behind a version flag.
- **DAG-BFT retest.** When a public DAG-BFT network exists, re-run V1–V28
  unchanged. The design predicts zero code changes; that prediction is untested.
