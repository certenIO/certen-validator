# Claude Code Prompt — Validator Trust Root research and AIP

Paste the block below into a fresh Claude Code session rooted at
**`C:\Accumulate_Stuff\certen\independant_validator`**.

That is the git repository any CERTEN-side notes land in. `accumulate-core` is a
**sibling of `certen`** at `C:\Accumulate_Stuff\accumulate-core`, referenced by
absolute path and **read-only**. AIPs are written to `C:\Accumulate_Stuff\AIPs\`,
which is not a git repository.

**End state:** a draft Accumulate Improvement Proposal that closes the one gap
left in CERTEN's cryptographic chain — that L4 verifies signatures against a
validator set the proof carries, with nothing binding that set to network
genesis.

---

```
You are closing the last gap in a proof system that is otherwise complete.

THE GAP, MEASURED 2026-08-28 ON THE LIVE FLEET:

  CERTEN's L4 verifies validator quorum signatures for real - ed25519.Verify
  over the derived digest, signer must be in the validator set AND active on
  the signing partition, threshold recomputed from the network's own
  AcceptThreshold over the active count, quorum counted over DISTINCT signers.
  None of that is a stub.

  And then layer4.go:255 sets `ValidatorSet: ni.Validators`, where ni came from
  a JSON-RPC "network-status" call at BUILD TIME (layer4.go:421).

  So offline verification proves the signatures are consistent with THE SET THE
  PROOF CARRIES. A forged proof carrying a fabricated validator set, with
  signatures made by that set's own keys, passes every check. It is
  self-consistent and worthless.

  Everything CERTEN sells rests on closing this. The codebase does not hide it -
  pkg/execution/layer5.go ships the caveat inside the artifact: "This attests to
  whatever was signed, NOT to whether the Accumulate validator set that signed
  L4 was the legitimate one." Your job is to make that sentence deletable.

THE REQUIREMENT, IN ONE LINE:

  For ANY transaction and ANY block, determine what the validator set was at
  that block, and prove that set cryptographically back to network genesis.

AUTHORITATIVE DOCUMENT - read in full before anything else:
  docs/l4/VALIDATOR_TRUST_ROOT_RUNBOOK.md

Its section 2 is a research head start: Accumulate has ALREADY BUILT most of
this (issue #4058 - a major-block "spine" with archived quorum signatures,
network-update proofs, and a fast-sync induction walk from a pinned genesis
snapshot). Section 2 gives you the file:line. TREAT IT AS A LEAD, NOT AS TRUTH -
it was read once, on one branch, and may be stale or wrong. Re-verify it. Where
it is wrong, say so plainly and correct it.

Background, if anything surprises you:
  docs/proof/DAGBFT_MIGRATION_ANALYSIS.md   (CometBFT -> DAG-BFT primitive map)
  docs/l4/PHASE8_RUNBOOK.md                 (the phase that closed everything else)
  accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/docs/
    CERTEN_GOVERANCE_PROOF_SPEC.MD          (esp. 1.2.2 - what is recorded, not re-derived)

CODE IN SCOPE

  A. accumulate-core - REFERENCE, READ ONLY, DO NOT MODIFY
       C:\Accumulate_Stuff\accumulate-core
       internal/api/private/api.go          MajorHeaderRanger, MinorRootRanger
       internal/api/private/types_gen.go    MajorHeaderRecord, NetworkUpdateProof
       internal/api/v3/major_header.go      the server side
       internal/fastsync/spine.go           the induction walk
       internal/fastsync/snapshot.go        the genesis trust anchor
       protocol/protocol.go                 Network, Globals, GenesisBlock
       protocol/types_gen.go                NetworkDefinition, NetworkGlobals
       pkg/api/v3/                          the PUBLIC service surface

  B. CERTEN verifier - the side you would eventually change
       accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/
         layer4.go  layer4_verify.go  layer4_types.go
       pkg/execution/layer5.go              ExternalClaim()

  C. AIP house style - MATCH IT
       C:\Accumulate_Stuff\AIPs\AIP-50\docs\050-user-transaction-fees.md

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. accumulate-core IS READ ONLY. No edits, no branches, no commits there. You
   are writing a proposal, not a patch.

2. CITE file:line FOR EVERY CLAIM about how Accumulate behaves. A design built
   on a guess about someone else's protocol is worse than no design, because it
   looks like research.

3. CHECK BOTH BRANCHES. The spine machinery was found on `dagbft-integration`.
   Determine what exists on `main` too. A proposal to "expose" something that
   only exists on an unmerged branch is a different proposal, and must say so.

4. DO NOT INVENT PROTOCOL. If Accumulate has a mechanism, propose exposing or
   extending it. Propose something new only after showing nothing existing fits,
   and say what you ruled out and why.

5. MEASURE ANYTHING THAT COSTS BANDWIDTH. If the design makes a verifier
   download a spine, say how many major blocks exist today and how big one
   record is. Show the measurement. "Should be small" is not an answer.

6. A TRUST ROOT IS OUT-OF-BAND OR IT IS NOT A TRUST ROOT. Be explicit about what
   the verifier must obtain independently and how they check they got the right
   thing. Never disguise a bootstrapping assumption as a proof - that is the
   exact defect you are here to remove, reintroduced one level up.

7. NAME WHAT IT DOES NOT SOLVE. An overclaiming proposal is its own defect. This
   project spent Phase 8 deleting an overclaiming sentence from its own spec;
   do not write a new one into someone else's protocol.

8. DISTINGUISH THE THREE FAILURES. Throughout this codebase: a thing that could
   not be READ is not a thing that REFUSED, and neither is a thing that was
   PROVEN ABSENT. Carry that discipline into the design - a verifier that cannot
   obtain the induction path must fail closed and say which of the three it hit.

9. RUNNING BEATS READING. Where a question can be answered by querying a live
   network (https://kermit.accumulatenetwork.io/v3, or mainnet), query it. Phase
   8 found five defects that every offline reading missed.

10. REPORT FAITHFULLY. If a question cannot be answered, record it as
    unanswered with what you tried. If section 2 of the runbook is wrong, say
    so. Do not describe a phase as done because the document says it should be.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0   Re-verify section 2 on both branches      -> Gate 0
  Runbook Phase 1   Q1-Q3  genesis identity, timeline, retention -> Gate 1
  Runbook Phase 2   Q4-Q6  point query, cost, DAG-BFT         -> Gate 2
  Runbook Phase 3   Q7     evaluate the options               -> Gate 3
  Runbook Phase 4   Q8     the CERTEN-side verifier contract  -> Gate 4
  Runbook Phase 5   Draft the AIP(s)                          -> Gate 5
  Runbook Phase 6   Adversarial review                        -> final gate

Gates are blocking. Do not draft the AIP before you have a recommendation, and
do not recommend before Q1-Q6 are answered or explicitly recorded as open.

═══════════════════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════════════════

  [ ] Every section-2 claim re-verified or corrected, on BOTH branches, with
      file:line.
  [ ] Q1 through Q8 each answered with citations, or recorded as unanswerable
      with what was tried.
  [ ] A recommended design, with the alternatives considered and the reason each
      lost.
  [ ] Measured sizes/counts wherever the design costs a verifier bandwidth.
  [ ] Draft AIP(s) saved under C:\Accumulate_Stuff\AIPs\, matching the AIP-50
      house style, plus a short GitLab issue body per AIP in the governance form
      (Summary / What is the need? / What is the desired behavior? / How will
      this be implemented?).
  [ ] An explicit statement of what the proposal does NOT solve and what trust
      remains after it ships.
  [ ] The CERTEN-side change described concretely: what layer4_verify.go would
      accept, what it would refuse, how the stored artifact grows, and whether
      govRoot moves (it must not, unless deliberately versioned - see
      pkg/proof/timing_evidence.go for the beside-the-hash pattern).
  [ ] One named adversary the design defeats, and one it does not.

Begin with Runbook Phase 0. Do not write a line of the AIP before Gate 3.
```
