# Claude Code Prompt — Validator Trust Root research and AIP

Paste the block below into a fresh Claude Code session rooted at
**`C:\Accumulate_Stuff\certen\independant_validator`**.

That is the git repository any CERTEN-side notes land in. `accumulate-core` is a
**sibling of `certen`** at `C:\Accumulate_Stuff\accumulate-core`, referenced by
absolute path and **read-only**. AIPs are written to `C:\Accumulate_Stuff\AIPs\`,
which is not a git repository.

**End state:** two draft Accumulate Improvement Proposals closing the one gap
left in CERTEN's cryptographic chain — that L4 verifies signatures against a
validator set the proof carries, with nothing binding that set to network
genesis. **AIP A targets the network running today (CometBFT). AIP B targets
DAG-BFT.** A must stand on its own.

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

READ SECTION 2A BEFORE SECTION 2.

Section 2 describes a major-block "spine" (#4058) that Accumulate has already
built - archived quorum signatures, network-update proofs, and a fast-sync
induction walk from a pinned genesis snapshot. It is real, and it is NOT
AVAILABLE: it lives on `dagbft-integration`, Kermit and mainnet do not run it,
and DAG-BFT is months away. `internal/fastsync/spine.go` and
`internal/api/v3/major_header.go` are BOTH ABSENT on origin/main.

Section 2A is what exists on main TODAY, and it is where the near-term answer
lives. Measured 2026-08-28:

  - A validator-set change is an ordinary `WriteData` on acc://dn.acme/network,
    with WriteToState MANDATORY (network_accounts.go on main). So every change
    already carries a receipt, provable by the L1-L3 machinery CERTEN already
    runs. The TIMELINE needs no new protocol.

  - That account's main chain has EXACTLY ONE ENTRY on mainnet AND on kermit: a
    `systemGenesis` transaction. The validator set has never changed on either
    network. The induction chain today has length zero.

  - The genesis entry is NOT receipt-provable through the normal chain-entry
    query ("ElementIndex ... not found") while ordinary writeData entries are.
    THE BASE CASE IS THE GAP - not the timeline, not the signatures.

TREAT BOTH SECTIONS AS LEADS, NOT AS TRUTH. They were read once and may be
stale or wrong. Re-verify. Where they are wrong, say so plainly and correct
them.

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

3. MAIN IS THE TARGET; dagbft-integration IS THE FUTURE. Kermit runs CometBFT.
   A proposal that only works after DAG-BFT lands does not unblock anything for
   months. Write AIP A against `origin/main` and make it stand alone. Write AIP
   B separately and mark it as depending on #4058. Never bundle B into A to look
   thorough.

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

9. RUNNING BEATS READING, AND THE PATH HAS NEVER RUN. Query the live networks
   (https://kermit.accumulatenetwork.io/v3, mainnet) for anything checkable. And
   note what section 2A.3 means: the validator set has NEVER changed on either
   network, so the update-proof path has zero production history. Simulate a
   real validator-set change - devnet, the simulator, or accumulate-core's own
   execute tests - and prove it end to end before claiming the timeline is
   provable. Phase 8's record on exactly this: five defects, every one findable
   only by running.

10. REPORT FAITHFULLY. If a question cannot be answered, record it as
    unanswered with what you tried. If section 2 of the runbook is wrong, say
    so. Do not describe a phase as done because the document says it should be.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0   Re-verify section 2 on both branches      -> Gate 0
  Runbook Phase 1   Q9 FIRST (is the genesis entry really unprovable, or is
                    it the wrong query shape? this decides whether AIP A is a
                    one-line API fix or a protocol change), then Q1-Q3 -> Gate 1
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
  [ ] AIP A (CometBFT, today) and AIP B (DAG-BFT, spine) saved separately under
      C:\Accumulate_Stuff\AIPs\, matching the AIP-50 house style, plus a short
      GitLab issue body per AIP in the governance form (Summary / What is the
      need? / What is the desired behavior? / How will this be implemented?).
      A must be implementable without B.
  [ ] A validator-set change SIMULATED and proven end to end, not reasoned about.
  [ ] An explicit statement of what the proposal does NOT solve and what trust
      remains after it ships.
  [ ] The CERTEN-side change described concretely: what layer4_verify.go would
      accept, what it would refuse, how the stored artifact grows, and whether
      govRoot moves (it must not, unless deliberately versioned - see
      pkg/proof/timing_evidence.go for the beside-the-hash pattern).
  [ ] One named adversary the design defeats, and one it does not.

Begin with Runbook Phase 0. Do not write a line of the AIP before Gate 3.
```
