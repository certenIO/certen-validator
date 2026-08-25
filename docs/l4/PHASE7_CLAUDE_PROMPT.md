# Claude Code Prompt — Phase 7 Execution (delegated + multi-sig governance, G0–G2 and L1–L4)

Paste the block below into a fresh Claude Code session rooted at
`C:\Accumulate_Stuff\certen`.

**End state:** an institution using M-of-N signing with delegated authority,
across more than one Accumulate partition, can obtain a G2 proof with a
complete L1–L4 chain that verifies offline — and can settle it on-chain.

---

```
You are making CERTEN's proof system support the governance shape the product
is actually for. Today it supports one shape: a single ed25519 key, 1-of-1.

FIVE DEFECTS, all verified, not inferred:

  D1  Delegated signatures are refused before any cryptography runs.
      signature_verifier.go:438 rejects every type that is not "ed25519";
      a DelegatedSignature's type is "delegated". A grep for delegation
      across the whole validator tree returns nothing but unrelated prose.

  D2  Multi-sig has never been exercised. All 400 governance_proof_levels
      rows are threshold_m=1, threshold_n=1. The M-of-N accounting,
      duplicate-key collapse and below-threshold failure mode have no
      production evidence.

  D3  Delegation changes the SIGNED BYTES, not just authority resolution.
      DelegatedSignature.Metadata() recurses, and verifySigSplit hashes the
      OUTERMOST metadata, so the inner ed25519 key signs a digest committing
      to every Delegator URL in the chain. Verifying the inner signature
      against a plain digest and resolving the path separately FAILS EVERY
      TIME. This is the same shape as the L4 signedHash-vs-txHash bug.

  D4  Two digests are accepted per signature - the metadata hash OR the
      Initiator() merkle hash (protocol/signature_utils.go:21-41). Only the
      first is implemented. A signature valid under the second is currently
      counted invalid, which - because G1 fails closed - surfaces as a
      governance REJECTION, indistinguishable from "the institution did not
      authorize this".

  D5  Governance can span partitions. DelegatedSignature.RoutingLocation()
      returns the INNERMOST signer's location, and Accumulate routes by
      account URL to a partition, so a delegated signer may live on a
      different BVN than the principal. ChainedProof carries exactly one BVN
      leg today.

AUTHORITATIVE DOCUMENTS - read both in full before any edit:
  independant_validator/docs/l4/PHASE7_DELEGATION_PLAN.md
  independant_validator/docs/l4/PHASE7_RUNBOOK.md

Background, if anything surprises you:
  independant_validator/docs/l4/L4_DESIGN.md            (esp. §1.3 Defect C)
  independant_validator/docs/l4/PHASE5_PLAN.md          (esp. §1.2, §8)
  independant_validator/docs/l4/PHASE6_PERSISTENCE_PLAN.md
  .../consolidated_governance-proof/docs/CERTEN_GOVERANCE_PROOF_SPEC.MD

CODE IN SCOPE - read each file COMPLETELY, not in fragments:
  A. accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/
       signature_verifier.go  g1_layer.go  g1_signature_evidence.go
       g1_signature_routes.go  authority_builder.go  types.go  common.go
  B. accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/
       types.go  proof_builder.go  proof_verifier.go
       layer4.go  layer4_types.go  layer4_verify.go
     THIS DIRECTORY IS EDITED IN THIS PHASE. The name is a warning, not a
     prohibition - Phase 4 widens ChainedProof itself.
  C. accumulate-lite-client-2/liteclient/proof/healing_proof.go
     pkg/proof/liteclient_adapter.go
  D. Accumulate core - REFERENCE, DO NOT MODIFY:
       C:\Accumulate_Stuff\accumulate-core
       protocol/signature.go        (Metadata, Verify, DelegatedSignature)
       protocol/signature_utils.go  (verifySig / verifySigSplit - THE spec)
       protocol/types_gen.go        (KeyPage, KeySpec, MarshalBinary)
       protocol/protocol.go:89      (DelegationDepthLimit = 20)

LIVE RESOURCES
  Accumulate v3 : https://kermit.accumulatenetwork.io/v3
  CERTEN host   : ssh -i ~/.ssh/certen_server root@116.202.214.38
  Proof DB      : docker exec certen-postgres psql -U certen -d certen_proofs
  Validators    : certen-validator-1..7, source at /root/certen-validators
  E2E           : node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand
  Backup        : _PROOF_BACKUPS/20260824_210857 (180 files, manifest verified)

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. BACKUP FIRST. Execute Runbook Phase 0 and verify the SHA-256 manifest
   before touching anything. Record the govRoot baseline.

2. BUILD THE CORPUS BEFORE THE CODE. Runbook Phase 1 comes first. Writing the
   verifier first and the tests second produces an implementation that is
   self-consistent and wrong, and nothing downstream will catch it.

3. VERDICTS COME FROM accumulate-core, NEVER FROM US. Every corpus expectation
   is computed with protocol.VerifyUserSignature against the real protocol
   package. Our job is to AGREE with it. A corpus verdicted by our own code
   proves only that we are consistent with ourselves.

4. DO NOT REIMPLEMENT THE CANONICAL ENCODING. Build real
   protocol.DelegatedSignature / protocol.ED25519Signature values and call
   .Metadata().Hash(). The encoding is field-tagged, omit-if-zero, varint
   length (types_gen.go:8996). Hand-rolling it is how the field-strictness
   bugs happened before.

5. THIS PHASE MOVES govROOT - ONCE, AT PHASE 6, UNDER A BUMPED VERSION.
   If govRoot moves earlier, or moves twice, STOP: the change has leaked into
   a slot that was not planned to move. Bump L4GovRootVersion to
   "certen:l4gov:v2"; never move the shape silently.

6. GATES ARE BLOCKING. Runbook Gate N green before step N+1. Do not batch
   steps and check at the end. Gate 2 (digest parity) is the one everything
   else rests on - if it is not green, nothing after it means anything.

7. FAIL CLOSED, WITH A DISTINCT REASON. Unsupported signature types (RCD1,
   BTC, ETH, RSA, EcdsaSha256, TypedData) must be refused with their own
   reason code. A silently skipped signature reads as a threshold shortfall,
   which reads as "the institution did not authorize this" - a false
   governance rejection is worse than an error.

8. NEVER OVER-COUNT. One key satisfies at most one key-page entry. Two
   signatures from the same key are ONE acceptance. Track visited pages and
   refuse cycles. Refuse beyond DelegationDepthLimit = 20 - Accumulate's
   number, not one you choose.

9. THE RESOLUTION PATH MUST EQUAL THE DIGEST'S CHAIN. A signature whose inner
   key is correct but whose delegator chain differs from the path you walked
   is NOT evidence for that path. Test this explicitly (corpus case J).

10. CANONICAL ORDERING IS LOAD-BEARING. Sort partition legs by partition ID.
    Unordered legs make two validators reading identical chain data produce
    different bytes - an intermittent, unreproducible TX2 revert, which is
    close to the worst failure mode this system has.

11. VERIFY EVERY LEG, EVERY TIME. Loop over all N legs corrupting each in
    turn. Do not spot-check one and generalise.

12. WATCH THE ELECTED EXECUTOR. Settlement runs on one validator chosen by
    BFT-DETERMINISTIC, not validator-1. Find it in the logs, then read that
    node. Confirmation can lag the consensus-complete line by ~90s - check
    chain_execution_results and the chain before declaring failure.

13. USE base-sepolia FOR e2e ($0.35 flat). ethereum-sepolia is ~$3.30/proof
    and its cost-basis gate goes stale after 48h of no traffic.

14. REPORT FAITHFULLY. If a gate fails, say so with the output. If you skipped
    something, say that. Every gate in the runbook is executable - execute it.
    Do not describe a step as done because the code looks right.

15. THE FLEET UPGRADE IS ATOMIC. Build once, deploy the same binary to all
    seven, verify a single distinct sha256 across all seven BEFORE starting
    any of them. A mixed-version fleet reverts every TX2 on every chain.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0  Safety + govRoot baseline           -> Gate 0
  Runbook Phase 1  The corpus (BEFORE any code)        -> Gate 1
  Runbook Phase 2  AcceptedDigests, both forms         -> Gate 2  <- FOUNDATION
  Runbook Phase 3  Authority resolution + enumeration  -> Gate 3
  Runbook Phase 4  Multi-partition ChainedProof        -> Gate 4
  Runbook Phase 5  Multi-partition verification        -> Gate 5
  Runbook Phase 6  govRoot bump, deliberately, once    -> Gate 6
  Runbook Phase 7  Live e2e, delegated multi-sig ADI   -> Gate 7
  Runbook Phase 8  Atomic fleet upgrade                -> final gate

═══════════════════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════════════════

  [ ] Corpus cases A-K exist, verdicted by accumulate-core, and C-F/I-J fail
      against the ORIGINAL code.
  [ ] Our digest set matches accumulate-core for every corpus signature, and
      at least one case is valid only under the Initiator() merkle form.
  [ ] 2-of-3 resolves; a duplicate key counts once; below threshold fails.
  [ ] Depth 21 refused; a cycle refused; a wrong delegator chain refused -
      each with its own readable reason.
  [ ] Unsupported signature types refused with an unsupported-type reason,
      never a threshold reason.
  [ ] A proof whose signers span two BVNs builds, carries a leg per partition
      in canonical order, and VERIFIES WITH THE NETWORK DISABLED.
  [ ] Corrupting leg i fails for every i; cross-bind refused at N legs; the
      34 existing single-partition mutations still rejected.
  [ ] govRoot moved exactly once, L4GovRootVersion == "certen:l4gov:v2",
      signer and submitter byte-identical.
  [ ] A live delegated multi-sig intent settles on base-sepolia, status 1.
  [ ] All seven validators report one distinct /app/validator sha256.
  [ ] go build ./... clean; go test ./pkg/... green; working-proof green.
      The three consolidated_governance-proof failures (TestURLUtils,
      TestG0Layer, TestCompleteWorkflow) are pre-existing, fail identically
      at baseline adb5cae, and must be left alone.

Begin with Runbook Phase 0. Do not write production code before Gate 1.
```
