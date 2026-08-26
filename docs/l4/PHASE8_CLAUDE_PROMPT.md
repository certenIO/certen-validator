# Claude Code Prompt — Phase 8 Execution (close what Phase 7 left open)

Paste the block below into a fresh Claude Code session rooted at
**`C:\Accumulate_Stuff\certen\independant_validator`**.

That is the git repository every edit lands in, so `git status`, `git diff` and
rollback all work without a `cd`. `C:\Accumulate_Stuff\certen` is *not* a
repository, and `accumulate-core` is a **sibling of `certen`** — referenced by
absolute path and read-only.

**End state:** a cross-partition governance intent settles on chain under a
govRoot that commits to every signer partition's quorum; the proof says which of
its claims rest on weaker evidence; and the rules the corpus could not reach are
proven against the network rather than against a fixture.

---

```
You are closing the six things Phase 7 left open. Phase 7 made delegated and
multi-signature governance work; it did not finish making the system honest
about what it proves.

THE SIX, ORDERED BY WHAT BREAKS IF THEY ARE WRONG - not by effort:

  1  CROSS-PARTITION PATH HAS NEVER RUN THROUGH SETTLEMENT.
     Zero multi-leg proofs have ever been stored: no proof has >2 layer-4 rows,
     no layer-1 row carries additionalLegs. Every piece is individually tested
     and the COMPOSITION has never run once. ConsensusProof.BVNs is omitempty,
     so every govRoot in production has had it ABSENT; a cross-partition intent
     produces the first preimage where it is present, and govRoot is what TX2
     verifies against. THIS IS THE ONLY ITEM WHERE BEING WRONG REVERTS MONEY.

  2  THE WEAKENED CROSS-PARTITION TIMING BASIS IS NOT RECORDED.
     For a cross-partition signer the localBlock<=execMBI comparison is skipped,
     correctly - those indices count different chains. Ordering rests instead on
     execution inclusion. That reasoning is in a COMMENT and `sameClock` is a
     LOCAL VARIABLE. A reader sees TimingVerified:true and cannot tell this
     signer's timing rests on a weaker basis. summary_only exists in this
     codebase precisely so a weaker claim cannot read as the stronger one.

  3  MULTI-AUTHORITY AND PAGE-2 ARE PROVEN OFFLINE ONLY.
     TestP7_Auth_* pins the rules against a purpose-built source. No corpus
     account has two authorities, and no book has a page 2 that signs, so the
     code that reads those FROM THE CHAIN has never run. In Phase 7, five
     defects were findable only by running. Offline-green was five for five not
     enough.

  4  A DEAD, INVENTED DIGEST IS STILL IN THE TREE.
     g1_enhanced_crypto.go verifies against sha256("accumulate/" || txHash ||
     version || timestamp). That is not the Accumulate digest and never was.
     processSignaturesWithSuperiorCrypto has no callers, so it is inert - and
     wiring it up yields a digest that never verifies, surfacing as a GOVERNANCE
     REJECTION indistinguishable from "the institution did not authorize this".

  5  ONLY AcceptThreshold IS MODELLED.
     KeyPage also carries RejectThreshold, ResponseThreshold and BlockThreshold.
     KeyPageState drops all three at parse.

  6  BODY-DERIVED EXTRA AUTHORITIES ARE NOT DERIVED.
     ResolveAccount takes extraAuthorities and nothing supplies them. An
     UpdateKeyPage that ADDS a delegate requires that delegate's approval;
     UpdateAccountAuth AddAuthority likewise. Accumulate also adds
     Header.Authorities from V2Baikonur.

  5 and 6 are "narrower claim than advertised", not "wrong answer". 1 through 3
  can produce a confidently wrong result. That is the ordering and it is not
  negotiable.

AUTHORITATIVE DOCUMENT - read in full before any edit:
  docs/l4/PHASE8_RUNBOOK.md

Background, if anything surprises you:
  docs/l4/PHASE7_RUNBOOK.md          (the phase this closes out)
  docs/l4/PHASE7_CORPUS_MANIFEST.md  (esp. section 6 - two-sided delegation)
  docs/l4/PHASE7_DELEGATION_PLAN.md
  accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/docs/CERTEN_GOVERANCE_PROOF_SPEC.MD

CODE IN SCOPE - read each COMPLETELY, not in fragments:
  A. consolidated_governance-proof/
       authority_resolution.go  authority_set.go  authority_page_source.go
       g1_signature_routes.go   g1_delegated_enumeration.go
       g1_enhanced_crypto.go    common.go  types.go
  B. pkg/proof/
       liteclient_adapter.go  signer_partitions.go
       governance_evidence.go   <- THE PATTERN FOR ITEM 2
       chained_proof_storage.go
  C. pkg/execution/contracts/phase6_invariant_test.go   <- the govRoot goldens
  D. Accumulate core - REFERENCE, DO NOT MODIFY:
       C:\Accumulate_Stuff\accumulate-core
       internal/core/execute/v2/block/transaction.go  (userTransactionIsReady,
         AuthorityDidVote, AuthorityWillVote - THE authority model)
       protocol/types_gen.go   (KeyPage, AccountAuth, AuthorityEntry)
  E. Reference implementation, DO NOT MODIFY:
       C:\Accumulate_Stuff\accumulate-explorer-clone\explorer
       src/components/common/Signatures.tsx  (authority derivation, item 6)

LIVE RESOURCES
  Accumulate v3 : https://kermit.accumulatenetwork.io/v3
  CERTEN host   : ssh -i ~/.ssh/certen_server root@116.202.214.38
  Proof DB      : docker exec certen-postgres psql -U certen -d certen_proofs
  Validators    : certen-validator-1..7, source at /root/certen-validators
  E2E           : node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand
  Corpus tool   : go run ./cmd/p7corpus -stage {keycheck|partitions|capture|prodpath|multileg}

═══════════════════════════════════════════════════════════════════
NON-NEGOTIABLE RULES
═══════════════════════════════════════════════════════════════════

1. BACKUP FIRST. Runbook Phase 0, manifest verified, before touching anything.
   Record the govRoot baseline: 15d8808e2ea6ab77, version certen:l4gov:v2.

2. RUNNING BEATS READING. Phase 7 found five defects that every offline test
   missed. When you have made something work in a test, run it against Kermit
   before you call it done. "The tests pass" is not the same claim as "it works"
   and you must never substitute one for the other.

3. VERDICTS COME FROM accumulate-core, NEVER FROM US. Every corpus expectation is
   protocol.VerifyUserSignature against the real protocol package. A corpus
   verdicted by our own code proves only that we agree with ourselves.

4. govROOT IS 15d8808e2ea6ab77 AND MUST NOT MOVE. Item 2 touches a struct
   REACHABLE FROM THE govROOT PREIMAGE (TimingVerified -> ValidatedSignature ->
   G1Result -> SetG1FromJSON). The marker goes BESIDE the hashed struct, the way
   GovReceiptEvidence did. If govRoot moves, you put it inside. Revert.

5. PHASE 1 CHANGES A PRODUCTION KEY PAGE. acc://certen-kermit-12.acme/book/1 is
   what every production intent signs from. Verify an ordinary intent still
   settles BEFORE attempting the cross-partition one - if the page change broke
   normal traffic, that must be found then, not blamed on the multi-leg path
   later. Rollback is in runbook 1.2.

6. GATES ARE BLOCKING. Gate N green before step N+1. Do not batch and check at
   the end.

7. A SUBMIT RESULT IS NOT AN EXECUTION RESULT. code:ok describes envelope
   acceptance and says nothing about execution. Verify against the ACCOUNT, the
   PAGE, or chain_execution_results - never against the thing you just sent.

8. FAIL CLOSED, AND SAY WHICH THING WENT WRONG. An authority that could not be
   READ is not an authority that REFUSED. A capability limit is not a governance
   rejection. A threshold shortfall and a signature we could not evaluate must
   never be reported the same way. A false governance rejection is worse than an
   error, because an error is obviously a problem and a false rejection looks
   like a finding.

9. NEVER SILENTLY SKIP. A `continue` that drops a page, a signature or an
   authority understates the authority and surfaces as an unmet threshold. In
   Phase 7 exactly one such `continue` hid a defect for three debugging rounds.
   If something cannot be evaluated, say so loudly and stop.

10. ONE IMPLEMENTATION OF A DIGEST. Item 4 exists because there were two. Do not
    leave a deprecated copy behind; a second implementation is a thing that can
    drift.

11. DO NOT REIMPLEMENT CANONICAL ENCODING. Build real protocol values and call
    their own methods. The encoding is field-tagged, omit-if-zero, varint
    length. Hand-rolling it is how the field-strictness bugs happened.

12. CANONICAL ORDERING IS LOAD-BEARING. Sort by partition, by authority URL, by
    signer. Discovery order is not stable, and unordered anything makes two
    validators reading identical chain data produce different bytes.

13. USE base-sepolia. $0.35 flat. ethereum-sepolia is ~$3.30/proof and its
    cost-basis gate goes stale after 48h of no traffic.

14. WATCH THE ELECTED EXECUTOR. Settlement runs on one validator chosen by
    BFT-DETERMINISTIC, not validator-1. Find it in the logs, then read that node.
    Confirmation can lag the consensus-complete line by ~90s.

15. THE FLEET UPGRADE IS ATOMIC, AND THERE ARE THREE BINARIES. /app/validator
    (L1-L5, linked in), /app/govproof (G0-G2, separate exe), /app/txhash (G2
    payload). A governance-only change leaves /app/validator byte-identical.
    Verify all three are single-distinct ON THE IMAGES BEFORE ANY CONTAINER
    STARTS - docker exec cannot do that, it needs a container.

16. REPORT FAITHFULLY. If a gate fails, say so with the output. If you skipped
    something, say that. Do not describe a step as done because the code looks
    right. When you find that something you already claimed was finished is not,
    say that plainly and fix it.

═══════════════════════════════════════════════════════════════════
ORDER OF WORK
═══════════════════════════════════════════════════════════════════

  Runbook Phase 0  Safety + baselines                    -> Gate 0
  Runbook Phase 1  Cross-partition through SETTLEMENT    -> Gate 1  <- HIGHEST RISK
  Runbook Phase 2  Timing basis recorded beside the hash -> Gate 2
  Runbook Phase 3  Cases L/M/N provisioned and proven    -> Gate 3
  Runbook Phase 4  Dead invented digest deleted          -> Gate 4
  Runbook Phase 5  Reject/Response/Block thresholds      -> Gate 5
  Runbook Phase 6  Body-derived extra authorities        -> Gate 6
  Runbook Phase 7  Spec claim reconciled                 -> Gate 7
  Runbook Phase 8  Atomic fleet upgrade                  -> final gate

═══════════════════════════════════════════════════════════════════
DEFINITION OF DONE
═══════════════════════════════════════════════════════════════════

  [ ] A cross-partition intent SETTLED on base-sepolia with status = 1, and its
      stored proof carries >=2 BVN legs plus the DN leg.
  [ ] That proof reassembles from storage and verifies OFFLINE, and its
      ConsensusProof carries a populated `bvns` - the first in production.
  [ ] An ordinary single-partition intent still settles, before and after.
  [ ] A cross-partition proof's evidence NAMES the signatures whose timing rests
      on execution inclusion rather than on local ordering; a same-partition one
      does not.
  [ ] Corpus cases L (two authorities), M (page 2 signs) and N (disabled
      authority) exist, are verdicted by accumulate-core, and are proven through
      the REAL G1 prover against Kermit.
  [ ] No second digest implementation remains anywhere in the tree.
  [ ] A page carrying a reject/response/block threshold is either evaluated or
      explicitly marked as carrying rules this proof did not verify.
  [ ] An UpdateKeyPage that adds a delegate requires that delegate's approval,
      derived rather than supplied.
  [ ] The spec claims only what is implemented, or names its exclusions.
  [ ] govRoot is 15d8808e2ea6ab77, or moved ONCE deliberately under a bumped
      version with the previous value still reproducible.
  [ ] All seven validators report one distinct sha256 for EACH of validator,
      govproof and txhash.
  [ ] go build ./... clean; go test ./pkg/... green; working-proof green. The
      three consolidated_governance-proof failures (TestURLUtils, TestG0Layer,
      TestCompleteWorkflow) are pre-existing, fail identically at baseline
      adb5cae, and must be left alone.

Begin with Runbook Phase 0. Do not touch the production key page before Gate 0.
```
