# G1 cross-partition design addendum (RB9) — evidence 2.1

Status: DRAFT for verifier review, 2026-10-17. Author: orchestrator, from `research/R9-cross-partition-semantics.md` (R9; every
`AC:` / `V:` citation below is R9's, to `accumulate@e1d1db9ebb7c` and `validator@979a03c`). On approval the implementer commits this
file verbatim to `independant_validator/docs/proof/G1_CROSS_PARTITION.md` on the RB9-B branch. It raises PROOF_V2.md §3 S3 / §5.2
and G1_COMPLETENESS_ARGUMENT.md; it lowers nothing. Where it differs from RB9 Phase A, R9 §4 shows the executor code that forces
the difference and this file follows the executor.

## 1. Facts the design rests on (R9)

1. The partition Y that holds a signer's page judges the key signature, page version, thresholds and delegate entries at Y's own
   arrival block (`AC:internal/core/execute/v2/block/sig_user.go:99-152`, `sig_authority.go:149-189`). The principal's partition X
   judges only "authority in the principal's list now" and "all required authorities accepted" (`sig_common.go:347-375`,
   `transaction.go:136-222`) and trusts Y through a validator-signed, DN-anchored proof (`msg_synthetic.go:316-389`).
2. A vote from a different root identity always takes the DN round trip (even on the same partition); a vote from the same root
   identity runs inline in the producing block (`exec_process.go:213-227`). Measured: Y block 14004595 -> DN 10693641 -> X 14001100
   (anchor) -> X 14001101 (counted, executed) (R9 M7).
3. Delegation: each hop is judged on the delegating PAGE's own partition; the edge is `KeySpec.Delegate` (a BOOK) on the delegating
   page; `DelegationDepthLimit = 20` (20 pass, 21 refused, checked only where the key signature is submitted, `sig_user.go:160-175`);
   **the executor has no cycle detection**, a cycle is legal and bounded only by the 20-delegator path limit.
4. Authority rules: `Header.Authorities` (Baikonur+) are accepted AND required, may be foreign (`sig_common.go:381-387`,
   `transaction.go:159-168`); disabled authorities are not required but may vote; **if every authority is disabled (or the list is
   empty) and the type is not UpdateAccountAuth, ANY authority's single vote suffices** (`sig_common.go:367-369`, `account_auth.go:21-28`);
   the first ready page of a book, in index order `1..PageCount`, decides the book's vote (`transaction.go:284-292`); thresholds
   are tallied per delegation-path group (`transaction.go:331-382`).
5. A Kermit page is provable at a past Y block B_Y through `ForHeight`; its receipt passes through the DN-executed
   `BlockValidatorAnchor.StateTreeAnchor` of Y (R9 M6, 49 steps, intermediate at step 16). Retention is about 945 s / 725-939 heights
   per partition, relative to Y's last state-changing commit; the newest state-changing block is unprovable until Y commits again
   (median 1-2 heights, max 886 s); a block older than the span is gone (R9 M3-M5).
6. Routing: partition = top bits of `sha256(lower(host))[:8]` of the ROOT identity, so all accounts of a root identity share one
   partition (R9 §1d). A sub-identity is on the parent's partition.
7. (S) the harbor-mfg refusals: the certified key page is the initiator/payer page `acc://harbor-mfg-erp-tcl1.acme/book/1` (BVN3),
   which is NOT an authority and whose own vote is `unauthorized` (R9 §3). RB9 Phase A's governing-set rule alone does not clear it.

## 2. Decisions

**D1 — Proven-page set.** For an intent the report proves, each at its own partition and block, the union of:
(a) the principal's chain (account + ADI inheritance chain, as today) at X's B;
(b) every authority book in the resolved set (enabled AND disabled, because a disabled authority may still vote), every page
    `1..PageCount` of each, on any identity (the first ready page decides, so lower pages matter);
(c) every `Header.Authorities` book, and the transaction body's additional authorities (`GetAdditionalAuthorities`), likewise;
(d) **the authority that actually voted**, taken from the principal's PROVEN vote records, when every list authority is disabled
    (D3) — so the set is derived from proven principal state AND proven votes, never from the list alone;
(e) for every page entry with `Delegate` set, the delegate book and all its pages, recursively with a visited set and a depth bound
    of 20 delegators (a cycle is NOT a refusal; reaching pages only beyond depth 20 is ignored because no executed signature can
    have a longer path; a recorded path longer than 20 is the named state `g1_delegation_depth_exceeded`);
(f) the initiator/payer page(s) (the signature whose initiator hash equals `Header.Initiator`, and `CreditPayment.Payer`) even when
    they are not authorities, plus every page in a counted vote's `Origin` and every page in a delegated vote's `Delegator` path.
The BindProofV2 certified-key-page rule is KEPT (raise, never lower): it is satisfied because (f) proves the page it names.
Lite identities and lite token/data accounts (`shared.go:26-46`) are supported exactly as the executor resolves them
(`LiteIdentity -> [itself]`; `LiteTokenAccount -> [Delegate]` if set else the root identity; `LiteDataAccount -> []`); a root ADI with
an empty authority list is an executor ERROR under Baikonur+ (`utils.go:138-174`), not an empty set, and G1 follows that.

**D2 — Block selection B_Y.** For each partition Y holding a proven page other than X: B_Y = the latest Y block whose
`BlockValidatorAnchor` the Directory executed at or before the DN block that executed X's anchor for B, and ≥ the block that
produced every counted vote/signature on Y (including `HoldUntil` releases, `sig_common.go:44-54`). R9 confirms this is sound
(X can count a vote only after the DN anchored Y's producing block). B_Y must be an anchor-bearing block (`block_end.go:499-551`).
For the same-root-identity inline hop the producing block and the counting block coincide and the DN-order argument is not used.
The principal's partition keeps B and its anchor. Arrival-time page states come from the certified timeline (PROOF_V2 §5.2) built
per page in its own partition and MUST include signatures arriving on every page of a probed book, not only the voting page.

**D3 — Votes are proven, not recomputed from the list.** The report carries `Votes[]` copied from the principal's proven signature
chain at X's B: `{authority, origin, vote, delegators[], cause, transport: inline | sequenced{source,destination,number}}` each with
the receipt placing it in the principal's signature chain. The verifier re-evaluates every book's vote with the executor rule on the
timeline (thresholds, tReject default, abstain rule, first ready page, per-path groups; R9 §1c) and requires `Origin` and `Vote` to
equal the recorded ones, then requires readiness (all required authorities Accept, ≥ 1 vote; `transaction.go:194-218`). A voter outside
the list/headers while some list authority is enabled is discarded exactly as the executor does (`Unauthorized`) and does not count;
it is not a binding failure.

**D4 — Evidence 2.1.** `PageState{URL, State, Receipt, Chains, PendingHash, ChainError, Partition, Roles}`; `Anchors map[partition]
PartitionAnchor{Message, Receipt}` for X and every Y; `Votes[]` (D3). `Partition` is DERIVED by the verifier from the anchor
message `Source`, never trusted from the evidence; mismatch = `g1_foreign_partition_mismatch{url,claimed,derived}`. `Roles` ⊂
{principal-chain, authority-book, authority-page, header-authority, delegate-book, delegate-page, voter, initiator-signer}, recorded
and checked against the re-derived set. The report lists every proven page as `(partition, block, role)`. `2.0` documents stay valid
forever and verify byte for byte as today. New domain tags (never reused): `certen:g1:v4`, govRoot `certen:govroot:v4`.

**D5 — Routing check.** The proof also carries the routing table (`acc://dn.acme/routing`) proven in the Directory at the certified
block and the verifier checks `Partition == route(URL)` for every page. The routing account has one write since Kermit genesis (R9
M10) so this is one small extra account proof. If the implementer finds the Directory-held account cannot be proven to the certified
root with the existing machinery, that is a recorded finding for the orchestrator (not a silent drop): the report then carries the
named state `g1_routing_unproven{url,partition}` for every page and the PR text says so; RB9 is not done until the routing proof exists.

**D6 — Retention and readiness are named states, never fallbacks.** Capture reads the partition's advertised `retainedBlocks` before
choosing its deadline, starts as soon as the DN has executed Y's anchor for the producing block, and retries Y until Y's next
state-changing commit makes B_Y servable. Named: `g1_state_not_ready{partition,block}` (retrying; becomes the next state at the
horizon), `g1_historical_unavailable{partition,block}` (below the retained range — a lull longer than the span makes the last
block permanently unprovable; this is a property of node configuration and is reported with the advertised span),
`g1_partition_anchor_unavailable{partition,block}`, `g1_chain_unbound_pending` / `g1_chain_moved` (with partition),
`g1_header_authority_missing{authority}`, `g1_authority_missing{authority}`, `g1_authority_voter_outside_list{authority}`,
`g1_delegate_entry_absent{page,delegate,block}`, `g1_initiator_page_unproven{page,partition}`, `g1_vote_held{block}`,
`g1_executor_version_unsupported{version,block}` (pre-Baikonur `Path`/inheritance semantics differ: `sig_authority.go:175-178`,
`utils.go:152-154`), and the existing `g1_completeness_unproven` which is finally emitted where the closure cannot be derived.
Open item for the owner (queued, not blocking): ask the Accumulate operators for a longer `bpt-history-depth` on Kermit.

**D7 — Consensus switch.** govRoot v4 / `certen:g1:v4` over the 2.1 report; a governed rules version that switches the whole fleet at
one block. The next rules version after v14 is **v15**, and the RB9 consensus branch is STACKED on the v14 branch
(`pv2/rb12-a-rules-v14`); activation by chain state exactly as v13/v14 (no date in the binary). Before activation the fleet judges
exactly as today (v3 required for 2.0); after, every intent carries 2.1. `BindProofV2` additionally requires every page of D1(a)-(f)
to be among the proven pages at its own partition/block. Stored 2.0 proofs unchanged (stop-the-line check against the baseline).

**D8 — Completeness argument.** `G1_COMPLETENESS_ARGUMENT.md` §"Where it is not yet sound" 1-2 are marked SUPERSEDED (date, commit)
and replaced by the argument: the closure of D1 is derived from proven state under the executor rules of §1, the executor bounds
(20 authorities x 20 pages x 100 entries per account, `globals.limits`) make it finite, and each omitted page is either proven absent
by the book's proven `PageCount`/entry lists or reported by name.

## 3. What this changes in the runbook (recorded as findings)

- RB9-F1: "a cycle is a named refusal, as the executor treats it" is REFUTED — cycles are legal; refuse only a path > 20 (R9 §1b).
- RB9-F2: the governing set also contains `Header.Authorities`, disabled-but-voting authorities and the actual voter under all-disabled
  (R9 §4.2); and the initiator page must be proven (R9 §3).
- RB9-F3: arrival-time states are per signature at its arrival block (timeline), not Y's state at B_Y (R9 §4.1a).

## 4. Acceptance of this design (verifier)

Every D-statement cites R9/executor code; every unavailable case is a named state; nothing lowers PROOF_V2.md §3 S3.
