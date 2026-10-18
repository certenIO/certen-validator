# G1 cross-partition design addendum (RB9) — evidence 2.1

Status: REVISED 2026-10-17 after verifier review (DEF-1..DEF-8 applied; checkins/RB9-A-DESIGN.md). Author: orchestrator, from
`research/R9-cross-partition-semantics.md` (R9). `AC:` = `accumulate@e1d1db9ebb7c` (module cache
`gitlab.com/accumulatenetwork/accumulate@v1.4.7-0.20260926030013-e1d1db9ebb7c`), `V:` = `validator@979a03c`. Commit this file verbatim to
`independant_validator/docs/proof/G1_CROSS_PARTITION.md`. It raises PROOF_V2.md §3 S3 / §5.2 and G1_COMPLETENESS_ARGUMENT.md; it lowers nothing.

## 1. Facts the design rests on (each re-read by the verifier in the executor source)

1. The partition Y holding a signer's page judges the key signature, page version, thresholds and delegate entries at Y's own arrival block
   (`AC:internal/core/execute/v2/block/sig_user.go:99-152`, `sig_authority.go:149-189`). The principal's partition X judges only "authority in
   the principal's list now" and "all required authorities accepted" (`sig_common.go:347-375`, `transaction.go:136-222`) and trusts Y through a
   validator-signed, DN-anchored proof (`msg_synthetic.go:316-389`).
2. Same-root-identity votes run inline in the producing block; any other identity (even on the same partition) takes the DN round trip
   (`exec_process.go:213-227`; `LocalTo` = equal root identity `pkg/url/url.go:397-401`). Measured Y 14004595 -> DN 10693641 -> X 14001100 -> X 14001101 (R9 M7).
3. Delegation: each hop is judged on the delegating PAGE's partition; the edge is `KeySpec.Delegate` (a BOOK) on the delegating page;
   `DelegationDepthLimit = 20` (`protocol/protocol.go:101-102`): 20 delegators pass, 21 refused (`sig_user.go:172-174`), no later hop re-tests
   (`sig_authority.go:32-55,149-189`). The executor has NO cycle detection; only direct self-delegation is refused at write time
   (`chain/update_key_page.go:165-166,185-186`), so a longer cycle is legal.
4. `Header.Authorities` (Baikonur+) are accepted and REQUIRED, may be foreign (`sig_common.go:381-387`, `transaction.go:159-168`). Disabled authorities
   are not required but may vote; if every authority is disabled (or the list is empty) and the type is not UpdateAccountAuth, ANY authority's vote
   is accepted (`sig_common.go:361-369`, `protocol/account_auth.go:21-28`, `access_control.go:11-19`). Readiness skips disabled entries and needs
   ≥ 1 recorded vote (`transaction.go:194-218`) — the VALUE of a disabled authority's vote is never examined, so with every authority disabled any
   one vote, even a Reject or Abstain, satisfies readiness. The first ready page of a book, in order `1..PageCount`, decides the book's vote
   (`transaction.go:284-292`; `protocol/authority.go:181-187`); thresholds are tallied per delegation-path group (`transaction.go:331-382`, iterating
   a Go map at :349, active sets cleared on send `sig_common.go:66-70,280-307`) — so re-evaluation must run per arrival event, never once on a final set.
5. A page is provable at a past Y block B_Y via `ForHeight`; its receipt passes through the DN-executed `BlockValidatorAnchor.StateTreeAnchor` of Y
   (R9 M6). Retention ≈ 945 s / 725-939 heights per partition, relative to Y's last state-changing commit; the newest state-changing block is
   unprovable until Y commits again (median 1-2 heights, max 886 s) (R9 M3-M5).
6. Routing: partition = top bits of `sha256(lower(host))[:8]` of the ROOT identity, so all accounts of a root identity (and sub-identities) share a
   partition (`pkg/url/url.go:437-442`, `internal/api/routing/tree.go:33-52,99-121`).
7. The harbor-mfg refusals: the certified key page is `acc://harbor-mfg-erp-tcl1.acme/book/1` (BVN3), not an authority, whose own vote is
   `unauthorized` (R9 §3; `V:pkg/intentcert/bind_v2.go:49-58`, `pkg/proof/signing_key_page.go:131-172`, `pkg/consensus/bft_integration.go:873-884`).

## 2. Decisions

**D1 — Proven-page set.** The report proves, each at its own partition and block, the union of:
(a) the principal's chain (account + ADI inheritance chain) at X's B;
(b) every authority book in the resolved set (enabled AND disabled), every page `1..PageCount` of each, on any identity;
(c) every `Header.Authorities` book and the body's additional authorities (`GetAdditionalAuthorities`, nil for WriteData: `protocol/transaction.go:140-177`);
(d) the authority that actually voted, from the principal's PROVEN vote records, when every list authority is disabled (D3);
(e) delegates: for every page entry with `Delegate` set, the delegate book and all its pages `1..PageCount`, by breadth-first search from each
    authority book (level 0), keeping per book the least level seen (a book reached again at a smaller level is re-expanded). A key page in a book
    at level n signs with n delegators, so books to level 20 inclusive are proven and the Delegate entries of level-20 pages are not followed
    (`sig_user.go:172`). A cycle is not a refusal. A recorded path of more than 20 delegators is the named state `g1_delegation_depth_exceeded{length}`;
(f) the certified key page exactly as `ResolveSigningKeyPage` resolves it (the page of the intent's declared book with a recorded signature on the
    transaction: `signing_key_page.go:131-172`, `bft_integration.go:873-884`), resolved by the capture at discovery from the declared book/page and
    the transaction's signer list, whatever its role; the initiator/payer page (`Header.Initiator`; `CreditPayment.Payer` is the innermost key page:
    `sig_user.go:517-537`, `protocol/signature.go:930`); every page named by a counted vote's `Origin`; every page in the `Delegator` path of a counted
    vote or of the initiator signature. Its partition's B_Y must be ≥ the arrival block of its signature on the transaction. Role `certified-key-page`
    is recorded; an unresolvable or uncaptured one is `g1_certified_page_unproven{page,partition}`.
The BindProofV2 certified-key-page rule is KEPT (raise, never lower): it is satisfied because (f) contains the page the rule names.
Lite identities and lite token/data accounts are supported as the executor resolves them (`AC:internal/core/block/shared/shared.go:26-46`:
`LiteIdentity -> [itself]`; `LiteTokenAccount -> [Delegate]` else root identity; `LiteDataAccount -> []`); a root ADI with an empty list is an
executor ERROR under Baikonur+ (`internal/core/execute/v2/block/utils.go:138-174`), not an empty set.

**D2 — Block selection B_Y.** For each partition Y holding a proven page other than X: the capture takes the smallest servable anchor-bearing Y block
≥ the bound "every counted vote's production block and every counted signature's arrival block on Y (including `HoldUntil` releases,
`sig_common.go:44-54,84-111,133-172`)"; "the latest Y block whose BlockValidatorAnchor the DN executed at or before the DN block that executed X's
anchor for B" is the admissible upper limit. Soundness only needs B_Y ≥ every counted production/arrival block (timeline folds history to B_Y). B_Y
must be found from the DN anchor pool (not guessed): a BVN block that only receives a DirectoryAnchor sends none unless `AnchorEmptyBlocks`
(`block_end.go:543-550`). Same-root-identity inline hops: producing and counting block coincide. The principal's partition keeps B and its anchor.
Arrival-time page states come from the certified timeline (PROOF_V2 §5.2) per page in its own partition, including signatures arriving on EVERY page
of a probed book.
- **D2a Soundness (code).** For X a BVN, X counts a foreign vote only if the proof's terminal root is a Directory root in X's `AnchorChain(Directory)`
  (`msg_synthetic.go:340`); the Kourou source-rooted alternative (`:347-356`) looks up `AnchorChain(Y)` on X, which only the Directory ever writes
  (`chain/partition_anchor.go:32-34,94`; `chain/directory_anchor.go:74` writes only the Directory chain) so it cannot hold on a BVN. Y releases block
  p's messages only after executing a DirectoryAnchor whose receipt names p (`block_begin.go:306-330`). Hence the DN executed Y's anchor for p before
  X's anchor for B, and the rule returns a block ≥ p.
- **D2b Y = Directory.** B_Y is a DN block whose DirectoryAnchor the spine verifies (the DN has no BlockValidatorAnchor: `chain/partition_anchor.go:32-34`;
  `page.go:153-175` accepts only that kind). The page is proven to that anchor's `StateTreeAnchor` through minor-root hops as `SetCheck.Hops` reach
  network/globals (`evidence.go` SetCheck; `validator_set_proof.go:238-251`). `Anchors["Directory"]` holds a DirectoryAnchor message; the anchor kind is
  checked per partition kind.
- **D2c X = Directory.** The DN counts a BVN vote once `holdsAnchorRoot(AnchorPool, Y, terminal)` holds (`msg_synthetic.go:347-356`), after it executed
  Y's BlockValidatorAnchor (`partition_anchor.go:94`). B_Y is the latest Y block whose anchor the DN executed at or before the principal's DN block B.
- A conformance vector for each of a/b/c is required before RB9-C.

**D3 — Votes are proven, not recomputed from the list.** The report carries `Votes[]` copied from the principal's proven signature chain at X's B:
`{authority, origin, vote, cause, transport: inline | sequenced{source,destination,number}}`, each with the receipt placing it in that chain.
`delegators[]` is NOT a field of the principal's vote (the last hop has `Delegator` empty, `sig_authority.go:185-188`). The path is rebuilt by following
`cause` back through each hop's AuthoritySignature, each recorded in its delegating page's own signature chain (`sig_authority.go:179`,
`sig_common.go:216-221`) with a receipt on its partition, to the key signature, whose own `Delegator` list (`sig_user.go:158-184`; `delegators[0]` is
nearest the key page) is the path. The verifier re-evaluates each page at each arrival event in order: the `signerCanSignTransaction` blacklist for
the key page and each delegating page (`sig_common.go:309-345`, `sig_authority.go:162-166`); signer version equality for the key signature
(`sig_user.go:249-252`) but not for delegated hops, which take the delegating page's current version (`sig_authority.go:169-173`); replacement of the
active set by a newer version (`sig_common.go:238-250`); Accept/Reject/Response thresholds, Abstain and per-path groups (`transaction.go:297-385`);
first ready page (`:284-292`); then readiness (`transaction.go:194-218`). With every authority disabled the verifier accepts exactly what the executor
did (any one recorded vote suffices) and reports `authorization_mode = all_authorities_disabled` (S3 then states what the executor required, not more).
Unauthorized authority signatures never reach the principal's chain (`sig_authority.go:127-136`), so nothing is "discarded" from `Votes[]`.

**D4 — Evidence 2.1.** `PageState{URL, State, Receipt, Chains, PendingHash, ChainError, Partition, Roles}`; `Anchors map[partition]PartitionAnchor{Message,
Receipt}` for X and every Y (anchor kind per partition kind, `page.go:34-39,153-175`); `Votes[]` (D3); the routing proof (D5). `Partition` is DERIVED by
the verifier from the anchor message `Source`, never trusted (mismatch = `g1_foreign_partition_mismatch{url,claimed,derived}`; today the verifier blanks
the routing table, `evidence.go:342-344`). `Roles` ⊂ {principal-chain, authority-book, authority-page, header-authority, delegate-book, delegate-page,
voter, initiator-signer, certified-key-page}, recorded and checked against the re-derived set. The report lists every proven page as
`(partition, block, role)`. `2.0` documents stay valid forever and verify byte for byte. New domain tags (never reused): `certen:g1:v4`, `certen:govroot:v4`.

**D5 — Routing proof.** `acc://dn.acme/routing` is proven with the machinery that proves dn.acme/network and dn.acme/globals: an `AccountStateProof`
(`validator_set_proof.go:199-231`, built by `fetchAccountStateProofWith` which supports `{"forHeight": block}`: `validator_set_builder.go:172-228`)
bound to the same certified `StateTreeAnchor` as `SetCheck` (`evidence.go` ~311-323), decoded as `protocol.RoutingTable` (`pkg/types/network/globals.go:143-144`),
with its main-chain height. The verifier applies the executor's route function (overrides keyed by identity hash, then the prefix tree) to every page
URL and requires `route(URL) == Partition`. A table with main-chain height 1 (never written since genesis; R9 M10) holds at every B_Y; for any other
height the report carries `g1_routing_history_unproven{height}`. The same route function and the R9 M9 vectors ship in Go and TS. RB9 is not done without this proof.

**D6 — Named states and verdict semantics.** Capture reads the partition's advertised `retainedBlocks` before choosing its deadline, starts as soon as the DN
executed Y's anchor for the producing block, and retries Y until its next state-changing commit makes B_Y servable. Each state below is an S3 verdict
`unproven{state,partition,block}` (the intent is not verified) except where marked: `g1_state_not_ready{partition,block}` (retrying; becomes the next at
the horizon), `g1_historical_unavailable{partition,block}` (below the retained range; a lull longer than the span makes the last block permanently
unprovable; reported with the advertised span), `g1_partition_anchor_unavailable{partition,block}`, `g1_chain_unbound_pending` / `g1_chain_moved` (with
partition), `g1_header_authority_missing{authority}`, `g1_authority_missing{authority}`, `g1_delegate_entry_absent{page,delegate,block}`,
`g1_certified_page_unproven{page,partition}`, `g1_executor_version_unsupported{version,block}` (pre-Baikonur Path/inheritance differ:
`sig_authority.go:175-178`, `utils.go:152-154`), `g1_executor_override_unsupported{type}`, `g1_closure_exceeds_budget{pages,limit}` (D1 closure larger than
the evidence budget = consensus block size), `g1_completeness_unproven`. DISCLOSURES (verified, not refusals): `g1_authority_voter_outside_list{authority}`
(executor accepts any voter when every authority is disabled, `sig_common.go:367-369`; `authorization_mode = all_authorities_disabled`);
`g1_vote_held{block}` is emitted only when a HoldUntil release's producing block cannot be established — a release is a supported vote whose producing
block is the Y block that released it, proven by the receipt of its SequencedMessage in Y's synthetic chain. The re-evaluation covers WriteData to a
non-lite data account (default rules, `chain/write_data.go:35-67`) and to a lite data account (any one vote); a body type with another executor override
(`chain/update_key.go:48`, `chain/utils.go:16-68`) is `g1_executor_override_unsupported`, never judged by the default rule. Open item for the owner (queued):
ask the Accumulate operators for a longer `bpt-history-depth` on Kermit. Added 2026-10-18 (RB9-C1a-F5, implemented in C1a): `g1_role_mismatch{partition,block}` (a page recorded roles differ from the roles re-derived from the proven states) and `g1_routing_mismatch{partition,block}` (the proven routing table, unchanged since genesis, sends a page to a partition other than the one its anchor names) are refusals of the same kind as the states above; the C1b-1 names are in section 5.

**D7 — Consensus switch (rules v15, stacked on v14).** Mechanics on top of `pv2/rb12-a-rules-v14` (d20f693; `origin/pv2/rb12-a-rules-v14:pkg/consensus/execution_rules.go`:
`CurrentExecutionRulesVersion = executionRulesV14` at :240, `compatibleContinuations` :258-264, `checkExecutionRulesVersion` :305-312): add `executionRulesV15 = 15`; set
`CurrentExecutionRulesVersion = executionRulesV15`; re-point EVERY `compatibleContinuations` entry v7..v13 from v14 to v15 and add v14 -> v15 (a missed
entry makes a node stamped v7..v13 refuse to start under a v15 binary); add the v15 case to `committedRulesVersion`, `rulesV15FirstVerdict` to the boot list
(`abci_validator.go` ~299) and the `recordFirstVerdict` sites (`committed_operations.go` ~122-126, 308-310) with `RulesFirstVerdict(15)`. Activation is a
committed fact: a new admin-quorum kind `certen.g1.crosspartition.activate/v1` (signed by `AdminSetAt` over the chain id, recorded append-only, refusal code
= next free, 18 at d20f693) accepted at block H. Blocks at height > H must carry 2.1. Before H the v15 binary decides every block exactly as v14 and
refuses a 2.1 certificate (`ErrIntentProofV21NotInForce`, beside `ErrIntentProofV3NotInForce`; `ProofV3Required` depends only on spine and registry:
`intent_certificate.go:82-89`, so it cannot carry the 2.1 switch). `IndexCommittedHistory` refuses to start on any committed activation-kind transaction
v15 did not decide. The number is v15 only if v14 merges first; RB9-C takes `Current+1` of its base and OWNER_QUEUE records the merge order.
govRoot v4 / `certen:g1:v4` over the 2.1 report. `BindProofV2` additionally requires every page of D1(a)-(f) to be among the proven pages at its own
partition/block. Stored 2.0 proofs unchanged (stop-the-line against `evidence/baseline-verdicts.json`). RB9-C must measure a 2.1 document against the
consensus block limit.

**D8 — Completeness argument.** `G1_COMPLETENESS_ARGUMENT.md` §"Where it is not yet sound" 1-2 are marked SUPERSEDED (date, commit) and replaced by: the
closure of D1 is derived from proven state under §1; finiteness follows from the proven `PageCount` of each book (`protocol/authority.go:181-187`) and the
proven entry lists — `globals.limits` (20/20/100) are mutable governance values and are NOT a premise; each omitted page is proven absent by those lists
or reported by name.

## 3. Findings recorded against the runbook
- RB9-F1: "a cycle is a named refusal" REFUTED (cycles legal; refuse only path > 20).  - RB9-F2: governing set also contains Header.Authorities,
  disabled-but-voting authorities, the actual voter under all-disabled, and the certified key page / initiator.  - RB9-F3: arrival-time states are per
  signature at its arrival block (timeline), not Y's state at B_Y.  - RB9-F4: Directory as X or Y needs D2b/D2c.

## 4. Acceptance (verifier)
Every D-statement cites code or a primary source; every unavailable case is a named state; nothing lowers PROOF_V2.md §3 S3.

## 5. Revision 2026-10-18 (RB9 Phase C1b-1: the certified timeline). Added; nothing above is changed.

**What C1a left, and what this delivers.** C1a proved each page against its own partition's anchor and that every counted signature is a member of its page's
signature chain at B_Y (so arrival <= B_Y), but did not judge a signature against the page as it stood when it arrived. PROOF_V2.md 5.2 steps 2-5 (the
certified timeline) did not exist in `pkg/proof/v2` at all, for 2.0 either (only step 1, the chain binding). They exist now for 2.1, as follows. Evidence 2.0
and its goldens are untouched.

**New evidence members (all `omitempty`, 2.1 only; a 2.0 document that carries a 2.1 member is refused as before).**
- `PageState.History` (`PageHistory`): the page's main chain from entry 0 to its height at B_Y (each entry a binary transaction; an UpdateKey also carries its
  initiating signature) and its `main-index` chain in full. The verifier folds the entry hashes with `merkle.State` to the `main` chain root bound in
  `PageState.Chains` and the index entries to the `main-index` root (equal height AND equal pending hashes): an entry inserted, omitted, changed or reordered
  is `g1_history_fold_mismatch`. The block of main entry j is the first `main-index` entry whose `Source` reaches j (the index must be strictly increasing and
  end at the last entry). The entries are replayed from the page's genesis transaction with the executor's rules (`govvote.GenesisPage`, `govvote.Replay`: one
  replay, shared with v1); the replay must end in the proven page in everything that decides who may sign (version, thresholds, blacklist, each entry's key hash
  and delegate), otherwise `g1_history_head_mismatch`; an entry the replay cannot apply as the executor did is `g1_history_unreplayable` (the replay declining
  to guess, not a fact about the page).
- `VoteHop.Arrival` (`Arrival`): the exact arrival block is DERIVED, never claimed (RB9-C1a-F1). The position p of the hop's message in the page's `signature`
  chain is fixed by its receipt: for a chain of n entries the sequence of Right flags of the receipt of entry p is determined (the bits of p inside its perfect
  subtree, one Right step for the smaller peaks combined, one non-Right step per larger peak, as `merkle.State.Anchor` combines them), and exactly one p < n has
  the receipt's shape (unit-tested against an independent step-by-step construction for every chain up to 70 entries). Two ADJACENT `signature-index` entries,
  each a member of the bound `signature-index` chain at its own derived position, bracket it: the previous entry's `Source` < p <= this entry's `Source`, and this
  entry's `BlockIndex` is the arrival block (`internal/core/execute/v2/block/utils.go` `addChainAnchor`). A claimed `Block` that differs, a missing previous entry
  (unless this is index entry 0), non-adjacent entries, or entries that do not bracket p is `g1_arrival_unproven`.
- `Vote.Counted`: the other signatures the pages on the cause chain counted (a threshold above 1), recorded like hops, with the arrival derived the same way.
- `Vote.Produced` (`Production`): the block that PRODUCED the vote, for HoldUntil (D6). A sequenced vote: the `SequencedMessage`'s entry in the source
  partition's synthetic ledger (`acc://bvn-Y.acme/synthetic`, a proven page with the new role `synthetic-chain`) `main` chain, its block derived as above; an
  inline vote: the vote's own entry in the principal's `signature` chain. A vote produced before the signature that caused it arrived is
  `g1_block_before_signature`. A vote with no production proof is reported as `g1_vote_held{partition,B_Y}` in `Report.Unproven` (the block that produced it - a
  HoldUntil release - is not established); a vote WITH the proof is a supported vote judged at its release block, not a disclosure.
- `Evidence.Transaction`: the governed transaction (binary), whose hash must be `TxHash` and whose principal the evidence's account (`g1_transaction_mismatch`). Its
  type decides the page blacklist and whether disabled authorities are required (UpdateAccountAuth); its header and body name the extra required authorities
  (`g1_header_authority_missing` if one has no proven pages). Every carried signature is bound to its chain entry (the `SignatureMessage` hash equals the entry) and
  a key signature must sign the transaction (`g1_signature_invalid`).

**The re-evaluation (step 5).** The vote model of v1 (`govvote`: the blacklist for the key page and each delegating page, version equality for the key signature
and not for delegated hops, replacement of the active set by a newer version, Accept/Reject/Response thresholds, Abstain, per-path groups, the first ready page
of the book, the recorded page checked against the replay) runs on the certified timelines with the derived arrival blocks as its facts. The verifier requires
its result to equal every recorded vote's Origin and Vote (`g1_vote_not_reproduced`, which also carries the model's own refusal when a recorded fact cannot be
reconciled with the certified history), and readiness: every required authority (enabled listed authorities, all listed when the type requires authorization,
plus header and body authorities) voted accept (`g1_authority_not_ready`). With every listed authority disabled and a type that does not require authorization the
report states `AuthorizationMode = all_authorities_disabled`: readiness is one recorded vote (of any value), exactly what the executor required, and a voter
outside the list is the disclosure `g1_authority_voter_outside_list`. Otherwise the mode is `authorities_required` and a vote by an authority outside the
principal's set is refused.

**The governing set follows the timeline.** A delegate book named by ANY state of a page with a certified history (not only its state at B_Y) is a delegate-book of the closure, with all its pages: the delegation a counted signature went through may have been removed after it arrived. A delegated hop is judged on the delegating page at the authority signature arrival: the page must hold the delegate entry then, and - unlike a key signature - takes its then-current version.

**When the evidence is silent.** Without the transaction, a history for every page a counted signature was recorded on, or the arrival proof of every counted
signature, the votes are NOT re-evaluated and the report says so by name (`g1_completeness_unproven`, with the missing member in its detail): never a verified S3.
A carried history is always verified, whatever else is missing.

**What the re-evaluation proves, precisely (RB9-C1b-1-F1).** It proves SUFFICIENCY: the recorded vote is derivable from signatures that were valid when they
arrived, on pages as they then stood. It does not enumerate every signature recorded on a page for the transaction (the per-transaction signature set is not
committed by the state tree; the `signature` chain holds the messages of every transaction), so that no other signature - on a lower page of the book or another
delegation path - would have decided differently is established by the executor's own recorded Origin (the first ready page decided), not re-derived. This is
stated here and not hidden.

**RB9-C1a-F3 (recorded).** The upper limit of D2 ("the latest Y block whose BlockValidatorAnchor the DN executed at or before the DN block that executed X's anchor
for B") is not re-checkable by a verifier: the DN execution blocks are not in the evidence. Soundness needs only B_Y >= every counted production and arrival
block, which the verifier establishes directly: every counted signature and vote is a member of a chain bound at B_Y, and its derived block is not after B_Y. The
capture keeps the upper limit as a rule it follows, not a fact the verifier relies on.

**RB9-C1a-F5 (done).** `g1_role_mismatch` and `g1_routing_mismatch` are added to D6 (above). New in C1b-1: `g1_history_fold_mismatch`, `g1_history_head_mismatch`,
`g1_history_unreplayable`, `g1_arrival_unproven`, `g1_vote_not_reproduced`, `g1_authority_not_ready`, `g1_transaction_mismatch`, `g1_signature_invalid`; each carries the
partition and block it was judged at (the page's partition and B_Y for a history or an arrival, the transaction's for a vote or readiness).

**Evidence 2.0 lacks the fold (finding, 2.0 NOT altered).** `Verify` for 2.0 binds a page's chains at the anchor block (step 1) and nothing more: a 2.0 page is "as of
the transaction's block", never the timeline that judged a signature, and it carries no history. To establish the fold, 2.0 would need the named state
`g1_history_unproven{partition,block}` for every page, which its verdict does not carry; 2.0 verdicts stay byte for byte (stop-the-line).

**Not in C1b-1 (next: RB9-C1b-2).** Build/Prove assembling a full 2.1 document from a capture (the capture does not yet record page histories, signature-index
receipts or the transaction), the Directory cases D2b/D2c, `g1_executor_version_unsupported`, `g1_closure_exceeds_budget`. Open (RB9-C1b-1-F2): a held vote is
judged at its release block for its production, but the model re-asks the page at the signature's arrival, while the executor re-asks `AuthorityWillVote` at the
release; the header/initiator/certified-page roles remain `Declared` (the transaction is now carried, so C1b-2 can derive them).
