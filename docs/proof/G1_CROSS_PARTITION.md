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
`(partition, block, role)`. `2.0` documents stay valid forever and verify byte for byte. New domain tags (never reused): `certen:g1:v4`, `certen:g2:v4`, `certen:govroot:v4`.

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

## 6. Revision 2026-10-18 (RB9 Phase C1b-2: assembly from a capture, the Directory cases, the remaining states). Added; nothing above is changed.

**Assembly (RB9-C1b-1-F4, done).** `Collector.Collect` records, per capture, the governed transaction (`Capture.Transaction`), the `History` of every key page a counted signature was
recorded on (read from the main and main-index chains and replayed at capture time with the verifier's own `HistoryStates`, so the delegate books an EARLIER state of a page named are
part of the closure), each hop's signature, the other signatures the pages on the cause chain recorded for the transaction (`Vote.Counted`, read from the transaction's signature
sets), and, for a sequenced vote, the hash of the `SequencedMessage` its source partition recorded (`synthetic.go: chain.AddEntry(seq.Hash())`) with the source partition's synthetic
ledger as a page of role `synthetic-chain`. `Builder.Build21` assembles the document from `Capture.Assembly`: the pages trimmed to their own partition's state root, `AnchorAt` for every
other partition at the certified root height, the vote receipts, the arrival proofs (`ProveEntry`: the receipt of the message in the page's `signature` chain, built by `ChainReceipt`
from the chain's entries and checked against the root the page proves, and the two adjacent `signature-index` entries that bracket its position), the production of each vote
(`Vote.Produced`: the principal's `signature` chain for an inline vote, the source partition's synthetic ledger `main` chain for a sequenced one), the transaction and the routing proof
(`BuildRoutingProofAt` at the check block). The producer verifies its own document with `Verify21FromGenesis`. Chain entries are append-only: the first n entries read now are the n
entries the chain had when its proven root had n, so they can be read after the block has left the node's retention; only the page states are retention-limited.
`Shadow.Prove` still refuses a cross-partition intent for a certificate, now by the name `g1_evidence_21_not_in_force` (the document is built and verified; consensus accepts it only
after the rules switch of D7): the interim `g1_evidence_21_required` is no longer emitted (the constant stays, superseded). The shadow build builds, verifies and stores the 2.1
document. `g1_completeness_unproven` is emitted by the verifier only when the evidence lacks a member the re-evaluation needs; a complete document carries no `Unproven` entry.

**Real data (done).** A live Kermit transaction on `certen-protocol.acme/billing-receipts` (BVN1) was captured promptly, assembled and verified end to end (`cmd/proofv2xbuild`;
`pkg/proof/v2/testdata/xpartition3/real-bvn1-billing-receipts/`, `pkg/proofv2shadow/testdata/capture21_*`): the history of the voting page (book/2), the arrival of its signature derived
from the real `signature-index` chain, the production of the vote in the principal's signature chain, the transaction, the routing table, the executor version from the partition's
ledger. BVN2 and BVN3 stayed idle (RB9-C1b-1-F5): the real document is single-partition; the cross-partition documents are the synthetic vectors. RB9-E needs live activity on every
partition it uses: a transaction whose principal is on one partition and whose authority book (and, for the delegated case, delegate book) lives on another identity on another
partition, signed and executed inside one retention window (about 945 s), with the book's page having at least one earlier main-chain entry (an `AddCredits` suffices) so the history
is not trivial; the live run must create that activity itself and capture within the window.

**D2b (Y = Directory) and D2c (X = Directory) (done; deviates from the text of D2b).** The Directory is proven like a block validator partition: `Anchors["acc://dn.acme"]` holds the DN's
own `DirectoryAnchor` self-anchor (Source = Destination = `dn.acme`, principal `dn.acme/anchors`) and the receipt from that anchor transaction to the certified root (measured live: the
self-anchor for a DN block is an entry of the pool's main chain and `AnchorAt` finds and proves it), not a walk through `SetCheck.Hops`: B_Y is any DN block whose self-anchor the
Directory executed at or before the bound, so a page can be proven at the block it needs, not only at a block the spine happens to certify. The anchor KIND is checked per partition kind
(`xdirectory.go anchorOf`): a block validator partition by a `BlockValidatorAnchor`, the Directory by its `DirectoryAnchor`; the wrong kind is
`g1_foreign_partition_mismatch{partition,block}`, and the partition is derived from the anchor's Source, never from the map key. Evidence 2.0 is unchanged (`anchorBody` still refuses a
`DirectoryAnchor`; a test pins its error text). For X = Directory the transaction's receipt must pass through the self-anchor's `RootChainAnchor` and the principal's pages are proven to
its `StateTreeAnchor`; the votes of BVN authorities are sequenced messages the DN counted after executing the BVN's `BlockValidatorAnchor` (D2c, unchanged). Capture:
`SelectPartitionBlock` runs over the Directory's own `anchor(directory)-root`; `DirectoryPosition` gives the principal's DN block (`DNBlock` = B, per D2c). Vectors
`pkg/proof/v2/testdata/xpartition3/` (12: D2a, D2b, D2c each valid plus the adversarial anchor-kind, block and partition cases). RB9-C1b-2-A1: before this change a 2.1 document whose
own-partition anchor was a `BlockValidatorAnchor` with Source `dn.acme` verified (no kind-versus-partition check). RB9-C1b-2-A2: a Directory-held authority book such as
`dn.acme/operators` is an OPERATOR book whose thresholds the network manages from globals; the default-rule replay may end in a named `g1_history_head_mismatch` or
`g1_history_unreplayable` (never a wrong verdict): the live run needs a Directory book that follows the default rules, or the operator-book rule must be added to `govvote`.

**Remaining D6 states (done).** `g1_executor_version_unsupported{partition,block}`: the executor version is `SystemLedger.ExecutorVersion` of `<partition>/ledger`; it is NOT in the network
or globals records the spine proves, so the partition's ledger is a proven page (new role `system-ledger`) and a version before Baikonur is refused. The capture reads the ledger of every
partition it reads pages from; an unreadable one is the note `g1_executor_version_unproven{partition,block}`. A document that carries no ledger page proves nothing about the version and
the verifier cannot add a named state for it without changing the pinned reports of earlier suites, so `BindProofV2` (RB9-C2) must require the ledger page of every partition among the
proven pages, as it requires the certified key page. MEASURED LIVE (Kermit BVN1, blocks 14715000, 14715100, 14715170, repeated): the node does NOT serve a historical receipt for a system ledger (`bind historical root: cannot generate a receipt when there are uncommitted changes`), so on Kermit today the capture's ledger read ends in the note `g1_executor_version_unproven{partition,block}` and the real document carries no ledger page: the executor version of a real intent is NOT proven yet. This is recorded as RB9-C1b-2-B2 (open): either the operators serve ledger receipts, or the version is established from an activation table keyed to the proven incarnation (the RB8 branch's `govsig/gate.go`, 28bf8ba, absent at this base); `BindProofV2` must not require the ledger page until one of the two exists, or no real 2.1 intent could bind. `g1_closure_exceeds_budget{pages,limit}`: the evidence travels in ONE intent-certificate transaction of CERTEN's consensus (CometBFT
v0.38.21; `pkg/consensus` sets no limit of its own), so `max_tx_bytes` = 1 MiB (`config.go:799`) binds before the 21 MiB block limit (`params.go:99`); `MaxEvidenceBytes` = 1 MiB - 96 KiB
reserved for the certificate = 950,272 (`xbudget.go`, with the measured sizes in its header).

**Declared roles (done; semantics).** With the transaction carried, `header-authority` is PROVEN: the books `Header.Authorities` and `GetAdditionalAuthorities()` name, each book and every page
of it; a recorded role that is not derived (or the reverse) is `g1_role_mismatch`, a named authority without proven pages `g1_header_authority_missing`. `initiator-signer` is PROVEN when the
evidence carries the signature that initiated the transaction (the cause-chain key signature whose initiator hash is `Header.Initiator`; the pages are the payer and every delegator of its
path); when it does not, the role is recorded and listed as Declared and the report says `g1_initiator_signature_not_carried{partition,block}`. `certified-key-page` stays Declared in every
case: it depends on the key book and page the INTENT declares, which only the intent certificate carries; the binding in RB9-C2 (`BindProofV2`) checks it against the certificate.

**Held votes (RB9-C1b-1-F2, resolved).** The executor does NOT re-ask `AuthorityWillVote` at the release (`sig_common.go:84-172`): the vote is computed when the completing signature
arrives, stored by `recordOnHoldAuthSig` (one slot per authority and transaction, replaced when the new origin page's priority is equal or better) and `releaseHeldAuthSigs` produces the
stored signature unchanged. The arrival-time model was right for the vote; it false-refused a held vote when a higher-numbered page had decided earlier and a lower page's vote replaced it.
`Facts.HoldUntil` and `RecordedVote.ReleasedAt` (the production block, from `Vote.Produced`) make the model match; with the production unproven the vote is judged strictly as before. The
sentence in section 5 and in the C1b-1 report saying that the executor re-asks `AuthorityWillVote` at the release was wrong and is superseded by this paragraph.

**Not done in C1b-2 (explicit).** TypeScript consumption of xpartition3 and xpartition3b (Go writes, TS consumes byte-identical copies with the manifest hash; the TS verifier must learn the
roles `synthetic-chain` and `system-ledger`); a live D2c capture (needs a recent transaction whose principal is on the Directory); xworld vectors for the held-vote rule, an over-budget
document and a ledger proven through another partition's anchor; BindProofV2 / govRoot v4 / rules v15 (RB9-C2 and the integration step).

**D6, the executor version is a pinned trust input of the binding (RB9 Phase I, resolves RB9-C1b-2-B2; added, nothing above is changed).** Live Kermit serves no historical receipt for
`<partition>/ledger`, so a real 2.1 document carries no ledger page and the version cannot be proven from the document. `BindProofV21` therefore does NOT require the ledger page. It
derives `g1_executor_version_unsupported{partition,block}` from a table pinned in `pkg/proof/v2/xexecutor_table.go` (`ExecutorFloorAt`, `KermitExecutorActivations`): for the
transaction's `(partition, block)` and for every `(partition, block)` a proven page is judged at, the table must prove an executor version from Baikonur on. What the table pins: each of the
Directory and BVN1-3 activated `v2-kourou` (9, above Baikonur 6) at one block - `directory` 9,538,105, `bvn1` 12,491,272, `bvn2` 12,492,057, `bvn3` 12,491,127 (research R8 M5, read from
Kermit's own system ledgers 2026-10-17) - so the version is proven for blocks AFTER the activation block only; at or before it, or on a partition the table does not name, it is NOT established
and the binding refuses by name (never assumed). The table is the same one RB8's signature-type gate pins (`govsig/gate.go`, branch `pv2/rb8-b-every-key-signature-type`, 71fd45a), copied value
for value because govsig is not in the RB9 stack's base; `TestExecutorTableIsPinned` pins the values, and when the RB8 branch merges one follow-up makes govsig the single source. It is a
TRUST INPUT in the sense of PROOF_V2 s1: a later activation on any partition needs a new row here (and a library bump), exactly as `protocol.ExecutorVersionLatest` does; a block the table
does not cover is refused, so a stale table fails closed. A ledger page, when a document does carry one, is evidence that must AGREE: its `ExecutorVersion` must be at least the table's
floor for its `(partition, block)`, otherwise the binding refuses with `g1_executor_version_unsupported` ("the ledger page disagrees with the pinned table"); the verifier's own pre-Baikonur
refusal for a ledger page is unchanged.

**The binding justifies the Declared roles (RB9 Phase I).** `certified-key-page` is the one role the verifier can only declare. `BindProofV21(rep, g0, g1, keyPageURL, keyBookURL, facts)`
requires the certified key page (G1's page) to be a proven page, recorded as `certified-key-page` (in `Declared`, or in `Roles`), a page of the book the certificate DECLARES (`keyBookURL`;
the page's URL parent, a lite identity being its own book), and a page of the governing set (it proves at least one other role - the harbor-mfg page is an unrelated identity's initiator and
proves only that, so the declared book is not itself required among the proven pages). `header-authority` and `initiator-signer` are satisfied by PROVEN roles only: a page that records
them only as `Declared` (the transaction or the initiating signature was not carried) is refused as "declared, not proven". The governing facts' transaction (`GoverningFacts.TxHash`) must be
the transaction the report proved (`g1_transaction_mismatch`), and a report with any `Unproven` entry is refused by that entry (it is not a verified S3). govRoot v4 commits the page's
recorded roles (proven and declared).

**govRoot v4 vote encoding (RB9-C2-F3, resolved).** The votes root no longer commits `json.Marshal(proofv2.Vote)`. Each leaf is `sha256("certen:g1:v4:vote:" ‖ EncodeVoteV4(vote))`, an explicit
layout over the final `Vote`/`VoteHop`/`Arrival`/`IndexProof`/`Production` shape, in a fixed field order: strings and bytes length-prefixed (4-byte big-endian), integers 8 bytes big-endian,
hex members as the bytes they encode, URLs lower-cased without a trailing slash, an absent optional member its flag 0 (never omitted); the layout is in the comment of `EncodeVoteV4`
(`pkg/intentcert/govroot_v4.go`), recomputed byte by byte in `TestVotesRootV4_IndependentRecomputation`, and `TestVoteEncodingV4CoversEveryField` fails when a member is added to any of the
structs until the encoding is extended under a new tag. The v4 golden was unreleased and was regenerated twice, never released: once for this encoding (and for the executor-valid blocks of its fixture)
and a second and last time for the verifier round VB (RB9-J2), which (a) commits `Production.Sequenced` - the `SequencedMessage` that binds a sequenced vote's production to the vote's message - as the last
member of the production (`hex(sequenced)`, zero-length for an inline vote) and (b) gives the G2 slot its own tag `certen:g2:v4` (it hashes the v4 G1 slot and was hashed under the v3 tag). `BindProofV21` refuses a
report that discloses `g1_vote_production_unbound` (a document made before the verifier carried the message). The v3 goldens are untouched.

**D7, the integration of the stack (RB9 Phase I; added, nothing above is changed).** (1) Consensus verifies the evidence of a 2.1 certificate with the real verifier: `proofv2.VerifyEvidence21FromSpine` (the spine as the
chain holds it, no I/O), chosen by the evidence version in `judgeProofV2` only after the activation gate has let the document through; `Verify`, `VerifyFromGenesis` and `VerifyFromSpine` still refuse
2.1, and the 2.1 entry point refuses 2.0. The merge condition of RB9-C2-F7 is `TestRulesV15AcceptsAVerifiedEvidence21`: the real stored 2.1 document of a live Kermit transaction goes through the
consensus judgement with the real verifier, the real `BindProofV21` and the real govRoot v4, and each edit of it is refused. (2) The switch is read per intent, never configured: the intent discovery asks
the proposer's activation in force for the next block (`G1CrossPartitionRequired`) and, exactly then, calls `Shadow.ProveG1`, which builds 2.1 for EVERY capture - from the block after the activation
consensus refuses a 2.0 certificate, so a one-partition intent needs 2.1 as well; before it nothing changes (`Shadow.Prove`, a cross-partition capture is `g1_evidence_21_not_in_force`). A report with
anything `Unproven`, a prover that cannot build 2.1, an unreadable activation and a capture holding a nonexistent listed authority book (`g1_authority_missing`; absence of an account is provable by no
receipt the evidence carries, so the capture refuses it by name at capture for a foreign capture and at assembly for 2.1) all hold the intent. (3) The builder maps a freshly served minor-root record
with no validator signature yet (`quorum not met: 0 of N validator signatures`) to `ErrNotYetCertified`, under the bound the builder callers already use; the verifiers are untouched.
