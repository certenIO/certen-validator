# Execution rules v15: the cross-partition G1 activation (RB9-C, evidence 2.1, govRoot v4)

**Status:** built and rehearsed on a live four-node test network with throwaway keys
(`TestRulesV15UpgradeAndG1ActivationRehearsalOnALiveNetwork`). Not deployed. Deploying v15 needs **no new key and no new
environment variable on the validators** from this change (check the pull requests of RB9-B and RB9-C1, which are merged
first, for any they add). The deploy and the activation are two separate acts: the deploy is the owner running one command
on all seven validators; the activation is an admin-signing queue item (admin-a, admin-b; threshold 2 of the admin set in
force) that **must not be signed before the RB9-E shadow exit** (below).

## Why

`docs/proof/G1_CROSS_PARTITION.md` (design D1-D8) raises the S3 claim: the authorities that approved an intent are judged
over the **complete** governing set, on every identity and partition, with delegation, each page proven at its own
partition's block. Two gaps in the stored proof v2 (evidence 2.0) are closed by evidence 2.1:

- a key book on another identity (the bank-compliance-book-on-a-customer-account model) is refused today
  (`g1_cross_identity_pending`; the harbor-mfg page-binding failures), because 2.0 proves only pages on the principal's
  partition at the principal's block;
- delegates are not followed, so a delegated approval is not proven.

2.1 changes what govRoot commits (the pages with `(partition, block, role)` and the proven vote records, under the new
domain tags `certen:g1:v4` and `certen:govroot:v4`; v3 tags and goldens are untouched), so the whole fleet must switch at
one block. Like the v14 anchor set, the switch is a **committed fact**, not a date and not a node's configuration.

## What the chain enforces

| Rule | Code | Why |
|---|---|---|
| `certen.g1.crosspartition.activate/v1`: version 1, for this chain id | 18 when refused | One activation per chain; a transaction signed for another chain is nothing here. |
| Authorised by at least the threshold of **distinct keys** of the admin set in force for the block (`AdminSetAt`) | 18 | The same authority as the BLS registry, the admin rotation and the anchor set. |
| Signatures cover the kind, the chain id and the version, length-prefixed | 18 | Nothing in it can be changed after signing. |
| A second activation, or one after the first, is refused by name | 18 | The activation cannot be replayed, moved or undone. |
| Recorded append-only at its height H (`/certen/g1_activation`), in force from block H+1 | - | A block is judged identically however often it is executed. |
| Blocks at height > H must carry evidence 2.1; a 2.0 certificate is refused (`ErrIntentProofV21Missing`) | 10 (intent certificate refused) | After H, every intent is bound by govRoot v4. |
| Blocks at height > H read a published cost basis of zero (base, or per-leg on a multi-leg chain) as no bound: the chain is unpriced, `ENTITLEMENT_UNPRICED` (PV2-F3, with an anchor set in force) | 4 | A zero sums to nothing and passes every ceiling; v14 counted a listed zero as a price and keeps doing so until H, so the change forks nothing. Every validator must run this binary before the activation is signed. |
| Blocks at height <= H are decided exactly as rules v14 decide them; a certificate carrying 2.1 is refused (`ErrIntentProofV21NotInForce`, beside `ErrIntentProofV3NotInForce`) | 10 | Before H nothing changes, so v15 continues v14 history without a reset. |

The accepted activation's id (`g1-activation:<hex SigningBytes>`) goes into the app hash. `IndexCommittedHistory`
(the boot history check) refuses to start on any committed activation-kind transaction v15 did not decide (a
ValidatorBlock's code, or an acceptance with no activation recorded for it).

## Until the activation: the v15 binary is v14

**Chosen behaviour, as for the v14 anchor set: the first committed activation is the v15 switch height.** Before it:

- every block is decided exactly as v14 decided it. Proved three ways: the existing consensus test suite; the app hashes
  and result codes of a fixed pre-activation history, measured at the rules v14 head (d20f693) and asserted by the v15
  binary (`TestRulesV15PreActivationDecisionsAreV14s`); and the rehearsal's step 2 (the v14 chain's committed history
  re-checked under the v15 binary, uncertified blocks decided as before);
- a certificate carrying evidence 2.1 is refused by name;
- proposers still build 2.0 certificates, so **no intent is held** by the deploy (unlike v14, which held intents until its
  anchor set existed).

Why a committed activation rather than the deploy itself: the switch height must be a fact of committed state every node
reads identically (a node that was behind would judge the same old blocks differently); a date in the binary is a guess;
and committed history holds no activation, so "no activation in force" marks exactly the blocks v14 decided.

## Deploy order (coordinated)

Prerequisites, merged to `main` by the owner, in this order: rules v14 (`pv2/rb12-a-rules-v14`), deployed with its anchor set in
a separate, earlier sitting, then the **one pull request `pv2/rb9-j-consensus`** (compare
`https://github.com/certenIO/certen-validator/compare/main...pv2/rb9-j-consensus`), which carries the whole RB9 stack: capture
(RB9-B), verification across partitions (RB9-C1), the consensus rules v15 (RB9-C2), the integration (RB9-I) and the verifier rounds
VA (proof and capture layer) and VB (consensus layer, this runbook's preflight). Its description is
`pr/independant_validator-pv2-rb9-integration.md`. The number is v15 only if v14 merged first: this branch takes
`CurrentExecutionRulesVersion + 1` of its base. The earlier branch names (`pv2/rb9-c2-consensus-v15`, `pv2/rb9-integration`,
`pv2/rb9-j-proof`) are history: nothing is merged from them.

Apply every env change **before** any rebuild (lesson of 2026-10-03: the NTFY_URL and the D4 outage).

1. **Gate: the v14 anchor set is committed and the fleet is v14.** `validator-rotate anchor-set status --rpc http://<validator>:26657`
   shows `anchor set v1 in force`; `abci_info` reports `"app_version":"14"` on all 7.
2. **History check before the deploy.** Build `validator-rotate` from the release commit and run it against one v14 validator
   that holds every block from 1:

   ```
   validator-rotate history-check --rules 15 --rpc http://<validator>:26657
   ```

   It must exit 0 and end with `v15 continues this chain's history exactly`. A v14 node serves no activation log, and none
   is needed: no committed history holds an activation, and an accepted one would be `FOUND` (no v14 node can have recorded
   one).
3. **All 7 validators together.** Stop every validator, install the v15 binary, start every validator. Each node, before
   CometBFT's handshake:
   - continues the older state (`compatibleContinuations`: v7..v14 continue as v15), with no `execution rules mismatch`;
   - re-checks its whole committed history once under the history-check version this binary names
     (`CommittedHistoryCheckVersion`), logging `[HISTORY] checking committed heights 1-N ...` and then
     `✅ [HISTORY] ... hold no transaction rules v15 decide differently`. A refusal names each block.

   Then verify on every node:

   ```
   curl -s http://<validator-N>:26657/abci_info                              # "app_version":"15" on all 7
   validator-rotate g1-activate status --rpc http://v1:26657,...,http://v7:26657
   ```

   `status` must print `cross-partition activation: none` for all seven, no `DISAGREE`, and
   `rules v15 not yet activated`. The state stays stamped v14 until the activation block (`committedRulesVersion`).
   Mixed versions are not a state to stay in: a v14 node and a v15 node decide the same block identically only until the
   activation, and the activation preflight is NO-GO unless all seven report v15.
4. **Wait for the RB9-E shadow exit. Do not continue to step 5 before it.** See the next section.
5. **Commit the activation** (the v15 switch). On the admin machine (secrets read from files, never printed):

   ```
   validator-rotate g1-activate propose --rpc http://v1:26657 \
     --admin-key-id admin-a --admin-secret @<admin-a seed file> --out g1-activate.json
   validator-rotate g1-activate sign --tx g1-activate.json --admin-key-id admin-b --admin-secret @<admin-b seed file>
   validator-rotate g1-activate preflight --tx g1-activate.json --rpc http://v1:26657,...,http://v7:26657
   validator-rotate g1-activate submit    --tx g1-activate.json --rpc http://v1:26657,...,http://v7:26657
   ```

   (`propose` also takes `--chain-id certen-testnet` instead of `--rpc` to work offline; with neither admin flag it writes
   the unsigned payload for the signers. `sign` is offline: each admin signs on their own machine and returns the file.)

   Preflight is GO only if:
   - every node runs rules v15, all on the same version and chain, and caught up;
   - every node reports the same admin set, and **no node records an activation**, all nodes agreeing on that;
   - every node **requires proof v3** (a verified Accumulate spine of the registry's incarnation is in force for the next block,
     `consensus.ProofV3Required`): evidence 2.1 is judged only where the v3 intent certificate is, so an activation on a chain with
     no spine yet would take effect at a time no one chose (finding F8); the preflight is NO-GO naming the node, and the
     activation is signed after the spine exists;
   - the chain's own rule (`VerifyG1Activation`) accepts the transaction for the next block: the threshold of distinct
     keys of the admin set in force signed it.

   Submit preflights again, commits through the first RPC (`--dry-run` stops after the preflight), and confirms the node
   recorded it at the commit height. It prints `ACCEPTED at height H ... Evidence 2.1 is required from height H+1`.
   **Record H.** One bad submission is not harmless: a *refused* activation (code 18) is a v15 verdict that stamps the state
   v15 and closes the v14 rollback, so preflight first.
6. **Verify (below).**

## Two handling rules for the activation (security)

1. **Sign the activation only at activation time.** A signed, unsubmitted activation has no height and no nonce: nothing in it
   binds it to a moment, so it is a bearer instrument until the admin set rotates - anyone who holds the file can submit it, at
   a moment no signer chose. The signers sign after the RB9-E shadow exit, in the sitting in which it is submitted, hand the
   file only to the person running `submit`, and delete every copy once the chain records the activation. If a signed file
   has been stored, shared or lost, rotate the admin set (`docs/runbooks/admin-set-rotation.md`) before relying on its absence.
2. **Keep the validator RPC firewalled.** Any submitter who can reach a validator can send a shape-valid activation-kind
   transaction. It is refused with code 18, **counted as a v15 verdict and stamps the state v15**, which closes the v14 rollback
   (the rollback in the section below only exists while the state is stamped v14). This is the same property as the v14
   anchor-set kind. Validator RPC and P2P ports are reachable only from the operator and the other validators until the
   activation is committed, and the preflight is run before any submission.

## Do not activate before the RB9-E shadow exit

Activation is **not** part of the deploy and is **not** signed because the binary is up. The admin signers sign only after
the RB9-E shadow exit (`PROOF_V2.md` §11, the owner's rule): a short live run covering each hard case (an approver key
book on another identity and partition; a delegate two hops deep; the same-partition regression) in which

- the v1 and v2 pages agree for every page both captured, delegates and foreign pages included (zero disagreements);
- the Go and TypeScript verifiers agree on every vector and every live document (zero disagreements);
- there are zero verification failures of the 2.1 documents the shadow built.

The activation is an `OWNER_QUEUE.md` item of its own, with the exact commands above and the post-activation checks below.
After H nothing relaxes: every intent must carry 2.1, so an intent whose 2.1 evidence cannot be built (a partition outside
its retention window, `g1_historical_unavailable{partition,block}`; an unsupported executor override) is **held, not
certified under weaker evidence** - which is why the shadow run must exercise the live partitions first.

## Verify, after the activation

- `validator-rotate g1-activate status --rpc <all 7>` shows `activated at height H` on every node, no `DISAGREE`, and
  `evidence 2.1 is required from height H+1`.
- `abci_info` still reports app version 15; the persisted stamp is v15 from the activation block.
- `validator-rotate history-check --rules 15 --rpc http://<validator>:26657` exits 0, lists
  `certen.g1.crosspartition.activate/v1`, and ends with `v15 continues this chain's history exactly`: the activation is found
  in its record.
- The first natural intent after H settles with evidence 2.1: its stored proof has `proof_version` 2.1, lists every
  proven page as `(partition, block, role)`, and verifies offline with `proofverify` and `@certen/proof-verify`. A
  validator log line `[INTENT-CERT] REJECTED ... ErrIntentProofV21Missing` means a proposer built a 2.0 certificate after H
  (a node still on the v14 build); the block is refused by every node and the intent retried.
- A certificate with evidence 2.0 at height H+1 is refused with `ErrIntentProofV21Missing` and one with 2.1 is accepted;
  the same blocks at H and below are decided as v14 decided them (`TestAppJudgesTheCertificateByTheActivationInForceAtItsHeight`,
  `TestACertificateOverEvidence21IsAcceptedFromTheNextHeight`, `TestTheCertificateGateFollowsTheActivation` - the gate tests
  drive consensus with a report they build; `TestRulesV15AcceptsAVerifiedEvidence21` runs the REAL verifier
  (`VerifyEvidence21FromSpine`), the real `BindProofV21` and the real govRoot v4 over the real stored 2.1 document).
- Restart the **whole fleet**: it comes back on one chain, stamped v15, app version 15, equal app hashes, and every node
  answering `g1-activate status` with the same H.

## Rollback

- **Before step 5** (no activation transaction decided; state stamped v14): stop all 7, install the v14 binary, start all
  7. The v14 binary ignores the v15 watermark key and keeps its own, which v15 never writes or deletes.
- **After step 5** (state stamped v15): **there is no rollback.** The v14 binary refuses to start (`execution rules
  mismatch ... NEWER v15`), as designed, and the activation cannot be moved or undone by any transaction (a second one is
  refused by name). The activation is one-way by design: a chain that accepted 2.1 evidence cannot go back to judging 2.0
  evidence without invalidating the intents it already certified. Roll forward only.
- If a node refuses at step 3, it names the reason and writes nothing that blocks a rollback to v14.

## What the rehearsal proves

`TestRulesV15UpgradeAndG1ActivationRehearsalOnALiveNetwork` runs four in-process CometBFT validators running this
`ValidatorApp`, driven with the `validator-rotate` binary built from the tree over each node's RPC, with throwaway admin
keys (2 of 3):

1. The chain as v14 leaves it: a refused admin rotation, a block naming a retired anchor accepted (v13's verdict), the
   anchor set committed through the tool (v14's activation, state stamped v14), then a retired anchor refused with code 17
   and the committed anchors accepted.
2. The upgrade: each ledger put back as the v14 binary wrote it (v14's history-check watermark), the fleet stopped, every
   node runs the v15 boot history check over its own block and state stores, the fleet restarts: app version 15, stamp
   still v14, `history-check --rules 15` exits 0, `g1-activate status` reports not yet activated, and blocks are decided
   as before.
3. The activation through the tool: propose, a NO-GO preflight with one approval, sign, a GO preflight, submit. Every node
   records it at the same height H, state stamped v15, in force at H+1 and not at H.
4. After H: a second submit is NO-GO by name, a second proposal is refused ("activates once"), the same activation signed by
   other admins is refused in a later block (code 18), blocks are decided as before, `history-check --rules 15` passes with
   the activation found in its record. (The network's blocks are uncertified - no BLS registry - so the certificate rule
   itself is pinned by the app-level tests above, not by the network.)
5. A whole-fleet restart comes back on one chain, stamped v15, app version 15, equal app hashes, every node answering
   `/certen/g1_activation` identically.

`validator-rotate`'s own tests (`TestG1Activate...`) pin the tool: it builds an activation the chain's rule accepts with 2
of 3 admins; preflight is NO-GO for a node on app version 14, for nodes that disagree, for an activation that already
exists, for a chain that does not require proof v3 (no spine; `TestG1ActivatePreflightRefusesWhenProofV3IsNotRequired`) and for fewer than the threshold; submit refuses on a NO-GO and commits nothing; `status` prints none, then H; and
`history-check --rules 15` finds an accepted activation without its record.

## Known limits at this change (carried to the pull request)

- Discovery builds evidence 2.1 exactly when the activation is in force for the next block (RB9-I: the proposer asks
  `G1CrossPartitionRequired` per intent and calls `Shadow.ProveG1`; before the activation it behaves as before). An intent
  whose 2.1 evidence cannot be built or is not complete is held (retried), never certified under 2.0 or a weaker binding. An
  intent captured by a build that did not record the transaction and the page histories (made before this change) cannot be
  re-evaluated and is held until it is re-captured. Deploy all 7, then sign the activation only after the shadow exit
  (RB9-E): zero disagreements over a live run.
- govRoot v4 exists in Go only (`pkg/intentcert`, `pkg/execution/contracts`); a Solidity recomputation of the root, if the
  anchor contract has one, has no v4 domain. The certificate is checked by consensus and by `execution.CheckIntentCertificate`.

## Related

- Design: `docs/proof/G1_CROSS_PARTITION.md` (D7 is this switch). Hash conventions: `docs/proof/GOVROOT_V3.md`.
- The admin quorum, rules v12 and the history-check watermark: `docs/runbooks/admin-set-rotation.md`.
- The v14 pattern this copies: `docs/runbooks/rules-v14-ceiling-anchor-set.md`.
