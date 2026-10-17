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
| Blocks at height <= H are decided exactly as rules v14 decide them; a certificate carrying 2.1 is refused (`ErrIntentProofV21NotInForce`, beside `ErrIntentProofV3NotInForce`) | 10 | Before H nothing changes, so v15 continues v14 history without a reset. |

The accepted activation's id (`g1-activation:<hex SigningBytes>`) goes into the app hash. `IndexCommittedHistory`
(the boot history check) refuses to start on any committed activation-kind transaction v15 did not decide (a
ValidatorBlock's code, or an acceptance with no activation recorded for it).

## Until the activation: the v15 binary is v14

**Chosen behaviour, as for the v14 anchor set: the first committed activation is the v15 switch height.** Before it:

- every block is decided exactly as v14 decided it (proved by the existing consensus test suite, the committed-history
  replay in the v14 -> v15 rehearsal, and the rehearsal's step 2: 2.0 intents are still decided as before);
- a certificate carrying evidence 2.1 is refused by name;
- proposers still build 2.0 certificates, so **no intent is held** by the deploy (unlike v14, which held intents until its
  anchor set existed).

Why a committed activation rather than the deploy itself: the switch height must be a fact of committed state every node
reads identically (a node that was behind would judge the same old blocks differently); a date in the binary is a guess;
and committed history holds no activation, so "no activation in force" marks exactly the blocks v14 decided.

## Deploy order (coordinated)

Prerequisites, all merged to `main` by the owner, in this order: rules v14 (`pv2/rb12-a-rules-v14`), RB9-B (capture,
types), RB9-C1 (verification across partitions), then this branch (`pv2/rb9-c2-consensus-v15`). The number is v15 only if
v14 merged first: this branch takes `CurrentExecutionRulesVersion + 1` of its base.

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
   - the chain's own rule (`VerifyG1Activation`) accepts the transaction for the next block: the threshold of distinct
     keys of the admin set in force signed it.

   Submit preflights again, commits through the first RPC (`--dry-run` stops after the preflight), and confirms the node
   recorded it at the commit height. It prints `ACCEPTED at height H ... Evidence 2.1 is required from height H+1`.
   **Record H.** One bad submission is not harmless: a *refused* activation (code 18) is a v15 verdict that stamps the state
   v15 and closes the v14 rollback, so preflight first.
6. **Verify (below).**

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
- A certificate with evidence 2.0 at height H+1 is refused with `ErrIntentProofV21Missing` and one with 2.1 is accepted
  (`TestRulesV15UpgradeAndG1ActivationRehearsalOnALiveNetwork` step 4 pins both on every node).
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

1. The chain as v14 left it (the anchor set committed, state stamped v14) and a 2.0 intent decided.
2. The upgrade: each ledger put back as the v14 binary wrote it, the fleet stopped, every node runs the v15 boot history
   check over its own block and state stores, the fleet restarts: app version 15, stamp v14, `history-check --rules 15`
   exits 0, `g1-activate status` reports none in force, and 2.0 intents are still decided exactly as before.
3. The activation through the tool: propose, a NO-GO preflight with one approval, sign, a GO preflight, submit. Every node
   records it at the same height H.
4. From H+1: a 2.0 certificate is refused (`ErrIntentProofV21Missing`) on every node and a 2.1 certificate is accepted.
5. `history-check --rules 15` passes with the activation found in its record; a whole-fleet restart comes back on one chain,
   stamped v15, equal app hashes.

`validator-rotate`'s own tests (`TestG1Activate...`) pin the tool: it builds an activation the chain's rule accepts with 2
of 3 admins; preflight is NO-GO for a node on app version 14, for nodes that disagree, for an activation that already
exists and for fewer than the threshold; submit refuses on a NO-GO and commits nothing; `status` prints none, then H; and
`history-check --rules 15` finds an accepted activation without its record.

## Related

- Design: `docs/proof/G1_CROSS_PARTITION.md` (D7 is this switch). Hash conventions: `docs/proof/GOVROOT_V3.md`.
- The admin quorum, rules v12 and the history-check watermark: `docs/runbooks/admin-set-rotation.md`.
- The v14 pattern this copies: `docs/runbooks/rules-v14-ceiling-anchor-set.md`.
