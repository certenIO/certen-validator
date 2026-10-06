# Execution rules v14: the binding cost ceiling and the anchor set (RB4-F6, RB4-F35)

**Status:** built and rehearsed on a live four-node test network with throwaway keys
(`TestRulesV14UpgradeAndAnchorSetRehearsalOnALiveNetwork`). Not deployed. Deploying v14 needs **no new key and no new
environment variable on the validators**. It does need the gateway change (`feat/entitlement-every-chain-priced`)
deployed first, and the admin quorum in force (admin-a, admin-b, admin-c, threshold 2) to sign one anchor set right after
the validators are upgraded.

## Why

Three defects, one rules version:

- **RB4-F6, the cost ceiling was skipped.** When an entitlement epoch published no cost basis for a chain the block settled
  on, the gate skipped the intent ceiling (`entitlement_cost.go` told the caller to). The gateway left out any chain without a
  30-day measurement of all three legs, so an unpriced chain spent CERTEN's money with no ceiling. A negative or
  overflowing basis was skipped too.
- **RB4-F35, anchors were not enforced in consensus.** Admission (RB4-F9) refuses a leg that declares an anchor other than
  `CERTEN_ANCHOR_V8_<chainId>`, but only on the proposer, before signing. FinalizeBlock compared a ValidatorBlock's chain
  targets with nothing. A proposer that skipped admission, or one misconfigured node, could commit a block naming any
  address.
- **The entitlement store used the environment's keys.** The proposer's store verified epochs against
  `CERTEN_ENTITLEMENT_KEYS`, read once at start. That is only the genesis seed, which a sealed chain ignores. Consensus
  judges by the sealed policy and every key rotation since. After a rotation in policy state the two disagreed: the store
  refused every epoch signed by the new key and kept building evidence under the retired key. Neither needs a rules
  version (the store is proposer-side), but it ships here because it is the same gate.

## What the chain enforces

| Rule | Code | Why |
|---|---|---|
| `certen.anchorset.set/v1`: the V8 anchor of each settlement chain it lists (11155111, 84532, 421614 in set 1), each once, each a catalogued chain and a non-zero `0x` address; a chain left out is refused by name (code 17) when a block targets it | 16 when refused | A set that leaves a chain out would leave that chain's blocks with nothing to be judged against. |
| Authorised by at least the threshold of **distinct keys** of the admin set in force for the block (`AdminSetAt`) | 16 | The same authority as the BLS registry and admin rotation. |
| Signatures cover the chain id, the version and every anchor, length-prefixed (below) | 16 | A set signed for one chain is nothing on another, and nothing in it can be changed after signing. |
| `version` = 1 + the newest version recorded | 16 | A set cannot be replayed, skipped or reordered. |
| Recorded append-only at its height (`/certen/anchor_set`), in force from the **next** height | - | A block is judged identically however often it is executed. |
| From the height after the first anchor set, every ValidatorBlock chain target names its chain's committed anchor (compared as an address) | 14, `ANCHOR_NOT_COMMITTED` | RB4-F35. |
| From the same height, a ceiling that touches a chain the epoch does not price is refused | 4, `ENTITLEMENT_UNPRICED` | RB4-F6. |
| From the same height, a negative basis, or one that overflows int64 for the block's legs, is refused | 4, `ENTITLEMENT_COST_BASIS_INVALID` | RB4-F6. |

The accepted set's id (`anchor-set:<hex SigningBytes>`) goes into the app hash.

### Canonical encoding

`SigningBytes` = sha256 over length-prefixed fields (4-byte big-endian length, then the bytes):
`certen.anchorset.set/v1`, chain id, version, number of anchors, then in chain-id order each chain id (decimal) and its
anchor in lowercase hex. Pinned in `TestTheAnchorSetEncodingIsPinned` against an independent computation (Python hashlib and
`printf | sha256sum`). For the live set below on `certen-testnet`, version 1, it is
`51985f55976189ba9fa5536aaf85a9988467d07dbbbfe8747bd171e52b272578`.

## Until an anchor set is committed: the v14 activation

**Chosen behaviour: the first committed anchor set is the v14 upgrade height.** v14's two ValidatorBlock rules (anchors
and the binding ceiling) apply from the height after the chain accepts its first anchor set. Before that, the v14 binary
decides every block exactly as v13 did. That window is not silent, because no v14 proposer admits any intent until the set
is committed: `planBatch` refuses each one by name (`ANCHOR_SET_NOT_COMMITTED`, wrapped in `ErrBatchUnavailable`) and the
intent is retried, never failed.

Why this behaviour and not "refuse anchored blocks from the deploy":

- The upgrade height must be a fact of committed state that every node reads identically, at every height, however often
  a block is replayed. A node's binary version is not such a fact: a node that was behind would judge the same old blocks
  differently from one that was not. A date written into the binary is a guess, and the BLS registry set the standard
  here ("activation by chain state, no guessed date").
- Committed history holds no anchor set. So "no anchor set in force" marks exactly the blocks v13 decided. "Refuse every
  anchored block while no set is in force" would refuse every block of the live chain's history: v14 could not continue
  v13 state, and the deploy would need a chain reset.
- The only blocks the rule leaves on v13's verdict are those between the fleet starting v14 and the anchor set
  committing. No honest v14 proposer builds one, because admission refuses every intent until the set exists. The deploy
  commits the set right after the fleet is up (step 4).

A node configured with an anchor that is not the committed one refuses by name too (`ANCHOR_NOT_COMMITTED: this node
settles chain N on X (CERTEN_ANCHOR_V8_N), but anchor set vK commits Y`), so a misconfigured node retries instead of
building blocks every peer refuses.

## Live addresses (the anchor set to commit)

| Chain | Chain id | V8 anchor |
|---|---|---|
| Ethereum Sepolia | 11155111 | `0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c` |
| Base Sepolia | 84532 | `0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c` |
| Arbitrum Sepolia | 421614 | `0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6` |

These must equal each validator's `CERTEN_ANCHOR_V8_<chainId>`. Check `.env.shared` before step 4: admission refuses a
node whose configured anchor differs from the committed one.

## Deploy order (coordinated)

Apply every env change **before** any rebuild (lesson of 2026-10-03: the NTFY_URL and the D4 outage).

1. **Gateway first: every epoch prices every settlement chain.**
   - Remove `BILLING_ENTITLEMENT_PUBLISH_COST_BASIS` from the gateway's env file. The new gateway refuses to start with
     `=false`, because an epoch without a basis is exactly the omission F6 forbids. `true` is accepted and does nothing.
   - Deploy `feat/entitlement-every-chain-priced`.
   - Verify:
     - `GET /v1/entitlement/current`: `header.cost_basis` has exactly three entries (11155111, 84532, 421614), each with
       positive `base_micro_usd` and `per_leg_micro_usd`;
     - `certen_gateway_entitlement_chain_unpriced` is 0 for all three chains, and `EntitlementChainUnpriced` is not firing.
   - If a chain cannot be priced from the last 30 days of measurements, the publisher refuses that epoch by name, the alert
     fires (ntfy, critical), and the previous epoch stays current until it expires (2 h). **Do not continue to step 3 while
     any chain is unpriced**: from the v14 activation, every intent with a ceiling on that chain would be refused
     `ENTITLEMENT_UNPRICED`. Price the chain with real measurements; never publish a guess.
   - v13 validators already understand the v2 (cost-basis) preimage, so publishing the basis changes nothing for them.
2. **History check before the validator deploy.** Build `validator-rotate` from the release commit and run it against one
   v13 validator that holds every block from 1:

   ```
   validator-rotate history-check --rules 14 --rpc http://<validator>:26657
   ```

   It must exit 0 and end with `v14 continues this chain's history exactly`. A v13 node serves no anchor set log, and none
   is needed: no committed history holds an anchor set, and an accepted one would be `FOUND` (no v13 node can have
   recorded one).
3. **All 7 validators together.** Stop every validator, install the v14 binary, start every validator. Each node, before
   CometBFT's handshake:
   - continues the v13 state (`compatibleContinuations`: v7..v13 continue as v14), with no `execution rules mismatch`;
   - re-checks its whole committed history once under history-check v4 (`CommittedHistoryCheckVersion` 3, ledger key
     `abci:kinds_checked_through:v14:checks4`), logging `[HISTORY] checking committed heights 1-N ...` and then
     `✅ [HISTORY] ... hold no transaction rules v14 decide differently (history-check v4, ...)`. A refusal names each block.

   Then verify on every node:

   ```
   curl -s http://<validator-N>:26657/abci_info                         # "app_version":"14" on all 7
   validator-rotate anchor-set status --rpc http://<validator-N>:26657  # "NO anchor set is in force", next version 1
   ```

   The state stays stamped v13 until the anchor set (step 4). From now until then, every new intent is retried with
   `ANCHOR_SET_NOT_COMMITTED` in the validator log. That is by design; continue to step 4 immediately.
4. **Commit the anchor set** (the v14 activation). On the admin machine (secrets read from files, never printed):

   ```
   validator-rotate anchor-set propose --rpc http://v1:26657 \
     --anchor 11155111=0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c,84532=0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c,421614=0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6 \
     --admin-key-id admin-a --admin-secret @<admin-a seed file> --out anchor-set-v1.json
   validator-rotate anchor-set sign --tx anchor-set-v1.json --admin-key-id admin-b --admin-secret @<admin-b seed file>
   validator-rotate anchor-set preflight --tx anchor-set-v1.json --rpc http://v1:26657,...,http://v7:26657 \
     --eth-rpc 11155111=<sepolia rpc>,84532=<base-sepolia rpc>,421614=<arbitrum-sepolia rpc>
   validator-rotate anchor-set submit    --tx anchor-set-v1.json --rpc http://v1:26657,...,http://v7:26657 \
     --eth-rpc 11155111=<sepolia rpc>,84532=<base-sepolia rpc>,421614=<arbitrum-sepolia rpc>
   ```

   Preflight is GO only if:
   - every node runs rules v14, all on the same version and chain, and caught up;
   - every node reports the same admin set and the same anchor-set log;
   - the chain's own rule (`VerifyAnchorSet`) accepts the set for the next block;
   - on every chain, the endpoint serves that chain id and the anchor holds code.

   Submit preflights again, commits through the first RPC, and confirms the record at the commit height.
5. **Verify.**
   - `anchor-set status` on all 7 shows `anchor set v1 in force` with the three addresses.
   - `abci_info` still reports app version 14; the persisted stamp is v14 from the anchor-set block.
   - `history-check --rules 14` against one node exits 0, and lists `certen.anchorset.set/v1`.
   - The next natural intent settles (validator log: no `ANCHOR_SET_NOT_COMMITTED` and no `[ANCHOR-SET] REJECTED`).

## Rollback

- **Gateway, any time before step 4:** roll back freely. v13 validators read epochs with or without a basis.
- **Gateway, after step 4:** never roll back to a build that can publish an epoch without every chain. Under v14, a
  ceiling over an unpriced chain is refused. Fix forward.
- **Validators, before step 4** (no anchor-set transaction decided; state stamped v13): stop all 7, install the v13 binary,
  start all 7. The v13 binary ignores the `v14:checks4` watermark and keeps its own `v13:checks3` key, which v14 never
  writes or deletes. A *refused* anchor set (code 16) is a v14 verdict too and stamps the state v14, so preflight before
  you submit: one bad submission closes the v13 rollback.
- **Validators, after step 4** (state stamped v14): the v13 binary refuses to start (`execution rules mismatch ... NEWER
  v14`), as designed. Roll forward only. To move an anchor (a new contract), commit anchor set v2 with the admin quorum,
  then change `CERTEN_ANCHOR_V8_<chainId>` on all 7 together. Until both match, admission retries intents on that chain by
  name.
- If a node refuses at step 3, it names the reason and writes nothing that blocks a rollback to v13.

## What the rehearsal proves

`TestRulesV14UpgradeAndAnchorSetRehearsalOnALiveNetwork` runs four in-process CometBFT validators running this
`ValidatorApp`. It drives them with the `validator-rotate` binary built from the tree, over each node's RPC:

1. The chain as v13 left it: a refused admin rotation (state stamped v13), and a block naming a retired anchor accepted.
2. The upgrade: each ledger is put back as the v13 binary wrote it (watermark `v13:checks3`, none of v14's). The fleet
   stops, and every node runs the v14 boot history check over its own block and state stores. The check covers the whole
   chain. The fleet then restarts: app version 14, stamp v13, `history-check --rules 14` exits 0, `anchor-set status`
   reports none in force, and a retired-anchor block is still decided as v13 decided it.
3. The anchor set through the tool:
   - propose;
   - a NO-GO preflight with one approval;
   - sign;
   - a NO-GO preflight against an endpoint where the anchor holds no code;
   - a GO preflight, then submit.

   Every node records it at the same height, and the state is stamped v14.
4. From the next height:
   - the mempool refuses a retired anchor (code 14);
   - a proposer that skips admission and the mempool puts a retired-anchor block straight into its block, and every
     node's FinalizeBlock refuses it (code 14, `ANCHOR_NOT_COMMITTED`) at the same height;
   - a block naming the committed anchors is accepted.
5. `history-check --rules 14` passes with the anchor set found in its record. A whole-fleet restart comes back on one chain:
   stamped v14, app version 14, equal app hashes, and every node answering the anchor set.

## Related

- The admin quorum, rules v12 and the history-check watermark: `docs/runbooks/admin-set-rotation.md`.
- History-check v3 adds the anchor-set kind check; `TestTheHistoryCheckVersionNamesItsChecks` pins it.
