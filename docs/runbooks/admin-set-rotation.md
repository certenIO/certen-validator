# Admin set rotation (execution rules v12, RB5-F37)

**Status:** built and rehearsed on a live four-node test network with throwaway keys. Not deployed. **No key needs to be
created or changed to deploy v12.** A key is generated only if, and when, the owner chooses to rotate the admin set
(Part B). Deploying v12 changes nothing about who the admins are: the set in force stays the one the v11 re-seal
installed (admin-a, admin-b, admin-c, threshold 2).

## Why

CERTEN's admin quorum is the chain's one authority for policy updates, validator consensus-key rotations and the BLS
registry. It was sealed at genesis, and no transaction could change it. When certen-testnet's sealed admin secrets were
lost, the only way out was a rules upgrade written for that one repair (v11's re-seal). Without v12, every future lost or
compromised admin key would need another one-time rules repair.

v12 adds the transaction kind `certen.admin.rotate/v1`. The admin quorum **in force** uses it to replace the admin set:
it can replace, add or remove keys and change the threshold. A lost or compromised key is then replaced by the keys that
remain, as an ordinary act of the chain.

## What the chain enforces

| Rule | Why |
|---|---|
| Authorised by at least the threshold of **distinct keys** of the admin set in force for the block (`AdminSetAt`) | One key named under two ids counts once. From v12 this applies to every admin-signed kind. |
| Signatures cover the chain id, the **sequence**, the **id of the set in force** and the **id of the new set** | A rotation signed for one chain does nothing on another. A rotation signed against a set that has since changed is refused as stale. |
| `sequence` = 1 + the number of admin-set changes recorded (the v11 re-seal counts) | A rotation cannot be replayed, skipped or reordered. On certen-testnet the first rotation is sequence **2**. |
| Every key of the new set signs a **proof of possession** under its own domain | Nobody can install a key they do not hold (a typo, an unkept secret, someone else's key). A key kept from the old set signs one too. A possession proof is never an approval. |
| Key ids are plain names; keys are lowercase hex ed25519; no key appears twice; at most 32 keys | Records have one spelling and an id is never ambiguous. |
| Threshold from 1 to n, and **at least 2 when there are 2 or more keys** | With n ≥ 2 keys, a threshold of 1 lets any one key act alone while the set looks like a quorum. A single-key set is allowed only explicitly, as a set of one key. |
| A key that has left the admin set can **never come back** | A key that left is presumed lost or compromised. |
| At most **one admin-set change per block** (the re-seal included) | A block's changes never depend on transaction order. |
| Takes effect from the **next height**. Every admin-signed transaction is judged by `AdminSetAt` for its own block | A block is judged identically however many times it is executed. |
| Refused with code **12** and a named reason | The reason is in the transaction result's log. |

Accepted, the rotation's id (`admin-rotation:<hex SigningBytes>`) goes into the app hash. The rotation is appended to the
same append-only record the re-seal writes (`EntitlementPolicyState.AdminReseals`, with `kind` and `sequence`).

### Canonical encoding

Each hash is sha256 over fields that are each **length-prefixed** (4-byte big-endian length, then the bytes). This
encoding is injective: no two field lists encode the same way, whatever the fields contain.

- `AdminSetID` = sha256( `certen:admin-set:v1`, threshold, number of keys, then for each id in sorted order: id,
  lowercase hex key ).
- `SigningBytes` (current admins sign) = sha256( `certen.admin.rotate/v1`, chain id, sequence, current set id, new set
  id ).
- `PossessionBytes` (every new key signs) = the same fields under `certen:admin-rotate-possession:v1`.

These are pinned in `TestTheAdminRotationEncodingIsPinned` against an independent shell computation (`printf` piped to
`sha256sum`).

## Part A: deploy v12 (coordinated, all 7 validators)

v12 continues v7..v11 state without a reset. It does not assume this: every node checks it at start (step 3), and the
operator checks the live chain beforehand (step 1).

1. **History check, before the deploy.** Build `validator-rotate` from the release commit. Run it against one
   validator's RPC; that node must hold every block from 1:

   ```
   validator-rotate history-check --rules 12 --rpc http://<validator>:26657
   ```

   It reads every block and its result codes and judges them the way a v12 node does. The output must end with
   `v12 continues this chain's history exactly`. Any `FOUND:` line means v12 must **not** be deployed on this chain.
2. **Deploy all 7 together.** Stop every validator, install the v12 binary, and start every validator. Nodes on
   different rules judge admin signatures differently, so the fleet must never run mixed versions while
   admin-signed transactions flow.
3. **Each node checks itself before CometBFT's handshake.** Each node:
   - continues the v11 state (no `execution rules mismatch` error);
   - refuses to start if any admin set its chain ever had names one key twice. certen-testnet's sets name distinct keys
     (`TestCertenTestnetAdminSetsNameDistinctKeys`);
   - reads every committed block once (logs `[HISTORY] checking committed heights 1-N ...` then `✅ [HISTORY] ... hold
     no transaction rules v12 decide differently`) and records that the chain is checked.

   If a node refuses, it names the reason and writes nothing that blocks a rollback. Roll back to the v11 binary.
4. **Verify app version 12 on every node:**

   ```
   curl -s http://<validator-N>:26657/abci_info        # "app_version":"12" on all 7
   validator-rotate admin-rotate status --rpc http://<validator-N>:26657
   ```

   `status` must show the same set id on all 7. The set must be admin-a/admin-b/admin-c with threshold 2, and the next
   rotation must carry sequence 2.
5. **Rollback window.** The state stays stamped v11 until a block makes a decision that only v12 makes: an admin rotation
   (accepted or refused), a second copy of a validator rotation in one block, or a policy update replayed from an earlier
   block. Until then the v11 binary can still start on this state.

## Part B: rotate the admin set (only when the owner chooses)

Secrets never leave their files and are never printed. The request file holds only public data, so it can be carried
between machines.

1. **Read the chain.** `validator-rotate admin-rotate status --rpc http://<validator>:26657` shows the set in force, its
   id, the next sequence and every recorded change.
2. **New keys, only for keys being added.** Each new key holder runs this on their own offline machine:

   ```
   validator-rotate admin-rotate keygen --out <new-key.seed>
   ```

   The secret goes to a new file (0600, never overwritten) and the public key is printed. Back the file up
   **offline** before going further.
3. **Write the new set** with public keys only, for example `new-set.json`:
   `{"admin_keys": {"admin-a": "<hex>", "admin-c": "<hex>", "admin-d": "<hex>"}, "threshold": 2}`. Keep the threshold
   below the number of keys: with threshold = n, losing any one key locks the set. The tool refuses that unless you
   pass `--accept-no-loss-tolerance`.
4. **Build the request:**

   ```
   validator-rotate admin-rotate request --rpc http://<validator>:26657 --new-set new-set.json --out req.json
   ```

   This reads the chain id, the sequence and the current set id from the node. Offline, pass `--chain-id`,
   `--sequence` and `--current-set-id` instead.
5. **Proof of possession, one per new-set key, kept keys included:**

   ```
   validator-rotate admin-rotate possess --tx req.json --key-id <id> --secret @<that key's seed file>
   ```

   The tool refuses a secret that does not match the key listed for that id.
6. **Approvals, offline, by at least the threshold of current admins:**

   ```
   validator-rotate admin-rotate sign --tx req.json --admin-key-id <id> --admin-secret @<seed file>
   ```

   It shows what is being approved: the chain, the sequence, the set being replaced and the new set.
7. **Preflight against all 7 validators:**

   ```
   validator-rotate admin-rotate preflight --tx req.json --rpc http://v1:26657,...,http://v7:26657
   ```

   The result is GO only if:
   - every node runs rules v12 or later, all on the same version, on the request's chain;
   - every node is caught up;
   - every node reports the same admin set;
   - the chain's own rule (`VerifyAdminRotate`) accepts the request for the next block: sequence, set in force,
     threshold of distinct current admins, and every possession proof.
8. **Submit:**

   ```
   validator-rotate admin-rotate submit --tx req.json --rpc http://v1:26657,...,http://v7:26657
   ```

   Submit preflights again, commits the rotation through the first RPC, and confirms that the node recorded it at the
   commit height. The new set authorises from the next height.
9. **Verify** with `status` on every node: the new set id, and the sequence advanced by one. Archive the old keys. A
   removed key can never be added back.

**A lost key:** the remaining keys meet the threshold (2 of 3), so they rotate to a set without the lost key plus a new
one. **A compromised key:** do the same, at once. One key alone can never act (threshold ≥ 2). If the keys left fall
below the threshold, v12 cannot help, and only a rules repair can. That is why the threshold should stay below the
number of keys.

## What the rehearsal proves

`TestAdminRotationRehearsalOnALiveNetwork` runs four in-process CometBFT validators running this `ValidatorApp`. It
drives them with the `validator-rotate` binary built from the tree, over each node's RPC, with throwaway keys:

- keygen, request, possess, sign, a NO-GO preflight with one approval, a GO preflight with two, and submit;
- every node records the rotation at the same height;
- a BLS registry and a policy update signed by the old admins are refused, and the same transactions signed by the new
  admins are accepted;
- the rotation resubmitted in other bytes is refused by its sequence;
- a second, chained rotation by the new set, after which that set is refused in turn;
- `history-check --rules 12` passes on the live chain;
- a whole-fleet restart comes back on one chain, stamped v12, with equal app hashes, app version 12, and every node
  answering the last set.

## Found and fixed while building v12

- **The v10/v11 history claims were checked only on unindexed blocks.** A node whose committed-operation index already
  covered the chain checked nothing. Every node now checks the whole chain once per rules version (a watermark kept per
  version), and every block it commits itself.
- **Re-executing a block could flip a refusal into an acceptance.** This affected policy updates, validator rotations and
  BLS registries. The replay check matched a refused transaction against the accepted one with the same content id,
  because the id excludes signatures. Each kind is now judged against the records below its block plus this execution's
  own acceptances. The first execution is unchanged; the pre-v12 chain test pins the v11 binary's codes and app hashes.
- **The same validator rotation twice in one block** (a byte-different copy, which anyone watching a mempool can submit)
  returned its validator updates twice. CometBFT refuses that as a duplicate entry, which halts the chain. v12 refuses
  the copy.
- **A policy update whose version an earlier block had scheduled was accepted again** as a no-op (code 0), whether or
  not it was signed. v12 refuses it by name.
- **Admin thresholds counted distinct ids, not keys**, and the genesis seed accepted one key under two ids. Both are
  fixed, with the startup continuity check from Part A step 3.
