# Runbook: App-Hash Idempotency Fix (transactional accumulator)

**Status:** implemented + unit-tested, ready to deploy · **Scope:** `pkg/consensus/abci_validator.go` · **Consensus-value impact:** none at current scale (identical app-hashes) · **Reset required:** no

---

## 1. Problem

A validator that restarts **while the network is producing blocks** (so it must catch up) could get
stuck, unable to rejoin — CometBFT blocksync rejected every block with:

```
wrong Block.Header.AppHash. Expected <network>, got <local>
```

and once a node's persisted app-hash drifted, no restart could recover it — only a genesis reset.

## 2. Root cause

The app-hash was an XOR of ValidatorBlock **bundle-ids** read from the in-memory `validatorBlocks`
map. Two properties made it non-reproducible and non-idempotent:

1. **Map is not persisted and is pruned** (last ~1000 VBs). After a restart the map is empty and
   rebuilds from a *different* starting point, so its pruned contents — and therefore the hash —
   diverge from a node that never restarted. (This means the *legacy* design was already
   restart-divergent at scale, independent of the newer accumulator work.)
2. **`FinalizeBlock` mutated committed state.** ABCI may call `FinalizeBlock` **without** a following
   `Commit` (rejected block, blocksync retry) or **replay** it. Each such call folded bundle-ids into
   the live accumulator, so retries/replays could compound into a corrupted value that persisted and
   survived restarts.

`FinalizeBlock` must be a **staging** operation; only `Commit` may mutate committed state. The old
code violated the ABCI contract.

## 3. Solution (transactional, staged accumulator)

App-hash = XOR of every **committed** VB bundle-id, held in `committedAccum` and derived from
**persisted** state (seeded from the persisted app-hash on restart), never from the map.

| Phase | Behavior |
|-------|----------|
| `FinalizeBlock(H)` | Computes `pendingAccum = stageAccum(committedAccum, block bundle-ids)` — folds this block's unique bundle-ids onto a **copy** of the committed accumulator. **Never mutates `committedAccum`.** Returns that as `ResponseFinalizeBlock.AppHash`. |
| `Commit` | **Only** place `committedAccum` is mutated: promotes `pendingAccum → committedAccum` and persists it as the app-hash. |
| restart | `seedAccumFromHash(persistedAppHash)` restores `committedAccum`; catch-up folds only the missed blocks. |
| queries | `validatorBlocks` map is retained purely as a query cache; it no longer affects the app-hash, so its pruning/restart-volatility is harmless. |

Key methods: `stageAccum` (pure — same inputs → same output, no mutation), `xorBundleInto`,
`appHashFromAccum`, `seedAccumFromHash`.

## 4. Why it's correct

- **Idempotent under replay/retry:** `stageAccum` reads `committedAccum` (unchanged until `Commit`),
  so calling `FinalizeBlock(H)` any number of times before `Commit` yields the identical result and
  never corrupts committed state.
- **No replay double-count:** CometBFT only re-runs `FinalizeBlock` for **uncommitted** heights
  (`> committed height`); those bundle-ids are not yet in `committedAccum`, so folding them is correct.
- **Reproducible after restart:** committed state is seeded from the persisted app-hash and only
  missed blocks are folded → a restarted/catch-up node reaches the same value as a from-genesis node.
- **Value-identical at current scale:** below the map-prune threshold the produced app-hashes equal
  the legacy values, so this is **not** a consensus change for the live testnet (height ≈ tens).

## 5. Tests (`pkg/consensus/abci_apphash_test.go`)

| Test | Guarantees |
|------|-----------|
| `TestStageAccumIdempotentAndPure` | `stageAccum` never mutates committed state, is idempotent across repeated calls, dedups duplicates within a block |
| `TestFinalizeWithoutCommitLeavesCommittedUnchanged` | a finalized-but-rejected block doesn't advance committed state; the retried+committed block matches a single-block reference (no double-count) |
| `TestAppHashAccumulatorReproducibleAcrossRestart` | restart-seeded + catch-up == from-genesis |
| `TestAppHashConsistencyAcrossRestart`, `TestFinalizeBlockAppHashMatchesCommit` | FinalizeBlock/Commit/Info agree, survive restart |

Run: `go build ./... && go test ./pkg/consensus/ -run 'AppHash|Accum|Finalize|Stage' -v`

## 6. Deployment (rolling, no reset)

Because app-hashes are value-identical at current scale, deploy **rolling** with no genesis reset.
Recreate is safe (restart-crash fix already in prod).

```bash
# on the server
cd /root/certen-validators
git pull origin main            # includes the idempotency commit
docker compose build            # recompiles the changed Go

# roll one validator at a time; 6/7 hold quorum throughout
for n in 1 2 3 4 5 6 7; do
  docker compose up -d validator-$n
  # wait for healthy before moving on
  for i in $(seq 1 20); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' certen-validator-$n)" = "healthy" ] && break
    sleep 3
  done
  # must be zero app-hash mismatches
  docker logs --since 2m certen-validator-$n 2>&1 | grep -c "wrong Block.Header.AppHash"
done
```

**Gate between nodes:** the mismatch count must be `0` and the node `healthy` before recreating the
next. If a node shows mismatches or won't go healthy, stop and go to §8.

## 7. Post-deploy verification (the scenario that used to break)

```bash
# 1. all 7 healthy, consensus current
docker ps --filter name=certen-validator --format '{{.Names}} {{.Status}}' | sort
curl -s localhost:26657/status | python3 -c "import sys,json;d=json.load(sys.stdin)['result']['sync_info'];print(d['latest_block_height'],d['catching_up'])"

# 2. drive activity, then restart ONE validator mid-activity (this is what previously got stuck)
#    (submit an intent from the harness) then:
docker restart certen-validator-2
#    watch it catch up cleanly: height climbs, catching_up -> False, zero mismatches
for i in $(seq 1 20); do
  s=$(curl -s localhost:26667/status | python3 -c "import sys,json;d=json.load(sys.stdin)['result']['sync_info'];print(d['latest_block_height'],d['catching_up'])")
  echo "$s"; echo "$s" | grep -q False && break; sleep 5
done
docker logs --since 2m certen-validator-2 2>&1 | grep -c "wrong Block.Header.AppHash"   # expect 0

# 3. (if P3 enabled) checkpoints still advancing + chain valid
```

**Pass criteria:** the restarted node returns to `catching_up: False` at the network height with
`0` app-hash mismatches — no genesis reset needed.

## 8. Rollback

The change is value-identical, so rollback is a normal redeploy — no reset:

```bash
cd /root/certen-validators
git revert --no-edit <idempotency-commit-sha>   # or: git checkout <prev-sha> -- pkg/consensus/abci_validator.go
git push origin main        # if reverting on the branch the server tracks
git pull origin main
docker compose build
docker compose up -d         # rolling as in §6
```

## 9. Recovery: a node already in a corrupted/inconsistent state

If a node's persisted CometBFT state and app-ledger have already drifted (e.g. from prior forced
recreates), the fix cannot un-drift it in place. Reset that **one** node to genesis (key-safe); it
re-syncs from the healthy majority. Keys are preserved.

```bash
cd /root/certen-validators
docker compose stop validator-<N>
docker run --rm \
  -v certen-validators_validator<N>_data:/d \
  -v certen-validators_validator<N>_keys:/k alpine \
  sh -c 'rm -rf /d/validator-ledger /d/gov_proofs /d/checkpoint_chain_head /k/validator-<N>/data; \
         echo "kept: $(ls /d) | $(ls /k/validator-<N>)"'
docker compose up -d validator-<N>
```

Preserved: `bls_key_validator-<N>.hex`, `ed25519_key.hex`, `/k/validator-<N>/config` (node keys +
genesis). The node blocksyncs from height 1, rebuilding the accumulator from empty (no seed, no
possible double-count). With this fix deployed, a genesis reset should no longer be needed in normal
operation — this remains only as a break-glass for an already-corrupted node.

## 10. Notes / future

- If the testnet is ever expected to exceed the legacy map-prune window (~1000 VBs) with **mixed**
  binary versions in the fleet, upgrade all nodes first — the accumulator (all-VB) and the legacy
  (pruned-window) hashes diverge beyond that point. At current scale this is moot; after a full-fleet
  upgrade it's permanently moot.
- The `validatorBlocks` map prune (`maxCachedBlocks = 1000`) is now purely a query-cache concern and
  can be tuned or replaced with a persistent store independently of consensus.
