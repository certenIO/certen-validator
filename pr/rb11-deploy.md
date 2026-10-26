# RB11 staged finality: deploy guide (branch `pv2/rb11-b2b2b-wire`)

What ships: the S7 staged-finality builders are now wired into the validator. For every settled leg of the four live chains the
validator appends `l1_posted` / `finalized` evidence to the leg's append-only addendum chain (migration 00027) and the
leg-independent L1 capture loops fill `proof_finality_capture` (migration 00028). Nothing here runs on the settlement,
attestation or write-back path, nothing is an input of any attestation message, outcome root or govRoot, and no consensus rule
changes. A level that cannot be built is a NAMED state (log line, metric, `proof_finality_status` row), never a failure of the leg.
Evidence is stored in insert-only tables: an addendum, once verified by its registered Kind and stored, is never updated or deleted.
All four live chains are wired: Ethereum Sepolia (`eth-sepolia/finalized/v1`, `pkg/finality/ethsepolia`, built by `wireSepolia`), Base Sepolia
(`l1_posted`, `finalized`), Arbitrum Sepolia (`l1_posted`, `finalized`) and Adiri (`finalized`).

The feature is **ON by default**. Every new variable below is optional; with none of them set the validator runs the public-provider
defaults. A malformed value never stops the validator (RB12-GO-INT F14): it is neither fatal nor silently replaced by a default. The finality
runtime stays off as the named state `finality_upgrader_disabled{reason,...}` (log line, `certen_finality_upgrader_disabled_total{chain="0",env}`,
`certen_finality_upgrader_enabled 0`, `upgrader_disabled_reason` in `/health/detailed`) until the setting is corrected and the process restarted;
consensus, attestation and settlement are not affected. The reasons are a closed set: `config_invalid` (a provider-list entry), `switch_invalid`,
`setting_invalid` (a number or duration), `pins_invalid`, `wiring_failed`, `launch_failed`, `start_panicked`. The state names the variable (and the
position and class of a refused provider entry, or the stage of a wiring failure) and never the value, which may hold a credential; every refused
setting is also logged by name so one restart corrects them all.

## 1. Environment variables

### 1.1 Switches (existing, `pkg/finality`)

| Variable | Default | Meaning / when missing |
|---|---|---|
| `CERTEN_FINALITY_UPGRADER_ENABLED` | `true` | Global switch. `false` logs `[FINALITY] upgrader DISABLED: finality_upgrader_disabled{effect=...,env="CERTEN_FINALITY_UPGRADER_ENABLED",value="false"}` and counts `certen_finality_upgrader_disabled_total{chain="0",env=...}`; nothing is appended or captured by this validator; proofs stay at the level they were stored at. A value that is not a boolean is `finality_upgrader_disabled{reason="switch_invalid",variable}` (the switch is not guessed on or off). |
| `CERTEN_FINALITY_CHAIN_<id>_ENABLED` | `true` | Per-chain switch for `11155111`, `84532`, `421614`, `2017`. `false` announces `finality_upgrader_disabled{env="CERTEN_FINALITY_CHAIN_<id>_ENABLED",value="false"}` once at launch for that chain, skips its legs and does not start its capture loops. |

### 1.2 Per-chain provider variables the wiring REUSES (existing, `pkg/ethrpc`)

The validator already reads these for settlement; the finality wiring reads the same lists, so no new URL has to be configured for
a chain the validator already settles on.

| Chain | Variables (in the order tried) | If no endpoint is configured |
|---|---|---|
| Ethereum Sepolia (11155111), used as the L1 block / log source | `ETHEREUM_SEPOLIA_RPC_URL`, `ETHEREUM_URL`, `ETHEREUM_SEPOLIA_URL_FALLBACKS`, `ETHEREUM_URL_FALLBACKS`, `INFURA_SEPOLIA_URL`, `ALCHEMY_SEPOLIA_URL`; then the public default `https://ethereum-sepolia-rpc.publicnode.com` | never missing: the public default is appended (override the whole list with `CERTEN_FINALITY_L1_RPC_URLS`). This list is also the header source of the Sepolia finalized prover (section 3.4): the owner SHOULD put an own node or a keyed provider first (`ETHEREUM_SEPOLIA_RPC_URL`) |
| Base Sepolia (84532), L2 | `BASE_SEPOLIA_RPC_URL`, `BASE_SEPOLIA_URL_FALLBACKS`, `INFURA_BASE_SEPOLIA_URL`, `ALCHEMY_BASE_SEPOLIA_URL` | Base is switched off by the named state `finality_upgrader_disabled{chain=84532,env="BASE_SEPOLIA_RPC_URL",value="unset"}` (logged once, counted). Production sets it already (the validators settle on Base). |
| Arbitrum Sepolia (421614), L2 | `ARBITRUM_SEPOLIA_RPC_URL`, `ARBITRUM_SEPOLIA_URL_FALLBACKS`, `INFURA_ARBITRUM_SEPOLIA_URL`, `ALCHEMY_ARBITRUM_SEPOLIA_URL` | Arbitrum is switched off by `finality_upgrader_disabled{chain=421614,env="ARBITRUM_SEPOLIA_RPC_URL",value="unset"}` |
| Telcoin Adiri (2017), CERTEN's own node (serves `eth_getProof` at an epoch seal) | `TELCOIN_ADIRI_RPC_URL`, `TELCOIN_ADIRI_URL_FALLBACKS`, `INFURA_TELCOIN_ADIRI_URL`, `ALCHEMY_TELCOIN_ADIRI_URL` | Optional: the public endpoint (below) serves every epoch record; without the own node only the compact proof form is unavailable |

### 1.3 New variables (`pkg/finality/runtime/config.go`)

| Variable | Default | Meaning |
|---|---|---|
| `CERTEN_FINALITY_L1_RPC_URLS` | the Sepolia list of 1.2 + `https://ethereum-sepolia-rpc.publicnode.com` | Comma-separated, ordered (the first is asked first) Ethereum Sepolia execution endpoints for blocks, headers, logs and receipts (not windowed) and for the header spine of the Sepolia finalized kind. Set it to give the finality builders an own node or a keyed provider without touching the settlement path's `ETHEREUM_SEPOLIA_RPC_URL`. An empty list switches Sepolia, Base and Arbitrum off by `finality_upgrader_disabled{env="CERTEN_FINALITY_L1_RPC_URLS"}`. |
| `CERTEN_FINALITY_L1_PROOF_URLS` | `https://0xrpc.io/sep`, `https://api.zan.top/eth-sepolia`, `https://1rpc.io/sepolia`, `https://sepolia.gateway.tenderly.co` | Near-head `eth_getProof` providers. Public providers hold proofs only near the head (Tenderly about 8 blocks, the others at most 100): this is why capture follows the head (V2_SPEC_S7 2.8). |
| `CERTEN_FINALITY_ARCHIVE_URLS` | unset | **OD4**: an archive or paid-tier provider that serves proofs beyond the near-head window; tried after the list above. Unset: see 3.2. Never printed; only its presence (`archive_provider=set`) is logged. |
| `CERTEN_FINALITY_LC_URLS` | `https://lodestar-sepolia.chainsafe.io` | Ordered Lodestar-compatible light-client endpoints (bootstrap, updates, finality_update). **OD3**: put CERTEN's own node first, e.g. `http://certen-sepolia-beacon:9596,https://lodestar-sepolia.chainsafe.io`. Endpoints are availability only, never evidence: the verifier judges every byte they serve. All failing is `finality_lc_unavailable{endpoints=<scheme://host labels>}`. |
| `CERTEN_FINALITY_BEACON_URLS` | `https://ethereum-sepolia-beacon-api.publicnode.com`, `https://lodestar-sepolia.chainsafe.io` | Beacon blob API bases (`/eth/v1/beacon/blobs/{slot}`) for the Base and Arbitrum batch blobs. A miss is `l1_blob_unavailable`. |
| `CERTEN_FINALITY_ADIRI_PUBLIC_URLS` | `https://rpc.telcoin.network` | Public Adiri endpoints for `tn_epochRecord` / `tn_getCurrentEpoch` / `eth_getBlockByNumber`. Epoch records are self-authenticating, so any one endpoint suffices (no provider agreement). The own-node list of 1.2 is appended. |
| `CERTEN_FINALITY_PINS_FILE` | unset (the embedded, hash-checked pins) | Explicit override path to a pins file. Parsed without an expected hash; the startup line then reports `pins_source=override:<sha256>`. Embedded bytes that do not hash to `finality.PinsSHA256`, or an override file that cannot be read or parsed, are `finality_upgrader_disabled{reason="pins_invalid",stage}`. |
| `CERTEN_FINALITY_RATE_LIMIT_RPS` | `5` | Requests per second **per provider host** (token bucket; the limiter is shared by every finality client, so one public host is never asked faster than this by the whole validator). Minimum 0.1. |
| `CERTEN_FINALITY_RATE_BURST` | `5` | Bucket size per host. |
| `CERTEN_FINALITY_MAX_BATCH` | `40` | Largest JSON-RPC batch sent to a provider; larger batches are split and re-joined in order (Arbitrum's public RPC answers 429 to 100-request batches). Values above 100 are `finality_upgrader_disabled{reason="setting_invalid",variable}` (public providers answer 429 to 100-request batches; 40 is the measured safe size). |
| `CERTEN_FINALITY_BACKOFF_RETRIES` | `5` | Retries after an HTTP 429 or 503 (Retry-After honoured, else 500 ms doubling). Each backoff increments `certen_finality_provider_throttled_total{provider_host}`. |
| `CERTEN_FINALITY_BACKOFF_MAX_SECONDS` | `60` | Longest single backoff. |
| `CERTEN_FINALITY_CAPTURE_INTERVAL_SECONDS` | `12` | Wait between ticks of a capture loop (floor 1 s: no loop spins). |
| `CERTEN_FINALITY_MAX_CAPTURE_BYTES_PER_LEG` | `4194304` (4 MiB, V2_SPEC_S7 2.8) | No capture row, and no captured L1 block (the rows one batch-inbox transaction or rollup event leaves), may exceed it; a larger one is refused as `finality_evidence_too_large{part,count,limit}` and counted in `certen_finality_capture_refused_total`, nothing partial is stored. Minimum 65536. |
| `CERTEN_FINALITY_CAPTURE_MAX_BLOCKS_PER_TICK` | `64` | L1 blocks one Base capture tick scans at most (catching up after a restart takes several ticks). |
| `CERTEN_FINALITY_UPGRADER_CONCURRENCY` | `4` | Legs processed at once. |
| `CERTEN_FINALITY_UPGRADER_INTERVAL_SECONDS` | `60` | Seconds between upgrader passes. |
| `CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS` | `300` | Deadline of one prover build or one verified append; a call that ignores its context is abandoned at it (`finality_build_timeout`). It is the wall-clock ceiling of the slowest builder, the Sepolia one: a 4.6k-header spine takes about 3 minutes against the public Sepolia RPC (it answers 429), so **recommend `600` while the Sepolia execution endpoint is the public one**; with an own node or a keyed provider the default 300 is ample. |

Retention: the capture and addendum tables are insert-only and the retention policy **deletes nothing**; budget the disk growth from
`certen_finality_capture_bytes_total` (Base about 1.1 MB per leg with blobs).

## 2. Migrations (stage BEFORE the merge)

| Migration | Adds |
|---|---|
| `db/migrations/00027_proof_finality_addenda.sql` | `proof_finality_addenda` (PK `(proof_id, seq)`, unique `(proof_id, level)`), `proof_finality_addenda_guard()` and two triggers: INSERT must extend the chain exactly; UPDATE, DELETE and TRUNCATE are refused (SQLSTATE 23001). |
| `db/migrations/00028_proof_finality_status_capture.sql` | `proof_finality_status` (mutable builder status, PK `(proof_id, target_level)`) and `proof_finality_capture` (PK `(chain, l1_block, l1_hash, item)`, insert-only: UPDATE, DELETE and TRUNCATE refused by trigger `proof_finality_capture_guard()`). |

Both are **expand-only**: new tables, one function per table, triggers; nothing existing is read or altered. The regenerated
`db/schema.fingerprint` is `ec366d024c83f4128f5dc9e68f622b362e57456ad189a0fcd18ab0fde72965fb` (the OBSERVED value of a fresh install
through 00028, written by RB11-B2B2a; `TestRunnerDatabaseGates/fresh_install` pins it). A production database adopted from the
baseline is judged by `migrate verify`, not by comparing fingerprints.

Why before the merge: `main.go` refuses to start (`Database schema verification failed`) when its migration catalog is ahead of the
database, unless `MIGRATE_ON_START=true`. The rebuild after a merge must therefore find the schema already there. An older binary
tolerates the newer history rows (`validateHistory` only rejects unknown versions at or below the version it requires), so applying
00027/00028 early is safe for the 7 running validators.

What the owner runs (real tooling of this repo, nothing invented):

1. Pre-merge, as root on the host, from the branch's source: the one-shot `schemamigrate` built by the Dockerfile
   (`/build/schemamigrate`; `cmd/schemamigrate`, the same `schema.Runner.Up` path as `MIGRATE_ON_START`), pointed at the
   validators' database with the validators' own `DATABASE_URL` (from `/root/certen-validators/.env.shared`, never typed or printed):
   `schemamigrate -verify` (reports the gap, writes nothing), then `schemamigrate -applied-by rb11` (applies 00027 and 00028; idempotent,
   a no-op once applied). Equivalent with a validator image built from the branch:
   `docker compose run --rm --no-deps validator-1 ./validator migrate up`, then `./validator migrate verify`.
   The orchestrator packages this as the owner-run staging script `/home/claude/<script>.sh` named in the OWNER_QUEUE entry (memory
   `deploy-env-before-merge`: env and migrations are staged before the merge link is handed over); this document gives the contents,
   the script only wraps them.
2. Env: **nothing is required.** Stage only the optional variables of 1.3 that apply (OD3 `CERTEN_FINALITY_LC_URLS`, OD4
   `CERTEN_FINALITY_ARCHIVE_URLS`) in `/root/certen-validators/.env.shared` (0600, edited by the owner, not echoed).
3. The normal deploy, `bash /root/certen-validators/deploy/certen-deploy.sh validators` (all 7, one sitting), also runs the migration
   before restarting any validator (`deploy/deploy-validators.sh`: `./validator migrate up`, "no validator was restarted" on failure), so
   it is safe even if step 1 was skipped; step 1 only removes the migration from the restart window.

## 3. What the owner must provide

### 3.1 OD3: CERTEN's own beacon node (Gloas light-client source)
Run it with `sudo bash /home/claude/rb11-od3-lodestar-node.sh plan|apply` (`pr/rb11-od3-lodestar-node.md`). When it is up, set
`CERTEN_FINALITY_LC_URLS=http://certen-sepolia-beacon:9596,https://lodestar-sepolia.chainsafe.io` (own node first, ChainSafe the
alternate). Lodestar keeps light-client updates only for periods it imported completely and has no backfill: `updates?start_period=P`
works from `start_period+1` about 27 to 55 hours after the first start, `finality_update` within minutes (V2_SPEC_S7 section 15, OD3).
Until then the ChainSafe endpoint serves them. It is not a blocker: endpoints are availability only.

### 3.2 OD4: an archive or paid-tier L1 provider
Set `CERTEN_FINALITY_ARCHIVE_URLS` to one provider that serves `eth_getProof` beyond the near-head window (also named in OQ-R11-4).
**Unset (the default)**: a capture that misses the public providers' window is not redone. It stays a named state,
`batcher_state_unavailable{l1_block}` / `l1_blob_unavailable{...}` (Base) or `l1_proof_window_unavailable{l1_block,providers}`
(Arbitrum), in `proof_finality_status` under the capture pseudo proof id `ffffffff-ffff-4fff-8fff-<chain as 12 hex digits>`
(84532 = `...-000000014a34`, 421614 = `...-000000066eee`), is retried only while the block is inside the 96-block window, then logged as
`given up at head ...` and left. The legs that block would have served keep the level they have; nothing weaker is stored. With the
provider set, the retry horizon extends to 20000 blocks. RB13's definition of done needs `l1_posted` on live legs, so OD4 is a
prerequisite of RB13, not of this deploy.

### 3.3 The Sepolia pins ledger and the light-client anchor
- The embedded pins file (hash-checked against `finality.PinsSHA256` = `fdba733e7fc4206d96d73c87352834c51801ee8fe0af76d60654cb461fbd5440`)
  carries the `eth_sepolia` **root pin** (period 1378 with its `block_root`). The light-client source (`pkg/finality/runtime/lc.go`)
  anchors there: it fetches the bootstrap by that block root, then the links and the final update from `CERTEN_FINALITY_LC_URLS`, and
  the verifier judges every byte. Base and Arbitrum `l1_posted` / `finalized` and Sepolia `finalized` are therefore expected to be
  built in production. Each period between the root pin and the finalized head adds one 26.4 KB link to the evidence until a longer
  ledger is merged (V2_SPEC_S7 4.3, OD2).
- `finality_pin_unknown` is a **failure signal**: the embedded ledger or its root pin was lost, or `CERTEN_FINALITY_PINS_FILE` points at a
  file without one. Investigate it as such. `finality_lc_unavailable{endpoints}` is a warning: every light-client endpoint failed (check
  `CERTEN_FINALITY_LC_URLS`); the legs keep `included` and the next pass retries.
- Adiri `finalized` needs no light client and is built from the first epoch after the deploy.

### 3.4 The Sepolia execution endpoint (own node or keyed provider: SHOULD)
The Ethereum Sepolia finalized kind (`pkg/finality/ethsepolia`, built by `wireSepolia` in `wire.go`; there is no seam and no
"kind absent" state) needs, besides the light-client list, the execution **headers of the spine** between the leg and the finalized head.
Measured by RB11-C2 on live Sepolia: evidence is 1.5 to 3.2 MB per leg, Go verification 170 to 240 ms; a 4.6k-header spine takes about
**3 minutes** against the public Sepolia RPC because it answers 429 (the source retries with a bounded backoff and the shared transport
rate-limits per host and splits batches to `CERTEN_FINALITY_MAX_BATCH`). The prover runs only in the background upgrader pass, under
`CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS`, never on the settlement path, so a slow endpoint delays only the Sepolia addendum. The owner
SHOULD provide an own Sepolia node or a keyed provider, through either of:
- `ETHEREUM_SEPOLIA_RPC_URL`: the validator's existing Sepolia provider variable (also read by the settlement path), or
- `CERTEN_FINALITY_L1_RPC_URLS`: an ordered list for the finality builders alone (the first is asked first).

Until then the public default works; set `CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS=600`. It is not a blocker: a provider is availability only
and every header is verified against the finalized head by the Kind.

Expected time to level after the leg's inclusion:

| Chain | Level | Time |
|---|---|---|
| Ethereum Sepolia | finalized | 13 to 19 min |
| Base Sepolia | l1_posted | about 17 to 20 min |
| Base Sepolia | finalized | about 5 days + 15 min |
| Arbitrum Sepolia | l1_posted | 14 to 21 min |
| Arbitrum Sepolia | finalized | 65 to 110 min (mean about 85) |
| Adiri | finalized | next epoch seal (uniform over 0 to 6 h, mean about 3 h) |

## 4. Order

1. **Stage** (owner, pre-merge): migrations 00027 + 00028 (section 2, step 1), optional env (OD3/OD4).
2. **Merge** the PR (owner); **deploy all 7 at once**: `bash /root/certen-validators/deploy/certen-deploy.sh validators`.
3. **Check** (read-only, any user with docker): `bash pr/rb11-deploy-check.sh` (copy to the host or `ssh claude@host 'bash -s' < pr/rb11-deploy-check.sh`).
   Expected per validator within a minute of start (URLs never appear; provider text is redacted):
   - `[FINALITY] runtime wiring: pins_source=embedded pins_sha256=12217758b3a8... chains_off_by_configuration=[] config=map[...]`
   - `[FINALITY] upgrader ENABLED (CERTEN_FINALITY_UPGRADER_ENABLED): concurrency=4 interval=1m0s chains=[2017 84532 421614 11155111] switched_off=map[]`
   - `[FINALITY] capturer base-sepolia/inbox: captured L1 block <n>` and the Arbitrum capture lines as batches appear
   - `[FINALITY] leg <proof> chain <id> reached <level> (addendum <seq>, kind <kind>)` as addenda are appended (Adiri within one 6 h epoch)
   - after ~30 min, once the finalized head covers a leg: `[FINALITY] leg <proof> chain 11155111 reached finalized` (13 to 19 min after inclusion) and `chain 84532|421614 reached l1_posted` lines
   Not expected anywhere: `panic`, `finality_prover_panicked`, `stored addendum chain does not verify`, `capturer ... stopped` repeating,
   `finality_upgrader_disabled` for a chain that should be on (it names the missing setting in `env`), `has no registered prover`, `finality_pin_unknown` (embedded ledger lost, section 3.3).
4. Alerts: `pr/rb11-alerts.md`.

## 5. Rollback and off switch

- Whole feature off, no redeploy of code: `CERTEN_FINALITY_UPGRADER_ENABLED=false` (the validator restarts; the named state
  `finality_upgrader_disabled` with `value="false"` is logged and counted, stored addenda are untouched and still served).
- One chain off: `CERTEN_FINALITY_CHAIN_<id>_ENABLED=false`.
- The tables are expand-only and insert-only: there is nothing to roll back in the schema, and nothing is ever dropped or deleted. An old
  binary keeps running against the migrated database (section 2).
- Verifiers are unaffected either way: `included` is derived from the stored Settlement, and an absent addendum chain is the
  stored-proof behaviour of every earlier v1/v2 proof.

## 6. Alert thresholds

See `pr/rb11-alerts.md` (metric, condition, severity, why). The same state, without history, is the `finality` member of
`/health/detailed`.

- Correction (RB12-EPS-DENIM, appended; the lines above are left as written): the embedded pins file is hash-checked against `finality.PinsSHA256` = `9f4fc10feca95909272c9f6eaef1a38d7a06110cfead0a88cb79e8ffd7a3d1cf` on branch `pv2/rb12-eps-denim` (the `base_sepolia.post_denim` capability row was appended; `fdba733e...5440` above is the hash before that row, and `13ee2d85...df05` was the hash before the e1-raise pins). Judge the deployed pins hash by `/health/detailed` and the status `pins_sha256`, not by this note.
