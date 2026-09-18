# Runbook — one owner for `certen_proofs`: a migration stream that can actually build the database

> ## STATUS: IMPLEMENTED. Sections 1–5 describe the problem and plan as they were on 2026-09-15.
>
> The design in §2 shipped between 2026-09-16 and 2026-09-18 (validator PRs #14–#21, #23, #24 and #27), and the
> last gaps closed in the change that added this status. **Read §7 first**: it says what shipped, where
> it differs from §2–§4, and what is still open. Nothing in §1 is a current defect; line numbers there
> refer to `4fa751b`.

Original status (2026-09-15): ready to implement. Owner: validator (`pkg/database`) + proofs_service. Base: `4fa751b`.
Severity: medium (no live outage). A fresh install is impossible, production drifts from the files, and
every validator start re-runs two migrations, one of which takes an ACCESS EXCLUSIVE lock.

---

## 1. What is wrong

### 1a. A fresh database cannot be built

- `MigrateUp` (`pkg/database/client.go:228-262`) wraps each file in one transaction
  (`applyMigration`, `:337-353`) and expects **the file** to insert its own `schema_migrations` row
  (comment at `:349-351`).
- **005 and 012–016 contain their own `BEGIN;`/`COMMIT;`.** The file's COMMIT ends the runner's
  transaction; the runner then reports `unexpected transaction status idle` and stops — after the work is
  already saved. Cost: **one restart per such file**.
- **010 fails permanently.** `010_backfill_leg_progress.sql:38-47` reads
  `batch_transactions.multi_leg_intent_id` (and `leg_id`), which **no validator migration creates**. They
  come from **proofs_service** `pkg/database/migrations/009_multi_leg_intents.sql:266`, applied by hand to
  the same database. So 011–017 are never reached on a fresh install.
- Even bypassing that, the app then fails on `custody_chain_events`
  (`proof_artifact_repository.go:1462`), which only proofs_service `003_proof_service_enhancements.sql`
  creates.

### 1b. Production's bookkeeping is wrong

| Symptom | Detail |
|---|---|
| `008_multi_leg_pending_state` not recorded | re-applied on **every start** of every validator |
| `'009'` recorded under a bare name | that row is **proofs_service's** `009_multi_leg_intents`; the validator's `009_intent_lifecycle_multi_chain` is therefore also re-applied every start, and it takes an **ACCESS EXCLUSIVE** lock on `intent_lifecycle` 5× per start |
| 003, 007, 008 do not self-register | same class of problem |
| 005 applied before 004 | 01-26 vs 01-27; nothing validates order |
| Applied files edited later | 011 (401dd84), 003 (0ffcbc5); no checksums, nothing noticed |
| Two services share `schema_migrations` | different file sets, colliding version names |

### 1c. Runner flaws (`pkg/database/client.go` unless noted)

1. Files self-register; the runner never writes the row (`:349-351`), and the version is just the filename (`:294`).
2. Per-file transaction clashes with in-file transaction control (`:338-353`).
3. Stops at the first error, and `main.go:524-527` only warns (`DATABASE_REQUIRED` defaults false,
   `config.go:142`) — nodes run on a schema older than their code. (`EnsurePersistenceProgressTable` in
   `repository_consensus.go:258-283` exists precisely to survive this.)
4. No global lock: `MigrateUp` reads the applied set once (`:238`) then races 6 peers. With 7 nodes on an
   empty database, 001 and 007 produce `pg_type_typname_nsp_index` duplicate errors.
5. No checksums, no order validation, unknown versions silently ignored (`:249`).
6. "Empty database" is inferred by matching the text `"does not exist"` (`:241`, `:365`).
7. No `lock_timeout`/`statement_timeout`.
8. Data backfills (010) run on the startup path and can RAISE.
9. DB tests skip silently without `CERTEN_TEST_DB` (`proof_artifact_repository_test.go:26-30`); no CI
   workflow runs them.

### 1d. Drift: production has objects no validator migration creates

- From proofs_service `009`: tables `certen_intents`, `intent_legs`, `leg_dependencies`,
  `intent_chain_groups`; 4 views; 3 functions + 3 triggers; the two `batch_transactions` leg columns
  (**the validator needs these**); extra columns on `anchor_records` and `proof_artifacts`.
- `custody_chain_events` (proofs_service 003; the validator's own 003 was deleted in dbea8bc).
- Definition differences: `chain_execution_results.status` nullable in prod vs `NOT NULL DEFAULT 0` in the
  file; `proof_artifacts.attestation_scheme` defaults `'bls12-381'` in prod vs `'ed25519'` in the file.
- Ops backup tables: `governance_proof_levels_backfill_backup_20260824`,
  `proof_artifacts_accum_tx_hash_backup_20260821`.
- Nothing exists in the migrations that is missing from production.

---

## 2. Target design

1. **One owner for the whole database.** A single migration stream in a shared module
   (`certen/db-schema`: embedded SQL + runner + a catalog fingerprint), imported by the validator and by
   proofs_service. proofs_service's own migrations are deleted; it only **verifies**.
2. **Deploy applies; services verify.** `certen-validator migrate up` runs from `deploy-validators.sh`
   **before** the restart groups. Validators start in verify mode and **refuse to start** if the schema is
   older than they need (fatal whenever a database is configured). `MIGRATE_ON_START=true` remains for
   dev/single-node. Validators then no longer need DDL privileges.
3. **A real runner:** goose v3 as a library, wrapped so that:
   - it writes its own history (`certen_schema_history`: version, name, sha256, applied_at, applied_by, duration);
   - **SQL files never contain BEGIN/COMMIT** (lint-enforced); each file runs in one transaction, except
     files explicitly marked `-- +goose NO TRANSACTION` (e.g. `CREATE INDEX CONCURRENTLY`);
   - a Postgres **advisory lock covers the whole run**;
   - `lock_timeout` and `statement_timeout` are set per file, with backoff retry on lock timeout;
   - it **fails fast** on a checksum mismatch, a gap/out-of-order version, or an unknown version below the
     newest the binary knows. A version *higher* than the binary knows is allowed (rolling deploys).
4. **Expand-only policy.** Destructive steps (DROP/RENAME/SET NOT NULL/constraint drops) ship one release
   after the code that stops needing them, and carry an annotation that lint enforces. Data backfills move
   out of startup into `migrate data`, re-runnable, never blocking boot.
5. **Baseline from reality.** `00000_baseline.sql` = production's `pg_dump --schema-only` minus the two
   ops backup tables. It therefore includes the proofs_service objects, `custody_chain_events` and the
   current defaults. Legacy 001–017 are frozen in git and no longer embedded.
6. **Adoption, not rewriting.** A one-time `migrate adopt` compares the live catalog fingerprint against
   the baseline (ignoring `*_backup_YYYYMMDD`), and on a match inserts one "adopted" baseline row. It
   never touches an existing object, any data, or the legacy `schema_migrations` table.

Rejected: patching 003/007/008/009/010 in place (edits applied history; a fresh install still would not
match production); a catch-up 018 (010 fails before it); only adding an advisory lock (leaves
self-registration, the transaction clash and missing checksums); golang-migrate (no per-file checksums,
"dirty" states need manual force); Atlas (viable; extra binary and possible licence — evaluate before
choosing); a schema per service (the core tables are genuinely shared).

---

## 3. Implementation

### Step 1 — capture the truth

1. `pg_dump --schema-only --no-owner --no-privileges` from production (structure only, no rows).
2. Strip the two `*_backup_*` tables → `migrations/00000_baseline.sql`.
3. Generate `schema.fingerprint`: a normalized catalog query (tables, columns+types+defaults+nullability,
   indexes, constraints, views, functions, triggers) hashed with sha256. Commit both.

### Step 2 — the module

`certen/db-schema` (new repo or `/db` in the validator repo, imported by proofs_service):

```
db-schema/
  migrations/00000_baseline.sql
  migrations/00001_*.sql …          # everything new, including anchor-quorum 018 if it lands after
  schema.fingerprint
  runner/                            # goose wrapper: history table, checksums, advisory lock, timeouts
  cmd/                               # migrate up | adopt | data | verify | fingerprint
```

### Step 3 — commands

| Command | Behaviour |
|---|---|
| `migrate up` | advisory lock; apply pending in order; write history rows; fail fast on checksum/order problems |
| `migrate adopt [--dry-run]` | runs only if `certen_schema_history` is empty and legacy `schema_migrations` exists; compares fingerprints; on match inserts the baseline row; on mismatch prints a diff and exits non-zero |
| `migrate verify --require <version>` | what services call at startup; exits non-zero if the schema is older |
| `migrate data <name>` | out-of-band backfills (the 010 class) |
| `migrate fingerprint` | prints the live fingerprint (used by CI and by adopt) |

### Step 4 — wire the services

- Validator `main.go`: replace `dbClient.MigrateUp` with `migrate verify`; **fatal** when a database is
  configured and the schema is too old (delete the "warning only" path at `:524-527`). Keep
  `MIGRATE_ON_START` for dev.
- `deploy-validators.sh`: `certen-validator migrate up` before the restart groups.
- proofs_service: delete `pkg/database/migrations`, its unused `MigrateUp`, and the `COPY migrations` line
  in its Dockerfile; call `migrate verify` at startup.
- Once the runner is guaranteed, reduce `EnsurePersistenceProgressTable`
  (`repository_consensus.go:258-283`) to an existence check.

### Step 5 — the legacy files

Freeze 001–017 under `legacy/` for history, un-embed them, and delete the old runner
(`client.go:228-396`). Record in the runbook that production's `schema_migrations` stays untouched for
rollback.

### Step 6 — later cleanups (each its own decision, after all 7 nodes are upgraded)

- `chain_execution_results.status` → NOT NULL (0 NULLs today).
- Settle one `attestation_scheme` default.
- Drop the ops backup tables when ops agrees.
- Drop `schema_migrations` once no rollback target reads it.

---

## 4. Verification — proving it is 100% correct

### A. CI (Postgres 15 service container; these are the gates)

| # | Test | Assertion |
|---|---|---|
| A1 | fresh install | one `migrate up` on an empty DB succeeds; fingerprint == `schema.fingerprint` |
| A2 | concurrency | 7 goroutines `migrate up` an empty DB; all succeed; exactly one history row per version |
| A3 | upgrade path | load the prod schema fixture + legacy `schema_migrations`; `adopt`; apply pending; fingerprint equals A1's |
| A4 | checksum | edit an applied file → run fails fast, nothing applied |
| A5 | order | a missing lower version → fails fast |
| A6 | forward compatibility | older binary against a newer schema → `verify` passes |
| A7 | lock timeout | hold a conflicting lock → runner retries, then fails cleanly (no partial file) |
| A8 | lint | a file containing BEGIN/COMMIT fails; destructive DDL without the annotation fails |
| A9 | **code matches schema** | PREPARE every repository SQL statement against the migrated DB |
| A10 | tests cannot skip | in CI, missing `CERTEN_TEST_DB` fails the run; `TestMain` migrates through the runner |

A9 is the check that would have caught the leg columns, `custody_chain_events`, and the dead references
(`bls_attestations`, `bundle_downloads`, `proof_cycle_completions`, `validator_set_snapshots`,
`proof_requests.priority`, …) — expect it to fail first and to force either code or schema fixes.

### B. Pre-deploy on a production **copy** (never on prod)

1. Restore a schema-only copy into a throwaway Postgres (port ≥ 15000).
2. `migrate adopt --dry-run` → expect "fingerprint matches baseline", empty diff.
3. `migrate adopt` → exactly one history row; `\d` output identical before/after (diff the catalogs).
4. `migrate up` → "no pending migrations".
5. Start a validator binary against it with `migrate verify` → starts; run the consensus + database test
   suites against it.

### C. Production adoption (metadata only)

1. `migrate adopt --dry-run` against prod (read-only) — reviewed and pasted into the change record.
2. `migrate adopt` — creates `certen_schema_history` and inserts **one** row. Verify:
   - `select count(*) from certen_schema_history` = 1;
   - `schema_migrations` row count unchanged;
   - catalog fingerprint unchanged (compare before/after).
3. No service restart is required for this step.

### D. Rolling deploy

- Groups 1-2, 3-4, 5-6, 7. After each group: the node starts, `verify` passes, height advances, and
  `[PERSIST]` shows no warnings.
- Old nodes in the same window still run the legacy runner harmlessly (008/009 re-run as today).
- Quorum holds throughout (≥ 5 of 7 up).

### E. After the fleet is upgraded

| # | Check | Gate |
|---|---|---|
| E1 | `009` no longer re-runs | no `ACCESS EXCLUSIVE` on `intent_lifecycle` at startup (`pg_locks` sampling or the log) |
| E2 | startup is schema-safe | stopping the DB → the node refuses to start with a clear message (staging) |
| E3 | fresh install works | a brand-new environment comes up from `migrate up` alone, with no manual SQL |
| E4 | no drift | `migrate fingerprint` on prod equals `schema.fingerprint` (modulo backup tables) |

---

## 5. Rollout and rollback

1. proofs_service release without its migrations (no DB effect).
2. Build baseline + fingerprint; CI green (A1–A10).
3. `migrate adopt --dry-run` on prod → review → `migrate adopt`.
4. Rolling validator deploy (verify mode).
5. New migrations from then on: `migrate up` in the deploy script, then the rolling restart.

**Rollback at any point:** the old binaries still work, because `schema_migrations` and every object are
untouched; `certen_schema_history` is additive and ignored by them. If adoption is wrong, drop
`certen_schema_history` — that is the only thing created.

**Optional stopgap (your call, a metadata write to prod):** insert the missing
`008_multi_leg_pending_state` and `009_intent_lifecycle_multi_chain` rows into `schema_migrations` to stop
the per-start exclusive lock immediately.

---

## 6. Sign-off checklist

- [ ] A1–A10 green in CI, including A9 (every repository statement prepares).
- [ ] B1–B5 done on a production copy; catalogs identical before/after adopt.
- [ ] C1–C3 done on prod; fingerprint unchanged; one history row.
- [ ] D: all 7 nodes upgraded, quorum never below 5, no persistence warnings.
- [ ] E1–E4 verified.
- [ ] Legacy runner deleted; proofs_service no longer ships migrations.
- [ ] Dead-object references from A9 resolved (code deleted or schema added), listed in the PR.

---

## 7. What shipped, where it differs, and what is left (2026-09-18)

### 7.1 Shipped

| Runbook item | Where it lives |
|---|---|
| One migration stream | `db/` (package `schema`): `migrations/00000_baseline.sql` + `00001…`, embedded; `schema.fingerprint` (after every migration) and `baseline.fingerprint` (the adopted production catalog) |
| Runner-written history with checksums | `certen_schema_history` (version, name, sha256, applied_at, applied_by, duration_ms); files never self-register |
| Global lock and timeouts | one advisory lock over the whole run; `lock_timeout` and `statement_timeout` per file; a transactional file that hits `lock_timeout` is retried with backoff (default 4 retries from 1 s), a non-transactional one is not |
| Fail fast | checksum mismatch, a gap, or an unknown version at or below the required one; a *newer* history row is allowed (rolling deploys) |
| Lint | no `BEGIN`/`COMMIT`/`ROLLBACK`, no session `SET`/`RESET` outside the baseline; `DROP`, `TRUNCATE`, and `ALTER TABLE/TYPE … DROP/RENAME/SET NOT NULL/TYPE` need `-- schema: destructive-approved`. Judged per statement, so a clause on a continuation line still counts |
| Deploy applies, services verify | `deploy/deploy-validators.sh` runs `validator migrate up` before any restart group; the validator calls `Runner.Verify` at startup and exits if the schema is older (`MIGRATE_ON_START=true` keeps the dev path); `cmd/schemamigrate` migrates without starting a validator |
| Commands | `validator migrate up`, `verify [--require V]`, `fingerprint`, `catalog`, `adopt [--dry-run]`, `data NAME` |
| Adoption without touching objects or data | production adopted on 2026-09-16 (`00000`, applied_by `emergency-recovery`); now at `00003`. The legacy `schema_migrations` (19 rows) is untouched, so old binaries remain a rollback target |
| proofs_service verifies only | its migrations, `MigrateUp` and the Dockerfile `COPY migrations` are gone; it exits at startup unless every entry of `database.RequiredSchema` (version **and** SHA-256) is in `certen_schema_history` |
| Legacy runner | deleted from the binary; `Client` has no `MigrateUp` |

### 7.2 Where it differs from §2–§4

- **Not goose.** The runner is ~550 lines in `db/runner.go`, not a goose wrapper. The goose features the
  plan wanted (history, checksums, lock, timeouts, a no-transaction opt-out) are all there. The opt-out
  marker is `-- schema: no-transaction` on the first non-empty line.
- **Not a separate Go module.** `db/` is a package in the validator module. proofs_service does not
  import it. It pins the versions and checksums its SQL was proven against (`RequiredSchema`), and its CI
  builds the database with the validator's own runner (`go run ./cmd/schemamigrate` from a checkout of
  certen-validator `main`), so there is still exactly one stream and one runner.
- **Legacy files are frozen in place**, at `pkg/database/migrations/` (001–020), not moved to `legacy/`.
  The 019/020 regression tests replay them. `TestLegacyMigrationCatalogIsFrozen` fails on any new file
  there, and `TestLegacyMigrationsAreNotEmbeddedInTheBinary` fails if non-test code embeds them.
- **A9 in both repos.** The validator's prepare gate walks the whole module (every non-test Go file, not
  only `pkg/database`); it prepares 195 statements, including 3 in `pkg/execution` and `pkg/proof` that
  nothing checked before. Templated queries are executed by `TestDynamicRepositoryQueriesExecuteAgainstSharedSchema`.
  In proofs_service the gate first failed on **66 statements in 64 functions**: `bls_attestations`,
  `validator_set_snapshots` and `proof_cycle_completions` do not exist, and `external_chain_results`,
  `aggregated_attestations`, `validator_attestations`, `anchor_batches`, `certen_anchor_proofs` and
  `proof_requests` have different columns. **None of the 64 functions (or the 3 that called them) had a
  caller**, so the fix was deletion, not schema. The 9 types only they used went with them.
- **Tests build their schema with the runner.** The last hand-written fixture schema (proofs_service's
  `batch_quorum_canonical_test.go`) is gone. It did `DROP TABLE … proof_artifacts, anchor_batches … CASCADE`
  on the test database before every run. `pkg/execution`'s database tests now migrate through the runner
  instead of relying on whichever package ran first.
- **Tests cannot skip in CI.** Every `CERTEN_TEST_DB` gate fails when `CI` is set and the variable is
  not. proofs_service's `TestMain` used to `os.Exit(0)` without a database, so the whole package,
  unit tests included, reported `ok` having run nothing.

### 7.3 Verification record

| Gate | Evidence |
|---|---|
| A1 fresh install, A2 seven concurrent migrators, A7 advisory-lock timeout | `db/runner_integration_test.go` |
| A7 table-lock timeout: retried then applied; never clears, so nothing applied | same file; mutation-checked (removing the retry turns the first red) |
| A4 edited applied file, A5 missing lower version, A6 older binary against newer schema | same file, against a real database (unit-level cases are in `schema_test.go`) |
| A8 lint | `TestLintRejectsUnsafeMigrationControl` |
| A9 code matches schema | validator: `TestStaticRepositorySQLPreparesAgainstSharedSchema` (195) + the dynamic test; proofs_service: `TestRepositorySQLPreparesAgainstSharedSchema` (100). Mutation-checked: one renamed column in `pkg/proof` turns the validator gate red |
| A10 no silent skip | as above; proofs_service CI is `.github/workflows/schema.yml` |
| B/C adoption | production history: `00000` 2026-09-16 10:54 UTC, then `00001`–`00003`; the checksums match the committed files |
| proofs_service startup | the real binary exits against an unmigrated database (`relation "public.certen_schema_history" does not exist`), and starts against a migrated one (`verified through migration 00003`) |
| Full validator suite | `go test -p 1 ./...` green on Postgres 15 |

### 7.4 Still open

1. **E4: prod fingerprint equals `schema.fingerprint`.** It has not been run against production in this
   change. Run this; it is read-only and prints one line:
   `docker compose run --rm --no-deps validator-1 ./validator migrate fingerprint`. Compare with `db/schema.fingerprint`.
2. **Database unreachable at startup.** Verify is fatal when the database connects and the schema is
   old. But when the connection itself fails and `DATABASE_REQUIRED` is false (the default), the
   validator still starts in degraded mode (`main.go`, Phase 5), so E2 as written does not hold. Whether
   a validator should refuse to start without its database is a fleet-availability decision, so it is
   left for the owner.
3. **DDL privileges.** Validators and proofs_service still connect as `certen`, which owns the schema.
   Now that no service runs DDL outside `migrate up` / `MIGRATE_ON_START`, they can move to a DML-only role.
4. **§3 Step 6 cleanups**, each its own decision: `chain_execution_results.status` → NOT NULL; one
   `attestation_scheme` default; drop the two `*_backup_2026082x` tables; drop `schema_migrations` once no
   rollback target reads it.
5. **proofs_service unreachable code whose SQL is valid.** `deadcode ./cmd/...` still lists about 60
   functions (e.g. most of `AnchorRepository`, the attestation counters, `CreateProofArtifact`). They
   prepare against the schema, so they are not a schema problem and were left alone.
