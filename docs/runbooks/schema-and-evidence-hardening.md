# Runbook — schema and evidence hardening

Eight pieces of work, in the order that most reduces the chance of repeating what happened between
2026-09-15 and 2026-09-18. The order is deliberate and it is **not** by effort: each step removes a way
for the system to be wrong *silently*, and the earlier steps are the ones that make the later steps
verifiable at all.

## What this exists to prevent

Every defect found in that window was a claim nothing checked:

| Claim the system made | What was true | How it was found |
|---|---|---|
| "root `d2d24ab3…` is in tx `0x9e4ff6ab…`" | that root was never published; that tx settled a different root | reading layer 5 by hand |
| "quorum met" (Transaction Center) | read from a per-validator shadow row | code audit |
| backfill refuses all 313 candidates | compared `operationCommitment` (empty on batch anchors) instead of `operationID` | first live dry run |
| canonical row complete | `anchor_create_tx` and `verify_block` blank | first live gate |
| layer 5 binds the anchor | binding keyed on a column the batch path never fills | first live gate |
| migration 021 merged and deployed | landed in a retired catalog; never applied | hand-checking a constraint |
| recovery tool disagrees with production | Windows CRLF checkout changed the migration's hash | outage triage |

None of them announced themselves. Six were found because somebody decided to look. **The work below is
mostly about making the looking automatic.**

Two practices did the actual finding, and both are cheap enough to be policy — see §8.

---

## 0. Deploy order for a schema change (do this every time)

**A binary whose catalog is ahead of the database exits on startup.** `main.go` calls `log.Fatalf` when
`schema.Runner.Verify` fails, and `validateHistory` returns `schema is older than required migration N`.
That is correct behaviour — a binary must not run against a schema it does not understand — but it makes
deploy order load-bearing.

On 2026-09-18 a merge-then-restart put all seven validators into a crash loop for ~4 minutes.

Safe orders, pick one:

```sh
# A. migrate first, then roll the binary  (preferred: no validator starts until the schema is ready)
DATABASE_URL=... schemamigrate -verify        # report the gap, change nothing
DATABASE_URL=... schemamigrate                # apply
# then restart the fleet

# B. let the first node migrate
MIGRATE_ON_START=true   # on the deploy, then restart
```

`cmd/schemamigrate` exists because there was previously no way to bring a schema forward *without*
starting a validator, which is exactly what an operator needs during an outage. It calls
`schema.Runner.Up` — the same path `MIGRATE_ON_START` takes — so history rows and checksums are written by
the runner rather than by hand. Never hand-insert a `certen_schema_history` row: it must carry the
migration's exact SHA-256, and a wrong one fails `Verify` in a way that reads like corruption.

**Build migrations on Linux, or with `db/migrations/*.sql` checked out as LF.** The bytes are hashed, so a
CRLF checkout yields a binary that rejects a healthy production database. `.gitattributes` now pins this;
the entry is there because it cost real minutes during the outage above.

**Gate:** `schemamigrate -verify` exits 0 against production before the new binary is rolled.

---

## 1. Collapse to one migration catalog

**Highest leverage. Do this first, with §2.**

`pkg/database/migrations/` (21 files) is no longer read by any running code — `main.go` uses
`schema.Runner` over `db/migrations/`. A migration was written, reviewed, merged, deployed, and did
nothing. This is worse than the false layer-5 binding because it is silent and applies to *every* future
schema change.

1. Confirm what the baseline already holds. `db/migrations/00000_baseline.sql` is a production snapshot
   taken after 018–020 applied, so `bundle_id`, `anchor_create_tx`, `evidence_source`, the layer-5
   `superseded_at`/`superseded_reason` columns and their comments are already in it. Verify each
   legacy migration's *effect* is present rather than assuming.
2. Port anything that is not, as a new `db/migrations/000NN_*.sql`.
3. Delete `pkg/database/migrations/` and `Client.MigrateUp`.
4. Add a CI check that fails if `pkg/database/migrations/` reappears.

New migrations must obey the runner's rules: no `BEGIN`/`COMMIT` (the runner owns transactions), no
session `SET`/`RESET`, and `-- schema: destructive-approved` on any `DROP`, or `ALTER TABLE … DROP /
RENAME / SET NOT NULL`. Regenerate `db/schema.fingerprint` by running the fresh-install gate and taking
the observed value; leave `db/baseline.fingerprint` alone.

**Gate:** `grep -r "MigrateUp" --include=*.go` returns nothing outside history; `go test ./db/` green;
`schemamigrate -verify` green against a copy of production.

## 2. Build test schemas with the production runner

**Same root cause as §1. Land them together — each is unsafe alone.**

`pkg/database` tests build their schema with `applyMigrationFilesDirectly` from the *legacy* catalog. That
is why `TestBackfilledRowRecordsAnUnknownLaneRatherThanInheritingOne` passed green while production
rejected the identical write on `valid_batch_type`. **A test that builds its own schema tests your
fixture, not your database.**

1. Replace every hand-rolled fixture schema and `applyMigrationFilesDirectly` with `schema.Runner.Up()`
   against a throwaway database (`db/runner_integration_test.go` has the helper).
2. Delete the hand-written `CREATE TABLE` fixtures in test files. They drift, and each drift costs a
   round of "discover one NOT NULL / CHECK constraint at a time".
3. Fix the **10 failing `pkg/database` tests on `main`** as part of this — they are this same rot.
   Broken tests that stay broken train everyone to ignore red.

**Gate:** `pkg/database` and `pkg/execution` green on a database built only by the runner; zero
hand-written schema left in tests.

## 3. Retire the shadow pipeline

Every intent still writes **1 canonical row + 7 shadow rows carrying a different root** — the exact
artifact that produced the `d2d24ab3` incident, manufactured on every transaction.

The retirement gate (all eight checks on one on-demand *and* one cadence intent) **passed on 2026-09-16**:
intents `c3ad250a` and `195fac5a`. This is ready.

1. Stop `routeIntentToBatchSystem`'s legacy `anchor_batches` write and the old processor's anchoring,
   behind `LEGACY_BATCH_PIPELINE=off`.
2. Soak, then delete the dead code and the flag.
3. Decide what happens to the ~71,000 existing shadow rows. They are already excluded from every reader
   (`bundle_id IS NOT NULL`); label them `evidence_source='legacy_shadow'` rather than deleting, so the
   record of what was written survives.

**Gate:** one intent of each lane produces exactly one `anchor_batches` row; `SELECT count(*) FROM
anchor_batches WHERE quorum_reached AND evidence_source='legacy_shadow'` stays 0.

## 4. Monitoring, so silence is impossible

Moved ahead of the remaining code work: it is cheap, and it is the only item that would have caught the
others without someone deciding to look.

Three alerts, all queries already written and baselined at 0:

```sql
-- a. a settled intent with no canonical quorum row (last hour)
SELECT count(DISTINCT bt.intent_id) FROM batch_transactions bt
 WHERE bt.created_at > NOW() - INTERVAL '1 hour' AND bt.intent_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM batch_transactions b2 JOIN anchor_batches a2 ON b2.batch_id=a2.id
                    WHERE b2.intent_id=bt.intent_id AND a2.bundle_id IS NOT NULL);

-- b. a layer-5 row contradicted by its own canonical anchor (migration 020's rule, as a standing check)
SELECT count(*) FROM chained_proof_layers cpl
  JOIN proof_artifacts pa ON pa.proof_id=cpl.proof_id
  JOIN batch_transactions bt ON bt.intent_id=pa.intent_id
  JOIN anchor_batches ab ON ab.id=bt.batch_id AND ab.bundle_id IS NOT NULL
 WHERE cpl.layer_number=5 AND cpl.superseded_at IS NULL
   AND LOWER(cpl.layer_json->>'batchRoot') <> encode(ab.merkle_root,'hex');
```

Plus `anchor_quorum_conflict` log occurrences (metric already emitted), and **schema version behind the
binary's requirement** — `schemamigrate -verify` on a timer, which turns §0's outage into a page *before*
a restart rather than after.

**Gate:** all four fire in staging when deliberately broken, and are quiet in production.

## 5. Close the two structural evidence gaps

These were worked *around*, not *through*, and the difference matters.

**a. `batch_transactions.accumulate_tx_hash` holds an operation id on canonical rows.** The layer-5
binding was re-keyed to `intent_id` to avoid it. The column is still mislabelled — the same class as
writing a ZK blob into a column named `aggregated_signature`.

**b. The batch path never sees the Accumulate transaction hash.** A member arrives as
(intent id, ADI, operation id, legs). The real fix threads it `PendingBatchIntent` → `LeafInput` →
`AnchorQuorumMember` → row; it touches the mempool's JSON persistence (`persistedMember`), which is
additive and backward-compatible.

Until then, **backfilled rows are structurally thinner than live ones** — no members, no lane — so
historical intents will never get a layer-5 binding. That is honest, but it is a permanent hole in the
audit story for everything before 2026-09-16, and it should be a stated limitation rather than a surprise.

**Gate:** `accumulate_tx_hash` holds an Accumulate transaction hash or nothing, on every row; a live
intent's canonical member row carries both its intent id and its Accumulate hash.

## 6. Make read-only actually read-only

`NewEthereumContractManager` requires a parseable private key, so the read-only backfill had to be handed
a throwaway signing key to satisfy a constructor. Split the read path from the transact path so a tool
that only issues `eth_call` / `eth_getTransactionReceipt` cannot hold a key at all.

**Gate:** `cmd/anchorquorumbackfill` runs with no `ETH_PRIVATE_KEY` in its environment.

## 7. Fix the RPC configuration

`BASE_SEPOLIA_RPC_URL` and `ETHEREUM_SEPOLIA_RPC_URL` point at publicnode, which serves transaction bodies
but returns `null` for historical **receipts**. Any verification of the past silently reports "not found"
for transactions that plainly exist.

1. Configure archive-capable endpoints (verified working: `sepolia.base.org`,
   `sepolia.gateway.tenderly.co`, `sepolia-rollup.arbitrum.io/rpc`).
2. Make the code distinguish **"the chain says no"** from **"this endpoint cannot answer"**. Today they
   are indistinguishable, and that ambiguity is what made the first 84 backfill candidates look like data
   problems.

**Gate:** fetching a receipt from 2026-08 succeeds on every configured chain; a deliberately pruned
endpoint produces a distinct, named error.

## 8. Keep the two practices that actually worked

Make these policy for anything that writes evidence.

**Golden vectors from real chain responses.** The `operationID` tuple-index bug was invisible to
hand-built fixtures and obvious against the live `anchors()` return, which is now pinned verbatim in
`TestDecodeAnchorStateReadsTheLiveAnchorLayout`. A fixture you wrote cannot contradict your assumption;
the chain can.

**Mutation-verify every evidence test.** Three times in that window a test passed, and passed *again* when
the thing it claimed to check was deliberately broken — including one that bypassed the very plumbing it
was written for. A test over evidence that has never been seen to fail is decoration. The discipline:
break the line the test exists for, watch it go red, restore.

---

## Order, and why

```
0  deploy order + schemamigrate      every time, and it is already in place
1  one catalog            ─┐ same root cause; each unsafe without the other
2  runner-built tests     ─┘
3  retire shadow pipeline    stops manufacturing the original defect daily
4  monitoring               cheap; the only item that removes "somebody had to look"
5  evidence gaps            real fixes for the two known workarounds
6  read-only access      ─┐
7  RPC configuration     ─┤ independent, parallelisable
8  testing practice      ─┘
```

§1 and §2 land together because collapsing the catalog without repointing the tests leaves the tests
building a schema that no longer exists, and repointing the tests without collapsing the catalog leaves
two sources of truth. Everything from §3 down is only *verifiable* once §2 makes a green test mean
something about production.
