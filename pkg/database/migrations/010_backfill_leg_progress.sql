-- Backfill the leg counters that nothing ever wrote.
--
-- Migration 009 added leg_count, legs_completed, legs_failed, target_chains and execution_mode.
-- The only code that populates them is UpsertOnDiscoveryMultiLeg and UpdateLegProgress, and
-- NEITHER had a caller: SetLegCompletionHandler was never invoked, so multiLegEnabled was
-- permanently false and every intent took the single-leg path.
--
-- The result, measured 2026-08-07: all 542 rows sat at the schema defaults — leg_count 1,
-- legs_completed 0, target_chains NULL — including 238 intents whose status was 'complete'.
-- 238 of 238 completed intents claimed zero completed legs.
--
-- That is not a cosmetic gap. Those columns are the first thing any analysis of multi-leg
-- behaviour reads, and reading them is what led three separate reviews to conclude that
-- multi-leg had never run in production. It had: batch_transactions holds 34 multi-leg intents
-- across 613 legs, every one of them with a transaction hash on chain. The execution path
-- recorded the work; the lifecycle table did not.
--
-- # WHAT IS DERIVED, AND FROM WHAT
--
--   leg_count       count of DISTINCT leg_id for the intent in batch_transactions.
--   legs_completed  count of DISTINCT leg_id that carries a non-empty transaction_hash. A leg
--                   with a transaction reached the chain; that is the evidence, not an
--                   assumption about it.
--   target_chains   the distinct to_chain values, sorted so the array is stable.
--
-- execution_mode is deliberately NOT backfilled. It is sequential / parallel / atomic and
-- nothing in batch_transactions records which was used — inferring it would put a fabricated
-- routing decision into the audit trail. NULL correctly means "not recorded".
--
-- batch_transactions is joined on multi_leg_intent_id, which is the ONLY key that identifies an
-- intent's legs as a set. Row counts in that table are meaningless as a measure of anything:
-- four runaway intents account for 59,376 of its 68,909 rows, and a single intent was written
-- into 35,962 separate batches while producing exactly one on-chain transaction. Everything
-- here counts DISTINCT leg_id for that reason.

-- ── Multi-leg intents: derive the real shape from the legs that executed ──────────────────
WITH legs AS (
    SELECT bt.multi_leg_intent_id AS intent_id,
           count(DISTINCT bt.leg_id) AS n_legs,
           count(DISTINCT bt.leg_id) FILTER (
               WHERE bt.transaction_hash IS NOT NULL AND bt.transaction_hash <> ''
           ) AS n_done,
           array_agg(DISTINCT bt.to_chain) FILTER (WHERE bt.to_chain IS NOT NULL) AS chains
    FROM batch_transactions bt
    WHERE bt.multi_leg_intent_id IS NOT NULL
      AND bt.leg_id IS NOT NULL
    GROUP BY bt.multi_leg_intent_id
)
UPDATE intent_lifecycle il
   SET leg_count      = legs.n_legs,
       legs_completed = legs.n_done,
       target_chains  = COALESCE(legs.chains, il.target_chains),
       updated_at     = now()
  FROM legs
 WHERE legs.intent_id = il.intent_id
   AND legs.n_legs > 0;

-- ── Single-leg intents that completed ────────────────────────────────────────────────────
--
-- An intent whose status is 'complete' and which has no multi-leg record completed its one leg,
-- by definition of having completed. leg_count is already 1 from the schema default.
--
-- Restricted to 'complete' on purpose. A 'failed' intent may have completed some legs before
-- failing, and this table cannot say how many — writing a count there would be inventing one.
-- Those rows keep 0 and remain honestly unknown.
UPDATE intent_lifecycle il
   SET legs_completed = GREATEST(COALESCE(il.leg_count, 1), 1),
       updated_at     = now()
 WHERE il.status = 'complete'
   AND COALESCE(il.legs_completed, 0) = 0
   AND NOT EXISTS (
       SELECT 1 FROM batch_transactions bt
        WHERE bt.multi_leg_intent_id = il.intent_id
   );

-- ── The invariant this migration exists to establish ──────────────────────────────────────
--
-- A completed intent must account for at least one completed leg. If this fires, the backfill
-- above did not cover some population and the transaction is rolled back rather than leaving
-- the table half-repaired — the migration runner applies each file in a transaction.
DO $$
DECLARE
    violations int;
BEGIN
    SELECT count(*) INTO violations
      FROM intent_lifecycle
     WHERE status = 'complete'
       AND COALESCE(legs_completed, 0) = 0;

    IF violations > 0 THEN
        RAISE EXCEPTION
            'leg-progress backfill incomplete: % completed intent(s) still report 0 completed legs',
            violations;
    END IF;
END $$;

-- Record this migration as applied.
--
-- REQUIRED: the runner does NOT insert this row — applyMigration executes the file and commits,
-- and each migration is expected to record itself. A file that omits this re-runs on every
-- startup of every validator, forever. That is survivable for an idempotent `ALTER ... IF NOT
-- EXISTS` (which is why 009 re-running has gone unnoticed) but not for the assertion above:
-- once live traffic produces a completed intent whose legs were not yet recorded, a permanent
-- re-run would turn a transient reporting gap into seven validators that refuse to boot.
--
-- The version string must equal the filename without its extension, because that is exactly
-- what getMigrations computes and what getAppliedMigrations compares against. `009` is recorded
-- as bare "009" and therefore never matches its own file — do not copy that.
INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('010_backfill_leg_progress',
        'Backfill leg_count/legs_completed/target_chains from executed legs',
        NOW())
ON CONFLICT (version) DO NOTHING;
