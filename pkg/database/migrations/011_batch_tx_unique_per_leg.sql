-- Let a multi-leg intent put all of its legs in one batch.
--
-- unique_tx_in_batch was UNIQUE (batch_id, accumulate_tx_hash). An intent has ONE Accumulate
-- transaction and may have many legs, and the on_cadence path routes each leg to the collector
-- separately — so the second leg of any multi-leg intent collided with the first and the whole
-- intent failed:
--
--     route multi-leg intent: route chain group base-sepolia: batch collector failed for leg 1:
--     duplicate key value violates unique constraint "unique_tx_in_batch"
--
-- Measured 2026-08-07 across the full intent matrix: a 3-leg on_cadence intent failed exactly
-- this way, while the same 3 legs as on_demand completed — the on_demand path is intent-keyed
-- and never inserts a second row for the same transaction.
--
-- The constraint was latent until multi-leg routing was enabled. With multiLegEnabled false,
-- every multi-leg intent fell through to the single-leg path and only ever produced one row per
-- transaction, so nothing ever hit it.
--
-- The rule it was reaching for is still worth keeping: the same LEG must not be collected twice
-- into the same batch. That is (batch_id, accumulate_tx_hash, leg_id) — the hash identifies the
-- intent, the leg_id identifies which part of it.
--
-- leg_id is NULL for single-leg intents, and in Postgres NULLs are distinct, so a plain UNIQUE
-- including it would let the same single-leg intent be collected repeatedly — reintroducing the
-- duplicate this constraint exists to stop. COALESCE to '' makes the absent leg a single
-- concrete value, so single-leg intents keep exactly the protection they had.

ALTER TABLE batch_transactions DROP CONSTRAINT IF EXISTS unique_tx_in_batch;

CREATE UNIQUE INDEX IF NOT EXISTS unique_tx_leg_in_batch
    ON batch_transactions (batch_id, accumulate_tx_hash, COALESCE(leg_id, ''));

COMMENT ON INDEX unique_tx_leg_in_batch IS
    'One row per (batch, intent transaction, leg). Replaces unique_tx_in_batch, which allowed only one leg per intent per batch and failed every multi-leg on_cadence intent.';

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('011_batch_tx_unique_per_leg',
        'Allow all legs of a multi-leg intent in one batch; keep per-leg uniqueness',
        NOW())
ON CONFLICT (version) DO NOTHING;
