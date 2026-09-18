-- Let an anchor row say it does not know which lane produced it.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY
--
--  anchor_batches.batch_type is NOT NULL, constrained to ('on_cadence','on_demand'), and defaults to
--  'on_cadence'. Every row written by the validator knows its lane, so that was always satisfiable.
--
--  A row reconstructed from the chain does not. The lane is a property of how this fleet SCHEDULED the
--  batch — one anchor per intent, or one per period — and nothing in executeComprehensiveProof's calldata
--  or in the anchor's stored state records it. A one-member batch is not evidence of the on-demand lane
--  either: a period can close with a single member.
--
--  So the chain backfill has three options, and only one of them is honest:
--
--    omit the column   -> the DEFAULT applies and every backfilled row claims 'on_cadence'
--    guess from shape  -> a one-member period silently becomes 'on_demand'
--    say "not known"   -> this migration
--
--  The first two invent a fact to satisfy a constraint, which is the same failure this whole change set
--  exists to remove: a column that reads as evidence while holding something nobody established.
--
--  'unknown' is therefore added as a THIRD permitted value, used only where the lane genuinely was not
--  observed. Live rows are unaffected: the writer sets the lane it actually ran.
--
--  The companion column `lane` (migration 018) stays NULL on these rows rather than carrying 'unknown'.
--  batch_type is NOT NULL and needs a value; lane is nullable and NULL already means "not recorded", so
--  spelling it twice would add a word without adding a fact.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

SELECT pg_advisory_xact_lock(8017000021);

ALTER TABLE anchor_batches DROP CONSTRAINT IF EXISTS valid_batch_type;
ALTER TABLE anchor_batches ADD CONSTRAINT valid_batch_type
  CHECK (batch_type::text = ANY (ARRAY['on_cadence', 'on_demand', 'unknown']::text[]));

COMMENT ON COLUMN anchor_batches.batch_type IS
  'Which lane scheduled this batch: on_demand (one anchor per intent) or on_cadence (one per period). '
  '''unknown'' means the row was reconstructed from the chain, which does not record the lane — see '
  'migration 021. NOT NULL with a default of on_cadence, so a writer that omits it asserts a lane; the '
  'backfill sets unknown explicitly rather than inheriting that default.';

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('021_anchor_batch_type_unknown',
        'Permit batch_type unknown for anchor rows reconstructed from the chain',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
