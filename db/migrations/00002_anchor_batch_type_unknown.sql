-- Let an anchor row say it does not know which lane produced it.
--
-- anchor_batches.batch_type is NOT NULL, constrained to ('on_cadence','on_demand'), and defaults to
-- 'on_cadence'. Every row the validator writes knows its lane, so that was always satisfiable.
--
-- A row reconstructed from the chain does not. The lane is a property of how this fleet SCHEDULED the
-- batch — one anchor per intent, or one per period — and neither executeComprehensiveProof's calldata nor
-- the anchor's stored state records it. A one-member batch is not evidence of the on-demand lane either:
-- a period can close with a single member.
--
-- So cmd/anchorquorumbackfill has three options and only one is honest:
--
--   omit the column   -> the DEFAULT applies and every backfilled row claims 'on_cadence'
--   guess from shape  -> a one-member period silently becomes 'on_demand'
--   say "not known"   -> this migration
--
-- The first two invent a fact to satisfy a constraint, which is the failure the anchor-quorum work exists
-- to remove: a column that reads as evidence while holding something nobody established. Caught when the
-- first -write run against production failed this constraint instead of writing 216 rows.
--
-- The companion column `lane` stays NULL on those rows rather than carrying 'unknown': it is nullable and
-- NULL already means "not recorded", so spelling it twice adds a word without adding a fact.
--
-- The constraint is replaced rather than widened in place, which is why this is marked destructive. It is
-- additive in effect: every value the old constraint accepted, the new one accepts.
-- schema: destructive-approved

ALTER TABLE public.anchor_batches DROP CONSTRAINT IF EXISTS valid_batch_type;

ALTER TABLE public.anchor_batches ADD CONSTRAINT valid_batch_type
    CHECK (((batch_type)::text = ANY ((ARRAY['on_cadence'::character varying, 'on_demand'::character varying, 'unknown'::character varying])::text[])));

COMMENT ON COLUMN public.anchor_batches.batch_type IS 'Which lane scheduled this batch: on_demand (one anchor per intent) or on_cadence (one per period). ''unknown'' means the row was reconstructed from the chain, which does not record the lane. NOT NULL with a default of on_cadence, so a writer that omits it asserts a lane; the backfill sets unknown explicitly rather than inheriting that default.';
