-- Withdraw layer-5 rows that the database itself contradicts.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT 019 COULD NOT REACH
--
--  019 withdrew layer-5 rows whose root exists ONLY on a per-validator shadow row. That caught the
--  d2d24ab3 class, where the claimed root was a local artefact. It cannot catch a root that appears on no
--  anchor row at all.
--
--  One such row was produced live on 2026-09-16, in the window between the canonical writer shipping and
--  the layer-5 binding being keyed correctly. Intent 7758cbed:
--
--      canonical anchor row   root da4c331b…   published, quorum of 7, proofExecuted on base-sepolia
--      layer 5 says           root 1d096d72…   in tx 0x689003b9… — the SETTLEMENT transaction
--
--  The root 1d096d72… is on no anchor row, canonical or shadow, so 019's rule never fires. The layer-5
--  row is nonetheless false: the batch this intent was anchored in has a different root, and the
--  transaction named is the settlement, which published nothing.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  THE RULE, AND WHY IT IS THIS ONE
--
--  Withdraw a layer-5 row when the intent it belongs to HAS a canonical anchor row and the layer names a
--  DIFFERENT root. That is a contradiction inside this database: the canonical row is written from a
--  quorum the chain executed, so where the two disagree the layer is wrong.
--
--  The condition deliberately requires a canonical row to exist. The obvious wider rule — "withdraw any
--  layer 5 whose root no canonical row holds" — would withdraw every historical row that the chain
--  backfill has not reached yet, replacing one false claim with thousands. Silence about a row is not
--  evidence against it; a canonical row that says otherwise is.
--
--  Nothing is deleted, for the same reason as 019: a claim that was published and withdrawn must stay
--  readable. Readers filter on superseded_at IS NULL.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

SELECT pg_advisory_xact_lock(8017000020);

-- 019 introduced these; re-stated so 020 applies to a database that somehow has 019's data columns
-- without its DDL (a restore, a hand-repaired node).
ALTER TABLE chained_proof_layers ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;
ALTER TABLE chained_proof_layers ADD COLUMN IF NOT EXISTS superseded_reason TEXT;

WITH contradicted AS (
    SELECT DISTINCT cpl.layer_id,
           LEFT(encode(ab.merkle_root, 'hex'), 16) AS canonical_prefix
      FROM chained_proof_layers cpl
      JOIN proof_artifacts pa   ON pa.proof_id  = cpl.proof_id
      JOIN batch_transactions bt ON bt.intent_id = pa.intent_id
      JOIN anchor_batches ab     ON ab.id = bt.batch_id
     WHERE cpl.layer_number = 5
       AND cpl.superseded_at IS NULL
       AND cpl.layer_json ? 'batchRoot'
       AND ab.bundle_id IS NOT NULL
       AND LOWER(cpl.layer_json->>'batchRoot') <> encode(ab.merkle_root, 'hex')
)
UPDATE chained_proof_layers cpl
   SET superseded_at = NOW(),
       superseded_reason =
         'batchRoot ' || LEFT(LOWER(cpl.layer_json->>'batchRoot'), 16) || '… is not the root this '
         'intent was anchored under (' || c.canonical_prefix || '…, from the canonical anchor row the '
         'quorum wrote). The transaction named here published a different root. See migration 020.',
       verified = FALSE
  FROM contradicted c
 WHERE cpl.layer_id = c.layer_id;

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('020_supersede_layer5_contradicted_by_canonical',
        'Withdraw layer 5 rows naming a root other than the canonical anchor their intent was published in',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
