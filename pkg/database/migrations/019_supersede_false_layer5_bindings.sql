-- Mark the layer-5 rows that bind a root no anchor ever held.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  A layer-5 row says: "leaf L is under batch root R, and R was published in transaction T". Some rows
--  in production say that about a root that was never published, in a transaction that published a
--  different root. Live, on intent f6cea77e:
--
--      batchRoot  d2d24ab3…   a per-validator SHADOW row: sha256 over four pending blobs, computed
--                             locally by the retired batch pipeline and published nowhere
--      anchorTx   0x9e4ff6ab… the SETTLEMENT transaction, which moved value and published root
--                             2fd899ae… — a different root
--
--  Both halves were wrong, from two independent defects: the binding query took whatever anchor_batches
--  row it joined (shadow rows included, since nothing distinguished them), and the anchor transaction
--  was taken from the settlement observation rather than from the anchor that published the root.
--  Migration 018 and the canonical reader in layer5_binding.go close both going forward. This migration
--  is about the rows already written.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT THIS MIGRATION MARKS, AND WHAT IT DELIBERATELY DOES NOT
--
--  It marks a layer-5 row superseded when its batchRoot matches a SHADOW anchor row (bundle_id IS NULL)
--  and matches NO canonical one. That is exactly the d2d24ab3 class: a root whose only existence in this
--  database is a local artefact, so the claim cannot be true however the anchor transaction is read.
--
--  It does NOT touch a layer-5 row merely because no canonical row covers its root yet. Canonical rows
--  only begin at migration 018, and the backfill (cmd/anchorquorumbackfill) fills the history
--  afterwards; marking every not-yet-backfilled row false would replace one wrong claim with thousands.
--
--  Nothing is deleted. A superseded row keeps its layer_json exactly as written: it is the evidence of
--  what was published, and a claim that was made and withdrawn must remain readable. Readers are
--  expected to filter on superseded_at IS NULL.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

-- Concurrent validators run migrations at the same time; one lock makes this an ordinary serial step.
SELECT pg_advisory_xact_lock(8017000019);

ALTER TABLE chained_proof_layers ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;
ALTER TABLE chained_proof_layers ADD COLUMN IF NOT EXISTS superseded_reason TEXT;

COMMENT ON COLUMN chained_proof_layers.superseded_at IS
  'When this layer row was withdrawn as a claim. NULL means the row stands. A superseded row is kept '
  'verbatim: it is the evidence of what was published, and deleting it would erase the record of the '
  'claim rather than correct it. Readers presenting layer rows as current must filter superseded_at '
  'IS NULL.';

COMMENT ON COLUMN chained_proof_layers.superseded_reason IS
  'Why the row was withdrawn, in words an auditor can act on — not an error code.';

-- The rows whose root exists ONLY as a shadow artefact.
WITH shadow_roots AS (
    SELECT DISTINCT encode(ab.merkle_root, 'hex') AS root_hex
      FROM anchor_batches ab
     WHERE ab.bundle_id IS NULL
       AND ab.merkle_root IS NOT NULL
       AND octet_length(ab.merkle_root) = 32
),
canonical_roots AS (
    SELECT DISTINCT encode(ab.merkle_root, 'hex') AS root_hex
      FROM anchor_batches ab
     WHERE ab.bundle_id IS NOT NULL
       AND ab.merkle_root IS NOT NULL
)
UPDATE chained_proof_layers cpl
   SET superseded_at = NOW(),
       superseded_reason =
         'batchRoot ' || LEFT(LOWER(cpl.layer_json->>'batchRoot'), 16) || '… was never published: it '
         'exists only as a per-validator shadow row from the retired batch pipeline, so no transaction '
         'can contain it. See migration 019.',
       verified = FALSE
 WHERE cpl.layer_number = 5
   AND cpl.superseded_at IS NULL
   AND cpl.layer_json ? 'batchRoot'
   AND LOWER(cpl.layer_json->>'batchRoot') IN (SELECT root_hex FROM shadow_roots)
   AND LOWER(cpl.layer_json->>'batchRoot') NOT IN (SELECT root_hex FROM canonical_roots);

-- Finding these rows again is a one-off audit question, not a hot path, so the index is partial and
-- narrow: only the withdrawn rows.
CREATE INDEX IF NOT EXISTS idx_cpl_superseded ON chained_proof_layers (superseded_at)
  WHERE superseded_at IS NOT NULL;

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('019_supersede_false_layer5_bindings',
        'Withdraw layer 5 rows binding a root that only ever existed on a shadow anchor row',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
