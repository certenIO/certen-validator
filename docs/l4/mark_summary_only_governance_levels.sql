-- Mark the governance levels whose receipt merkle path was never persisted.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT THIS FIXES, AND WHAT IT DELIBERATELY DOES NOT
--
--  Before Stage 2, governance_proof_levels stored the CONCLUSION of the governance check and none of
--  the evidence for it. Worse than the L4 case, it did not even store the conclusion in its own shape:
--  the rows held verdict flags about an EVM settlement (inclusion_verified, finality_achieved,
--  threshold_m/n, authority_url, confirmations) plus, for G1, a bare threshold_met boolean. The real
--  G0Result/G1Result/G2Result never reached the database at all.
--
--  Those levels are not WRONG. The governance proof was generated in flight and the govRoot commits to
--  its canonical hash, so the fleet checked what it says it checked. They are simply not re-checkable
--  by anyone reading the database — which is a weaker claim than 'verified' has been used to mean.
--
--  Left with verified = true, a level whose evidence was never stored is indistinguishable from one
--  that was recomputed from storage. This marks the difference so that 'verified' keeps meaning one
--  thing. It is the same marking the 402 summary_only proofs got, one layer up.
--
--  IT DOES NOT RECONSTRUCT THE MISSING EVIDENCE, AND NO SCRIPT EVER SHOULD.
--
--  The temptation is obvious: the receipt is still queryable from Accumulate, so why not fetch it and
--  fill in the path? Because the receipt fetched today is not necessarily the one the proof was built
--  on. An anchor advances; a chain entry's receipt is relative to the anchor in force when it was
--  taken. Re-coupling a stored artifact to live network state is the governance-layer version of
--  rebuilding a historical validator set, and it produces a record that LOOKS checkable and attests to
--  something nobody verified. A synthesized record is worse than an absent one, because the absent one
--  is honest about what it does not know.
--
--  Idempotent, and self-limiting: it only ever touches rows with no 'receipt' key in level_json, so
--  levels written after Stage 2 are never marked, and re-running it after new proofs land is safe.
--
--  MEASURED 2026-08-25, production:
--    1,133 governance levels total (401 G0 / 366 G1 / 366 G2)
--    1,106 carry no 'receipt' key           <- these are marked
--       27 already carry one from some other path
--  Note 401 + 366 + 366 = 1,133 = 1,106 + 27. Count first and reconcile; never assume.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

-- ── STEP 1: COUNT FIRST. Run this alone and record the numbers before running the UPDATE. ──────────
\echo '--- levels that will be marked summary-only (no receipt evidence) ---'
SELECT count(*) AS will_mark
FROM governance_proof_levels
WHERE NOT (level_json ? 'receipt');

\echo '--- reconciliation: total, with receipt, without ---'
SELECT count(*) AS total,
       count(*) FILTER (WHERE level_json ? 'receipt')       AS with_receipt,
       count(*) FILTER (WHERE NOT (level_json ? 'receipt')) AS without_receipt
FROM governance_proof_levels;

\echo '--- current distribution by level and verified flag ---'
SELECT gov_level, verified, count(*) FROM governance_proof_levels GROUP BY 1, 2 ORDER BY 1, 2;

-- ── STEP 2: THE MARKING. ───────────────────────────────────────────────────────────────────────────
--
-- verified = false is the honest value for a level that cannot be recomputed from storage. It does
-- NOT mean the governance check failed — nothing was checked and nothing was found wrong — and the
-- reason is recorded in level_json.summary_only_reason so that distinction survives in the row itself
-- rather than only in this file.
--
-- ADDITIVE, as everything in Stage 2 is: jsonb || adds two keys and leaves every existing key alone.
-- The evidence report and the approval console read inclusion_verified, finality_achieved,
-- threshold_m/n, authority_url and confirmations, and keep reading exactly what they read before.
BEGIN;

UPDATE governance_proof_levels
SET verified   = false,
    level_json = COALESCE(level_json, '{}'::jsonb) || jsonb_build_object(
        'summary_only', true,
        'summary_only_reason',
        'No receipt merkle path was persisted for this level, so it cannot be recomputed offline. '
        'This is NOT a verification failure: the governance proof was generated and checked in flight '
        'and the govRoot commits to its canonical hash. The evidence was never captured and CANNOT be '
        'reconstructed — a receipt fetched today is not necessarily the one this proof was built on.'
    )
WHERE NOT (level_json ? 'receipt');

\echo '--- distribution after marking ---'
SELECT gov_level, verified, count(*) FROM governance_proof_levels GROUP BY 1, 2 ORDER BY 1, 2;

-- No level that HAS receipt evidence may have been marked. If this returns anything, roll back.
\echo '--- must be zero: levels with receipt evidence wrongly marked summary-only ---'
SELECT count(*) AS wrongly_marked
FROM governance_proof_levels
WHERE (level_json ? 'receipt') AND (level_json ? 'summary_only');

-- Nor may any level have lost what it already carried. If this returns anything, roll back.
--
-- The check is "does the row still have keys OTHER than the two markers", NOT "does it have one of
-- four specific flags". An earlier version asked the narrower question and reported 11 rows, which
-- read like data loss and was not: those rows come from two other writer paths and never carried any
-- of the four flags to begin with — the legacy stub writes level/name/verified/block_height/
-- finality_time, and a backfill path writes G2-specific keys (payload_verified, effect_verified,
-- outcome_binding, security_level, g2_proof_complete). Both are intact.
--
-- The marking cannot lose a key by construction: jsonb || only ADDS or overwrites the keys named on
-- its right-hand side, and no row carried summary_only or summary_only_reason before this ran.
\echo '--- must be zero: marked levels left with nothing but the two markers ---'
SELECT count(*) AS lost_everything
FROM governance_proof_levels
WHERE (level_json ? 'summary_only')
  AND (SELECT count(*) FROM jsonb_object_keys(level_json)) <= 2;

\echo '--- key counts on marked rows (min must be > 2: two markers plus what was there) ---'
SELECT gov_level, count(*) AS rows,
       min((SELECT count(*) FROM jsonb_object_keys(level_json))) AS min_keys,
       max((SELECT count(*) FROM jsonb_object_keys(level_json))) AS max_keys
FROM governance_proof_levels
WHERE level_json ? 'summary_only'
GROUP BY 1 ORDER BY 1;

COMMIT;
