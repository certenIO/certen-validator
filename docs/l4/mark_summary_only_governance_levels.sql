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

-- Nor may any level have lost a flag the console reads. If this returns anything, roll back.
\echo '--- must be zero: marked levels that lost their verdict flags ---'
SELECT count(*) AS lost_flags
FROM governance_proof_levels
WHERE (level_json ? 'summary_only')
  AND NOT (level_json ? 'inclusion_verified')
  AND NOT (level_json ? 'threshold_met')
  AND NOT (level_json ? 'operation_commitment')
  AND NOT (level_json ? 'governance_root');

COMMIT;
