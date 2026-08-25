-- Mark the proofs whose L4 quorum evidence was never persisted.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT THIS FIXES, AND WHAT IT DELIBERATELY DOES NOT
--
--  Before Phase 6, every proof stored the CONCLUSION of the L4 quorum check and none of the evidence
--  for it. Those proofs are not wrong: the quorum was checked in flight and the governance root
--  commits to its conclusion. They are simply not re-checkable by anyone reading the database, which
--  is a weaker claim than 'verified' has been used to mean.
--
--  Left as 'verified', a proof whose evidence was never stored is indistinguishable from one that was
--  re-verified from storage. This marks the difference so that 'verified' keeps meaning one thing.
--
--  It does NOT reconstruct the missing evidence, and no script ever should. SequencedMessage and the
--  historical validator set are not recoverable from what was kept, and re-querying Accumulate returns
--  TODAY's validator set, not the one that signed. A proof "repaired" that way would carry a quorum
--  that never existed — a fabricated quorum in an audit record is worse than an absent one, because
--  the absent one is at least honest about what it does not know.
--
--  Idempotent, and self-limiting: it only ever touches rows that have no layer-4 row, so proofs
--  written after Phase 6 are never marked, and re-running it after a later backfill is safe.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

-- ── STEP 1: COUNT FIRST. Run this alone and record the number before running the UPDATE. ───────────
\echo '--- proofs that will be marked summary_only ---'
SELECT count(*) AS will_mark
FROM proof_artifacts
WHERE proof_id NOT IN (SELECT DISTINCT proof_id FROM chained_proof_layers WHERE layer_number = 4)
  AND verification_status = 'verified';

\echo '--- current distribution ---'
SELECT verification_status, count(*) FROM proof_artifacts GROUP BY 1 ORDER BY 1;

-- ── STEP 2: THE MARKING. ───────────────────────────────────────────────────────────────────────────
BEGIN;

UPDATE proof_artifacts
SET verification_status = 'summary_only'
WHERE proof_id NOT IN (SELECT DISTINCT proof_id FROM chained_proof_layers WHERE layer_number = 4)
  AND verification_status = 'verified';

\echo '--- distribution after marking ---'
SELECT verification_status, count(*) FROM proof_artifacts GROUP BY 1 ORDER BY 1;

-- No proof that HAS layer-4 evidence may have been marked. If this returns anything, roll back.
\echo '--- must be zero: proofs with L4 evidence wrongly marked summary_only ---'
SELECT count(*) AS wrongly_marked
FROM proof_artifacts pa
WHERE pa.verification_status = 'summary_only'
  AND EXISTS (SELECT 1 FROM chained_proof_layers c WHERE c.proof_id = pa.proof_id AND c.layer_number = 4);

COMMIT;
