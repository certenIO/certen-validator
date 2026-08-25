-- Stage 2 — put the governance proof into governance_proof_levels.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  governance_proof_levels did not contain the governance proof.
--
--  The rows in it were built from EVM observation results plus key-page thresholds. Measured against
--  production on 2026-08-25, the stored key set was:
--
--      inclusion_verified, finality_achieved, confirmations,
--      threshold_m, threshold_n, authority_url
--
--  Those are verdict flags about an EVM settlement. 0 of 401 G0 rows contained "entries"; 27 of 1,133
--  rows mentioned a receipt at all. The real G0Result/G1Result/G2Result existed the whole time, on
--  PendingAttestation (async_attestation.go), and died at the persistence boundary.
--
--  Two separate defects produced that, and they are worth naming because neither is obvious:
--
--    1. The legacy writer read ComprehensiveData["g0Proof"] — a key that is READ in exactly one place
--       and WRITTEN IN ZERO. The only writer in the tree emits "att.G0Proof". So the extracted value
--       was always the empty string and that function always took its stub fallback. The pipe was
--       never connected; polishing it would have changed nothing.
--    2. The production writer (unified_orchestrator, two separate call sites) never looked for the
--       G-results at all.
--
--  G1 is "did the RIGHT KEY PAGE authorize this". It is the product's central claim, and it was
--  persisted as threshold_met — a boolean with nothing behind it.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY THIS MIGRATION IS MOSTLY A COMMENT
--
--  level_json is already jsonb, so storing the result and its merkle path needed NO schema change —
--  the blocker was three writers that did not put them there. Same shape as 013: the migration exists
--  to RECORD THE INTENT, so the next reader of \d governance_proof_levels learns what the two new
--  keys mean rather than inferring it from data.
--
--  The two columns added below are PROJECTIONS, for querying. level_json is authoritative. If a
--  projection and level_json ever disagree, level_json is right and the projection is a bug — exactly
--  the rule 013 set for signature_count / threshold / signed_hash.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  THE TRAP THIS AVOIDED, STATED SO IT IS NOT RE-ENTERED
--
--  The obvious way to persist a receipt path is to add Entries to GovReceiptData. That struct is the
--  Receipt field of G0Result; G0Result is embedded in G1Result, which is embedded in G2Result; and all
--  three are hashed into the govRoot. CanonicalJSONMarshal is json.Marshal, so struct layout IS the
--  wire format. Widening it would move EVERY govRoot ever signed, and every already-signed TX2 on the
--  fleet commits to the current one.
--
--  So the evidence goes BESIDE the conclusion, under level_json."receipt", in a type
--  (GovReceiptEvidence) that no canonical hash can reach. Phase 6 proved the shape works: the L4 legs
--  went onto CompleteProof and the production govRoot e23ce107… did not move.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  ROWS WRITTEN BEFORE THIS ARE summary_only AND CANNOT BE REPAIRED
--
--  1,106 rows (measured 2026-08-25) carry no "receipt" key. Their merkle paths were never captured.
--  They are marked, not reconstructed: a receipt fetched from Accumulate today is not necessarily the
--  one the proof was built on, and re-coupling a stored artifact to live network state is the
--  governance-layer version of rebuilding a historical validator set. A synthesized record is worse
--  than an absent one, because the absent one is honest about what it does not know.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

ALTER TABLE governance_proof_levels
  ADD COLUMN IF NOT EXISTS receipt_entry_count integer,
  ADD COLUMN IF NOT EXISTS receipt_anchor      bytea;

COMMENT ON COLUMN governance_proof_levels.level_json IS
  'Verdict flags, PLUS the real G0/G1/G2 result under "result" and its receipt merkle path under '
  '"receipt". The flags (inclusion_verified, finality_achieved, threshold_m/n, authority_url, '
  'confirmations) are unchanged and still read by the evidence report and the approval console — the '
  'two new keys are ADDITIVE. Rows written before stage 2 have the flags only and are summary_only: '
  'their evidence was never captured and CANNOT be reconstructed.';

COMMENT ON COLUMN governance_proof_levels.receipt_entry_count IS
  'Number of merkle steps in level_json->''receipt''->''entries''. A projection for querying — '
  'level_json is the authoritative evidence and the only thing the offline recomputation reads. '
  'NULL means no receipt evidence was stored, i.e. this level is summary-only. Note that 0 is NOT the '
  'same as NULL: a zero-length path is legitimate for a single-leaf receipt, where the leaf IS the '
  'anchor, and that case verifies only because start == anchor.';

COMMENT ON COLUMN governance_proof_levels.receipt_anchor IS
  'The 32-byte anchor the receipt path must reach. A projection, never trusted: the recomputation '
  'reads the anchor out of level_json so the stored evidence is checked against itself rather than '
  'against a column an operator could edit independently.';

-- "Show me the levels that can actually be recomputed" is the question this stage creates, and it is
-- a jsonb key test over a table that is mostly historical. Partial, so it costs almost nothing.
CREATE INDEX IF NOT EXISTS idx_gov_levels_with_receipt
  ON governance_proof_levels (proof_id, gov_level)
  WHERE level_json ? 'receipt';

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('015_governance_receipt_evidence',
        'Store the real G0/G1/G2 result and its receipt merkle path in level_json, beside the flags',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
