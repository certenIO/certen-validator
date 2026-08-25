-- Layer 4 — where the quorum evidence lives, so a stored proof can be checked.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  L4 is built, verified in flight, and committed into the governance root as L4ConsensusProofH.
--  What reached PostgreSQL was the CONCLUSION of the quorum check, never the evidence for it:
--
--    batch_transactions.chained_proof.consensus_proof   partition, threshold, sorted signers,
--                                                       signedHash, the two anchors — conclusions
--    governance_proof_levels.level_json                 threshold_m/n, inclusion_verified — verdicts
--    chained_proof_layers                               rows 1, 2 and 3. There was no row 4.
--
--  A verifier reading the database could recompute L1→L2→L3 and READ what L4 concluded, and could
--  not independently re-verify that a validator quorum ever signed anything. Measured directly
--  against the stored blob for proof b7a48634-733a-4999-84eb-06d2c84db112:
--  signature=f, validatorSet=f, publicKeyHash=f. Governance spec §4 — "a governance proof MUST be
--  verifiable offline" — was therefore unmet for L4 on the persisted artifact.
--
--  The summary is deliberately thin, and stays thin. It is the govRoot preimage, and
--  CanonicalJSONMarshal is json.Marshal, so its struct layout IS the wire format: widening it to
--  carry ~6 KB of signed bytes and validator keys would move every govRoot ever signed. The defect
--  was never the summary's narrowness — it was that the evidence had no second home. This migration
--  is that home.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY NO CHECK CONSTRAINT ON layer_number, AND WHY THIS MIGRATION IS MOSTLY A COMMENT
--
--  layer_number is already a plain integer and layer_json already jsonb, so writing layer 4 needed
--  no schema change at all — the blocker was a hardcoded `for layer := 1; layer <= 3` in two
--  orchestrators, not the table. This migration exists to RECORD THE INTENT, so the next reader of
--  \d chained_proof_layers learns that 4 is a quorum leg rather than inferring it from data.
--
--  A CHECK (layer_number BETWEEN 1 AND 4) is deliberately NOT added. It would reject a future L5 at
--  write time, in a table whose whole history is that a hardcoded upper bound silently truncated the
--  proof. layer_number 0 is also in use and must keep working: unified_orchestrator writes it to
--  record a FAILED L1-L3 generation attempt.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  THE THREE COLUMNS ARE FOR QUERYING. layer_json IS THE EVIDENCE.
--
--  signature_count / threshold / signed_hash exist so an operator can ask "show me proofs whose DN
--  leg had fewer than three signers" without unpacking jsonb on every row. They are a projection,
--  and a verifier must never trust them: the authoritative record is layer_json, which holds the
--  full chained_proof.Layer4 — sequencedMessage, signatures, validatorSet, acceptThreshold — and is
--  the only field the offline verifier reads. If the projection and layer_json ever disagree,
--  layer_json is right and the projection is a bug.
--
--  All three are NULLABLE and stay NULL on rows 1-3, which have no quorum. They are also NULL on
--  every row written before this migration, which is correct: those proofs have no layer-4 row at
--  all, and are marked verification_status = 'summary_only' rather than 'verified' precisely so that
--  "not verifiable from storage" is never read as "verified".
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

ALTER TABLE chained_proof_layers
  ADD COLUMN IF NOT EXISTS signature_count integer,
  ADD COLUMN IF NOT EXISTS threshold       integer,
  ADD COLUMN IF NOT EXISTS signed_hash     bytea;

COMMENT ON COLUMN chained_proof_layers.layer_number IS
  '1..3 state layers; 4 = quorum signature leg (one row per partition, BVN and DN). '
  '0 records a failed L1-L3 generation attempt. No CHECK constraint: a future L5 must not be '
  'rejected by this table, whose defect history is precisely a hardcoded upper bound.';

COMMENT ON COLUMN chained_proof_layers.signature_count IS
  'Layer 4 only: number of signatures carried in layer_json. A projection for querying — layer_json '
  'is the authoritative evidence and the only thing the offline verifier reads.';

COMMENT ON COLUMN chained_proof_layers.threshold IS
  'Layer 4 only: distinct valid signers required, recomputed by the verifier from acceptThreshold '
  'over the validators active on this partition. Stored for querying, never trusted.';

COMMENT ON COLUMN chained_proof_layers.signed_hash IS
  'Layer 4 only: the 32 bytes the validator quorum actually signed — the hash of the SequencedMessage '
  'wrapping the anchor transaction, NOT the transaction hash. The two differ; conflating them yields '
  'a well-formed digest that never verifies.';

-- The lookup this phase adds is "give me every layer of proof X, in order", issued once per proof by
-- ChainedProofFromStorage. proof_id alone is already indexed; including layer_number keeps the read
-- index-ordered so the reassembly does not sort.
CREATE INDEX IF NOT EXISTS idx_cpl_proof_layer
  ON chained_proof_layers (proof_id, layer_number);

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('013_layer4_persistence',
        'Persist the L4 quorum evidence so a stored proof verifies offline, not merely plausibly',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
