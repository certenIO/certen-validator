-- Stage 3 — L5-lite: bind a proof to the batch that was anchored on an external chain.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  The external anchor coordinates were stored and nothing verified them, and nothing proved that THIS
--  proof was in THAT anchored batch. Measured against production, 2026-08-25:
--
--      batch_transactions.merkle_path      70,253 / 70,253   the leaf -> batch-root path
--      batch_transactions.tree_index       70,253 / 70,253   the leaf index
--      anchor_batches.merkle_root          67,847 / 67,847   the batch root
--      proof_artifacts.anchor_tx_hash         410 / 418      external coordinates
--      proof_artifacts.batch_id                 0 / 418      MISSING: proof -> batch
--      proof_artifacts.merkle_path              0 / 418      MISSING: per-proof path
--      anchor_batches.anchor_tx_hash            0 / 67,847   MISSING: batch -> external tx
--      certen_anchor_proofs                     0 rows       the L5 slot, empty
--
--  Every missing item is a JOIN, not a missing measurement. The path was computed, stored under the
--  batch, and never connected to the proof. So the database could say "we have a tx hash somewhere"
--  and could not say "here is the path proving this proof is in that anchored batch".
--
--  certen_anchor_proofs was in exactly the state chained_proof_layers layer 4 was in before Phase 6:
--  a slot with the right shape and nothing in it.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT L5 DOES AND DOES NOT ESTABLISH — SAY THIS PLAINLY TO ANYONE WHO ASKS
--
--  L5 DOES NOT ADD A SECURITY PROPERTY. CERTEN already anchors the govRoot externally on every intent
--  (createBatchAnchor on base-sepolia), so the immutability/timestamp property ALREADY EXISTS. L5
--  makes it CHECKABLE.
--
--  The offline half is leaf -> batch root, and it is real: recomputed through pkg/merkle, network
--  disabled, empty path accepted ONLY when the leaf IS the root. The step from batch root to external
--  chain is COORDINATES plus an optional online check, and is never claimed as offline — proving that
--  offline needs a light client for the target chain, and "offline" stops meaning anything once you
--  must trust a block header handed to you from somewhere.
--
--  L5 DOES NOT establish that the Accumulate validator set which signed L4 is the legitimate one.
--  Nothing in this work does. An external timestamp attests to WHATEVER WAS SIGNED; it says nothing
--  about whether the signers were the right ones. Closing that needs an Accumulate validator-set
--  history rooted at genesis, and no part of this touches it.
--
--  Accumulate does NOT anchor into Bitcoin or Ethereum. Verified: every anchor type in
--  accumulate-core/protocol/types_gen.go is internal (BlockValidatorAnchor, DirectoryAnchor,
--  PartitionAnchor, AnchorLedger), and AnchorLedger.MajorBlockIndex is Accumulate's own periodic
--  checkpoint, not a publication elsewhere. L5 does not consume it and is not waiting for it.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  L5 IS NOT IN THE govROOT, AND STRUCTURALLY CANNOT BE
--
--  ComputeAccumulateGovRoot is a fixed ten-slot, 352-byte preimage and the EVM contract agrees with
--  it, so an eleventh slot is a contract change plus an atomic fleet upgrade. But the deeper reason is
--  ORDERING: L5 describes the anchoring of a govRoot that must ALREADY EXIST before the anchor can be
--  written. It cannot be inside what it describes. L5 is storage and read-path only, which is exactly
--  why this migration needs no fleet coordination.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  NO SCHEMA CHANGE, AGAIN
--
--  layer_number is a plain integer and 013 deliberately added NO CHECK on it, precisely so a future L5
--  would not be rejected by a table whose whole defect history is a hardcoded upper bound. That
--  decision is what makes this migration a comment and an index rather than an ALTER.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

COMMENT ON COLUMN chained_proof_layers.layer_number IS
  '1..3 state layers; 4 = quorum signature leg (one row per partition, BVN and DN); '
  '5 = external anchor binding (leaf -> batch root -> external chain tx). 0 records a failed L1-L3 '
  'attempt. No CHECK constraint: a future L6 must not be rejected by this table, whose defect history '
  'is precisely a hardcoded upper bound. Layer 5 is NOT committed to by the govRoot and structurally '
  'cannot be — it describes the anchoring of a govRoot that must already exist before the anchor is '
  'written.';

COMMENT ON COLUMN proof_artifacts.batch_id IS
  'The anchor_batches row whose merkle root covers this proof''s leaf. NULL on every row written '
  'before stage 3, and on proofs that settled outside the batch path — those are one-member trees '
  'whose root IS their leaf. The join, not the evidence: chained_proof_layers layer 5 carries the '
  'path and is what the offline recomputation reads.';

COMMENT ON COLUMN proof_artifacts.merkle_path IS
  'This proof''s leaf -> batch-root path, copied from batch_transactions.merkle_path so the proof can '
  'be read without a join. A projection for querying and display — layer 5''s layer_json is '
  'authoritative. NULL means no path was recorded; an empty ARRAY means the path IS empty, i.e. the '
  'leaf is the root. Those are different facts and must not be conflated: an empty path that is '
  'accepted without leaf == root makes every proof verify vacuously.';

COMMENT ON COLUMN anchor_batches.anchor_tx_hash IS
  'The external-chain transaction that published this batch''s merkle_root. NULL on every row written '
  'before stage 3. Without it the batch root is a number nobody can point at a chain, and the L5 claim '
  'degenerates to "this leaf is under some root". Written once and never overwritten: a second, '
  'different hash means a re-anchor or a bug, and replacing the first would erase the evidence needed '
  'to tell which.';

-- The lookup stage 3 adds is "give me the batch this proof belongs to", issued once per proof.
-- Partial, because it is NULL on every historical row and stays NULL for single-leaf settlements.
CREATE INDEX IF NOT EXISTS idx_pa_batch_id ON proof_artifacts (batch_id)
  WHERE batch_id IS NOT NULL;

-- And its inverse, "which batches have actually been anchored" — the question that could not be
-- asked at all while the column was empty.
CREATE INDEX IF NOT EXISTS idx_ab_anchor_tx ON anchor_batches (anchor_tx_hash)
  WHERE anchor_tx_hash IS NOT NULL;

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('016_layer5_external_anchor',
        'Record layer 5 as the external anchor binding and join proofs to the batches that were anchored',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
