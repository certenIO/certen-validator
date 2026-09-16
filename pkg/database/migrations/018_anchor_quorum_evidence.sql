-- Canonical anchor rows: the quorum that was actually proven on-chain.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  anchor_batches' Phase 5 columns were never written by any live path. Measured on the fleet:
--
--      anchor_batches                     70,236 rows all time (on_demand) + 852 (on_cadence)
--      ... with quorum_reached = true          0, ever
--      anchor_records                          0 rows, ever
--      consensus_entries joined to a batch     0 of 7,756 (they are keyed by SHA1(bundle_id), a
--                                              different thing: one validator's own single signature)
--
--  Three separate causes, all confirmed:
--
--   1. The only writer, ConsensusCoordinator, is never constructed — `NewConsensusCoordinator(` has no
--      caller outside tests. UpdateBatchPhase5 and MarkConsensusQuorumMet were dead code.
--   2. The rows that DO exist are per-validator shadow copies: collector.go inserts one per validator
--      with a random UUID (~8.6 per intent), over leaves computed as sha256(4 blobs) rather than the
--      on-chain keccak("certen:batchleaf:v1"…). Their roots are therefore never the roots that are
--      published, and the old anchoring path that would have used them fails every time.
--   3. The real quorum (e.g. "700 of 700 voting power from 7 signers") was computed in prove() and
--      discarded: it returned only `error`.
--
--  The visible damage: proofs_service reads COALESCE(ab.quorum_reached, FALSE), so every intent showed
--  batch_quorum_met = false, and the L5 binding picked the newest shadow row — publishing a binding that
--  says root d2d24ab3… is in tx 0x9e4ff6ab…, a transaction that settled root 2fd899ae….
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT THIS MIGRATION ADDS
--
--  The columns that identify an anchor the way the CONTRACT does — (chain_id, bundle_id) — plus the
--  evidence of the quorum over it. A canonical row is one with bundle_id IS NOT NULL; every pre-existing
--  row is labelled legacy_shadow and is never read as evidence again.
--
--  Additive only. The previous binary keeps inserting and reading its rows unchanged: every new column is
--  nullable, and the unique index covers only rows that carry a bundle_id.

-- Seven validators run MigrateUp at the same time on this database. Serialise the whole file (the lock is
-- released when MigrateUp's transaction ends): concurrent ADD COLUMN IF NOT EXISTS / CREATE INDEX can
-- still collide on the catalog, and a loser stops MigrateUp before any later migration. Same lock id as
-- 017, so the two cannot interleave either.
SELECT pg_advisory_xact_lock(8017000017);

ALTER TABLE anchor_batches
    ADD COLUMN IF NOT EXISTS chain_id            BIGINT,
    ADD COLUMN IF NOT EXISTS bundle_id           VARCHAR(80),
    ADD COLUMN IF NOT EXISTS batch_operation_id  VARCHAR(80),
    ADD COLUMN IF NOT EXISTS anchor_create_tx    VARCHAR(80),
    ADD COLUMN IF NOT EXISTS verify_tx           VARCHAR(80),
    ADD COLUMN IF NOT EXISTS verify_block        BIGINT,
    ADD COLUMN IF NOT EXISTS message_hash        VARCHAR(80),
    ADD COLUMN IF NOT EXISTS signed_voting_power NUMERIC(78, 0),
    ADD COLUMN IF NOT EXISTS total_voting_power  NUMERIC(78, 0),
    ADD COLUMN IF NOT EXISTS signers             JSONB,
    ADD COLUMN IF NOT EXISTS evidence_source     VARCHAR(32),
    ADD COLUMN IF NOT EXISTS lane                VARCHAR(16);

COMMENT ON COLUMN anchor_batches.bundle_id IS
    'The anchor''s own identifier on-chain (0x-hex, 32 bytes). NULL on legacy shadow rows, which were '
    'never published and must not be read as evidence.';
COMMENT ON COLUMN anchor_batches.evidence_source IS
    'live = written by the validator that proved the quorum; chain_backfill = reconstructed from the '
    'verify transaction and verified against the registry; legacy_shadow = pre-2026-09 per-validator row '
    'with no published root.';
COMMENT ON COLUMN anchor_batches.signers IS
    'JSON array of {address, voting_power} for the validators whose partials the aggregate covers — the '
    'set the anchor itself re-derives signedVotingPower from.';

-- One canonical row per (chain, bundle), whichever validator writes first. Partial, so the ~71k legacy
-- rows (bundle_id IS NULL) are untouched and unconstrained.
CREATE UNIQUE INDEX IF NOT EXISTS uq_anchor_batches_chain_bundle
    ON anchor_batches (chain_id, bundle_id)
    WHERE bundle_id IS NOT NULL;

-- Readers (L5 binding, proofs_service) filter to canonical rows; this keeps that cheap.
CREATE INDEX IF NOT EXISTS idx_anchor_batches_canonical
    ON anchor_batches (bundle_id)
    WHERE bundle_id IS NOT NULL;

-- Label what is already there. These rows are real history — they record that a validator collected an
-- intent into a batch — but they are not evidence of a published anchor, and nothing may promote them.
UPDATE anchor_batches SET evidence_source = 'legacy_shadow'
 WHERE evidence_source IS NULL AND bundle_id IS NULL;

-- Per-signer attestation rows for a canonical anchor. bls_signature becomes nullable because a backfilled
-- signer is known from the aggregate's validatorAddresses without its individual partial, which was never
-- stored; the aggregate itself is on the anchor row and is what verifies.
ALTER TABLE batch_attestations
    ADD COLUMN IF NOT EXISTS evm_address  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS voting_power NUMERIC(78, 0);

ALTER TABLE batch_attestations
    ALTER COLUMN bls_signature DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ba_evm_address ON batch_attestations (evm_address);

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('018_anchor_quorum_evidence',
        'Identify anchors by (chain_id, bundle_id) and record the quorum evidence proven on-chain',
        NOW())
ON CONFLICT (version) DO NOTHING;
