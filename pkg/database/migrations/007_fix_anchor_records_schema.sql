-- Migration: 007_fix_anchor_records_schema.sql
-- Description: Fix anchor_records table schema to match repository code
-- Created: 2026-01-19
--
-- The original anchor_records table in 001_initial_schema.sql has a different
-- structure than what the repository_anchor.go code expects. This migration
-- recreates the table with the correct schema.
--
-- Key changes:
-- - Rename 'id' to 'anchor_id'
-- - Rename 'tx_hash' to 'anchor_tx_hash'
-- - Rename 'block_number' to 'anchor_block_number'
-- - Rename 'block_hash' to 'anchor_block_hash'
-- - Rename 'required_conf' to 'required_confirmations'
-- - Rename 'gas_price' to 'gas_price_wei'
-- - Change chain_id from BIGINT to VARCHAR
-- - Add missing columns: network_name, contract_address, anchor_timestamp,
--   merkle_root, accumulate_height, operation_commitment, cross_chain_commitment,
--   governance_root, confirmed_at, total_cost_wei, total_cost_usd, validator_id

BEGIN;

-- Step 1: Drop dependent objects (indexes, foreign keys)
DROP INDEX IF EXISTS idx_anchors_batch;
DROP INDEX IF EXISTS idx_anchors_tx_hash;
DROP INDEX IF EXISTS idx_anchors_status;
DROP INDEX IF EXISTS idx_anchors_chain;
DROP INDEX IF EXISTS idx_anchors_unconfirmed;

-- Step 2: Drop foreign key constraints that reference anchor_records
ALTER TABLE IF EXISTS certen_anchor_proofs DROP CONSTRAINT IF EXISTS certen_anchor_proofs_anchor_id_fkey;
ALTER TABLE IF EXISTS comprehensive_proofs DROP CONSTRAINT IF EXISTS comprehensive_proofs_anchor_id_fkey;
ALTER TABLE IF EXISTS proof_artifacts DROP CONSTRAINT IF EXISTS proof_artifacts_anchor_id_fkey;

-- Step 3: Rename old table for backup
ALTER TABLE IF EXISTS anchor_records RENAME TO anchor_records_old;

-- Step 4: Create new anchor_records table with correct schema
CREATE TABLE anchor_records (
    anchor_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id                UUID NOT NULL REFERENCES anchor_batches(id),
    target_chain            VARCHAR(50) NOT NULL,
    chain_id                VARCHAR(50),                 -- Changed from BIGINT to VARCHAR
    network_name            VARCHAR(50),                 -- NEW: e.g., 'mainnet', 'sepolia'
    contract_address        VARCHAR(66),                 -- NEW: Contract address
    anchor_tx_hash          VARCHAR(66) NOT NULL,        -- Renamed from tx_hash
    anchor_block_number     BIGINT NOT NULL,             -- Renamed from block_number
    anchor_block_hash       VARCHAR(66),                 -- Renamed from block_hash
    anchor_timestamp        TIMESTAMPTZ,                 -- NEW: Block timestamp
    merkle_root             VARCHAR(66),                 -- NEW: Merkle root anchored
    accumulate_height       BIGINT,                      -- NEW: Accumulate block height
    operation_commitment    VARCHAR(66),                 -- NEW: Operation commitment hash
    cross_chain_commitment  VARCHAR(66),                 -- NEW: Cross-chain commitment hash
    governance_root         VARCHAR(66),                 -- NEW: Governance proof root
    confirmations           INTEGER NOT NULL DEFAULT 0,
    required_confirmations  INTEGER NOT NULL DEFAULT 12, -- Renamed from required_conf
    confirmed_at            TIMESTAMPTZ,                 -- NEW: When confirmations met
    is_final                BOOLEAN NOT NULL DEFAULT FALSE,
    gas_used                BIGINT,
    gas_price_wei           VARCHAR(50),                 -- Renamed from gas_price
    total_cost_wei          VARCHAR(50),                 -- NEW: Total cost in wei
    total_cost_usd          NUMERIC(20, 8),              -- NEW: USD cost estimate
    validator_id            VARCHAR(256),                -- NEW: Validator that created anchor
    status                  VARCHAR(30) NOT NULL DEFAULT 'pending',
    error_message           TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at            TIMESTAMPTZ,

    CONSTRAINT valid_anchor_chain CHECK (target_chain IN ('ethereum', 'bitcoin', 'polygon', 'arbitrum')),
    CONSTRAINT valid_anchor_status CHECK (status IN ('pending', 'confirming', 'finalized', 'failed'))
);

-- Step 5: Migrate data from old table (if any exists)
INSERT INTO anchor_records (
    anchor_id,
    batch_id,
    target_chain,
    chain_id,
    anchor_tx_hash,
    anchor_block_number,
    anchor_block_hash,
    confirmations,
    required_confirmations,
    is_final,
    gas_used,
    gas_price_wei,
    status,
    error_message,
    created_at,
    updated_at,
    finalized_at
)
SELECT
    id,
    batch_id,
    target_chain,
    CAST(chain_id AS VARCHAR),
    tx_hash,
    block_number,
    block_hash,
    confirmations,
    required_conf,
    is_final,
    gas_used,
    gas_price,
    status,
    error_message,
    created_at,
    updated_at,
    finalized_at
FROM anchor_records_old;

-- Step 6: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_anchors_batch ON anchor_records(batch_id);
CREATE INDEX IF NOT EXISTS idx_anchors_tx_hash ON anchor_records(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_anchors_status ON anchor_records(status);
CREATE INDEX IF NOT EXISTS idx_anchors_chain ON anchor_records(target_chain);
CREATE INDEX IF NOT EXISTS idx_anchors_unconfirmed ON anchor_records(is_final, status)
    WHERE is_final = FALSE AND status NOT IN ('failed', 'finalized');
CREATE INDEX IF NOT EXISTS idx_anchors_validator ON anchor_records(validator_id);
CREATE INDEX IF NOT EXISTS idx_anchors_confirmations ON anchor_records(confirmations, required_confirmations)
    WHERE is_final = FALSE;

-- Step 7: Recreate foreign key constraints
ALTER TABLE certen_anchor_proofs
    ADD CONSTRAINT certen_anchor_proofs_anchor_id_fkey
    FOREIGN KEY (anchor_id) REFERENCES anchor_records(anchor_id);

-- Note: comprehensive_proofs and proof_artifacts FK only added if those tables exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'comprehensive_proofs') THEN
        ALTER TABLE comprehensive_proofs
            ADD CONSTRAINT comprehensive_proofs_anchor_id_fkey
            FOREIGN KEY (anchor_id) REFERENCES anchor_records(anchor_id);
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'proof_artifacts') THEN
        ALTER TABLE proof_artifacts
            ADD CONSTRAINT proof_artifacts_anchor_id_fkey
            FOREIGN KEY (anchor_id) REFERENCES anchor_records(anchor_id);
    END IF;
END $$;

-- Step 8: Drop old table (commented out for safety - uncomment after verification)
-- DROP TABLE IF EXISTS anchor_records_old;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('007', 'Fix anchor_records schema to match repository code', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
