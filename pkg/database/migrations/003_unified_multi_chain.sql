-- Copyright 2025 Certen Protocol
--
-- Migration 003: Unified Multi-Chain Architecture
-- Adds support for multiple attestation schemes and chain platforms
--
-- This migration is IDEMPOTENT - safe to run multiple times
-- Handles both fresh installs and partial previous runs
--
-- Per Unified Multi-Chain Architecture:
-- - Unified attestations table (scheme-agnostic)
-- - Aggregated attestations table
-- - Chain execution results table
-- - Updates to proof_artifacts table

-- =============================================================================
-- ADD COLUMNS TO EXISTING TABLES
-- =============================================================================

-- Add attestation scheme and chain platform to proof_artifacts
ALTER TABLE proof_artifacts
    ADD COLUMN IF NOT EXISTS attestation_scheme VARCHAR(32) DEFAULT 'ed25519';
ALTER TABLE proof_artifacts
    ADD COLUMN IF NOT EXISTS chain_platform VARCHAR(32) DEFAULT 'evm';
ALTER TABLE proof_artifacts
    ADD COLUMN IF NOT EXISTS target_chain VARCHAR(64);

-- Add unified tracking columns
ALTER TABLE proof_artifacts
    ADD COLUMN IF NOT EXISTS unified_attestation_id UUID;
ALTER TABLE proof_artifacts
    ADD COLUMN IF NOT EXISTS chain_execution_id UUID;

-- =============================================================================
-- UNIFIED ATTESTATIONS TABLE
-- =============================================================================

-- Create unified_attestations if not exists
CREATE TABLE IF NOT EXISTS unified_attestations (
    attestation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID,
    cycle_id VARCHAR(255) NOT NULL,
    scheme VARCHAR(32) NOT NULL,
    validator_id VARCHAR(255) NOT NULL,
    validator_index INT,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    message_hash BYTEA NOT NULL,
    weight BIGINT DEFAULT 1,
    signature_valid BOOLEAN,
    verified_at TIMESTAMPTZ,
    verification_notes TEXT,
    attested_block_number BIGINT,
    attested_block_hash BYTEA,
    attested_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure all columns exist (for upgrades from older versions)
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS proof_id UUID;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS cycle_id VARCHAR(255);
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS scheme VARCHAR(32);
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS validator_id VARCHAR(255);
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS validator_index INT;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS public_key BYTEA;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS signature BYTEA;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS message_hash BYTEA;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS weight BIGINT DEFAULT 1;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS signature_valid BOOLEAN;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS verification_notes TEXT;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS attested_block_number BIGINT;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS attested_block_hash BYTEA;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS attested_at TIMESTAMPTZ;
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE unified_attestations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Add foreign key if not exists (safe: referencing existing proof_artifacts)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'unified_attestations_proof_id_fkey'
    ) THEN
        ALTER TABLE unified_attestations
            ADD CONSTRAINT unified_attestations_proof_id_fkey
            FOREIGN KEY (proof_id) REFERENCES proof_artifacts(proof_id);
    END IF;
END $$;

-- Add unique constraint if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'unified_attestations_proof_id_validator_id_scheme_key'
    ) THEN
        ALTER TABLE unified_attestations
            ADD CONSTRAINT unified_attestations_proof_id_validator_id_scheme_key
            UNIQUE (proof_id, validator_id, scheme);
    END IF;
EXCEPTION
    WHEN duplicate_table THEN NULL;
END $$;

-- =============================================================================
-- AGGREGATED ATTESTATIONS TABLE
-- =============================================================================

-- Create aggregated_attestations if not exists
CREATE TABLE IF NOT EXISTS aggregated_attestations (
    aggregation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID,
    cycle_id VARCHAR(255) NOT NULL,
    scheme VARCHAR(32) NOT NULL,
    message_hash BYTEA NOT NULL,
    aggregated_signature BYTEA,
    aggregated_public_key BYTEA,
    participant_ids JSONB NOT NULL,
    participant_count INT NOT NULL,
    validator_bitfield BYTEA,
    total_weight BIGINT NOT NULL,
    achieved_weight BIGINT NOT NULL,
    threshold_weight BIGINT NOT NULL,
    threshold_met BOOLEAN NOT NULL,
    threshold_numerator INT DEFAULT 2,
    threshold_denominator INT DEFAULT 3,
    aggregation_valid BOOLEAN,
    verified_at TIMESTAMPTZ,
    verification_notes TEXT,
    attestation_ids JSONB,
    first_attestation_at TIMESTAMPTZ,
    last_attestation_at TIMESTAMPTZ,
    aggregated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure all columns exist (for upgrades from older versions)
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS proof_id UUID;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS cycle_id VARCHAR(255);
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS scheme VARCHAR(32);
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS message_hash BYTEA;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS aggregated_signature BYTEA;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS aggregated_public_key BYTEA;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS participant_ids JSONB;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS participant_count INT;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS validator_bitfield BYTEA;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS total_weight BIGINT;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS achieved_weight BIGINT;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS threshold_weight BIGINT;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS threshold_met BOOLEAN;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS threshold_numerator INT DEFAULT 2;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS threshold_denominator INT DEFAULT 3;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS aggregation_valid BOOLEAN;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS verification_notes TEXT;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS attestation_ids JSONB;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS first_attestation_at TIMESTAMPTZ;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS last_attestation_at TIMESTAMPTZ;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS aggregated_at TIMESTAMPTZ;
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE aggregated_attestations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Add foreign key if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'aggregated_attestations_proof_id_fkey'
    ) THEN
        ALTER TABLE aggregated_attestations
            ADD CONSTRAINT aggregated_attestations_proof_id_fkey
            FOREIGN KEY (proof_id) REFERENCES proof_artifacts(proof_id);
    END IF;
END $$;

-- Add unique constraint if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'aggregated_attestations_proof_id_scheme_key'
    ) THEN
        ALTER TABLE aggregated_attestations
            ADD CONSTRAINT aggregated_attestations_proof_id_scheme_key
            UNIQUE (proof_id, scheme);
    END IF;
EXCEPTION
    WHEN duplicate_table THEN NULL;
END $$;

-- =============================================================================
-- CHAIN EXECUTION RESULTS TABLE
-- =============================================================================

-- Create chain_execution_results if not exists
CREATE TABLE IF NOT EXISTS chain_execution_results (
    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID,
    cycle_id VARCHAR(255) NOT NULL,
    chain_platform VARCHAR(32) NOT NULL,
    chain_id VARCHAR(64) NOT NULL,
    network_name VARCHAR(64),
    tx_hash VARCHAR(128) NOT NULL,
    block_number BIGINT,
    block_hash VARCHAR(128),
    block_timestamp TIMESTAMPTZ,
    status SMALLINT NOT NULL DEFAULT 0,
    gas_used BIGINT,
    gas_cost VARCHAR(78),
    confirmations INT DEFAULT 0,
    required_confirmations INT,
    is_finalized BOOLEAN DEFAULT FALSE,
    result_hash BYTEA,
    merkle_proof BYTEA,
    receipt_proof BYTEA,
    state_root BYTEA,
    transactions_root BYTEA,
    receipts_root BYTEA,
    raw_receipt JSONB,
    logs JSONB,
    platform_data JSONB,
    observer_validator_id VARCHAR(255),
    workflow_step SMALLINT,
    anchor_id BYTEA,
    submitted_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    finalized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure all columns exist (for upgrades from older versions)
-- This is the CRITICAL section - ensures anchor_id exists before index creation
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS proof_id UUID;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS cycle_id VARCHAR(255);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS chain_platform VARCHAR(32);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS chain_id VARCHAR(64);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS network_name VARCHAR(64);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(128);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS block_number BIGINT;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS block_hash VARCHAR(128);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS block_timestamp TIMESTAMPTZ;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS status SMALLINT DEFAULT 0;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS gas_used BIGINT;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS gas_cost VARCHAR(78);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS confirmations INT DEFAULT 0;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS required_confirmations INT;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS is_finalized BOOLEAN DEFAULT FALSE;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS result_hash BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS merkle_proof BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS receipt_proof BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS state_root BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS transactions_root BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS receipts_root BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS raw_receipt JSONB;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS logs JSONB;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS platform_data JSONB;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS observer_validator_id VARCHAR(255);
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS workflow_step SMALLINT;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS anchor_id BYTEA;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ;
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE chain_execution_results ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Add foreign key if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'chain_execution_results_proof_id_fkey'
    ) THEN
        ALTER TABLE chain_execution_results
            ADD CONSTRAINT chain_execution_results_proof_id_fkey
            FOREIGN KEY (proof_id) REFERENCES proof_artifacts(proof_id);
    END IF;
END $$;

-- Add unique constraint if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'chain_execution_results_chain_id_tx_hash_key'
    ) THEN
        ALTER TABLE chain_execution_results
            ADD CONSTRAINT chain_execution_results_chain_id_tx_hash_key
            UNIQUE (chain_id, tx_hash);
    END IF;
EXCEPTION
    WHEN duplicate_table THEN NULL;
END $$;

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- Note: All columns MUST exist before creating indexes
-- =============================================================================

-- Unified attestations indexes
CREATE INDEX IF NOT EXISTS idx_unified_attestations_proof
    ON unified_attestations(proof_id);
CREATE INDEX IF NOT EXISTS idx_unified_attestations_scheme
    ON unified_attestations(scheme);
CREATE INDEX IF NOT EXISTS idx_unified_attestations_validator
    ON unified_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_unified_attestations_cycle
    ON unified_attestations(cycle_id);
CREATE INDEX IF NOT EXISTS idx_unified_attestations_created
    ON unified_attestations(created_at DESC);

-- Aggregated attestations indexes
CREATE INDEX IF NOT EXISTS idx_aggregated_attestations_proof
    ON aggregated_attestations(proof_id);
CREATE INDEX IF NOT EXISTS idx_aggregated_attestations_scheme
    ON aggregated_attestations(scheme);
CREATE INDEX IF NOT EXISTS idx_aggregated_attestations_cycle
    ON aggregated_attestations(cycle_id);
CREATE INDEX IF NOT EXISTS idx_aggregated_attestations_threshold
    ON aggregated_attestations(threshold_met);

-- Chain execution results indexes
CREATE INDEX IF NOT EXISTS idx_chain_execution_proof
    ON chain_execution_results(proof_id);
CREATE INDEX IF NOT EXISTS idx_chain_execution_chain
    ON chain_execution_results(chain_id, tx_hash);
CREATE INDEX IF NOT EXISTS idx_chain_execution_platform
    ON chain_execution_results(chain_platform);
CREATE INDEX IF NOT EXISTS idx_chain_execution_status
    ON chain_execution_results(status);
CREATE INDEX IF NOT EXISTS idx_chain_execution_finalized
    ON chain_execution_results(is_finalized);
CREATE INDEX IF NOT EXISTS idx_chain_execution_cycle
    ON chain_execution_results(cycle_id);
CREATE INDEX IF NOT EXISTS idx_chain_execution_anchor
    ON chain_execution_results(anchor_id);

-- Proof artifacts new column indexes
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_attestation_scheme
    ON proof_artifacts(attestation_scheme);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_chain_platform
    ON proof_artifacts(chain_platform);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_target_chain
    ON proof_artifacts(target_chain);

-- =============================================================================
-- UPDATE TRIGGER FOR TIMESTAMPS
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for auto-updating timestamps
DROP TRIGGER IF EXISTS update_unified_attestations_updated_at ON unified_attestations;
CREATE TRIGGER update_unified_attestations_updated_at
    BEFORE UPDATE ON unified_attestations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_aggregated_attestations_updated_at ON aggregated_attestations;
CREATE TRIGGER update_aggregated_attestations_updated_at
    BEFORE UPDATE ON aggregated_attestations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_chain_execution_results_updated_at ON chain_execution_results;
CREATE TRIGGER update_chain_execution_results_updated_at
    BEFORE UPDATE ON chain_execution_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- VIEWS FOR COMMON QUERIES
-- =============================================================================

-- View: Proof artifacts with attestation summary
CREATE OR REPLACE VIEW v_proof_with_attestations AS
SELECT
    pa.proof_id,
    pa.intent_id,
    pa.proof_type,
    pa.proof_class,
    pa.attestation_scheme,
    pa.chain_platform,
    pa.target_chain,
    pa.status,
    pa.created_at,
    aa.aggregation_id,
    aa.participant_count,
    aa.achieved_weight,
    aa.threshold_weight,
    aa.threshold_met,
    aa.aggregation_valid,
    cer.result_id AS execution_result_id,
    cer.tx_hash AS anchor_tx_hash,
    cer.is_finalized AS anchor_finalized
FROM proof_artifacts pa
LEFT JOIN aggregated_attestations aa ON pa.proof_id = aa.proof_id
LEFT JOIN chain_execution_results cer ON pa.proof_id = cer.proof_id AND cer.workflow_step = 1;

-- View: Attestation statistics by scheme
CREATE OR REPLACE VIEW v_attestation_stats AS
SELECT
    scheme,
    COUNT(*) AS total_attestations,
    COUNT(DISTINCT validator_id) AS unique_validators,
    COUNT(CASE WHEN signature_valid THEN 1 END) AS valid_signatures,
    AVG(weight)::DECIMAL(10,2) AS avg_weight,
    MIN(attested_at) AS first_attestation,
    MAX(attested_at) AS latest_attestation
FROM unified_attestations
GROUP BY scheme;

-- View: Chain execution statistics
CREATE OR REPLACE VIEW v_chain_execution_stats AS
SELECT
    chain_platform,
    chain_id,
    network_name,
    COUNT(*) AS total_executions,
    COUNT(CASE WHEN status = 1 THEN 1 END) AS successful,
    COUNT(CASE WHEN status = 2 THEN 1 END) AS failed,
    COUNT(CASE WHEN is_finalized THEN 1 END) AS finalized,
    AVG(gas_used)::BIGINT AS avg_gas_used,
    AVG(confirmations)::INT AS avg_confirmations
FROM chain_execution_results
GROUP BY chain_platform, chain_id, network_name;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE unified_attestations IS
    'Stores individual validator attestations across all cryptographic schemes (BLS, Ed25519, etc.)';

COMMENT ON TABLE aggregated_attestations IS
    'Stores aggregated/collected attestations after quorum threshold is reached';

COMMENT ON TABLE chain_execution_results IS
    'Stores results of anchor operations across all supported blockchain platforms';

COMMENT ON COLUMN unified_attestations.scheme IS
    'Cryptographic scheme: bls12-381, ed25519, schnorr, threshold';

COMMENT ON COLUMN chain_execution_results.chain_platform IS
    'Blockchain platform: evm, cosmwasm, solana, move, ton, near';

COMMENT ON COLUMN chain_execution_results.workflow_step IS
    'Anchor workflow step: 1=create, 2=verify, 3=governance';
