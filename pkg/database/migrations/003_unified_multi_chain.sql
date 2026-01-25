-- Copyright 2025 Certen Protocol
--
-- Migration 003: Unified Multi-Chain Architecture
-- Adds support for multiple attestation schemes and chain platforms
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

-- Unified attestations table (scheme-agnostic)
-- Stores individual validator attestations regardless of cryptographic scheme
CREATE TABLE IF NOT EXISTS unified_attestations (
    attestation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),
    cycle_id VARCHAR(255) NOT NULL,

    -- Attestation scheme (bls12-381, ed25519, schnorr, threshold)
    scheme VARCHAR(32) NOT NULL,

    -- Validator identity
    validator_id VARCHAR(255) NOT NULL,
    validator_index INT,
    public_key BYTEA NOT NULL,

    -- Signature data
    signature BYTEA NOT NULL,
    message_hash BYTEA NOT NULL,

    -- Weight for quorum calculation
    weight BIGINT DEFAULT 1,

    -- Verification status
    signature_valid BOOLEAN,
    verified_at TIMESTAMPTZ,
    verification_notes TEXT,

    -- Block information at time of attestation
    attested_block_number BIGINT,
    attested_block_hash BYTEA,

    -- Timestamps
    attested_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure unique attestation per validator per proof per scheme
    UNIQUE(proof_id, validator_id, scheme)
);

-- =============================================================================
-- AGGREGATED ATTESTATIONS TABLE
-- =============================================================================

-- Aggregated attestations table (scheme-agnostic)
-- Stores aggregated/collected attestations after threshold is met
CREATE TABLE IF NOT EXISTS aggregated_attestations (
    aggregation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),
    cycle_id VARCHAR(255) NOT NULL,

    -- Scheme
    scheme VARCHAR(32) NOT NULL,
    message_hash BYTEA NOT NULL,

    -- Aggregated signature (BLS only, NULL for Ed25519)
    aggregated_signature BYTEA,
    aggregated_public_key BYTEA,

    -- Participants
    participant_ids JSONB NOT NULL, -- Array of validator IDs
    participant_count INT NOT NULL,
    validator_bitfield BYTEA, -- Compact bitfield of participating validators

    -- Threshold tracking
    total_weight BIGINT NOT NULL,
    achieved_weight BIGINT NOT NULL,
    threshold_weight BIGINT NOT NULL,
    threshold_met BOOLEAN NOT NULL,

    -- Threshold configuration
    threshold_numerator INT DEFAULT 2,
    threshold_denominator INT DEFAULT 3,

    -- Verification
    aggregation_valid BOOLEAN,
    verified_at TIMESTAMPTZ,
    verification_notes TEXT,

    -- Individual attestation references
    attestation_ids JSONB, -- Array of attestation_id UUIDs

    -- Timestamps
    first_attestation_at TIMESTAMPTZ,
    last_attestation_at TIMESTAMPTZ,
    aggregated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure unique aggregation per proof per scheme
    UNIQUE(proof_id, scheme)
);

-- =============================================================================
-- CHAIN EXECUTION RESULTS TABLE
-- =============================================================================

-- Chain execution results (platform-agnostic)
-- Stores results of anchor operations across all supported chains
CREATE TABLE IF NOT EXISTS chain_execution_results (
    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),
    cycle_id VARCHAR(255) NOT NULL,

    -- Chain identification
    chain_platform VARCHAR(32) NOT NULL, -- evm, cosmwasm, solana, move, ton, near
    chain_id VARCHAR(64) NOT NULL,
    network_name VARCHAR(64),

    -- Transaction details
    tx_hash VARCHAR(128) NOT NULL,
    block_number BIGINT,
    block_hash VARCHAR(128),
    block_timestamp TIMESTAMPTZ,

    -- Execution status (0=pending, 1=success, 2=failed)
    status SMALLINT NOT NULL DEFAULT 0,
    gas_used BIGINT,
    gas_cost VARCHAR(78), -- For large numbers (wei, lamports, etc.)

    -- Confirmations
    confirmations INT DEFAULT 0,
    required_confirmations INT,
    is_finalized BOOLEAN DEFAULT FALSE,

    -- Cryptographic data
    result_hash BYTEA,
    merkle_proof BYTEA,
    receipt_proof BYTEA,
    state_root BYTEA,
    transactions_root BYTEA,
    receipts_root BYTEA,

    -- Platform-specific data (JSON for flexibility)
    raw_receipt JSONB,
    logs JSONB, -- Event logs
    platform_data JSONB, -- Any platform-specific fields

    -- Observer information
    observer_validator_id VARCHAR(255),

    -- Anchor workflow step (1=create, 2=verify, 3=governance)
    workflow_step SMALLINT,
    anchor_id BYTEA,

    -- Timestamps
    submitted_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    finalized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure unique tx per chain
    UNIQUE(chain_id, tx_hash)
);

-- =============================================================================
-- INDEXES FOR PERFORMANCE
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
    pa.cycle_id,
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
