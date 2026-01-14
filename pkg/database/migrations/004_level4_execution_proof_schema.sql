-- Migration: 004_level4_execution_proof_schema.sql
-- Description: Level 4 External Chain Execution Proof Schema
-- Created: 2026-01-02
--
-- This migration adds tables for complete Level 4 proof artifact storage:
-- - external_chain_results: Ethereum execution observation data
-- - bls_result_attestations: Individual BLS12-381 validator attestations
-- - aggregated_bls_attestations: Aggregated multi-validator BLS signatures
-- - synthetic_transactions: Write-back transactions to Accumulate
-- - proof_cycle_completions: Complete proof cycle records
-- - execution_merkle_proofs: Tx/receipt inclusion proofs from external chains
--
-- Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phases 7-10

BEGIN;

-- ============================================================================
-- TABLE 1: external_chain_results - Phase 7 Observation Data
-- ============================================================================
-- Stores the complete external chain execution result that validators observe
-- This is the cryptographic foundation for Level 4 proofs

CREATE TABLE IF NOT EXISTS external_chain_results (
    result_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Link to originating proof/bundle
    proof_id                UUID REFERENCES proof_artifacts(proof_id),
    bundle_id               BYTEA NOT NULL,              -- 32 bytes - ValidatorBlock bundle ID
    operation_id            BYTEA NOT NULL,              -- 32 bytes - CertenIntent operation ID

    -- External Chain Identification
    chain_type              VARCHAR(50) NOT NULL,        -- 'ethereum', 'bitcoin', etc.
    chain_id                BIGINT NOT NULL,             -- Network ID (e.g., 11155111 for Sepolia)
    network_name            VARCHAR(50),                 -- 'mainnet', 'sepolia', etc.

    -- Transaction Details
    tx_hash                 BYTEA NOT NULL,              -- 32 bytes
    tx_index                INTEGER NOT NULL,            -- Position in block
    tx_nonce                BIGINT,
    tx_gas_limit            BIGINT,
    tx_gas_used             BIGINT NOT NULL,
    tx_gas_price_wei        NUMERIC(78, 0),              -- Wei (can be very large)
    tx_value_wei            NUMERIC(78, 0),
    tx_input_data           BYTEA,                       -- Call data
    tx_from_address         BYTEA NOT NULL,              -- 20 bytes
    tx_to_address           BYTEA,                       -- 20 bytes (null for contract creation)

    -- Block Details
    block_number            BIGINT NOT NULL,
    block_hash              BYTEA NOT NULL,              -- 32 bytes
    block_timestamp         TIMESTAMPTZ NOT NULL,
    block_parent_hash       BYTEA,                       -- 32 bytes

    -- State Roots (Cryptographic Binding)
    state_root              BYTEA NOT NULL,              -- 32 bytes - post-execution state root
    transactions_root       BYTEA NOT NULL,              -- 32 bytes - block's tx trie root
    receipts_root           BYTEA NOT NULL,              -- 32 bytes - block's receipt trie root

    -- Execution Status
    execution_status        SMALLINT NOT NULL,           -- 0 = failed, 1 = success
    execution_success       BOOLEAN NOT NULL,
    revert_reason           TEXT,                        -- If failed, decoded revert reason

    -- Contract Interaction
    contract_address        BYTEA,                       -- 20 bytes - CertenAnchorV3 address
    function_selector       BYTEA,                       -- 4 bytes

    -- Log Events (serialized)
    logs_bloom              BYTEA,                       -- 256 bytes bloom filter
    logs_json               JSONB,                       -- Parsed event logs

    -- Confirmation Tracking
    confirmation_blocks     INTEGER NOT NULL DEFAULT 0,
    required_confirmations  INTEGER NOT NULL DEFAULT 12,
    is_finalized            BOOLEAN NOT NULL DEFAULT FALSE,
    finalized_at            TIMESTAMPTZ,

    -- Computed Hashes for Verification
    result_hash             BYTEA NOT NULL,              -- 32 bytes - SHA256 of canonical result
    rlp_encoded_tx          BYTEA,                       -- RLP encoded transaction
    rlp_encoded_receipt     BYTEA,                       -- RLP encoded receipt

    -- Observer Information
    observer_validator_id   VARCHAR(256) NOT NULL,
    observed_at             TIMESTAMPTZ NOT NULL,

    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_chain_type CHECK (chain_type IN ('ethereum', 'bitcoin', 'solana', 'polygon')),
    CONSTRAINT valid_execution_status CHECK (execution_status IN (0, 1))
);

-- Indexes for external_chain_results
CREATE INDEX IF NOT EXISTS idx_ecr_bundle ON external_chain_results(bundle_id);
CREATE INDEX IF NOT EXISTS idx_ecr_operation ON external_chain_results(operation_id);
CREATE INDEX IF NOT EXISTS idx_ecr_tx_hash ON external_chain_results(tx_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_block ON external_chain_results(chain_id, block_number);
CREATE INDEX IF NOT EXISTS idx_ecr_result_hash ON external_chain_results(result_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_finalized ON external_chain_results(is_finalized) WHERE is_finalized = TRUE;
CREATE INDEX IF NOT EXISTS idx_ecr_proof ON external_chain_results(proof_id) WHERE proof_id IS NOT NULL;

-- ============================================================================
-- TABLE 2: execution_merkle_proofs - Tx/Receipt Inclusion Proofs
-- ============================================================================
-- Stores the Merkle proofs that cryptographically bind transactions/receipts
-- to block roots. Required for independent verification.

CREATE TABLE IF NOT EXISTS execution_merkle_proofs (
    merkle_proof_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,

    -- Proof Type
    proof_type              VARCHAR(30) NOT NULL,        -- 'transaction', 'receipt'

    -- Leaf Data
    leaf_hash               BYTEA NOT NULL,              -- 32 bytes - Keccak256(RLP(tx/receipt))
    leaf_index              INTEGER NOT NULL,            -- Position in trie (tx index)
    leaf_rlp_data           BYTEA NOT NULL,              -- RLP encoded leaf data

    -- Merkle Path (Patricia Trie proof for Ethereum)
    proof_nodes             BYTEA[] NOT NULL,            -- Array of proof nodes
    proof_node_count        INTEGER NOT NULL,

    -- Expected Root (from block header)
    expected_root           BYTEA NOT NULL,              -- 32 bytes

    -- Verification
    verified                BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at             TIMESTAMPTZ,
    verification_error      TEXT,

    -- Metadata
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_proof_type CHECK (proof_type IN ('transaction', 'receipt'))
);

-- Indexes for execution_merkle_proofs
CREATE INDEX IF NOT EXISTS idx_emp_result ON execution_merkle_proofs(result_id);
CREATE INDEX IF NOT EXISTS idx_emp_type ON execution_merkle_proofs(result_id, proof_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_emp_unique ON execution_merkle_proofs(result_id, proof_type);

-- ============================================================================
-- TABLE 3: bls_result_attestations - Phase 8 Individual BLS Attestations
-- ============================================================================
-- Stores individual BLS12-381 attestations from each validator
-- These are aggregated into AggregatedAttestation

CREATE TABLE IF NOT EXISTS bls_result_attestations (
    attestation_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,

    -- What is being attested (must match across all attestations for same result)
    result_hash             BYTEA NOT NULL,              -- 32 bytes - Hash of ExternalChainResult
    bundle_id               BYTEA NOT NULL,              -- 32 bytes - Original bundle ID
    message_hash            BYTEA NOT NULL,              -- 32 bytes - Hash that was signed

    -- Validator Identity
    validator_id            VARCHAR(256) NOT NULL,
    validator_address       BYTEA NOT NULL,              -- 20 bytes - Ethereum address
    validator_index         INTEGER NOT NULL,            -- Index in validator set

    -- BLS12-381 Signature (48 bytes compressed G1 point)
    bls_signature           BYTEA NOT NULL,              -- 48 bytes for BLS12-381
    bls_public_key          BYTEA NOT NULL,              -- 96 bytes for BLS12-381 G2

    -- Domain Separation
    signature_domain        VARCHAR(50) NOT NULL DEFAULT 'CERTEN_RESULT_ATTESTATION_V1',

    -- Block Binding
    attested_block_number   BIGINT NOT NULL,
    attested_block_hash     BYTEA,                       -- 32 bytes
    confirmations_at_attest INTEGER NOT NULL,

    -- Verification Status
    signature_valid         BOOLEAN,
    verified_at             TIMESTAMPTZ,
    verification_error      TEXT,

    -- Timestamps
    attestation_time        TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent duplicate attestations from same validator
    CONSTRAINT unique_validator_attestation UNIQUE (result_id, validator_id)
);

-- Indexes for bls_result_attestations
CREATE INDEX IF NOT EXISTS idx_bra_result ON bls_result_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_bra_validator ON bls_result_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_bra_bundle ON bls_result_attestations(bundle_id);
CREATE INDEX IF NOT EXISTS idx_bra_message ON bls_result_attestations(message_hash);
CREATE INDEX IF NOT EXISTS idx_bra_valid ON bls_result_attestations(result_id, signature_valid) WHERE signature_valid = TRUE;

-- ============================================================================
-- TABLE 4: aggregated_bls_attestations - Phase 8 Aggregated Signatures
-- ============================================================================
-- Stores aggregated BLS signatures combining multiple validator attestations
-- This is the cryptographic proof of multi-validator consensus

CREATE TABLE IF NOT EXISTS aggregated_bls_attestations (
    aggregation_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,

    -- Core Attestation Data (same across all individual attestations)
    result_hash             BYTEA NOT NULL,              -- 32 bytes
    bundle_id               BYTEA NOT NULL,              -- 32 bytes
    message_hash            BYTEA NOT NULL,              -- 32 bytes
    attested_block_number   BIGINT NOT NULL,

    -- Aggregated BLS Signature (48 bytes compressed)
    aggregate_signature     BYTEA NOT NULL,              -- 48 bytes BLS12-381

    -- Aggregated Public Key (for verification)
    aggregate_public_key    BYTEA,                       -- 96 bytes - Optional, can be derived

    -- Participating Validators
    validator_bitfield      BYTEA NOT NULL,              -- Bitmap of participating validators
    validator_count         INTEGER NOT NULL,
    validator_addresses     BYTEA[] NOT NULL,            -- Array of 20-byte addresses
    validator_indices       INTEGER[] NOT NULL,          -- Array of indices

    -- Individual attestation IDs (for audit)
    attestation_ids         UUID[] NOT NULL,

    -- Voting Power Tracking
    total_voting_power      NUMERIC(78, 0) NOT NULL,     -- Total power in validator set
    signed_voting_power     NUMERIC(78, 0) NOT NULL,     -- Power of attestors
    voting_power_percentage NUMERIC(5, 2) NOT NULL,      -- Percentage (e.g., 66.67)

    -- Threshold Configuration
    threshold_numerator     INTEGER NOT NULL DEFAULT 2,  -- 2/3 threshold
    threshold_denominator   INTEGER NOT NULL DEFAULT 3,
    threshold_met           BOOLEAN NOT NULL,

    -- Timing
    first_attestation_at    TIMESTAMPTZ NOT NULL,
    last_attestation_at     TIMESTAMPTZ NOT NULL,
    finalized_at            TIMESTAMPTZ,

    -- Verification Status
    aggregate_verified      BOOLEAN,
    verified_at             TIMESTAMPTZ,
    verification_error      TEXT,

    -- Computed Hash for Chaining
    aggregation_hash        BYTEA NOT NULL,              -- 32 bytes - Hash of aggregation

    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_threshold CHECK (threshold_numerator > 0 AND threshold_denominator > 0)
);

-- Indexes for aggregated_bls_attestations
CREATE UNIQUE INDEX IF NOT EXISTS idx_aba_result ON aggregated_bls_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_aba_bundle ON aggregated_bls_attestations(bundle_id);
CREATE INDEX IF NOT EXISTS idx_aba_threshold ON aggregated_bls_attestations(threshold_met) WHERE threshold_met = TRUE;
CREATE INDEX IF NOT EXISTS idx_aba_finalized ON aggregated_bls_attestations(finalized_at) WHERE finalized_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_aba_hash ON aggregated_bls_attestations(aggregation_hash);

-- ============================================================================
-- TABLE 5: synthetic_transactions - Phase 9 Write-Back to Accumulate
-- ============================================================================
-- Stores the synthetic transaction that writes proof cycle results back to Accumulate

CREATE TABLE IF NOT EXISTS synthetic_transactions (
    synth_tx_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregation_id          UUID NOT NULL REFERENCES aggregated_bls_attestations(aggregation_id),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id),

    -- Transaction Identification
    tx_id                   BYTEA NOT NULL,              -- 32 bytes - Accumulate tx ID
    tx_hash                 BYTEA NOT NULL,              -- 32 bytes - Accumulate tx hash
    tx_type                 VARCHAR(50) NOT NULL DEFAULT 'CertenProofResult',

    -- Source Data References
    origin_bundle_id        BYTEA NOT NULL,              -- 32 bytes
    origin_result_hash      BYTEA NOT NULL,              -- 32 bytes
    origin_aggregation_hash BYTEA NOT NULL,              -- 32 bytes

    -- Target Accumulate Account
    principal_url           VARCHAR(512) NOT NULL,       -- e.g., acc://certen.acme/results

    -- Transaction Body (canonical JSON)
    body_json               JSONB NOT NULL,
    body_hash               BYTEA NOT NULL,              -- 32 bytes - SHA256 of canonical body

    -- Proof Cycle Result Summary
    intent_hash             BYTEA NOT NULL,              -- 32 bytes
    intent_block_height     BIGINT NOT NULL,
    operation_id            BYTEA NOT NULL,              -- 32 bytes

    -- External Chain Execution Summary
    target_chain            VARCHAR(50) NOT NULL,
    target_chain_id         BIGINT NOT NULL,
    execution_tx_hash       BYTEA NOT NULL,              -- 32 bytes
    execution_block_number  BIGINT NOT NULL,
    execution_success       BOOLEAN NOT NULL,
    execution_gas_used      BIGINT NOT NULL,

    -- Attestation Summary
    attestation_count       INTEGER NOT NULL,
    attestation_power       NUMERIC(78, 0) NOT NULL,
    attestation_threshold   BOOLEAN NOT NULL,

    -- Final Proof Cycle Hash
    proof_cycle_hash        BYTEA NOT NULL,              -- 32 bytes

    -- Validator Signatures on Synthetic Tx
    signatures_json         JSONB NOT NULL,              -- Array of {validator_id, signature}
    signature_count         INTEGER NOT NULL,

    -- Accumulate Submission
    submitted_at            TIMESTAMPTZ,
    accumulate_block_height BIGINT,
    accumulate_block_hash   BYTEA,                       -- 32 bytes

    -- Status
    status                  VARCHAR(30) NOT NULL DEFAULT 'pending',
    error_message           TEXT,

    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_synth_status CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed'))
);

-- Indexes for synthetic_transactions
CREATE UNIQUE INDEX IF NOT EXISTS idx_st_tx_hash ON synthetic_transactions(tx_hash);
CREATE INDEX IF NOT EXISTS idx_st_aggregation ON synthetic_transactions(aggregation_id);
CREATE INDEX IF NOT EXISTS idx_st_result ON synthetic_transactions(result_id);
CREATE INDEX IF NOT EXISTS idx_st_bundle ON synthetic_transactions(origin_bundle_id);
CREATE INDEX IF NOT EXISTS idx_st_principal ON synthetic_transactions(principal_url);
CREATE INDEX IF NOT EXISTS idx_st_status ON synthetic_transactions(status);
CREATE INDEX IF NOT EXISTS idx_st_cycle_hash ON synthetic_transactions(proof_cycle_hash);

-- ============================================================================
-- TABLE 6: proof_cycle_completions - Phase 10 Complete Cycle Records
-- ============================================================================
-- Master record linking all Level 4 proof artifacts into a complete cycle

CREATE TABLE IF NOT EXISTS proof_cycle_completions (
    cycle_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Origin References
    proof_id                UUID REFERENCES proof_artifacts(proof_id),
    intent_id               VARCHAR(256) NOT NULL,       -- CertenIntent identifier
    bundle_id               BYTEA NOT NULL,              -- 32 bytes
    operation_id            BYTEA NOT NULL,              -- 32 bytes

    -- Level 3 References (Validator Consensus & Anchor)
    anchor_tx_hash          BYTEA NOT NULL,              -- 32 bytes - External chain anchor
    anchor_block_number     BIGINT NOT NULL,
    anchor_chain            VARCHAR(50) NOT NULL,
    anchor_chain_id         BIGINT NOT NULL,

    -- Level 4 References
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id),
    aggregation_id          UUID NOT NULL REFERENCES aggregated_bls_attestations(aggregation_id),
    synth_tx_id             UUID REFERENCES synthetic_transactions(synth_tx_id),

    -- Execution Merkle Proof IDs
    tx_merkle_proof_id      UUID REFERENCES execution_merkle_proofs(merkle_proof_id),
    receipt_merkle_proof_id UUID REFERENCES execution_merkle_proofs(merkle_proof_id),

    -- Cryptographic Lineage Chain
    -- Each hash includes the previous, creating unbroken lineage
    chained_proof_root      BYTEA,                       -- 32 bytes - From Level 1-2
    governance_proof_root   BYTEA,                       -- 32 bytes - From G0/G1/G2
    anchor_commitment       BYTEA NOT NULL,              -- 32 bytes - Level 3 commitment
    execution_result_hash   BYTEA NOT NULL,              -- 32 bytes - Level 4 result
    attestation_hash        BYTEA NOT NULL,              -- 32 bytes - Aggregated attestation
    cycle_completion_hash   BYTEA NOT NULL,              -- 32 bytes - Final cycle hash

    -- Verification Summary
    level1_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    level2_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    level3_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    level4_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    all_levels_verified     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timing
    intent_timestamp        TIMESTAMPTZ NOT NULL,
    anchor_timestamp        TIMESTAMPTZ NOT NULL,
    execution_timestamp     TIMESTAMPTZ NOT NULL,
    attestation_timestamp   TIMESTAMPTZ NOT NULL,
    writeback_timestamp     TIMESTAMPTZ,
    completion_timestamp    TIMESTAMPTZ NOT NULL,

    -- Total Cycle Duration
    cycle_duration_ms       BIGINT NOT NULL,

    -- Status
    status                  VARCHAR(30) NOT NULL DEFAULT 'completed',

    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_cycle_status CHECK (status IN ('in_progress', 'completed', 'failed', 'partial'))
);

-- Indexes for proof_cycle_completions
CREATE UNIQUE INDEX IF NOT EXISTS idx_pcc_bundle ON proof_cycle_completions(bundle_id);
CREATE INDEX IF NOT EXISTS idx_pcc_proof ON proof_cycle_completions(proof_id) WHERE proof_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pcc_intent ON proof_cycle_completions(intent_id);
CREATE INDEX IF NOT EXISTS idx_pcc_operation ON proof_cycle_completions(operation_id);
CREATE INDEX IF NOT EXISTS idx_pcc_result ON proof_cycle_completions(result_id);
CREATE INDEX IF NOT EXISTS idx_pcc_completion_hash ON proof_cycle_completions(cycle_completion_hash);
CREATE INDEX IF NOT EXISTS idx_pcc_all_verified ON proof_cycle_completions(all_levels_verified) WHERE all_levels_verified = TRUE;
CREATE INDEX IF NOT EXISTS idx_pcc_status ON proof_cycle_completions(status);

-- ============================================================================
-- TABLE 7: validator_set_snapshots - Validator Set at Attestation Time
-- ============================================================================
-- Stores validator set configuration at the time of attestation
-- Required for independent verification of threshold calculations

CREATE TABLE IF NOT EXISTS validator_set_snapshots (
    snapshot_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregation_id          UUID NOT NULL REFERENCES aggregated_bls_attestations(aggregation_id),

    -- Snapshot Identification
    snapshot_block_number   BIGINT NOT NULL,             -- Block at which set was captured
    snapshot_timestamp      TIMESTAMPTZ NOT NULL,

    -- Validator Set Data
    validator_count         INTEGER NOT NULL,
    total_voting_power      NUMERIC(78, 0) NOT NULL,

    -- Individual Validators (JSON array)
    validators_json         JSONB NOT NULL,              -- [{id, address, index, power, bls_pubkey}]

    -- Merkle Root of Validator Set (for verification)
    validator_set_root      BYTEA NOT NULL,              -- 32 bytes

    -- Threshold Configuration at Snapshot
    threshold_numerator     INTEGER NOT NULL,
    threshold_denominator   INTEGER NOT NULL,
    required_power          NUMERIC(78, 0) NOT NULL,     -- Pre-computed threshold

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for validator_set_snapshots
CREATE UNIQUE INDEX IF NOT EXISTS idx_vss_aggregation ON validator_set_snapshots(aggregation_id);
CREATE INDEX IF NOT EXISTS idx_vss_block ON validator_set_snapshots(snapshot_block_number);
CREATE INDEX IF NOT EXISTS idx_vss_root ON validator_set_snapshots(validator_set_root);

-- ============================================================================
-- VIEWS: Level 4 Proof Verification Views
-- ============================================================================

-- View: Complete Level 4 proof status
CREATE OR REPLACE VIEW level4_proof_status_view AS
SELECT
    pcc.cycle_id,
    pcc.bundle_id,
    pcc.operation_id,
    pcc.status AS cycle_status,

    -- External Chain Result
    ecr.result_id,
    ecr.chain_type,
    ecr.tx_hash AS execution_tx_hash,
    ecr.execution_success,
    ecr.is_finalized AS execution_finalized,
    ecr.confirmation_blocks,

    -- Merkle Proofs
    (SELECT verified FROM execution_merkle_proofs WHERE result_id = ecr.result_id AND proof_type = 'transaction') AS tx_proof_verified,
    (SELECT verified FROM execution_merkle_proofs WHERE result_id = ecr.result_id AND proof_type = 'receipt') AS receipt_proof_verified,

    -- BLS Attestations
    aba.validator_count AS attestation_count,
    aba.voting_power_percentage,
    aba.threshold_met,
    aba.aggregate_verified,

    -- Synthetic Transaction
    st.status AS writeback_status,
    st.accumulate_block_height AS writeback_block,

    -- Verification Summary
    pcc.level3_verified,
    pcc.level4_verified,
    pcc.all_levels_verified,

    -- Timing
    pcc.cycle_duration_ms,
    pcc.completion_timestamp

FROM proof_cycle_completions pcc
JOIN external_chain_results ecr ON ecr.result_id = pcc.result_id
JOIN aggregated_bls_attestations aba ON aba.aggregation_id = pcc.aggregation_id
LEFT JOIN synthetic_transactions st ON st.synth_tx_id = pcc.synth_tx_id;

-- View: BLS attestation verification status
CREATE OR REPLACE VIEW bls_attestation_status_view AS
SELECT
    aba.aggregation_id,
    aba.bundle_id,
    aba.validator_count,
    aba.voting_power_percentage,
    aba.threshold_met,
    aba.aggregate_verified,

    -- Individual attestation stats
    (SELECT COUNT(*) FROM bls_result_attestations bra WHERE bra.result_id = aba.result_id AND bra.signature_valid = TRUE) AS valid_attestations,
    (SELECT COUNT(*) FROM bls_result_attestations bra WHERE bra.result_id = aba.result_id AND bra.signature_valid = FALSE) AS invalid_attestations,
    (SELECT COUNT(*) FROM bls_result_attestations bra WHERE bra.result_id = aba.result_id AND bra.signature_valid IS NULL) AS unverified_attestations,

    -- Validator set snapshot
    vss.validator_count AS total_validators,
    vss.validator_set_root

FROM aggregated_bls_attestations aba
LEFT JOIN validator_set_snapshots vss ON vss.aggregation_id = aba.aggregation_id;

-- ============================================================================
-- FUNCTIONS: Level 4 Verification Helpers
-- ============================================================================

-- Function: Compute attestation message hash (matches Go implementation)
CREATE OR REPLACE FUNCTION compute_attestation_message_hash(
    p_result_hash BYTEA,
    p_bundle_id BYTEA,
    p_block_number BIGINT
) RETURNS BYTEA AS $$
DECLARE
    v_data BYTEA;
BEGIN
    -- Domain separator + result_hash + bundle_id + block_number
    v_data := 'CERTEN_RESULT_ATTESTATION_V1'::bytea ||
              p_result_hash ||
              p_bundle_id ||
              int8send(p_block_number);

    RETURN sha256(v_data);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Compute cycle completion hash
CREATE OR REPLACE FUNCTION compute_cycle_completion_hash(
    p_bundle_id BYTEA,
    p_anchor_commitment BYTEA,
    p_execution_result_hash BYTEA,
    p_attestation_hash BYTEA
) RETURNS BYTEA AS $$
DECLARE
    v_data BYTEA;
BEGIN
    v_data := 'CERTEN_PROOF_CYCLE_V1'::bytea ||
              p_bundle_id ||
              p_anchor_commitment ||
              p_execution_result_hash ||
              p_attestation_hash;

    RETURN sha256(v_data);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Verify threshold is met
CREATE OR REPLACE FUNCTION verify_threshold_met(
    p_signed_power NUMERIC,
    p_total_power NUMERIC,
    p_numerator INTEGER,
    p_denominator INTEGER
) RETURNS BOOLEAN AS $$
BEGIN
    -- signed >= (total * numerator) / denominator
    RETURN p_signed_power >= (p_total_power * p_numerator) / p_denominator;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- TRIGGERS: Automatic Hash Computation
-- ============================================================================

-- Trigger: Auto-compute message hash for BLS attestations
CREATE OR REPLACE FUNCTION trigger_compute_message_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.message_hash IS NULL THEN
        NEW.message_hash := compute_attestation_message_hash(
            NEW.result_hash,
            NEW.bundle_id,
            NEW.attested_block_number
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bls_attestation_message_hash
    BEFORE INSERT ON bls_result_attestations
    FOR EACH ROW
    EXECUTE FUNCTION trigger_compute_message_hash();

-- Trigger: Auto-compute cycle completion hash
CREATE OR REPLACE FUNCTION trigger_compute_cycle_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.cycle_completion_hash IS NULL THEN
        NEW.cycle_completion_hash := compute_cycle_completion_hash(
            NEW.bundle_id,
            NEW.anchor_commitment,
            NEW.execution_result_hash,
            NEW.attestation_hash
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cycle_completion_hash
    BEFORE INSERT ON proof_cycle_completions
    FOR EACH ROW
    EXECUTE FUNCTION trigger_compute_cycle_hash();

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('004', 'Level 4 External Chain Execution Proof Schema', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
