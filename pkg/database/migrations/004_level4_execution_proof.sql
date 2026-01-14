-- Migration: 004_level4_execution_proof.sql
-- Description: Level 4 External Chain Execution Proof tables
-- Created: 2025-01-XX
--
-- This migration adds tables required for Level 4 cryptographic verification:
-- - external_chain_results: Execution results with hash chain binding
-- - bls_attestations: Individual BLS12-381 attestations
-- - aggregated_attestations: Aggregated BLS attestations
-- - validator_set_snapshots: Validator set state at attestation time
-- - proof_cycle_completions: Track complete proof cycles through all 4 levels

BEGIN;

-- ============================================================================
-- TABLE 1: external_chain_results - Execution Results with Hash Chain
-- ============================================================================

CREATE TABLE IF NOT EXISTS external_chain_results (
    result_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    -- External Chain Reference
    chain_id            VARCHAR(100) NOT NULL,
    chain_name          VARCHAR(256) NOT NULL,
    block_number        BIGINT NOT NULL,
    block_hash          BYTEA NOT NULL,
    transaction_hash    BYTEA NOT NULL,

    -- Execution Details
    execution_status    SMALLINT NOT NULL,
    gas_used            BIGINT NOT NULL,
    return_data         BYTEA,

    -- Patricia/Merkle Proof (Keccak256-based for Ethereum)
    storage_proof_json  JSONB,
    storage_proof_hash  BYTEA,

    -- Hash Chain Binding (RFC8785 canonical JSON)
    sequence_number     BIGINT NOT NULL DEFAULT 0,
    previous_result_hash BYTEA,
    result_hash         BYTEA NOT NULL,

    -- Binding to Level 3 Anchor Proof
    anchor_proof_hash   BYTEA NOT NULL,

    -- Full Artifact JSON
    artifact_json       JSONB NOT NULL,

    -- Verification Status
    verified            BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure unique sequence per proof
    CONSTRAINT unique_sequence_per_proof UNIQUE (proof_id, sequence_number)
);

-- Indexes for external chain results
CREATE INDEX IF NOT EXISTS idx_ecr_proof ON external_chain_results(proof_id);
CREATE INDEX IF NOT EXISTS idx_ecr_chain ON external_chain_results(chain_id);
CREATE INDEX IF NOT EXISTS idx_ecr_block ON external_chain_results(chain_id, block_number);
CREATE INDEX IF NOT EXISTS idx_ecr_tx_hash ON external_chain_results(transaction_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_result_hash ON external_chain_results(result_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_sequence ON external_chain_results(proof_id, sequence_number DESC);
CREATE INDEX IF NOT EXISTS idx_ecr_created ON external_chain_results(created_at DESC);

-- ============================================================================
-- TABLE 2: validator_set_snapshots - Validator Set State at Attestation Time
-- ============================================================================

CREATE TABLE IF NOT EXISTS validator_set_snapshots (
    snapshot_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Snapshot Binding
    block_number        BIGINT NOT NULL,
    block_hash          BYTEA,

    -- Validator Set (Array of ValidatorEntry)
    validators_json     JSONB NOT NULL,

    -- Computed Values
    validator_root      BYTEA NOT NULL,          -- Merkle root of validators
    validator_count     INTEGER NOT NULL,
    total_weight        BIGINT NOT NULL,
    threshold_weight    BIGINT NOT NULL,         -- 2/3+1 of total

    -- Snapshot Hash (RFC8785 canonical JSON)
    snapshot_hash       BYTEA NOT NULL,

    -- Chain Reference
    chain_id            VARCHAR(100) NOT NULL,
    chain_name          VARCHAR(256) NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent duplicate snapshots for same state
    CONSTRAINT unique_snapshot_hash UNIQUE (snapshot_hash)
);

-- Indexes for validator set snapshots
CREATE INDEX IF NOT EXISTS idx_vss_chain ON validator_set_snapshots(chain_id);
CREATE INDEX IF NOT EXISTS idx_vss_block ON validator_set_snapshots(chain_id, block_number DESC);
CREATE INDEX IF NOT EXISTS idx_vss_hash ON validator_set_snapshots(snapshot_hash);
CREATE INDEX IF NOT EXISTS idx_vss_created ON validator_set_snapshots(created_at DESC);

-- ============================================================================
-- TABLE 3: bls_attestations - Individual BLS12-381 Attestations
-- ============================================================================

CREATE TABLE IF NOT EXISTS bls_attestations (
    attestation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id           UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,
    snapshot_id         UUID NOT NULL REFERENCES validator_set_snapshots(snapshot_id),

    -- Validator Identity
    validator_id        VARCHAR(256) NOT NULL,
    public_key          BYTEA NOT NULL,          -- BLS12-381 G2 point (96 bytes compressed)

    -- Message Being Attested
    message_hash        BYTEA NOT NULL,          -- SHA256 of canonical result

    -- BLS Signature
    signature           BYTEA NOT NULL,          -- BLS12-381 G1 point (48 bytes compressed)

    -- Validator Weight
    weight              BIGINT NOT NULL,

    -- Subgroup Validation (security check)
    subgroup_valid      BOOLEAN NOT NULL DEFAULT FALSE,

    -- Verification Status
    signature_valid     BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    attested_at         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent duplicate attestations from same validator for same result
    CONSTRAINT unique_validator_result UNIQUE (result_id, validator_id)
);

-- Indexes for BLS attestations
CREATE INDEX IF NOT EXISTS idx_bls_att_result ON bls_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_bls_att_snapshot ON bls_attestations(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_bls_att_validator ON bls_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_bls_att_message ON bls_attestations(message_hash);
CREATE INDEX IF NOT EXISTS idx_bls_att_attested ON bls_attestations(attested_at DESC);
CREATE INDEX IF NOT EXISTS idx_bls_att_valid ON bls_attestations(result_id, signature_valid) WHERE signature_valid = TRUE;

-- ============================================================================
-- TABLE 4: aggregated_attestations - BLS Aggregated Attestations
-- ============================================================================

CREATE TABLE IF NOT EXISTS aggregated_attestations (
    aggregation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id           UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,
    snapshot_id         UUID NOT NULL REFERENCES validator_set_snapshots(snapshot_id),

    -- Aggregated Message (must match all individual attestations)
    message_hash        BYTEA NOT NULL,

    -- Aggregated BLS Signature
    aggregated_signature BYTEA NOT NULL,         -- BLS12-381 G1 point
    aggregated_public_key BYTEA NOT NULL,        -- BLS12-381 G2 point

    -- Participant Information
    participant_ids     JSONB NOT NULL,          -- JSON array of validator IDs
    participant_count   INTEGER NOT NULL,

    -- Weight Calculations
    total_weight        BIGINT NOT NULL,
    threshold_weight    BIGINT NOT NULL,         -- 2/3+1 of total
    achieved_weight     BIGINT NOT NULL,

    -- Threshold Met
    threshold_met       BOOLEAN NOT NULL DEFAULT FALSE,

    -- Message Consistency Check (all attestations signed same message)
    message_consistency_valid BOOLEAN NOT NULL DEFAULT FALSE,

    -- Verification Status
    aggregation_valid   BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    aggregated_at       TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for aggregated attestations
CREATE INDEX IF NOT EXISTS idx_agg_att_result ON aggregated_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_agg_att_snapshot ON aggregated_attestations(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_agg_att_message ON aggregated_attestations(message_hash);
CREATE INDEX IF NOT EXISTS idx_agg_att_threshold ON aggregated_attestations(threshold_met) WHERE threshold_met = TRUE;
CREATE INDEX IF NOT EXISTS idx_agg_att_aggregated ON aggregated_attestations(aggregated_at DESC);

-- ============================================================================
-- TABLE 5: proof_cycle_completions - Track Complete Proof Cycles
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_cycle_completions (
    completion_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    -- Level 1: Chained Proof
    level1_complete     BOOLEAN NOT NULL DEFAULT FALSE,
    level1_proof_id     UUID,
    level1_hash         BYTEA,

    -- Level 2: Governance Proof
    level2_complete     BOOLEAN NOT NULL DEFAULT FALSE,
    level2_proof_id     UUID,
    level2_hash         BYTEA,

    -- Level 3: Anchor Proof
    level3_complete     BOOLEAN NOT NULL DEFAULT FALSE,
    level3_proof_id     UUID,
    level3_hash         BYTEA,

    -- Level 4: Execution Proof
    level4_complete     BOOLEAN NOT NULL DEFAULT FALSE,
    level4_result_id    UUID,
    level4_hash         BYTEA,

    -- Cross-Level Bindings Valid
    bindings_valid      BOOLEAN NOT NULL DEFAULT FALSE,

    -- Complete Cycle Hash (all levels bound together)
    cycle_hash          BYTEA,

    -- Cycle Status
    all_levels_complete BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamps
    level1_at           TIMESTAMPTZ,
    level2_at           TIMESTAMPTZ,
    level3_at           TIMESTAMPTZ,
    level4_at           TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One completion record per proof
    CONSTRAINT unique_proof_completion UNIQUE (proof_id)
);

-- Indexes for proof cycle completions
CREATE INDEX IF NOT EXISTS idx_pcc_proof ON proof_cycle_completions(proof_id);
CREATE INDEX IF NOT EXISTS idx_pcc_incomplete ON proof_cycle_completions(all_levels_complete) WHERE all_levels_complete = FALSE;
CREATE INDEX IF NOT EXISTS idx_pcc_complete ON proof_cycle_completions(completed_at DESC) WHERE all_levels_complete = TRUE;
CREATE INDEX IF NOT EXISTS idx_pcc_cycle_hash ON proof_cycle_completions(cycle_hash) WHERE cycle_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pcc_created ON proof_cycle_completions(created_at DESC);

-- ============================================================================
-- VIEWS: Convenient Query Views
-- ============================================================================

-- View: Level 4 execution status
CREATE OR REPLACE VIEW level4_execution_status AS
SELECT
    ecr.result_id,
    ecr.proof_id,
    ecr.chain_id,
    ecr.chain_name,
    ecr.block_number,
    ecr.execution_status,
    ecr.sequence_number,
    ecr.verified,
    ecr.created_at,
    aa.aggregation_id,
    aa.threshold_met,
    aa.achieved_weight,
    aa.threshold_weight,
    aa.message_consistency_valid,
    aa.aggregation_valid,
    vss.validator_count,
    (SELECT COUNT(*) FROM bls_attestations ba WHERE ba.result_id = ecr.result_id) AS attestation_count,
    (SELECT COUNT(*) FROM bls_attestations ba WHERE ba.result_id = ecr.result_id AND ba.signature_valid = TRUE) AS valid_attestation_count
FROM external_chain_results ecr
LEFT JOIN aggregated_attestations aa ON aa.result_id = ecr.result_id
LEFT JOIN validator_set_snapshots vss ON vss.snapshot_id = aa.snapshot_id;

-- View: Proof cycle progress
CREATE OR REPLACE VIEW proof_cycle_progress AS
SELECT
    pcc.completion_id,
    pcc.proof_id,
    pa.accum_tx_hash,
    pa.account_url,
    pcc.level1_complete,
    pcc.level2_complete,
    pcc.level3_complete,
    pcc.level4_complete,
    pcc.bindings_valid,
    pcc.all_levels_complete,
    CASE
        WHEN pcc.all_levels_complete THEN 'complete'
        WHEN pcc.level4_complete THEN 'verifying_bindings'
        WHEN pcc.level3_complete THEN 'awaiting_level4'
        WHEN pcc.level2_complete THEN 'awaiting_level3'
        WHEN pcc.level1_complete THEN 'awaiting_level2'
        ELSE 'awaiting_level1'
    END AS progress_stage,
    pcc.level1_at,
    pcc.level2_at,
    pcc.level3_at,
    pcc.level4_at,
    pcc.completed_at,
    pcc.created_at
FROM proof_cycle_completions pcc
JOIN proof_artifacts pa ON pa.proof_id = pcc.proof_id;

-- ============================================================================
-- FUNCTIONS: Helper Functions
-- ============================================================================

-- Function: Verify hash chain integrity for external chain results
CREATE OR REPLACE FUNCTION verify_result_hash_chain(p_proof_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_prev_hash BYTEA;
    v_curr_hash BYTEA;
    v_prev_seq BIGINT;
    v_curr_seq BIGINT;
    v_record RECORD;
    v_first BOOLEAN := TRUE;
BEGIN
    FOR v_record IN
        SELECT result_hash, previous_result_hash, sequence_number
        FROM external_chain_results
        WHERE proof_id = p_proof_id
        ORDER BY sequence_number ASC
    LOOP
        IF v_first THEN
            -- First record should have NULL or empty previous hash
            IF v_record.previous_result_hash IS NOT NULL AND length(v_record.previous_result_hash) > 0 THEN
                RETURN FALSE;
            END IF;
            v_first := FALSE;
        ELSE
            -- Check hash chain linkage
            IF v_record.previous_result_hash IS DISTINCT FROM v_prev_hash THEN
                RETURN FALSE;
            END IF;
            -- Check sequence continuity
            IF v_record.sequence_number != v_prev_seq + 1 THEN
                RETURN FALSE;
            END IF;
        END IF;

        v_prev_hash := v_record.result_hash;
        v_prev_seq := v_record.sequence_number;
    END LOOP;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate threshold weight (2/3 + 1)
CREATE OR REPLACE FUNCTION calculate_threshold_weight(p_total_weight BIGINT)
RETURNS BIGINT AS $$
BEGIN
    -- Byzantine fault tolerance: need more than 2/3 to reach consensus
    -- threshold = floor(2 * total / 3) + 1
    RETURN (2 * p_total_weight / 3) + 1;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('004', 'Level 4 external chain execution proof tables', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
