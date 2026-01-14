-- Migration: 005_anchor_proof_enhancements.sql
-- Description: Anchor Proof Enhancements for Phase 5 Production Hardening
-- Created: 2026-01-05
--
-- This migration adds tables and columns for:
-- - Enhanced anchor batch tracking with proof data
-- - Multi-validator attestation storage
-- - Consensus coordination state
-- - Event watcher checkpoints
--
-- Per ANCHOR_V3_IMPLEMENTATION_PLAN.md Phase 5

BEGIN;

-- ============================================================================
-- TABLE MODIFICATIONS: anchor_batches Enhancements
-- ============================================================================
-- Add columns for real proof data per HIGH-002, HIGH-003 fixes

ALTER TABLE anchor_batches
ADD COLUMN IF NOT EXISTS bpt_root BYTEA,                     -- Real BPT root from Accumulate (HIGH-002)
ADD COLUMN IF NOT EXISTS governance_root BYTEA,               -- Real governance Merkle root (HIGH-003)
ADD COLUMN IF NOT EXISTS proof_data_included BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS attestation_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS aggregated_signature BYTEA,          -- BLS aggregate signature
ADD COLUMN IF NOT EXISTS aggregated_public_key BYTEA,         -- BLS aggregate public key
ADD COLUMN IF NOT EXISTS quorum_reached BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS consensus_completed_at TIMESTAMPTZ;

-- Add index for proof lookup
CREATE INDEX IF NOT EXISTS idx_anchor_batches_bpt_root
ON anchor_batches(bpt_root) WHERE bpt_root IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_anchor_batches_governance_root
ON anchor_batches(governance_root) WHERE governance_root IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_anchor_batches_quorum
ON anchor_batches(quorum_reached) WHERE quorum_reached = TRUE;

-- ============================================================================
-- TABLE 1: batch_attestations - Multi-Validator Attestation Storage
-- ============================================================================
-- Stores individual validator attestations for batch anchors
-- Per Phase 4 Task 4.1: AttestationBroadcaster

CREATE TABLE IF NOT EXISTS batch_attestations (
    attestation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL,                        -- References anchor_batches
    validator_id        VARCHAR(256) NOT NULL,
    merkle_root         BYTEA NOT NULL,                       -- 32 bytes

    -- BLS12-381 Signature
    bls_signature       BYTEA NOT NULL,                       -- 48 bytes for BLS12-381
    bls_public_key      BYTEA NOT NULL,                       -- 96 bytes for BLS12-381 G2

    -- Attestation Data
    tx_count            INTEGER NOT NULL,
    block_height        BIGINT NOT NULL,
    attestation_time    TIMESTAMPTZ NOT NULL,

    -- Verification Status
    signature_valid     BOOLEAN,
    verified_at         TIMESTAMPTZ,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent duplicate attestations
    CONSTRAINT unique_batch_validator_attestation UNIQUE (batch_id, validator_id)
);

-- Indexes for batch_attestations
CREATE INDEX IF NOT EXISTS idx_ba_batch ON batch_attestations(batch_id);
CREATE INDEX IF NOT EXISTS idx_ba_validator ON batch_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_ba_valid ON batch_attestations(signature_valid) WHERE signature_valid = TRUE;
CREATE INDEX IF NOT EXISTS idx_ba_time ON batch_attestations(attestation_time DESC);

-- ============================================================================
-- TABLE 2: consensus_entries - Consensus State Tracking
-- ============================================================================
-- Tracks the state of multi-validator consensus for each batch
-- Per Phase 4 Task 4.3: ConsensusCoordinator

CREATE TABLE IF NOT EXISTS consensus_entries (
    entry_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL UNIQUE,                 -- One entry per batch
    merkle_root         BYTEA NOT NULL,                       -- 32 bytes
    anchor_tx_hash      VARCHAR(66),                          -- Ethereum tx hash
    block_number        BIGINT,
    tx_count            INTEGER NOT NULL,

    -- Consensus State
    state               VARCHAR(30) NOT NULL DEFAULT 'initiated',

    -- Attestation Summary
    attestation_count   INTEGER NOT NULL DEFAULT 0,
    required_count      INTEGER NOT NULL,
    quorum_fraction     NUMERIC(5, 4) NOT NULL DEFAULT 0.667,

    -- Aggregate Signature (once quorum reached)
    aggregate_signature BYTEA,
    aggregate_pubkey    BYTEA,

    -- Timing
    start_time          TIMESTAMPTZ NOT NULL,
    last_update         TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,

    -- Result (JSON for errors, etc.)
    result_json         JSONB,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_consensus_state CHECK (
        state IN ('initiated', 'collecting', 'quorum_met', 'completed', 'failed', 'timeout')
    )
);

-- Indexes for consensus_entries
CREATE INDEX IF NOT EXISTS idx_ce_state ON consensus_entries(state);
CREATE INDEX IF NOT EXISTS idx_ce_active ON consensus_entries(state)
    WHERE state IN ('initiated', 'collecting');
CREATE INDEX IF NOT EXISTS idx_ce_completed ON consensus_entries(completed_at DESC)
    WHERE completed_at IS NOT NULL;

-- ============================================================================
-- TABLE 3: event_watcher_checkpoints - Event Watcher State
-- ============================================================================
-- Tracks the last processed block for each watched contract
-- Per Phase 4 Task 4.2: EventWatcher

CREATE TABLE IF NOT EXISTS event_watcher_checkpoints (
    checkpoint_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Contract Identification
    chain_id            BIGINT NOT NULL,
    contract_address    BYTEA NOT NULL,                       -- 20 bytes

    -- Checkpoint Data
    last_block_number   BIGINT NOT NULL,
    last_block_hash     BYTEA,                                -- 32 bytes
    last_processed_at   TIMESTAMPTZ NOT NULL,

    -- Event Counts (for monitoring)
    events_processed    BIGINT NOT NULL DEFAULT 0,
    errors_count        INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,

    -- Configuration
    poll_interval_ms    INTEGER NOT NULL DEFAULT 15000,
    block_lookback      BIGINT NOT NULL DEFAULT 100,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_contract_checkpoint UNIQUE (chain_id, contract_address)
);

-- Indexes for event_watcher_checkpoints
CREATE INDEX IF NOT EXISTS idx_ewc_chain ON event_watcher_checkpoints(chain_id);
CREATE INDEX IF NOT EXISTS idx_ewc_contract ON event_watcher_checkpoints(contract_address);

-- ============================================================================
-- TABLE 4: anchor_events - Contract Event Storage
-- ============================================================================
-- Stores parsed events from CertenAnchorV3 contract
-- Per Phase 4 Task 4.2: EventWatcher

CREATE TABLE IF NOT EXISTS anchor_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Event Identification
    event_type          VARCHAR(50) NOT NULL,
    bundle_id           BYTEA,                                -- 32 bytes (indexed in event)

    -- Block Information
    block_number        BIGINT NOT NULL,
    block_hash          BYTEA,                                -- 32 bytes
    tx_hash             BYTEA NOT NULL,                       -- 32 bytes
    log_index           INTEGER NOT NULL,

    -- Event Data (JSON for flexibility)
    event_data          JSONB NOT NULL,

    -- Parsed Fields (common across event types)
    validator_address   BYTEA,                                -- 20 bytes
    transaction_hash    BYTEA,                                -- 32 bytes (from proof events)

    -- Verification Flags (from ProofExecuted events)
    merkle_verified     BOOLEAN,
    bls_verified        BOOLEAN,
    governance_verified BOOLEAN,

    -- Failure Info (from ProofVerificationFailed events)
    failure_reason      TEXT,

    -- Timestamps
    event_timestamp     BIGINT,                               -- From event
    parsed_at           TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_event_type CHECK (
        event_type IN (
            'AnchorCreated', 'ProofExecuted', 'ProofVerificationFailed',
            'GovernanceExecuted', 'ValidatorRegistered', 'ValidatorRemoved',
            'ThresholdUpdated', 'GovernanceVerifierUpdated', 'BLSVerifierUpdated'
        )
    )
);

-- Indexes for anchor_events
CREATE INDEX IF NOT EXISTS idx_ae_type ON anchor_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ae_bundle ON anchor_events(bundle_id) WHERE bundle_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ae_block ON anchor_events(block_number DESC);
CREATE INDEX IF NOT EXISTS idx_ae_tx ON anchor_events(tx_hash);
CREATE INDEX IF NOT EXISTS idx_ae_validator ON anchor_events(validator_address) WHERE validator_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ae_failures ON anchor_events(event_type, created_at DESC)
    WHERE event_type = 'ProofVerificationFailed';

-- ============================================================================
-- TABLE 5: governance_proofs - Governance Proof Storage
-- ============================================================================
-- Stores governance proofs (G0/G1/G2) for batch transactions
-- Per HIGH-003: Real governance root computation

CREATE TABLE IF NOT EXISTS governance_proofs (
    proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL,

    -- Governance Level
    level               VARCHAR(5) NOT NULL,                  -- 'G0', 'G1', 'G2'

    -- Transaction Reference
    tx_hash             BYTEA NOT NULL,                       -- 32 bytes
    account_url         VARCHAR(512) NOT NULL,
    chain               VARCHAR(256),

    -- Proof Data
    receipt_root        BYTEA,                                -- 32 bytes
    authority_proof     BYTEA,                                -- Variable (for G1+)
    outcome_proof       BYTEA,                                -- Variable (for G2)

    -- Computed Hash
    proof_hash          BYTEA NOT NULL,                       -- 32 bytes - SHA256 of proof

    -- Raw Proof (JSON)
    proof_json          JSONB NOT NULL,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_gov_level CHECK (level IN ('G0', 'G1', 'G2'))
);

-- Indexes for governance_proofs
CREATE INDEX IF NOT EXISTS idx_gp_batch ON governance_proofs(batch_id);
CREATE INDEX IF NOT EXISTS idx_gp_level ON governance_proofs(level);
CREATE INDEX IF NOT EXISTS idx_gp_tx ON governance_proofs(tx_hash);
CREATE INDEX IF NOT EXISTS idx_gp_hash ON governance_proofs(proof_hash);

-- ============================================================================
-- TABLE 6: crypto_chain_proofs - L1-L4 Crypto Proof Storage
-- ============================================================================
-- Stores crypto chain proofs (L1-L4) for batch transactions
-- Per HIGH-002: Real BPT root extraction

CREATE TABLE IF NOT EXISTS crypto_chain_proofs (
    proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL,

    -- Transaction Reference
    tx_hash             BYTEA NOT NULL,                       -- 32 bytes
    account_url         VARCHAR(512) NOT NULL,

    -- L1: Account State
    account_hash        BYTEA,                                -- 32 bytes
    bpt_proof           BYTEA[],                              -- Merkle path

    -- L2: Partition
    partition_root      BYTEA,                                -- 32 bytes
    partition_proof     BYTEA[],                              -- Merkle path to DN

    -- L3: Directory Network
    dn_block_hash       BYTEA,                                -- 32 bytes
    validator_sigs      BYTEA,                                -- Aggregated signatures

    -- BPT Root (extracted from proof)
    bpt_root            BYTEA,                                -- 32 bytes

    -- Raw Proof (JSON)
    proof_json          JSONB NOT NULL,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for crypto_chain_proofs
CREATE INDEX IF NOT EXISTS idx_ccp_batch ON crypto_chain_proofs(batch_id);
CREATE INDEX IF NOT EXISTS idx_ccp_tx ON crypto_chain_proofs(tx_hash);
CREATE INDEX IF NOT EXISTS idx_ccp_bpt ON crypto_chain_proofs(bpt_root) WHERE bpt_root IS NOT NULL;

-- ============================================================================
-- VIEWS: Anchor Proof Status Views
-- ============================================================================

-- View: Complete batch status with attestations
CREATE OR REPLACE VIEW anchor_batch_status_view AS
SELECT
    ab.id AS batch_id,
    ab.merkle_root,
    ab.tx_count,
    ab.status,
    ab.created_at,

    -- Proof Data
    ab.bpt_root,
    ab.governance_root,
    ab.proof_data_included,

    -- Consensus Status
    ab.attestation_count,
    ab.quorum_reached,
    ab.consensus_completed_at,

    -- Attestation Details
    (SELECT COUNT(*) FROM batch_attestations ba WHERE ba.batch_id = ab.id) AS total_attestations,
    (SELECT COUNT(*) FROM batch_attestations ba WHERE ba.batch_id = ab.id AND ba.signature_valid = TRUE) AS valid_attestations,

    -- Governance Proofs
    (SELECT COUNT(*) FROM governance_proofs gp WHERE gp.batch_id = ab.id) AS governance_proof_count,

    -- Crypto Proofs
    (SELECT COUNT(*) FROM crypto_chain_proofs ccp WHERE ccp.batch_id = ab.id) AS crypto_proof_count

FROM anchor_batches ab;

-- View: Recent contract events
CREATE OR REPLACE VIEW recent_anchor_events_view AS
SELECT
    event_id,
    event_type,
    bundle_id,
    block_number,
    tx_hash,
    validator_address,
    merkle_verified,
    bls_verified,
    governance_verified,
    failure_reason,
    parsed_at
FROM anchor_events
ORDER BY block_number DESC, log_index DESC
LIMIT 1000;

-- View: Active consensus processes
CREATE OR REPLACE VIEW active_consensus_view AS
SELECT
    ce.entry_id,
    ce.batch_id,
    ce.state,
    ce.attestation_count,
    ce.required_count,
    ce.quorum_fraction,
    ce.start_time,
    ce.last_update,
    EXTRACT(EPOCH FROM (NOW() - ce.start_time)) AS duration_seconds,

    -- Attestation details
    (SELECT array_agg(validator_id) FROM batch_attestations ba WHERE ba.batch_id = ce.batch_id) AS validators

FROM consensus_entries ce
WHERE ce.state IN ('initiated', 'collecting');

-- ============================================================================
-- FUNCTIONS: Proof Computation Helpers
-- ============================================================================

-- Function: Compute governance proof hash
CREATE OR REPLACE FUNCTION compute_governance_proof_hash(
    p_level VARCHAR,
    p_tx_hash BYTEA,
    p_receipt_root BYTEA,
    p_authority_proof BYTEA,
    p_outcome_proof BYTEA
) RETURNS BYTEA AS $$
DECLARE
    v_data BYTEA;
BEGIN
    v_data := p_level::bytea || COALESCE(p_tx_hash, ''::bytea) ||
              COALESCE(p_receipt_root, ''::bytea) ||
              COALESCE(p_authority_proof, ''::bytea) ||
              COALESCE(p_outcome_proof, ''::bytea);
    RETURN sha256(v_data);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Compute contract merkle root (matches Solidity)
CREATE OR REPLACE FUNCTION compute_contract_merkle_root(
    p_operation_commitment BYTEA,
    p_cross_chain_commitment BYTEA,
    p_governance_root BYTEA
) RETURNS BYTEA AS $$
BEGIN
    -- SHA256 for testing (Keccak256 in Solidity)
    RETURN sha256(p_operation_commitment || p_cross_chain_commitment || p_governance_root);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- TRIGGERS: Auto-update timestamps
-- ============================================================================

-- Trigger: Update consensus_entries.last_update
CREATE OR REPLACE FUNCTION trigger_update_consensus_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_update := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER consensus_entries_update_timestamp
    BEFORE UPDATE ON consensus_entries
    FOR EACH ROW
    EXECUTE FUNCTION trigger_update_consensus_timestamp();

-- Trigger: Update event_watcher_checkpoints.updated_at
CREATE OR REPLACE FUNCTION trigger_update_checkpoint_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER event_watcher_checkpoints_update_timestamp
    BEFORE UPDATE ON event_watcher_checkpoints
    FOR EACH ROW
    EXECUTE FUNCTION trigger_update_checkpoint_timestamp();

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('005', 'Anchor Proof Enhancements for Phase 5 Production Hardening', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
