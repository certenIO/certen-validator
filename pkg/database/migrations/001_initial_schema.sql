-- Migration: 001_initial_schema.sql
-- Description: Complete consolidated database schema for Certen Validator
-- Created: 2026-01-22
--
-- This is a CONSOLIDATED schema containing all tables in their final form.
-- No incremental migrations needed - this is the complete schema.

-- ============================================================================
-- TABLE 0: schema_migrations - Migration Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version         VARCHAR(64) PRIMARY KEY,
    description     TEXT NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- TABLE 1: anchor_batches - Batch Management
-- ============================================================================

CREATE TABLE IF NOT EXISTS anchor_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_type      VARCHAR(20) NOT NULL DEFAULT 'on_cadence',
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    merkle_root     BYTEA,
    tx_count        INTEGER NOT NULL DEFAULT 0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    target_chain    VARCHAR(50) NOT NULL DEFAULT 'ethereum',
    anchor_tx_hash  VARCHAR(66),
    anchor_block_num BIGINT,
    gas_used        BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    anchored_at     TIMESTAMPTZ,
    confirmed_at    TIMESTAMPTZ,
    -- Batch timing and source tracking
    batch_start_time TIMESTAMPTZ DEFAULT NOW(),
    batch_end_time  TIMESTAMPTZ,
    validator_id    VARCHAR(100),
    error_message   TEXT,
    -- Accumulate block reference
    accumulate_block_height BIGINT,
    accumulate_block_hash VARCHAR(66),
    -- Phase 5 additions
    bpt_root        BYTEA,
    governance_root BYTEA,
    proof_data_included BOOLEAN DEFAULT FALSE,
    attestation_count INTEGER DEFAULT 0,
    aggregated_signature BYTEA,
    aggregated_public_key BYTEA,
    quorum_reached  BOOLEAN DEFAULT FALSE,
    consensus_completed_at TIMESTAMPTZ,

    CONSTRAINT valid_batch_type CHECK (batch_type IN ('on_cadence', 'on_demand')),
    CONSTRAINT valid_batch_status CHECK (status IN ('pending', 'closed', 'anchoring', 'anchored', 'confirmed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_batches_status ON anchor_batches(status);
CREATE INDEX IF NOT EXISTS idx_batches_type ON anchor_batches(batch_type);
CREATE INDEX IF NOT EXISTS idx_batches_chain ON anchor_batches(target_chain);
CREATE INDEX IF NOT EXISTS idx_batches_created ON anchor_batches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_batches_pending ON anchor_batches(batch_type, target_chain, status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_anchor_batches_bpt_root ON anchor_batches(bpt_root) WHERE bpt_root IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_anchor_batches_governance_root ON anchor_batches(governance_root) WHERE governance_root IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_anchor_batches_quorum ON anchor_batches(quorum_reached) WHERE quorum_reached = TRUE;

-- ============================================================================
-- TABLE 2: batch_transactions - Transactions within Batches
-- ============================================================================

CREATE TABLE IF NOT EXISTS batch_transactions (
    id              BIGSERIAL PRIMARY KEY,
    batch_id        UUID NOT NULL REFERENCES anchor_batches(id) ON DELETE CASCADE,
    accumulate_tx_hash VARCHAR(128) NOT NULL,
    account_url     VARCHAR(512) NOT NULL,
    tree_index      INTEGER NOT NULL,
    merkle_path     JSONB,
    transaction_hash BYTEA,
    chained_proof   JSONB,
    chained_proof_valid BOOLEAN DEFAULT FALSE,
    governance_proof JSONB,
    governance_level VARCHAR(10),
    governance_valid BOOLEAN DEFAULT FALSE,
    intent_type     VARCHAR(100),
    intent_data     JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_tx_in_batch UNIQUE (batch_id, accumulate_tx_hash),
    CONSTRAINT valid_gov_level_tx CHECK (governance_level IS NULL OR governance_level IN ('G0', 'G1', 'G2'))
);

CREATE INDEX IF NOT EXISTS idx_batch_tx_batch ON batch_transactions(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_tx_hash ON batch_transactions(accumulate_tx_hash);
CREATE INDEX IF NOT EXISTS idx_batch_tx_account ON batch_transactions(account_url);
CREATE INDEX IF NOT EXISTS idx_batch_tx_created ON batch_transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_batch_tx_tree_index ON batch_transactions(batch_id, tree_index);

-- ============================================================================
-- TABLE 3: anchor_records - External Chain Anchor Records (Final Schema)
-- ============================================================================

CREATE TABLE IF NOT EXISTS anchor_records (
    anchor_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL REFERENCES anchor_batches(id),
    target_chain        VARCHAR(50) NOT NULL,
    chain_id            VARCHAR(50),
    network_name        VARCHAR(50),
    contract_address    VARCHAR(66),
    anchor_tx_hash      VARCHAR(66) NOT NULL,
    anchor_block_number BIGINT NOT NULL,
    anchor_block_hash   VARCHAR(66),
    anchor_timestamp    TIMESTAMPTZ,
    merkle_root         VARCHAR(66),
    accumulate_height   BIGINT,
    operation_commitment VARCHAR(66),
    cross_chain_commitment VARCHAR(66),
    governance_root     VARCHAR(66),
    confirmations       INTEGER NOT NULL DEFAULT 0,
    required_confirmations INTEGER NOT NULL DEFAULT 12,
    confirmed_at        TIMESTAMPTZ,
    is_final            BOOLEAN NOT NULL DEFAULT FALSE,
    gas_used            BIGINT,
    gas_price_wei       VARCHAR(50),
    total_cost_wei      VARCHAR(50),
    total_cost_usd      NUMERIC(20, 8),
    validator_id        VARCHAR(256),
    status              VARCHAR(30) NOT NULL DEFAULT 'pending',
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at        TIMESTAMPTZ,

    CONSTRAINT valid_anchor_chain CHECK (target_chain IN ('ethereum', 'bitcoin', 'polygon', 'arbitrum')),
    CONSTRAINT valid_anchor_status CHECK (status IN ('pending', 'confirming', 'finalized', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_anchors_batch ON anchor_records(batch_id);
CREATE INDEX IF NOT EXISTS idx_anchors_tx_hash ON anchor_records(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_anchors_status ON anchor_records(status);
CREATE INDEX IF NOT EXISTS idx_anchors_chain ON anchor_records(target_chain);
CREATE INDEX IF NOT EXISTS idx_anchors_unconfirmed ON anchor_records(is_final, status) WHERE is_final = FALSE AND status NOT IN ('failed', 'finalized');
CREATE INDEX IF NOT EXISTS idx_anchors_validator ON anchor_records(validator_id);
CREATE INDEX IF NOT EXISTS idx_anchors_confirmations ON anchor_records(confirmations, required_confirmations) WHERE is_final = FALSE;

-- ============================================================================
-- TABLE 4: certen_anchor_proofs - Complete Certen Anchor Proofs
-- ============================================================================

CREATE TABLE IF NOT EXISTS certen_anchor_proofs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    accum_tx_hash           VARCHAR(128) NOT NULL,
    account_url             VARCHAR(512) NOT NULL,
    batch_id                UUID NOT NULL REFERENCES anchor_batches(id),
    anchor_id               UUID REFERENCES anchor_records(anchor_id),
    governance_level        VARCHAR(10) NOT NULL DEFAULT 'G0',
    proof_version           VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    chained_proof_json      TEXT,
    governance_proof_json   TEXT,
    anchor_ref_json         TEXT,
    merkle_proof_json       TEXT,
    full_proof_json         TEXT,
    proof_hash              BYTEA,
    is_verified             BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_gov_level CHECK (governance_level IN ('G0', 'G1', 'G2'))
);

CREATE INDEX IF NOT EXISTS idx_proofs_tx_hash ON certen_anchor_proofs(accum_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proofs_account ON certen_anchor_proofs(account_url);
CREATE INDEX IF NOT EXISTS idx_proofs_batch ON certen_anchor_proofs(batch_id);
CREATE INDEX IF NOT EXISTS idx_proofs_anchor ON certen_anchor_proofs(anchor_id) WHERE anchor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proofs_gov_level ON certen_anchor_proofs(governance_level);
CREATE INDEX IF NOT EXISTS idx_proofs_verified ON certen_anchor_proofs(is_verified);
CREATE INDEX IF NOT EXISTS idx_proofs_created ON certen_anchor_proofs(created_at DESC);

-- ============================================================================
-- TABLE 5: proof_artifacts - Master Proof Registry
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_artifacts (
    proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_type          VARCHAR(50) NOT NULL,
    proof_version       VARCHAR(20) NOT NULL DEFAULT '1.0',
    accum_tx_hash       VARCHAR(128) NOT NULL,
    account_url         VARCHAR(512) NOT NULL,
    batch_id            UUID REFERENCES anchor_batches(id),
    batch_position      INTEGER,
    anchor_id           UUID REFERENCES anchor_records(anchor_id),
    anchor_tx_hash      VARCHAR(128),
    anchor_block_number BIGINT,
    anchor_chain        VARCHAR(50),
    merkle_root         BYTEA,
    leaf_hash           BYTEA,
    leaf_index          INTEGER,
    gov_level           VARCHAR(10),
    proof_class         VARCHAR(20) NOT NULL,
    validator_id        VARCHAR(128) NOT NULL,
    status              VARCHAR(30) NOT NULL DEFAULT 'pending',
    verification_status VARCHAR(30),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anchored_at         TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    artifact_json       JSONB NOT NULL,
    artifact_hash       BYTEA NOT NULL,

    CONSTRAINT valid_proof_type CHECK (proof_type IN ('certen_anchor', 'chained', 'governance')),
    CONSTRAINT valid_gov_level CHECK (gov_level IS NULL OR gov_level IN ('G0', 'G1', 'G2')),
    CONSTRAINT valid_proof_class CHECK (proof_class IN ('on_cadence', 'on_demand'))
);

CREATE INDEX IF NOT EXISTS idx_proof_artifacts_tx_hash ON proof_artifacts(accum_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_account ON proof_artifacts(account_url);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_batch ON proof_artifacts(batch_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_anchor_tx ON proof_artifacts(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_merkle_root ON proof_artifacts(merkle_root);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_validator ON proof_artifacts(validator_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_gov_level ON proof_artifacts(gov_level) WHERE gov_level IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_status ON proof_artifacts(status);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_created ON proof_artifacts(created_at DESC);

-- ============================================================================
-- TABLE 6: validator_attestations - Multi-Validator Signatures (Complete)
-- ============================================================================

CREATE TABLE IF NOT EXISTS validator_attestations (
    attestation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,
    batch_id            UUID REFERENCES anchor_batches(id) ON DELETE CASCADE,
    validator_id        VARCHAR(128) NOT NULL,
    validator_pubkey    BYTEA NOT NULL,
    attested_hash       BYTEA NOT NULL,
    signature           BYTEA NOT NULL,
    anchor_tx_hash      VARCHAR(128),
    merkle_root         BYTEA,
    block_number        BIGINT,
    signature_valid     BOOLEAN DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,
    attested_at         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT attestation_has_parent CHECK (proof_id IS NOT NULL OR batch_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_attestations_proof ON validator_attestations(proof_id);
CREATE INDEX IF NOT EXISTS idx_attestations_batch ON validator_attestations(batch_id);
CREATE INDEX IF NOT EXISTS idx_attestations_validator ON validator_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_attestations_anchor ON validator_attestations(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_attestations_merkle ON validator_attestations(merkle_root);
CREATE INDEX IF NOT EXISTS idx_attestations_time ON validator_attestations(attested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_unique_proof ON validator_attestations(proof_id, validator_id) WHERE proof_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_unique_batch ON validator_attestations(batch_id, validator_id) WHERE batch_id IS NOT NULL;

-- ============================================================================
-- TABLE 7: batch_attestations - Batch-level BLS Attestations
-- ============================================================================

CREATE TABLE IF NOT EXISTS batch_attestations (
    attestation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL,
    validator_id        VARCHAR(256) NOT NULL,
    merkle_root         BYTEA NOT NULL,
    bls_signature       BYTEA NOT NULL,
    bls_public_key      BYTEA NOT NULL,
    tx_count            INTEGER NOT NULL,
    block_height        BIGINT NOT NULL,
    attestation_time    TIMESTAMPTZ NOT NULL,
    signature_valid     BOOLEAN,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_batch_validator_attestation UNIQUE (batch_id, validator_id)
);

CREATE INDEX IF NOT EXISTS idx_ba_batch ON batch_attestations(batch_id);
CREATE INDEX IF NOT EXISTS idx_ba_validator ON batch_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_ba_valid ON batch_attestations(signature_valid) WHERE signature_valid = TRUE;
CREATE INDEX IF NOT EXISTS idx_ba_time ON batch_attestations(attestation_time DESC);

-- ============================================================================
-- TABLE 8: consensus_entries - Consensus State Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS consensus_entries (
    entry_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id            UUID NOT NULL UNIQUE,
    merkle_root         BYTEA NOT NULL,
    anchor_tx_hash      VARCHAR(66),
    block_number        BIGINT,
    tx_count            INTEGER NOT NULL,
    state               VARCHAR(30) NOT NULL DEFAULT 'initiated',
    attestation_count   INTEGER NOT NULL DEFAULT 0,
    required_count      INTEGER NOT NULL,
    quorum_fraction     NUMERIC(5, 4) NOT NULL DEFAULT 0.667,
    aggregate_signature BYTEA,
    aggregate_pubkey    BYTEA,
    start_time          TIMESTAMPTZ NOT NULL,
    last_update         TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    result_json         JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_consensus_state CHECK (
        state IN ('initiated', 'collecting', 'quorum_met', 'completed', 'failed', 'timeout')
    )
);

CREATE INDEX IF NOT EXISTS idx_ce_state ON consensus_entries(state);
CREATE INDEX IF NOT EXISTS idx_ce_active ON consensus_entries(state) WHERE state IN ('initiated', 'collecting');
CREATE INDEX IF NOT EXISTS idx_ce_completed ON consensus_entries(completed_at DESC) WHERE completed_at IS NOT NULL;

-- ============================================================================
-- TABLE 9: proof_bundles - Self-contained Verification Bundles
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_bundles (
    bundle_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,
    bundle_format       VARCHAR(20) NOT NULL DEFAULT 'certen_v1',
    bundle_version      VARCHAR(20) NOT NULL DEFAULT '1.0',
    bundle_data         BYTEA NOT NULL,
    bundle_hash         BYTEA NOT NULL,
    bundle_size_bytes   INTEGER NOT NULL,
    includes_chained    BOOLEAN NOT NULL DEFAULT TRUE,
    includes_governance BOOLEAN NOT NULL DEFAULT TRUE,
    includes_merkle     BOOLEAN NOT NULL DEFAULT TRUE,
    includes_anchor     BOOLEAN NOT NULL DEFAULT TRUE,
    attestation_count   INTEGER NOT NULL DEFAULT 0,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_bundle_format CHECK (bundle_format IN ('certen_v1', 'json', 'cbor'))
);

CREATE INDEX IF NOT EXISTS idx_bundles_proof ON proof_bundles(proof_id);
CREATE INDEX IF NOT EXISTS idx_bundles_created ON proof_bundles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bundles_hash ON proof_bundles(bundle_hash);

-- ============================================================================
-- TABLE 10: api_keys - External API Access Control
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    key_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash            BYTEA NOT NULL,
    client_name         VARCHAR(256) NOT NULL,
    client_type         VARCHAR(50) NOT NULL,
    can_read_proofs     BOOLEAN NOT NULL DEFAULT TRUE,
    can_request_proofs  BOOLEAN NOT NULL DEFAULT FALSE,
    can_bulk_download   BOOLEAN NOT NULL DEFAULT FALSE,
    rate_limit_per_min  INTEGER NOT NULL DEFAULT 100,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at          TIMESTAMPTZ,
    description         TEXT,
    contact_email       VARCHAR(256),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ,

    CONSTRAINT valid_client_type CHECK (client_type IN (
        'auditor', 'service', 'institution', 'developer', 'internal'
    ))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- TABLE 11: proof_requests - On-demand Proof Request Queue
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_requests (
    request_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    accum_tx_hash       VARCHAR(128),
    account_url         VARCHAR(512),
    proof_class         VARCHAR(20) NOT NULL,
    governance_level    VARCHAR(10),
    api_key_id          UUID REFERENCES api_keys(key_id),
    callback_url        VARCHAR(1024),
    status              VARCHAR(30) NOT NULL DEFAULT 'pending',
    proof_id            UUID REFERENCES proof_artifacts(proof_id),
    error_message       TEXT,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at        TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,

    CONSTRAINT valid_request_class CHECK (proof_class IN ('on_cadence', 'on_demand')),
    CONSTRAINT valid_request_gov_level CHECK (governance_level IS NULL OR governance_level IN ('G0', 'G1', 'G2')),
    CONSTRAINT valid_request_status CHECK (status IN (
        'pending', 'processing', 'completed', 'failed', 'cancelled'
    )),
    CONSTRAINT request_has_target CHECK (accum_tx_hash IS NOT NULL OR account_url IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_requests_status ON proof_requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_tx ON proof_requests(accum_tx_hash) WHERE accum_tx_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_requests_pending ON proof_requests(created_at) WHERE status = 'pending';

-- ============================================================================
-- TABLE 12: external_chain_results - Level 4 Execution Results
-- ============================================================================

CREATE TABLE IF NOT EXISTS external_chain_results (
    result_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id                UUID REFERENCES proof_artifacts(proof_id),
    bundle_id               BYTEA NOT NULL,
    operation_id            BYTEA NOT NULL,
    chain_type              VARCHAR(50) NOT NULL,
    chain_id                BIGINT NOT NULL,
    network_name            VARCHAR(50),
    tx_hash                 BYTEA NOT NULL,
    tx_index                INTEGER NOT NULL,
    tx_gas_used             BIGINT NOT NULL,
    tx_from_address         BYTEA NOT NULL,
    tx_to_address           BYTEA,
    block_number            BIGINT NOT NULL,
    block_hash              BYTEA NOT NULL,
    block_timestamp         TIMESTAMPTZ NOT NULL,
    state_root              BYTEA NOT NULL,
    transactions_root       BYTEA NOT NULL,
    receipts_root           BYTEA NOT NULL,
    execution_status        SMALLINT NOT NULL,
    execution_success       BOOLEAN NOT NULL,
    revert_reason           TEXT,
    contract_address        BYTEA,
    logs_json               JSONB,
    confirmation_blocks     INTEGER NOT NULL DEFAULT 0,
    required_confirmations  INTEGER NOT NULL DEFAULT 12,
    is_finalized            BOOLEAN NOT NULL DEFAULT FALSE,
    finalized_at            TIMESTAMPTZ,
    result_hash             BYTEA NOT NULL,
    observer_validator_id   VARCHAR(256) NOT NULL,
    observed_at             TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_chain_type CHECK (chain_type IN ('ethereum', 'bitcoin', 'solana', 'polygon')),
    CONSTRAINT valid_execution_status CHECK (execution_status IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_ecr_bundle ON external_chain_results(bundle_id);
CREATE INDEX IF NOT EXISTS idx_ecr_tx_hash ON external_chain_results(tx_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_result_hash ON external_chain_results(result_hash);
CREATE INDEX IF NOT EXISTS idx_ecr_finalized ON external_chain_results(is_finalized) WHERE is_finalized = TRUE;

-- ============================================================================
-- TABLE 13: bls_result_attestations - Individual BLS Attestations
-- ============================================================================

CREATE TABLE IF NOT EXISTS bls_result_attestations (
    attestation_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,
    result_hash             BYTEA NOT NULL,
    bundle_id               BYTEA NOT NULL,
    message_hash            BYTEA NOT NULL,
    validator_id            VARCHAR(256) NOT NULL,
    validator_address       BYTEA NOT NULL,
    validator_index         INTEGER NOT NULL,
    bls_signature           BYTEA NOT NULL,
    bls_public_key          BYTEA NOT NULL,
    signature_domain        VARCHAR(50) NOT NULL DEFAULT 'CERTEN_RESULT_ATTESTATION_V1',
    attested_block_number   BIGINT NOT NULL,
    attested_block_hash     BYTEA,
    confirmations_at_attest INTEGER NOT NULL,
    signature_valid         BOOLEAN,
    verified_at             TIMESTAMPTZ,
    verification_error      TEXT,
    attestation_time        TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_validator_attestation UNIQUE (result_id, validator_id)
);

CREATE INDEX IF NOT EXISTS idx_bra_result ON bls_result_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_bra_validator ON bls_result_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_bra_bundle ON bls_result_attestations(bundle_id);

-- ============================================================================
-- TABLE 14: aggregated_bls_attestations - Aggregated BLS Signatures
-- ============================================================================

CREATE TABLE IF NOT EXISTS aggregated_bls_attestations (
    aggregation_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id               UUID NOT NULL REFERENCES external_chain_results(result_id) ON DELETE CASCADE,
    result_hash             BYTEA NOT NULL,
    bundle_id               BYTEA NOT NULL,
    message_hash            BYTEA NOT NULL,
    attested_block_number   BIGINT NOT NULL,
    aggregate_signature     BYTEA NOT NULL,
    aggregate_public_key    BYTEA,
    validator_bitfield      BYTEA NOT NULL,
    validator_count         INTEGER NOT NULL,
    validator_addresses     BYTEA[] NOT NULL,
    validator_indices       INTEGER[] NOT NULL,
    attestation_ids         UUID[] NOT NULL,
    total_voting_power      NUMERIC(78, 0) NOT NULL,
    signed_voting_power     NUMERIC(78, 0) NOT NULL,
    voting_power_percentage NUMERIC(5, 2) NOT NULL,
    threshold_numerator     INTEGER NOT NULL DEFAULT 2,
    threshold_denominator   INTEGER NOT NULL DEFAULT 3,
    threshold_met           BOOLEAN NOT NULL,
    first_attestation_at    TIMESTAMPTZ NOT NULL,
    last_attestation_at     TIMESTAMPTZ NOT NULL,
    finalized_at            TIMESTAMPTZ,
    aggregate_verified      BOOLEAN,
    verified_at             TIMESTAMPTZ,
    verification_error      TEXT,
    aggregation_hash        BYTEA NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_threshold CHECK (threshold_numerator > 0 AND threshold_denominator > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_aba_result ON aggregated_bls_attestations(result_id);
CREATE INDEX IF NOT EXISTS idx_aba_bundle ON aggregated_bls_attestations(bundle_id);
CREATE INDEX IF NOT EXISTS idx_aba_threshold ON aggregated_bls_attestations(threshold_met) WHERE threshold_met = TRUE;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('001_initial_schema', 'Complete consolidated database schema for Certen Validator', NOW())
ON CONFLICT (version) DO NOTHING;
