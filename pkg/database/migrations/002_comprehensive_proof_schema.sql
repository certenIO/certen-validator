-- Migration: 004_comprehensive_proof_schema.sql
-- Description: Comprehensive proof artifact storage schema
-- Created: 2025-01-XX
--
-- This migration implements the full proof storage schema for Certen Protocol
-- per PROOF_SCHEMA_DESIGN.md

BEGIN;

-- ============================================================================
-- TABLE 1: proof_artifacts - Master Proof Registry
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_artifacts (
    -- Primary Key
    proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Classification
    proof_type          VARCHAR(50) NOT NULL,
    proof_version       VARCHAR(20) NOT NULL DEFAULT '1.0',

    -- Transaction Reference (PRIMARY LOOKUP KEY)
    accum_tx_hash       VARCHAR(128) NOT NULL,
    account_url         VARCHAR(512) NOT NULL,

    -- Batch Reference
    batch_id            UUID REFERENCES anchor_batches(batch_id),
    batch_position      INTEGER,

    -- Anchor Reference
    anchor_id           UUID REFERENCES anchor_records(anchor_id),
    anchor_tx_hash      VARCHAR(128),
    anchor_block_number BIGINT,
    anchor_chain        VARCHAR(50),

    -- Merkle Inclusion
    merkle_root         BYTEA,
    leaf_hash           BYTEA,
    leaf_index          INTEGER,

    -- Governance Level
    gov_level           VARCHAR(10),

    -- Proof Class (pricing tier)
    proof_class         VARCHAR(20) NOT NULL,

    -- Validator Attribution
    validator_id        VARCHAR(128) NOT NULL,

    -- Status & Lifecycle
    status              VARCHAR(30) NOT NULL DEFAULT 'pending',
    verification_status VARCHAR(30),

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    anchored_at         TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,

    -- Full JSON Artifacts
    artifact_json       JSONB NOT NULL,

    -- Computed Fields
    artifact_hash       BYTEA NOT NULL,

    CONSTRAINT valid_proof_type CHECK (proof_type IN ('certen_anchor', 'chained', 'governance')),
    CONSTRAINT valid_gov_level CHECK (gov_level IS NULL OR gov_level IN ('G0', 'G1', 'G2')),
    CONSTRAINT valid_proof_class CHECK (proof_class IN ('on_cadence', 'on_demand'))
);

-- Primary access indexes
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_tx_hash ON proof_artifacts(accum_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_account ON proof_artifacts(account_url);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_batch ON proof_artifacts(batch_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_anchor_tx ON proof_artifacts(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_merkle_root ON proof_artifacts(merkle_root);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_validator ON proof_artifacts(validator_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_gov_level ON proof_artifacts(gov_level) WHERE gov_level IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_status ON proof_artifacts(status);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_created ON proof_artifacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_anchored ON proof_artifacts(anchored_at DESC) WHERE anchored_at IS NOT NULL;

-- Composite indexes
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_account_time ON proof_artifacts(account_url, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_batch_position ON proof_artifacts(batch_id, batch_position);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_type_status ON proof_artifacts(proof_type, status);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_chain_block ON proof_artifacts(anchor_chain, anchor_block_number);

-- JSONB index
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_artifact_gin ON proof_artifacts USING GIN (artifact_json);

-- ============================================================================
-- TABLE 2: chained_proof_layers - L1/L2/L3 Breakdown
-- ============================================================================

CREATE TABLE IF NOT EXISTS chained_proof_layers (
    layer_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    layer_number        INTEGER NOT NULL,
    layer_name          VARCHAR(50) NOT NULL,

    -- Layer 1 Fields (TX → BVN)
    bvn_partition       VARCHAR(50),
    receipt_anchor      BYTEA,

    -- Layer 2 Fields (BVN → DN)
    bvn_root            BYTEA,
    dn_root             BYTEA,
    anchor_sequence     BIGINT,
    bvn_partition_id    VARCHAR(50),

    -- Layer 3 Fields (DN → Consensus)
    dn_block_hash       BYTEA,
    dn_block_height     BIGINT,
    consensus_timestamp TIMESTAMPTZ,

    -- Full Layer Artifact
    layer_json          JSONB NOT NULL,

    -- Verification
    verified            BOOLEAN DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_layer_number CHECK (layer_number IN (1, 2, 3))
);

CREATE INDEX IF NOT EXISTS idx_chained_layers_proof ON chained_proof_layers(proof_id);
CREATE INDEX IF NOT EXISTS idx_chained_layers_number ON chained_proof_layers(proof_id, layer_number);
CREATE INDEX IF NOT EXISTS idx_chained_layers_dn_block ON chained_proof_layers(dn_block_height) WHERE layer_number = 3;
CREATE INDEX IF NOT EXISTS idx_chained_layers_bvn ON chained_proof_layers(bvn_partition) WHERE layer_number = 1;

-- ============================================================================
-- TABLE 3: governance_proof_levels - G0/G1/G2 Breakdown
-- ============================================================================

CREATE TABLE IF NOT EXISTS governance_proof_levels (
    level_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    gov_level           VARCHAR(10) NOT NULL,
    level_name          VARCHAR(50) NOT NULL,

    -- G0 Fields (Inclusion & Finality)
    block_height        BIGINT,
    finality_timestamp  TIMESTAMPTZ,
    anchor_height       BIGINT,
    is_anchored         BOOLEAN,

    -- G1 Fields (Governance Correctness)
    authority_url       VARCHAR(512),
    key_page_count      INTEGER,
    threshold_m         INTEGER,
    threshold_n         INTEGER,
    signature_count     INTEGER,

    -- G2 Fields (Outcome Binding)
    outcome_type        VARCHAR(100),
    outcome_hash        BYTEA,
    binding_enforced    BOOLEAN,

    -- Full Level Artifact
    level_json          JSONB NOT NULL,

    -- Verification
    verified            BOOLEAN DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_gov_level_check CHECK (gov_level IN ('G0', 'G1', 'G2'))
);

CREATE INDEX IF NOT EXISTS idx_gov_levels_proof ON governance_proof_levels(proof_id);
CREATE INDEX IF NOT EXISTS idx_gov_levels_level ON governance_proof_levels(proof_id, gov_level);
CREATE INDEX IF NOT EXISTS idx_gov_levels_authority ON governance_proof_levels(authority_url) WHERE gov_level = 'G1';
CREATE INDEX IF NOT EXISTS idx_gov_levels_outcome ON governance_proof_levels(outcome_type) WHERE gov_level = 'G2';

-- ============================================================================
-- TABLE 4: merkle_inclusion_proofs - Merkle Path Storage
-- ============================================================================

CREATE TABLE IF NOT EXISTS merkle_inclusion_proofs (
    inclusion_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    merkle_root         BYTEA NOT NULL,
    leaf_hash           BYTEA NOT NULL,
    leaf_index          INTEGER NOT NULL,
    tree_size           INTEGER NOT NULL,

    merkle_path         JSONB NOT NULL,

    verified            BOOLEAN DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_merkle_inclusion_proof ON merkle_inclusion_proofs(proof_id);
CREATE INDEX IF NOT EXISTS idx_merkle_inclusion_root ON merkle_inclusion_proofs(merkle_root);
CREATE INDEX IF NOT EXISTS idx_merkle_inclusion_leaf ON merkle_inclusion_proofs(leaf_hash);

-- ============================================================================
-- TABLE 5: validator_attestations - Multi-Validator Signatures
-- ============================================================================

CREATE TABLE IF NOT EXISTS validator_attestations (
    attestation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    proof_id            UUID REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,
    batch_id            UUID REFERENCES anchor_batches(batch_id) ON DELETE CASCADE,

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
-- TABLE 6: anchor_references - External Chain Anchors
-- ============================================================================

CREATE TABLE IF NOT EXISTS anchor_references (
    reference_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    target_chain        VARCHAR(50) NOT NULL,
    chain_id            VARCHAR(50) NOT NULL,
    network_name        VARCHAR(50) NOT NULL,

    anchor_tx_hash      VARCHAR(128) NOT NULL,
    anchor_block_number BIGINT NOT NULL,
    anchor_block_hash   VARCHAR(128),
    anchor_timestamp    TIMESTAMPTZ,

    contract_address    VARCHAR(128),

    confirmations       INTEGER DEFAULT 0,
    is_confirmed        BOOLEAN DEFAULT FALSE,
    confirmed_at        TIMESTAMPTZ,

    gas_used            BIGINT,
    gas_price_wei       VARCHAR(50),
    total_cost_wei      VARCHAR(50),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anchor_refs_proof ON anchor_references(proof_id);
CREATE INDEX IF NOT EXISTS idx_anchor_refs_tx ON anchor_references(anchor_tx_hash);
CREATE INDEX IF NOT EXISTS idx_anchor_refs_chain_block ON anchor_references(target_chain, anchor_block_number);
CREATE INDEX IF NOT EXISTS idx_anchor_refs_contract ON anchor_references(contract_address);
CREATE INDEX IF NOT EXISTS idx_anchor_refs_confirmed ON anchor_references(is_confirmed, confirmed_at);

-- ============================================================================
-- TABLE 7: receipt_steps - Merkle Receipt Path Steps
-- ============================================================================

CREATE TABLE IF NOT EXISTS receipt_steps (
    step_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    layer_id            UUID NOT NULL REFERENCES chained_proof_layers(layer_id) ON DELETE CASCADE,

    step_index          INTEGER NOT NULL,
    hash                BYTEA NOT NULL,
    is_right            BOOLEAN NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_receipt_steps_layer ON receipt_steps(layer_id);
CREATE INDEX IF NOT EXISTS idx_receipt_steps_order ON receipt_steps(layer_id, step_index);

-- ============================================================================
-- TABLE 8: validated_signatures - Governance Signature Details
-- ============================================================================

CREATE TABLE IF NOT EXISTS validated_signatures (
    sig_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level_id            UUID NOT NULL REFERENCES governance_proof_levels(level_id) ON DELETE CASCADE,

    signer_url          VARCHAR(512) NOT NULL,
    key_hash            BYTEA NOT NULL,
    public_key          BYTEA NOT NULL,
    key_type            VARCHAR(50) NOT NULL,

    signature           BYTEA NOT NULL,
    signed_hash         BYTEA NOT NULL,

    is_valid            BOOLEAN NOT NULL,
    validated_at        TIMESTAMPTZ,

    key_page_index      INTEGER,
    key_index           INTEGER,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_validated_sigs_level ON validated_signatures(level_id);
CREATE INDEX IF NOT EXISTS idx_validated_sigs_signer ON validated_signatures(signer_url);
CREATE INDEX IF NOT EXISTS idx_validated_sigs_key ON validated_signatures(key_hash);

-- ============================================================================
-- TABLE 9: proof_verifications - Verification Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_verifications (
    verification_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    verification_type   VARCHAR(50) NOT NULL,

    passed              BOOLEAN NOT NULL,
    error_message       TEXT,
    error_code          VARCHAR(50),

    verifier_id         VARCHAR(128),
    verification_method VARCHAR(100),

    duration_ms         INTEGER,

    artifacts_json      JSONB,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verifications_proof ON proof_verifications(proof_id);
CREATE INDEX IF NOT EXISTS idx_verifications_type ON proof_verifications(verification_type);
CREATE INDEX IF NOT EXISTS idx_verifications_passed ON proof_verifications(passed);
CREATE INDEX IF NOT EXISTS idx_verifications_time ON proof_verifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verifications_verifier ON proof_verifications(verifier_id);

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('002', 'Comprehensive proof artifact schema', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
