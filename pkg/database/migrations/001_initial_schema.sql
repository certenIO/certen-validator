-- Migration: 001_initial_schema.sql
-- Description: Initial database schema for Certen Validator
-- Created: 2025-01-XX
--
-- This migration creates the core tables for:
-- - anchor_batches: Batch management for transaction anchoring
-- - batch_transactions: Individual transactions within batches
-- - anchor_records: Records of anchors on external chains
-- - certen_anchor_proofs: Complete Certen anchor proofs
-- - validator_attestations: Multi-validator attestations
-- - schema_migrations: Migration tracking

BEGIN;

-- ============================================================================
-- TABLE 0: schema_migrations - Migration Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version         VARCHAR(20) PRIMARY KEY,
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
    target_chain    VARCHAR(50) NOT NULL DEFAULT 'ethereum',
    anchor_tx_hash  VARCHAR(66),
    anchor_block_num BIGINT,
    gas_used        BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    anchored_at     TIMESTAMPTZ,
    confirmed_at    TIMESTAMPTZ,

    CONSTRAINT valid_batch_type CHECK (batch_type IN ('on_cadence', 'on_demand')),
    CONSTRAINT valid_batch_status CHECK (status IN ('pending', 'closed', 'anchoring', 'anchored', 'confirmed', 'failed'))
);

-- Indexes for anchor_batches
CREATE INDEX IF NOT EXISTS idx_batches_status ON anchor_batches(status);
CREATE INDEX IF NOT EXISTS idx_batches_type ON anchor_batches(batch_type);
CREATE INDEX IF NOT EXISTS idx_batches_chain ON anchor_batches(target_chain);
CREATE INDEX IF NOT EXISTS idx_batches_created ON anchor_batches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_batches_pending ON anchor_batches(batch_type, target_chain, status) WHERE status = 'pending';

-- ============================================================================
-- TABLE 2: batch_transactions - Transactions within Batches
-- ============================================================================

CREATE TABLE IF NOT EXISTS batch_transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id        UUID NOT NULL REFERENCES anchor_batches(id) ON DELETE CASCADE,
    accum_tx_hash   VARCHAR(128) NOT NULL,
    account_url     VARCHAR(512) NOT NULL,
    leaf_hash       BYTEA NOT NULL,
    leaf_index      INTEGER NOT NULL,
    merkle_path     TEXT,
    proof_json      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_tx_in_batch UNIQUE (batch_id, accum_tx_hash)
);

-- Indexes for batch_transactions
CREATE INDEX IF NOT EXISTS idx_batch_tx_batch ON batch_transactions(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_tx_hash ON batch_transactions(accum_tx_hash);
CREATE INDEX IF NOT EXISTS idx_batch_tx_account ON batch_transactions(account_url);
CREATE INDEX IF NOT EXISTS idx_batch_tx_created ON batch_transactions(created_at DESC);

-- ============================================================================
-- TABLE 3: anchor_records - External Chain Anchor Records
-- ============================================================================

CREATE TABLE IF NOT EXISTS anchor_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id        UUID NOT NULL REFERENCES anchor_batches(id),
    target_chain    VARCHAR(50) NOT NULL,
    chain_id        BIGINT NOT NULL,
    tx_hash         VARCHAR(66) NOT NULL,
    block_number    BIGINT NOT NULL,
    block_hash      VARCHAR(66),
    confirmations   INTEGER NOT NULL DEFAULT 0,
    required_conf   INTEGER NOT NULL DEFAULT 12,
    gas_used        BIGINT,
    gas_price       VARCHAR(50),
    status          VARCHAR(30) NOT NULL DEFAULT 'pending',
    is_final        BOOLEAN NOT NULL DEFAULT FALSE,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at    TIMESTAMPTZ,

    CONSTRAINT valid_anchor_chain CHECK (target_chain IN ('ethereum', 'bitcoin', 'polygon', 'arbitrum')),
    CONSTRAINT valid_anchor_status CHECK (status IN ('pending', 'confirming', 'finalized', 'failed'))
);

-- Indexes for anchor_records
CREATE INDEX IF NOT EXISTS idx_anchors_batch ON anchor_records(batch_id);
CREATE INDEX IF NOT EXISTS idx_anchors_tx_hash ON anchor_records(tx_hash);
CREATE INDEX IF NOT EXISTS idx_anchors_status ON anchor_records(status);
CREATE INDEX IF NOT EXISTS idx_anchors_chain ON anchor_records(target_chain);
CREATE INDEX IF NOT EXISTS idx_anchors_unconfirmed ON anchor_records(is_final, status) WHERE is_final = FALSE AND status NOT IN ('failed', 'finalized');

-- ============================================================================
-- TABLE 4: certen_anchor_proofs - Complete Certen Anchor Proofs
-- ============================================================================

CREATE TABLE IF NOT EXISTS certen_anchor_proofs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    accum_tx_hash           VARCHAR(128) NOT NULL,
    account_url             VARCHAR(512) NOT NULL,
    batch_id                UUID NOT NULL REFERENCES anchor_batches(id),
    anchor_id               UUID REFERENCES anchor_records(id),
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

-- Indexes for certen_anchor_proofs
CREATE INDEX IF NOT EXISTS idx_proofs_tx_hash ON certen_anchor_proofs(accum_tx_hash);
CREATE INDEX IF NOT EXISTS idx_proofs_account ON certen_anchor_proofs(account_url);
CREATE INDEX IF NOT EXISTS idx_proofs_batch ON certen_anchor_proofs(batch_id);
CREATE INDEX IF NOT EXISTS idx_proofs_anchor ON certen_anchor_proofs(anchor_id) WHERE anchor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proofs_gov_level ON certen_anchor_proofs(governance_level);
CREATE INDEX IF NOT EXISTS idx_proofs_verified ON certen_anchor_proofs(is_verified);
CREATE INDEX IF NOT EXISTS idx_proofs_created ON certen_anchor_proofs(created_at DESC);

-- ============================================================================
-- TABLE 5: validator_attestations - Multi-Validator Attestations (basic)
-- ============================================================================

CREATE TABLE IF NOT EXISTS validator_attestations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id        UUID NOT NULL REFERENCES certen_anchor_proofs(id) ON DELETE CASCADE,
    validator_id    VARCHAR(256) NOT NULL,
    validator_addr  VARCHAR(42) NOT NULL,
    signature       BYTEA NOT NULL,
    signed_at       TIMESTAMPTZ NOT NULL,
    is_valid        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_validator_proof UNIQUE (proof_id, validator_id)
);

-- Indexes for validator_attestations
CREATE INDEX IF NOT EXISTS idx_attestations_proof ON validator_attestations(proof_id);
CREATE INDEX IF NOT EXISTS idx_attestations_validator ON validator_attestations(validator_id);
CREATE INDEX IF NOT EXISTS idx_attestations_valid ON validator_attestations(is_valid) WHERE is_valid = TRUE;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('001', 'Initial database schema for Certen Validator', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
