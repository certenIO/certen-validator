-- Migration: 005_intent_metadata.sql
-- Description: Add intent metadata columns to batch_transactions for Transaction Center integration
-- Created: 2026-01-26
--
-- This migration adds:
-- - Intent metadata columns to batch_transactions (chain info, addresses, amount)
-- - Indexes for Transaction Center queries
--
-- Per Transaction Center Data Migration Analysis

BEGIN;

-- ============================================================================
-- TABLE MODIFICATIONS: batch_transactions Intent Metadata
-- ============================================================================
-- Add columns for Firestore intent metadata to enable PostgreSQL-based queries

ALTER TABLE batch_transactions
ADD COLUMN IF NOT EXISTS from_chain VARCHAR(64),
ADD COLUMN IF NOT EXISTS to_chain VARCHAR(64),
ADD COLUMN IF NOT EXISTS from_address VARCHAR(256),
ADD COLUMN IF NOT EXISTS to_address VARCHAR(256),
ADD COLUMN IF NOT EXISTS amount VARCHAR(78),
ADD COLUMN IF NOT EXISTS token_symbol VARCHAR(32),
ADD COLUMN IF NOT EXISTS adi_url VARCHAR(256),
ADD COLUMN IF NOT EXISTS created_at_client TIMESTAMPTZ;

-- ============================================================================
-- INDEXES: Transaction Center Query Optimization
-- ============================================================================

-- Primary lookup by user and intent (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_batch_tx_user_intent
ON batch_transactions(user_id, intent_id)
WHERE user_id IS NOT NULL;

-- User's transactions ordered by time (Operations mode)
CREATE INDEX IF NOT EXISTS idx_batch_tx_user_created
ON batch_transactions(user_id, created_at DESC)
WHERE user_id IS NOT NULL;

-- Chain-based filtering for audit
CREATE INDEX IF NOT EXISTS idx_batch_tx_chains
ON batch_transactions(from_chain, to_chain)
WHERE from_chain IS NOT NULL;

-- Token-based filtering
CREATE INDEX IF NOT EXISTS idx_batch_tx_token
ON batch_transactions(token_symbol)
WHERE token_symbol IS NOT NULL;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('005_intent_metadata', 'Add intent metadata for Transaction Center integration', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
