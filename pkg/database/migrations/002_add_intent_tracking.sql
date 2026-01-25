-- Migration: 002_add_intent_tracking.sql
-- Description: Add user_id and intent_id columns for Firestore intent linking
-- Created: 2026-01-25
--
-- This migration adds tracking columns to link PostgreSQL proofs back to Firestore intents
-- for the web app UI integration.

-- ============================================================================
-- ADD INTENT TRACKING TO proof_artifacts
-- ============================================================================

-- Add user_id column to track which user submitted the intent
ALTER TABLE proof_artifacts ADD COLUMN IF NOT EXISTS user_id VARCHAR(256);

-- Add intent_id column to link back to Firestore intent document
ALTER TABLE proof_artifacts ADD COLUMN IF NOT EXISTS intent_id VARCHAR(256);

-- Create partial indexes for efficient lookups (only on non-null values)
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_user ON proof_artifacts(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_intent ON proof_artifacts(intent_id) WHERE intent_id IS NOT NULL;

-- ============================================================================
-- ADD INTENT TRACKING TO batch_transactions
-- ============================================================================

-- Add user_id column to track which user submitted the transaction
ALTER TABLE batch_transactions ADD COLUMN IF NOT EXISTS user_id VARCHAR(256);

-- Add intent_id column to link back to Firestore intent document
ALTER TABLE batch_transactions ADD COLUMN IF NOT EXISTS intent_id VARCHAR(256);

-- Create partial indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_batch_tx_user ON batch_transactions(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_batch_tx_intent ON batch_transactions(intent_id) WHERE intent_id IS NOT NULL;

-- ============================================================================
-- RECORD MIGRATION
-- ============================================================================

INSERT INTO schema_migrations (version, description)
VALUES ('002_add_intent_tracking', 'Add user_id and intent_id for Firestore linking')
ON CONFLICT (version) DO NOTHING;
