-- Migration: 006_add_merkle_path.sql
-- Description: Add merkle_path JSONB to proof_artifacts for MerkleTreeVisualization
-- Created: 2026-01-27
--
-- This adds the merkle_path column to store the Merkle inclusion proof path.
-- Format: [{"hash": "0x...", "right": true}, {"hash": "0x...", "right": false}, ...]
-- Used by MerkleTreeVisualization component in the web app.

-- ============================================================================
-- ADD MERKLE_PATH TO PROOF_ARTIFACTS
-- ============================================================================

-- Add merkle_path column to proof_artifacts
-- Stores the array of sibling hashes and directions for Merkle inclusion proof
ALTER TABLE proof_artifacts
ADD COLUMN IF NOT EXISTS merkle_path JSONB;

-- Add index for queries that check if merkle_path exists
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_has_merkle_path
ON proof_artifacts((merkle_path IS NOT NULL))
WHERE merkle_path IS NOT NULL;

-- ============================================================================
-- ADD RECEIPT_ENTRIES TO CHAINED_PROOF_LAYERS
-- ============================================================================

-- Add receipt_entries column to chained_proof_layers
-- Stores the receipt entries (hash + direction) for each layer
-- Used by ProofChainDiagram component in the web app
ALTER TABLE chained_proof_layers
ADD COLUMN IF NOT EXISTS receipt_entries JSONB;

-- Add source_hash and target_hash for cleaner API mapping
ALTER TABLE chained_proof_layers
ADD COLUMN IF NOT EXISTS source_hash BYTEA;

ALTER TABLE chained_proof_layers
ADD COLUMN IF NOT EXISTS target_hash BYTEA;

-- ============================================================================
-- RECORD MIGRATION
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('006_add_merkle_path', 'Add merkle_path to proof_artifacts and receipt_entries to chained_proof_layers', NOW())
ON CONFLICT (version) DO NOTHING;
