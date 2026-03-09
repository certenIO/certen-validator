-- Migration 009: Intent Lifecycle Multi-Chain Support
-- Adds columns to support multi-leg intents spanning multiple target chains (GAP 8)

ALTER TABLE intent_lifecycle ADD COLUMN IF NOT EXISTS target_chains TEXT[];
ALTER TABLE intent_lifecycle ADD COLUMN IF NOT EXISTS leg_count INTEGER DEFAULT 1;
ALTER TABLE intent_lifecycle ADD COLUMN IF NOT EXISTS execution_mode VARCHAR(20);
ALTER TABLE intent_lifecycle ADD COLUMN IF NOT EXISTS legs_completed INTEGER DEFAULT 0;
ALTER TABLE intent_lifecycle ADD COLUMN IF NOT EXISTS legs_failed INTEGER DEFAULT 0;
