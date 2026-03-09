-- Migration 008: Multi-Leg Aggregator Persistence
-- Persists in-flight multi-leg aggregation state to survive validator crashes (GAP 4).
-- Without this, a validator crash after partial chain group completion permanently
-- loses progress and the intent never completes.

CREATE TABLE IF NOT EXISTS multi_leg_pending_state (
    intent_id       VARCHAR(128) PRIMARY KEY,
    operation_id    VARCHAR(128) NOT NULL,
    total_legs      INTEGER NOT NULL,
    execution_mode  VARCHAR(20) NOT NULL DEFAULT 'parallel',
    leg_mapping     JSONB NOT NULL,              -- map[int]LegChainInfo
    leg_indices_per_chain JSONB NOT NULL,         -- map[string][]int
    completed_cycles JSONB NOT NULL DEFAULT '{}', -- map[string]serialized cycle result summary
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '2 hours'
);

-- Index for cleanup of expired entries
CREATE INDEX IF NOT EXISTS idx_multi_leg_pending_expires ON multi_leg_pending_state(expires_at);

-- Index for listing active pending intents
CREATE INDEX IF NOT EXISTS idx_multi_leg_pending_created ON multi_leg_pending_state(created_at DESC);
