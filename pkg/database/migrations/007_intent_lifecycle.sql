-- Migration 007: Intent Lifecycle Status Tracking
-- Unified tracking of intent lifecycle: submitted → pending_signatures → authorized → in_process → complete | failed

CREATE TABLE IF NOT EXISTS intent_lifecycle (
    id              BIGSERIAL PRIMARY KEY,
    intent_id       VARCHAR(256) NOT NULL,
    accum_tx_hash   VARCHAR(128) NOT NULL,
    user_id         VARCHAR(256),
    status          VARCHAR(32) NOT NULL DEFAULT 'submitted',
    target_chain    VARCHAR(64),
    proof_class     VARCHAR(20),
    error_message   TEXT,
    block_height    BIGINT,
    cycle_id        VARCHAR(256),
    write_back_tx   VARCHAR(128),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at    TIMESTAMPTZ,
    authorized_at   TIMESTAMPTZ,
    in_process_at   TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ
);

-- Unique constraint: one lifecycle row per intent
CREATE UNIQUE INDEX IF NOT EXISTS idx_intent_lifecycle_intent_id ON intent_lifecycle(intent_id);

-- Lookup by Accumulate transaction hash
CREATE INDEX IF NOT EXISTS idx_intent_lifecycle_accum_tx_hash ON intent_lifecycle(accum_tx_hash);

-- Filter by status for monitoring dashboards
CREATE INDEX IF NOT EXISTS idx_intent_lifecycle_status ON intent_lifecycle(status);

-- Filter by user for per-user queries
CREATE INDEX IF NOT EXISTS idx_intent_lifecycle_user_id ON intent_lifecycle(user_id);

-- Time-based queries for recent lifecycle entries
CREATE INDEX IF NOT EXISTS idx_intent_lifecycle_created_at ON intent_lifecycle(created_at DESC);
