-- Migration: 003_proof_service_enhancements.sql
-- Description: Proof Service enhancements for bundle storage, custody chain, and API access
-- Created: 2025-01-XX
--
-- This migration adds tables required for the Proof Artifact Service:
-- - proof_bundles: Self-contained verification bundles
-- - custody_chain_events: Audit trail for proof lifecycle
-- - api_keys: External API access control
-- - proof_pricing_tiers: Pricing configuration
-- - bundle_downloads: Download tracking for auditing

BEGIN;

-- ============================================================================
-- TABLE 1: proof_bundles - Self-contained Verification Bundles
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_bundles (
    bundle_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    -- Bundle metadata
    bundle_format       VARCHAR(20) NOT NULL DEFAULT 'certen_v1',
    bundle_version      VARCHAR(20) NOT NULL DEFAULT '1.0',

    -- Bundle data (gzipped JSON)
    bundle_data         BYTEA NOT NULL,
    bundle_hash         BYTEA NOT NULL,          -- SHA256 of uncompressed JSON
    bundle_size_bytes   INTEGER NOT NULL,

    -- Component flags
    includes_chained    BOOLEAN NOT NULL DEFAULT TRUE,
    includes_governance BOOLEAN NOT NULL DEFAULT TRUE,
    includes_merkle     BOOLEAN NOT NULL DEFAULT TRUE,
    includes_anchor     BOOLEAN NOT NULL DEFAULT TRUE,

    -- Attestation count at bundle creation
    attestation_count   INTEGER NOT NULL DEFAULT 0,

    -- Expiration (optional, for temporary bundles)
    expires_at          TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_bundle_format CHECK (bundle_format IN ('certen_v1', 'json', 'cbor'))
);

-- Indexes for bundle retrieval
CREATE INDEX IF NOT EXISTS idx_bundles_proof ON proof_bundles(proof_id);
CREATE INDEX IF NOT EXISTS idx_bundles_created ON proof_bundles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bundles_hash ON proof_bundles(bundle_hash);
CREATE INDEX IF NOT EXISTS idx_bundles_expires ON proof_bundles(expires_at) WHERE expires_at IS NOT NULL;

-- Composite index for format + version queries
CREATE INDEX IF NOT EXISTS idx_bundles_format_version ON proof_bundles(bundle_format, bundle_version);

-- ============================================================================
-- TABLE 2: proof_pricing_tiers - Pricing Configuration
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_pricing_tiers (
    tier_id             VARCHAR(50) PRIMARY KEY,
    tier_name           VARCHAR(100) NOT NULL,
    base_cost_usd       NUMERIC(10, 4) NOT NULL,
    batch_delay_seconds INTEGER NOT NULL,
    priority            INTEGER NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default pricing tiers
INSERT INTO proof_pricing_tiers (tier_id, tier_name, base_cost_usd, batch_delay_seconds, priority)
VALUES
    ('on_cadence', 'On-Cadence (Batched)', 0.05, 900, 1),    -- ~15 min delay, $0.05/proof
    ('on_demand', 'On-Demand (Immediate)', 0.25, 0, 10)       -- No delay, $0.25/proof
ON CONFLICT (tier_id) DO NOTHING;

-- ============================================================================
-- TABLE 3: custody_chain_events - Audit Trail
-- ============================================================================

CREATE TABLE IF NOT EXISTS custody_chain_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            UUID NOT NULL REFERENCES proof_artifacts(proof_id) ON DELETE CASCADE,

    -- Event classification
    event_type          VARCHAR(50) NOT NULL,
    event_timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Actor information
    actor_type          VARCHAR(50) NOT NULL,
    actor_id            VARCHAR(256),

    -- Chain hashes for tamper detection
    previous_hash       BYTEA,
    current_hash        BYTEA NOT NULL,

    -- Event details (JSONB for flexibility)
    event_details       JSONB,

    -- Optional signature for validator events
    signature           BYTEA,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_event_type CHECK (event_type IN (
        'created', 'pending', 'batched', 'anchored',
        'attested', 'verified', 'failed', 'retrieved',
        'bundle_created', 'bundle_downloaded', 'expired'
    )),
    CONSTRAINT valid_actor_type CHECK (actor_type IN (
        'validator', 'coordinator', 'api', 'system', 'external', 'auditor'
    ))
);

-- Indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_custody_proof ON custody_chain_events(proof_id);
CREATE INDEX IF NOT EXISTS idx_custody_timestamp ON custody_chain_events(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_custody_event_type ON custody_chain_events(event_type);
CREATE INDEX IF NOT EXISTS idx_custody_actor ON custody_chain_events(actor_type, actor_id);

-- Composite index for proof timeline
CREATE INDEX IF NOT EXISTS idx_custody_proof_timeline ON custody_chain_events(proof_id, event_timestamp ASC);

-- ============================================================================
-- TABLE 4: api_keys - External API Access Control
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    key_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash            BYTEA NOT NULL,          -- SHA256 of the actual key

    -- Client information
    client_name         VARCHAR(256) NOT NULL,
    client_type         VARCHAR(50) NOT NULL,

    -- Permissions
    can_read_proofs     BOOLEAN NOT NULL DEFAULT TRUE,
    can_request_proofs  BOOLEAN NOT NULL DEFAULT FALSE,
    can_bulk_download   BOOLEAN NOT NULL DEFAULT FALSE,

    -- Rate limiting
    rate_limit_per_min  INTEGER NOT NULL DEFAULT 100,

    -- Status
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at          TIMESTAMPTZ,

    -- Metadata
    description         TEXT,
    contact_email       VARCHAR(256),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ,

    CONSTRAINT valid_client_type CHECK (client_type IN (
        'auditor', 'service', 'institution', 'developer', 'internal'
    ))
);

-- Indexes for API key lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_api_keys_client ON api_keys(client_name);
CREATE INDEX IF NOT EXISTS idx_api_keys_type ON api_keys(client_type);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- TABLE 5: bundle_downloads - Download Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS bundle_downloads (
    download_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id           UUID NOT NULL REFERENCES proof_bundles(bundle_id) ON DELETE CASCADE,
    api_key_id          UUID REFERENCES api_keys(key_id),

    -- Request info
    client_ip           VARCHAR(45) NOT NULL,    -- IPv4 or IPv6
    user_agent          VARCHAR(512),

    -- Response info
    response_code       INTEGER NOT NULL,
    bytes_sent          INTEGER NOT NULL,

    downloaded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for download tracking
CREATE INDEX IF NOT EXISTS idx_downloads_bundle ON bundle_downloads(bundle_id);
CREATE INDEX IF NOT EXISTS idx_downloads_api_key ON bundle_downloads(api_key_id);
CREATE INDEX IF NOT EXISTS idx_downloads_time ON bundle_downloads(downloaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_downloads_ip ON bundle_downloads(client_ip);

-- ============================================================================
-- TABLE 6: proof_requests - On-demand Proof Request Queue
-- ============================================================================

CREATE TABLE IF NOT EXISTS proof_requests (
    request_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Request identification
    accum_tx_hash       VARCHAR(128),
    account_url         VARCHAR(512),

    -- Request configuration
    proof_class         VARCHAR(20) NOT NULL,
    governance_level    VARCHAR(10),

    -- Requestor information
    api_key_id          UUID REFERENCES api_keys(key_id),
    callback_url        VARCHAR(1024),

    -- Status
    status              VARCHAR(30) NOT NULL DEFAULT 'pending',
    proof_id            UUID REFERENCES proof_artifacts(proof_id),

    -- Error handling
    error_message       TEXT,
    retry_count         INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
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

-- Indexes for request processing
CREATE INDEX IF NOT EXISTS idx_requests_status ON proof_requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_tx ON proof_requests(accum_tx_hash) WHERE accum_tx_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_requests_account ON proof_requests(account_url) WHERE account_url IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_requests_api_key ON proof_requests(api_key_id);
CREATE INDEX IF NOT EXISTS idx_requests_created ON proof_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_pending ON proof_requests(created_at) WHERE status = 'pending';

-- ============================================================================
-- VIEWS: Convenient Query Views
-- ============================================================================

-- View: Complete proof status with bundle availability
CREATE OR REPLACE VIEW proof_status_view AS
SELECT
    pa.proof_id,
    pa.proof_type,
    pa.accum_tx_hash,
    pa.account_url,
    pa.gov_level,
    pa.status,
    pa.created_at,
    pa.anchored_at,
    pa.verified_at,
    pb.bundle_id,
    pb.bundle_format,
    pb.bundle_size_bytes,
    pb.attestation_count AS bundle_attestation_count,
    (SELECT COUNT(*) FROM validator_attestations va WHERE va.proof_id = pa.proof_id) AS current_attestation_count,
    (SELECT COUNT(*) FROM custody_chain_events ce WHERE ce.proof_id = pa.proof_id) AS custody_event_count
FROM proof_artifacts pa
LEFT JOIN proof_bundles pb ON pb.proof_id = pa.proof_id;

-- View: API key usage statistics
CREATE OR REPLACE VIEW api_key_usage_view AS
SELECT
    ak.key_id,
    ak.client_name,
    ak.client_type,
    ak.is_active,
    ak.rate_limit_per_min,
    ak.last_used_at,
    (SELECT COUNT(*) FROM bundle_downloads bd WHERE bd.api_key_id = ak.key_id) AS total_downloads,
    (SELECT COUNT(*) FROM proof_requests pr WHERE pr.api_key_id = ak.key_id) AS total_requests,
    (SELECT SUM(bytes_sent) FROM bundle_downloads bd WHERE bd.api_key_id = ak.key_id) AS total_bytes_downloaded
FROM api_keys ak;

-- ============================================================================
-- FUNCTIONS: Helper Functions
-- ============================================================================

-- Function: Get next custody chain hash for a proof
CREATE OR REPLACE FUNCTION get_next_custody_hash(
    p_proof_id UUID,
    p_event_type VARCHAR(50),
    p_event_details JSONB
) RETURNS BYTEA AS $$
DECLARE
    v_previous_hash BYTEA;
    v_chain_data TEXT;
    v_new_hash BYTEA;
BEGIN
    -- Get the latest custody hash for this proof
    SELECT current_hash INTO v_previous_hash
    FROM custody_chain_events
    WHERE proof_id = p_proof_id
    ORDER BY event_timestamp DESC
    LIMIT 1;

    -- Build chain data: previous_hash + event_type + event_details + timestamp
    v_chain_data := COALESCE(encode(v_previous_hash, 'hex'), '') ||
                    p_event_type ||
                    COALESCE(p_event_details::text, '{}') ||
                    NOW()::text;

    -- Compute SHA256 hash
    v_new_hash := sha256(v_chain_data::bytea);

    RETURN v_new_hash;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- MIGRATION RECORD
-- ============================================================================

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('003', 'Proof service enhancements for bundles, custody chain, and API access', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
