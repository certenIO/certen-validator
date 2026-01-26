-- Migration 004: Add Proof Detail Tables
-- These tables support GetProofWithDetails functionality
-- Adding: anchor_references, governance_proof_levels, verification_history, chained_proof_layers

-- Anchor References - Links proofs to external chain anchors
CREATE TABLE IF NOT EXISTS anchor_references (
    reference_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),

    -- Target Chain
    target_chain VARCHAR(64) NOT NULL,
    chain_id VARCHAR(64) NOT NULL,
    network_name VARCHAR(64),

    -- Anchor Transaction
    anchor_tx_hash VARCHAR(128) NOT NULL,
    anchor_block_number BIGINT NOT NULL,
    anchor_block_hash VARCHAR(128),
    anchor_timestamp TIMESTAMPTZ,

    -- Contract Reference
    contract_address VARCHAR(64),

    -- Confirmation Status
    confirmations INT DEFAULT 0,
    is_confirmed BOOLEAN DEFAULT FALSE,
    confirmed_at TIMESTAMPTZ,

    -- Gas Costs
    gas_used BIGINT,
    gas_price_wei VARCHAR(78),
    total_cost_wei VARCHAR(78),

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anchor_references_proof ON anchor_references(proof_id);
CREATE INDEX IF NOT EXISTS idx_anchor_references_chain ON anchor_references(chain_id, anchor_tx_hash);

-- Governance Proof Levels - G0/G1/G2 governance proofs
CREATE TABLE IF NOT EXISTS governance_proof_levels (
    level_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),

    -- Level identification
    gov_level VARCHAR(8) NOT NULL, -- G0, G1, G2
    level_name VARCHAR(64),

    -- G0 Fields (Inclusion and Finality)
    block_height BIGINT,
    finality_timestamp TIMESTAMPTZ,
    anchor_height BIGINT,
    is_anchored BOOLEAN,

    -- G1 Fields (Governance Correctness)
    authority_url VARCHAR(255),
    key_page_count INT,
    threshold_m INT,
    threshold_n INT,
    signature_count INT,

    -- G2 Fields (Outcome Binding)
    outcome_type VARCHAR(64),
    outcome_hash BYTEA,
    binding_enforced BOOLEAN,

    -- Level-specific JSON data
    level_json JSONB,

    -- Verification
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_levels_proof ON governance_proof_levels(proof_id);
CREATE INDEX IF NOT EXISTS idx_governance_levels_level ON governance_proof_levels(gov_level);

-- Verification History - Audit trail of proof verifications
CREATE TABLE IF NOT EXISTS verification_history (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),

    -- Verification details
    verification_type VARCHAR(64) NOT NULL,
    passed BOOLEAN NOT NULL,
    error_message TEXT,
    error_code VARCHAR(64),

    -- Verifier info
    verifier_id VARCHAR(255),
    verification_method VARCHAR(64),
    duration_ms INT,

    -- Metadata
    artifacts_json JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verification_history_proof ON verification_history(proof_id);
CREATE INDEX IF NOT EXISTS idx_verification_history_type ON verification_history(verification_type);

-- Add missing columns if table already exists (idempotent)
ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS error_code VARCHAR(64);
ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS verification_method VARCHAR(64);
-- Rename verification_data to artifacts_json if it exists (handle both column names)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='verification_history' AND column_name='verification_data') THEN
        ALTER TABLE verification_history RENAME COLUMN verification_data TO artifacts_json;
    ELSIF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='verification_history' AND column_name='artifacts_json') THEN
        ALTER TABLE verification_history ADD COLUMN artifacts_json JSONB;
    END IF;
END $$;

-- Chained Proof Layers - L1/L2/L3 Accumulate proof chain
CREATE TABLE IF NOT EXISTS chained_proof_layers (
    layer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID REFERENCES proof_artifacts(proof_id),

    -- Layer identification
    layer_number INT NOT NULL, -- 1, 2, 3
    layer_name VARCHAR(64),

    -- L1 Fields (Transaction to BVN)
    bvn_partition VARCHAR(64),
    receipt_anchor BYTEA,
    bvn_root BYTEA,

    -- L2 Fields (BVN to DN)
    dn_root BYTEA,
    anchor_sequence BIGINT,
    bvn_partition_id VARCHAR(64),
    dn_block_hash BYTEA,

    -- L3 Fields (DN to Consensus)
    dn_block_height BIGINT,
    consensus_timestamp TIMESTAMPTZ,

    -- Layer-specific JSON data
    layer_json JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chained_layers_proof ON chained_proof_layers(proof_id);
CREATE INDEX IF NOT EXISTS idx_chained_layers_number ON chained_proof_layers(layer_number);

-- Record migration
INSERT INTO schema_migrations (version, applied_at)
VALUES ('004_add_proof_detail_tables', NOW())
ON CONFLICT (version) DO NOTHING;
