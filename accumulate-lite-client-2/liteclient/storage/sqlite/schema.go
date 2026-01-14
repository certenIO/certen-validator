// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package sqlite

import (
	"database/sql"
	"fmt"

	// Note: modernc.org/sqlite import removed for vendor compatibility
	// Add back: _ "modernc.org/sqlite" // Pure Go SQLite driver
)

// Schema contains all table creation statements and migrations
const Schema = `
-- Artifact sources and provenance tracking
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                    -- 'v3', 'v2', 'explorer', 'cache'
    endpoint TEXT NOT NULL,               -- Full endpoint URL
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'failed', 'deprecated'
    last_success TIMESTAMP,
    last_failure TIMESTAMP,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(kind, endpoint)
);

-- Network state snapshots
CREATE TABLE IF NOT EXISTS network_states (
    id INTEGER PRIMARY KEY,
    network TEXT NOT NULL,                -- 'mainnet', 'testnet', 'devnet'
    height INTEGER NOT NULL,
    block_hash BLOB,
    timestamp TIMESTAMP NOT NULL,
    operator_count INTEGER,
    bvn_count INTEGER,
    metadata TEXT,                        -- JSON metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(network, height)
);

-- Accounts and their basic metadata
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,            -- Full account URL
    type TEXT NOT NULL,                  -- 'identity', 'lite', 'token', 'keybook'
    authority TEXT,                      -- Account authority (domain)
    local_name TEXT,                     -- Local account name
    chain_id BLOB,                       -- Account chain identifier
    last_updated TIMESTAMP,
    metadata TEXT,                       -- JSON account data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Account chains (main, scratch, etc.)
CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    name TEXT NOT NULL,                  -- 'main', 'scratch', 'anchor'
    type TEXT NOT NULL,                  -- 'transaction', 'anchor', 'system'
    root_hash BLOB,                      -- Current chain root
    height INTEGER DEFAULT 0,
    last_entry_hash BLOB,
    last_updated TIMESTAMP,
    metadata TEXT,                       -- JSON chain metadata
    FOREIGN KEY(account_id) REFERENCES accounts(id),
    UNIQUE(account_id, name)
);

CREATE INDEX IF NOT EXISTS idx_chains_account_name ON chains(account_id, name);
CREATE INDEX IF NOT EXISTS idx_chains_type ON chains(type);

-- Chain entries (transactions, anchors, etc.)
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    entry_index INTEGER NOT NULL,       -- Position in chain
    entry_hash BLOB NOT NULL UNIQUE,
    entry_type TEXT NOT NULL,           -- 'transaction', 'anchor', 'synthetic'
    data BLOB NOT NULL,                 -- Serialized entry data
    timestamp TIMESTAMP,
    block_height INTEGER,
    principal_hash BLOB,                -- Principal involved
    metadata TEXT,                      -- JSON entry metadata
    FOREIGN KEY(chain_id) REFERENCES chains(id),
    UNIQUE(chain_id, entry_index)
);

CREATE INDEX IF NOT EXISTS idx_entries_chain_idx ON entries(chain_id, entry_index);
CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(entry_hash);
CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);

-- BVN and DN anchor data
CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY,
    source_chain_id INTEGER,            -- Chain being anchored (optional)
    target_system TEXT NOT NULL,        -- 'bvn', 'dn'
    target_partition TEXT,              -- BVN partition name
    anchor_height INTEGER NOT NULL,
    anchor_hash BLOB NOT NULL,
    source_height INTEGER,              -- Height in source chain
    anchor_data BLOB NOT NULL,          -- Serialized anchor record
    receipt BLOB,                       -- Merkle receipt data
    timestamp TIMESTAMP,
    network TEXT DEFAULT 'mainnet',
    metadata TEXT,                      -- JSON anchor metadata
    FOREIGN KEY(source_chain_id) REFERENCES chains(id)
);

CREATE INDEX IF NOT EXISTS idx_anchors_target ON anchors(target_system, target_partition);
CREATE INDEX IF NOT EXISTS idx_anchors_height ON anchors(anchor_height);
CREATE INDEX IF NOT EXISTS idx_anchors_hash ON anchors(anchor_hash);

-- Merkle receipts and proofs
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY,
    proof_type TEXT NOT NULL,           -- 'account_to_bvn', 'bvn_to_dn', 'merkle_path'
    source_hash BLOB NOT NULL,
    target_hash BLOB NOT NULL,
    merkle_path BLOB NOT NULL,          -- Serialized Merkle path
    path_length INTEGER NOT NULL,
    receipt_data BLOB,                  -- Complete receipt structure
    validated BOOLEAN DEFAULT FALSE,
    validation_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT                       -- JSON receipt metadata
);

CREATE INDEX IF NOT EXISTS idx_receipts_type ON receipts(proof_type);
CREATE INDEX IF NOT EXISTS idx_receipts_source ON receipts(source_hash);
CREATE INDEX IF NOT EXISTS idx_receipts_target ON receipts(target_hash);

-- Complete proof bundles
CREATE TABLE IF NOT EXISTS bundles (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,             -- 'strategy-f', 'strategy-a', etc.
    schema_version TEXT NOT NULL,
    bundle_hash BLOB NOT NULL UNIQUE,   -- SHA-256 of canonical bundle
    bundle_data BLOB NOT NULL,          -- Complete JSON bundle
    verification_status TEXT NOT NULL,   -- 'valid', 'invalid', 'unknown'
    verification_error TEXT,
    components_count INTEGER DEFAULT 0,
    missing_components TEXT,            -- JSON array of missing components
    proven_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    source_endpoints TEXT,              -- JSON array of source endpoints
    healing_actions TEXT,               -- JSON array of healing actions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(account_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_bundles_account ON bundles(account_id);
CREATE INDEX IF NOT EXISTS idx_bundles_strategy ON bundles(strategy);
CREATE INDEX IF NOT EXISTS idx_bundles_hash ON bundles(bundle_hash);
CREATE INDEX IF NOT EXISTS idx_bundles_status ON bundles(verification_status);
CREATE INDEX IF NOT EXISTS idx_bundles_expires ON bundles(expires_at);

-- Operator keys and signatures (public data only)
CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY,
    network TEXT NOT NULL DEFAULT 'mainnet',
    operator_index INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ed25519',
    operator_name TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    activation_height INTEGER,
    deactivation_height INTEGER,
    signature_count INTEGER DEFAULT 0,
    last_signature TIMESTAMP,
    keybook_hash BLOB,                  -- DN keybook hash when recorded
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(network, operator_index),
    UNIQUE(network, public_key)
);

CREATE INDEX IF NOT EXISTS idx_operators_network ON operators(network);
CREATE INDEX IF NOT EXISTS idx_operators_active ON operators(is_active);
CREATE INDEX IF NOT EXISTS idx_operators_keybook ON operators(keybook_hash);

-- Operator signatures for DN authenticity
CREATE TABLE IF NOT EXISTS operator_signatures (
    id INTEGER PRIMARY KEY,
    operator_id INTEGER NOT NULL,
    dn_root_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    signature_height INTEGER,
    signature_timestamp TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    verification_error TEXT,
    bundle_id INTEGER,                  -- Associated bundle (optional)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(operator_id) REFERENCES operators(id),
    FOREIGN KEY(bundle_id) REFERENCES bundles(id),
    UNIQUE(operator_id, dn_root_hash)
);

CREATE INDEX IF NOT EXISTS idx_signatures_operator ON operator_signatures(operator_id);
CREATE INDEX IF NOT EXISTS idx_signatures_root ON operator_signatures(dn_root_hash);
CREATE INDEX IF NOT EXISTS idx_signatures_bundle ON operator_signatures(bundle_id);

-- Cache management and TTL
CREATE TABLE IF NOT EXISTS cache_entries (
    id INTEGER PRIMARY KEY,
    cache_key TEXT NOT NULL UNIQUE,
    cache_type TEXT NOT NULL,           -- 'account', 'chain', 'anchor', 'receipt'
    data BLOB NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    access_count INTEGER DEFAULT 0,
    last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cache_key ON cache_entries(cache_key);
CREATE INDEX IF NOT EXISTS idx_cache_type ON cache_entries(cache_type);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries(expires_at);

-- Metadata and configuration
CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial metadata
INSERT OR IGNORE INTO metadata (key, value, description) VALUES 
    ('schema_version', '1.0', 'Database schema version'),
    ('created_at', datetime('now'), 'Database creation timestamp'),
    ('migration_level', '001', 'Current migration level');
`

// InitSchema initializes the database schema
func InitSchema(db *sql.DB) error {
	// Execute schema creation
	if _, err := db.Exec(Schema); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}
	
	// Verify schema was created correctly
	if err := verifySchema(db); err != nil {
		return fmt.Errorf("schema verification failed: %w", err)
	}
	
	return nil
}

// verifySchema checks that all required tables exist
func verifySchema(db *sql.DB) error {
	requiredTables := []string{
		"sources", "network_states", "accounts", "chains", "entries",
		"anchors", "receipts", "bundles", "operators", "operator_signatures",
		"cache_entries", "metadata",
	}
	
	for _, table := range requiredTables {
		var count int
		query := "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?"
		if err := db.QueryRow(query, table).Scan(&count); err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
		
		if count == 0 {
			return fmt.Errorf("required table %s not found", table)
		}
	}
	
	return nil
}

// GetSchemaVersion returns the current schema version
func GetSchemaVersion(db *sql.DB) (string, error) {
	var version string
	query := "SELECT value FROM metadata WHERE key = 'schema_version'"
	if err := db.QueryRow(query).Scan(&version); err != nil {
		return "", fmt.Errorf("failed to get schema version: %w", err)
	}
	
	return version, nil
}

// Migration001 contains the first migration (same as initial schema)
const Migration001 = Schema

// Migrations contains all database migrations
var Migrations = map[string]string{
	"001": Migration001,
	// Future migrations would be added here
	// "002": Migration002,
}