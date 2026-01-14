-- schema.sql
-- SQLite schema for Accumulate Lite Client storage (scaffolding only, not used by runtime)
-- This schema is prepared for future implementation but is not currently active.

-- Accounts table for caching account data
CREATE TABLE IF NOT EXISTS accounts (
    url TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    type TEXT NOT NULL,
    state_hash TEXT,
    retrieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    INDEX idx_type (type),
    INDEX idx_expires (expires_at)
);

-- Proofs table for caching cryptographic proofs
CREATE TABLE IF NOT EXISTS proofs (
    account_url TEXT NOT NULL,
    proof_hash TEXT PRIMARY KEY,
    proof_data BLOB NOT NULL,
    proof_type TEXT NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP,
    FOREIGN KEY (account_url) REFERENCES accounts(url),
    INDEX idx_account (account_url),
    INDEX idx_valid (valid_until)
);

-- Network status cache
CREATE TABLE IF NOT EXISTS network_status (
    partition_id TEXT PRIMARY KEY,
    status_data BLOB NOT NULL,
    last_block_height INTEGER,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_updated (updated_at)
);

-- BPT (Binary Patricia Trie) cache for proof components
CREATE TABLE IF NOT EXISTS bpt_cache (
    hash TEXT PRIMARY KEY,
    node_data BLOB NOT NULL,
    node_type TEXT NOT NULL,
    height INTEGER,
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_height (height)
);

-- Routing table cache
CREATE TABLE IF NOT EXISTS routing_table (
    version INTEGER PRIMARY KEY,
    table_data BLOB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Metrics table for performance tracking
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation TEXT NOT NULL,
    duration_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_operation (operation),
    INDEX idx_timestamp (timestamp)
);

-- Version table for schema migrations
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

-- Initial version
INSERT INTO schema_version (version, description) 
VALUES (1, 'Initial schema for Accumulate Lite Client storage');