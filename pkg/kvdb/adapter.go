// Copyright 2025 Certen Protocol
//
// KV Adapter for CometBFT Database Integration
// Wraps CometBFT's dbm.DB interface to implement ledger.KV

package kvdb

import (
	dbm "github.com/cometbft/cometbft-db"
)

// KVAdapter wraps a CometBFT dbm.DB and exposes the ledger.KV interface.
// This allows LedgerStore to use CometBFT's persistent storage directly.
type KVAdapter struct {
	db dbm.DB
}

// NewKVAdapter creates a new KVAdapter for the given underlying DB.
func NewKVAdapter(db dbm.DB) *KVAdapter {
	return &KVAdapter{db: db}
}

// Get implements ledger.KV.Get
func (a *KVAdapter) Get(key []byte) ([]byte, error) {
	if a.db == nil {
		return nil, nil
	}

	// CometBFT DB returns (val, error)
	if v, err := a.db.Get(key); err != nil {
		return nil, err
	} else {
		// v may be nil if key not found – that's fine, ledger treats nil as "not present".
		return v, nil
	}
}

// Set implements ledger.KV.Set
func (a *KVAdapter) Set(key, value []byte) error {
	if a.db == nil {
		return nil
	}

	// Use SetSync for durable writes at commit time
	if err := a.db.SetSync(key, value); err != nil {
		return err
	}
	return nil
}