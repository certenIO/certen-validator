// Copyright 2025 Certen Protocol
//
// HIGH-002: Persistent Replay Protection — bbolt implementation
// Uses bbolt (pure Go, no CGO) for durable nonce storage that survives restarts.
//
// Storage layout:
//   Bucket "nonces":  key = nonce (string)  →  value = expires_at (8-byte big-endian int64)

package consensus

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var nonceBucket = []byte("nonces")

// BboltReplayStore implements ReplayStore using bbolt for persistence.
type BboltReplayStore struct {
	db *bolt.DB
}

// NewBboltReplayStore opens (or creates) a bbolt database at dbPath.
// The parent directory is created if it does not exist.
func NewBboltReplayStore(dbPath string) (*BboltReplayStore, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create replay store directory %s: %w", dir, err)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout:      2 * time.Second,
		NoGrowSync:   false,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		return nil, fmt.Errorf("open replay store %s: %w", dbPath, err)
	}

	// Create the nonces bucket if it doesn't exist
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(nonceBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create nonces bucket: %w", err)
	}

	log.Printf("✅ [REPLAY-STORE] Opened persistent replay store at %s", dbPath)
	return &BboltReplayStore{db: db}, nil
}

// HasNonce returns true if the nonce has been seen before.
func (s *BboltReplayStore) HasNonce(_ context.Context, nonce string) (bool, error) {
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nonceBucket)
		if b == nil {
			return nil
		}
		found = b.Get([]byte(nonce)) != nil
		return nil
	})
	return found, err
}

// MarkNonce atomically checks and records a nonce. Returns error if already used.
func (s *BboltReplayStore) MarkNonce(_ context.Context, nonce string, expiresAt int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nonceBucket)
		if b == nil {
			return fmt.Errorf("nonces bucket missing")
		}

		key := []byte(nonce)

		// Atomic check-and-set: reject if already present
		if existing := b.Get(key); existing != nil {
			return fmt.Errorf("nonce already used: %s", nonce)
		}

		// Store expires_at as 8-byte big-endian
		val := make([]byte, 8)
		binary.BigEndian.PutUint64(val, uint64(expiresAt))
		return b.Put(key, val)
	})
}

// CleanExpired removes all nonces whose expires_at is before beforeTimestamp.
func (s *BboltReplayStore) CleanExpired(_ context.Context, beforeTimestamp int64) error {
	var cleaned int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nonceBucket)
		if b == nil {
			return nil
		}

		// Collect keys to delete (can't delete during iteration)
		var toDelete [][]byte
		err := b.ForEach(func(k, v []byte) error {
			if len(v) >= 8 {
				expiresAt := int64(binary.BigEndian.Uint64(v))
				if expiresAt < beforeTimestamp {
					toDelete = append(toDelete, append([]byte{}, k...)) // copy key
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		for _, key := range toDelete {
			if err := b.Delete(key); err != nil {
				return err
			}
			cleaned++
		}
		return nil
	})

	if cleaned > 0 {
		log.Printf("🧹 [REPLAY-STORE] Cleaned %d expired nonces (before %d)", cleaned, beforeTimestamp)
	}
	return err
}

// Close closes the bbolt database.
func (s *BboltReplayStore) Close() error {
	return s.db.Close()
}
