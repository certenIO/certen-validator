// Copyright 2025 Certen Protocol
//
// HIGH-002: Persistent Replay Protection
// Interface for durable nonce tracking that survives validator restarts.

package consensus

import "context"

// ReplayStore provides persistent nonce tracking for replay protection.
// Implementations must be safe for concurrent access.
type ReplayStore interface {
	// HasNonce returns true if the nonce has been seen before.
	HasNonce(ctx context.Context, nonce string) (bool, error)

	// MarkNonce records a nonce as used with its expiry time.
	// Returns error if already used (atomic check-and-set).
	MarkNonce(ctx context.Context, nonce string, expiresAt int64) error

	// CleanExpired removes nonces whose expires_at is before the given Unix timestamp.
	CleanExpired(ctx context.Context, beforeTimestamp int64) error

	// Close releases any resources held by the store.
	Close() error
}
