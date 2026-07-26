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

// ClaimResult reports the outcome of an owner-aware nonce claim.
type ClaimResult struct {
	// OK is true when the caller holds the nonce — either it just claimed it, or
	// it already held it.
	OK bool
	// Owner is whoever holds the nonce. On a conflict this is the OTHER holder,
	// which is what makes the refusal reportable.
	Owner string
	// Reclaimed is true when this owner already held the nonce, i.e. the caller
	// is retrying rather than replaying.
	Reclaimed bool
}

// NonceClaimer is an owner-aware extension of ReplayStore.
//
// # WHY PLAIN MarkNonce IS NOT ENOUGH
//
// MarkNonce treats the second sight of a nonce as a replay, full stop. But the
// validator legitimately re-processes the SAME intent: the on-demand chained
// proof retries to absorb DN-anchoring latency, and a restart can re-queue work.
// Under MarkNonce the first attempt burns the nonce and every legitimate retry
// is then refused as an attack — replay protection that breaks the retry path is
// worse than none, because it fails on exactly the intents that needed patience.
//
// A replay is the same nonce presented by a DIFFERENT transaction. So the claim
// is keyed by nonce and remembers WHO claimed it: re-entry by the same owner is
// idempotent, re-use by anyone else is refused.
//
// The owner must be something an attacker cannot copy from the victim's intent
// while producing a different execution — the Accumulate transaction hash is
// exactly that, since a fresh submission always gets a fresh hash.
type NonceClaimer interface {
	ClaimNonce(ctx context.Context, nonce, owner string, expiresAt int64) (ClaimResult, error)
}
