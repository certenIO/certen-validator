// Copyright 2025 Certen Protocol
//
// Nonce Tracker - Transaction Sequence Management for Accumulate
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
//
// This module tracks nonces (sequence numbers) for Accumulate transactions
// to ensure proper ordering and prevent replay attacks.

package execution

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// =============================================================================
// NONCE TRACKER
// =============================================================================

// NonceTracker manages transaction nonces for Accumulate submissions
type NonceTracker struct {
	mu sync.Mutex

	// Signer URL for nonce queries
	signerURL string

	// Accumulate client for querying current nonce
	client *accumulate.LiteClientAdapter

	// Local nonce state
	lastKnownNonce uint64
	pendingNonces  map[uint64]*NonceState
	lastQuery      time.Time

	// Configuration
	queryInterval time.Duration
	maxPending    int

	// Logging
	logger *log.Logger
}

// NonceState tracks the state of a nonce
type NonceState struct {
	Nonce      uint64
	Status     string // "reserved", "submitted", "confirmed", "failed"
	ReservedAt time.Time
	SubmittedAt time.Time
	ConfirmedAt time.Time
}

// NewNonceTracker creates a new nonce tracker
func NewNonceTracker(signerURL string, client *accumulate.LiteClientAdapter, logger *log.Logger) *NonceTracker {
	if logger == nil {
		logger = log.New(log.Writer(), "[NonceTracker] ", log.LstdFlags)
	}

	return &NonceTracker{
		signerURL:     signerURL,
		client:        client,
		pendingNonces: make(map[uint64]*NonceState),
		queryInterval: 30 * time.Second,
		maxPending:    100,
		logger:        logger,
	}
}

// GetNextNonce returns the next available nonce for a transaction
func (t *NonceTracker) GetNextNonce(ctx context.Context) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Query chain nonce if cache is stale
	if time.Since(t.lastQuery) > t.queryInterval {
		if err := t.refreshChainNonce(ctx); err != nil {
			t.logger.Printf("⚠️ Failed to refresh chain nonce: %v (using cached value)", err)
			// Continue with cached value if query fails
		}
	}

	// Find next available nonce
	nextNonce := t.lastKnownNonce + 1

	// Skip any pending nonces
	for {
		if state, exists := t.pendingNonces[nextNonce]; exists {
			if state.Status == "reserved" || state.Status == "submitted" {
				nextNonce++
				continue
			}
		}
		break
	}

	// Check for too many pending nonces
	if len(t.pendingNonces) >= t.maxPending {
		return 0, fmt.Errorf("too many pending nonces: %d", len(t.pendingNonces))
	}

	// Reserve this nonce
	t.pendingNonces[nextNonce] = &NonceState{
		Nonce:      nextNonce,
		Status:     "reserved",
		ReservedAt: time.Now(),
	}

	t.logger.Printf("📝 Reserved nonce: %d (chain nonce: %d, pending: %d)", nextNonce, t.lastKnownNonce, len(t.pendingNonces))

	return nextNonce, nil
}

// MarkSubmitted marks a nonce as submitted
func (t *NonceTracker) MarkSubmitted(nonce uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, exists := t.pendingNonces[nonce]; exists {
		state.Status = "submitted"
		state.SubmittedAt = time.Now()
		t.logger.Printf("✅ Nonce %d marked as submitted", nonce)
	}
}

// MarkConfirmed marks a nonce as confirmed and updates the chain nonce
func (t *NonceTracker) MarkConfirmed(nonce uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, exists := t.pendingNonces[nonce]; exists {
		state.Status = "confirmed"
		state.ConfirmedAt = time.Now()
		t.logger.Printf("✅ Nonce %d confirmed", nonce)
	}

	// Update last known nonce if this was the next expected nonce
	if nonce == t.lastKnownNonce+1 {
		t.lastKnownNonce = nonce

		// Clean up confirmed nonces
		t.cleanupConfirmed()
	}
}

// MarkFailed marks a nonce as failed (can be reused)
func (t *NonceTracker) MarkFailed(nonce uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, exists := t.pendingNonces[nonce]; exists {
		state.Status = "failed"
		t.logger.Printf("❌ Nonce %d marked as failed (will be reused)", nonce)
	}
}

// GetPendingCount returns the number of pending nonces
func (t *NonceTracker) GetPendingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pendingNonces)
}

// GetLastKnownNonce returns the last known chain nonce
func (t *NonceTracker) GetLastKnownNonce() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastKnownNonce
}

// =============================================================================
// INTERNAL METHODS
// =============================================================================

// refreshChainNonce queries the current nonce from the Accumulate network
func (t *NonceTracker) refreshChainNonce(ctx context.Context) error {
	t.logger.Printf("🔄 Querying chain nonce for: %s", t.signerURL)

	// Query current nonce from Accumulate
	nonce, err := t.client.GetSignerNonce(ctx, t.signerURL)
	if err != nil {
		return fmt.Errorf("failed to query nonce: %w", err)
	}

	t.lastKnownNonce = nonce
	t.lastQuery = time.Now()
	t.logger.Printf("✅ Chain nonce updated: %d", nonce)

	return nil
}

// cleanupConfirmed removes confirmed nonces from the pending map
func (t *NonceTracker) cleanupConfirmed() {
	threshold := time.Now().Add(-5 * time.Minute)

	for nonce, state := range t.pendingNonces {
		if state.Status == "confirmed" && state.ConfirmedAt.Before(threshold) {
			delete(t.pendingNonces, nonce)
		}
		// Also clean up old failed nonces
		if state.Status == "failed" && state.ReservedAt.Before(threshold) {
			delete(t.pendingNonces, nonce)
		}
	}
}

// ForceRefresh forces a refresh of the chain nonce
func (t *NonceTracker) ForceRefresh(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.refreshChainNonce(ctx)
}

// Reset resets the nonce tracker state (for testing/recovery)
func (t *NonceTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.lastKnownNonce = 0
	t.pendingNonces = make(map[uint64]*NonceState)
	t.lastQuery = time.Time{}
	t.logger.Printf("🔄 Nonce tracker reset")
}

// =============================================================================
// TIMESTAMP NONCE STRATEGY (Alternative)
// =============================================================================

// TimestampNonceTracker uses timestamps as nonces (simpler but less efficient)
// This is useful when precise sequence tracking isn't required
type TimestampNonceTracker struct {
	mu        sync.Mutex
	lastNonce uint64
	logger    *log.Logger
}

// NewTimestampNonceTracker creates a timestamp-based nonce tracker
func NewTimestampNonceTracker(logger *log.Logger) *TimestampNonceTracker {
	if logger == nil {
		logger = log.New(log.Writer(), "[TSNonceTracker] ", log.LstdFlags)
	}
	return &TimestampNonceTracker{logger: logger}
}

// GetNextNonce returns the next nonce based on timestamp
func (t *TimestampNonceTracker) GetNextNonce(ctx context.Context) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Use microsecond timestamp
	nonce := uint64(time.Now().UnixMicro())

	// Ensure nonce is always increasing
	if nonce <= t.lastNonce {
		nonce = t.lastNonce + 1
	}

	t.lastNonce = nonce
	return nonce, nil
}

// MarkSubmitted is a no-op for timestamp nonces
func (t *TimestampNonceTracker) MarkSubmitted(nonce uint64) {}

// MarkConfirmed is a no-op for timestamp nonces
func (t *TimestampNonceTracker) MarkConfirmed(nonce uint64) {}

// MarkFailed is a no-op for timestamp nonces
func (t *TimestampNonceTracker) MarkFailed(nonce uint64) {}
