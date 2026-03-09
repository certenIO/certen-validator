// Copyright 2025 Certen Protocol
//
// Intent Lifecycle Status Types
// Unified status tracking for intents across their full lifecycle

package database

import (
	"time"

	"github.com/lib/pq"
)

// IntentLifecycleStatus represents the lifecycle state of an intent
type IntentLifecycleStatus string

const (
	// IntentLifecycleSubmitted - Intent written to Accumulate (set retroactively by validator)
	IntentLifecycleSubmitted IntentLifecycleStatus = "submitted"

	// IntentLifecyclePendingSignatures - Multi-sig awaiting signatures (future: set by api-bridge)
	IntentLifecyclePendingSignatures IntentLifecycleStatus = "pending_signatures"

	// IntentLifecycleAuthorized - Accumulate delivered (statusNo=201), committed to block
	IntentLifecycleAuthorized IntentLifecycleStatus = "authorized"

	// IntentLifecycleInProcess - Validators running proof cycle (Phase 7-9)
	IntentLifecycleInProcess IntentLifecycleStatus = "in_process"

	// IntentLifecycleComplete - Phase 9 writeback to Accumulate succeeded
	IntentLifecycleComplete IntentLifecycleStatus = "complete"

	// IntentLifecycleFailed - Any phase failed
	IntentLifecycleFailed IntentLifecycleStatus = "failed"
)

// IsTerminal returns true if this status represents a final state
func (s IntentLifecycleStatus) IsTerminal() bool {
	return s == IntentLifecycleComplete || s == IntentLifecycleFailed
}

// IntentLifecycleEnriched extends IntentLifecycle with transaction metadata from batch_transactions
type IntentLifecycleEnriched struct {
	IntentLifecycle
	FromChain   *string `json:"from_chain,omitempty"`
	ToChain     *string `json:"to_chain,omitempty"`
	FromAddress *string `json:"from_address,omitempty"`
	ToAddress   *string `json:"to_address,omitempty"`
	Amount      *string `json:"amount,omitempty"`
	TokenSymbol *string `json:"token_symbol,omitempty"`
	AccountURL  *string `json:"account_url,omitempty"`
}

// IntentLifecycle represents a row in the intent_lifecycle table
type IntentLifecycle struct {
	ID            int64                 `json:"id" db:"id"`
	IntentID      string                `json:"intent_id" db:"intent_id"`
	AccumTxHash   string                `json:"accum_tx_hash" db:"accum_tx_hash"`
	UserID        *string               `json:"user_id,omitempty" db:"user_id"`
	Status        IntentLifecycleStatus `json:"status" db:"status"`
	TargetChain   *string               `json:"target_chain,omitempty" db:"target_chain"`
	ProofClass    *string               `json:"proof_class,omitempty" db:"proof_class"`
	ErrorMessage  *string               `json:"error_message,omitempty" db:"error_message"`
	BlockHeight   *int64                `json:"block_height,omitempty" db:"block_height"`
	CycleID       *string               `json:"cycle_id,omitempty" db:"cycle_id"`
	WriteBackTx   *string               `json:"write_back_tx,omitempty" db:"write_back_tx"`
	TargetChains  pq.StringArray        `json:"target_chains,omitempty" db:"target_chains"`
	LegCount      *int                  `json:"leg_count,omitempty" db:"leg_count"`
	ExecutionMode *string               `json:"execution_mode,omitempty" db:"execution_mode"`
	LegsCompleted *int                  `json:"legs_completed,omitempty" db:"legs_completed"`
	LegsFailed    *int                  `json:"legs_failed,omitempty" db:"legs_failed"`
	CreatedAt     time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at" db:"updated_at"`
	SubmittedAt   *time.Time            `json:"submitted_at,omitempty" db:"submitted_at"`
	AuthorizedAt  *time.Time            `json:"authorized_at,omitempty" db:"authorized_at"`
	InProcessAt   *time.Time            `json:"in_process_at,omitempty" db:"in_process_at"`
	CompletedAt   *time.Time            `json:"completed_at,omitempty" db:"completed_at"`
	FailedAt      *time.Time            `json:"failed_at,omitempty" db:"failed_at"`
}
