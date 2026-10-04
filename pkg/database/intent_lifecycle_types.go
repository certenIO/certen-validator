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
	// IntentLifecycleSubmitted - Intent written to Accumulate. Not written by the validators: they see an intent only once
	// it executed, and record it authorized (RB4-F73 - this said "set retroactively by validator", which nothing does).
	IntentLifecycleSubmitted IntentLifecycleStatus = "submitted"

	// IntentLifecyclePendingSignatures - Multi-sig awaiting signatures. Never written by the validators, and never
	// will be: they read executed transactions, and a transaction awaiting signatures has not executed. Nor can the
	// bridge write it - seven independent databases behind a read-only lifecycle API, and a validator does not record
	// state on another service's word. An intent awaiting signatures is reported from Accumulate's own records by the
	// api-bridge (src/intent-state.ts, `intent.state: awaiting_signatures`, source accumulate) and shown by the gateway
	// (RB4-F63). Kept so a reader of the bridge's mapping of it finds why it is never produced.
	IntentLifecyclePendingSignatures IntentLifecycleStatus = "pending_signatures"

	// IntentLifecycleAuthorized - Accumulate delivered (statusNo=201), committed to block
	IntentLifecycleAuthorized IntentLifecycleStatus = "authorized"

	// IntentLifecycleInProcess - Validators running proof cycle (Phase 7-9)
	IntentLifecycleInProcess IntentLifecycleStatus = "in_process"

	// IntentLifecycleSettling - consensus is done and the target-chain write is IN
	// FLIGHT: submitted, no terminal receipt yet.
	//
	// STAGE 1. There was no state for this, which is exactly why 'complete' was
	// overloaded: an intent was reported complete while its chain write was still
	// unresolved. Measured on intent 1638327d-af2c-439c-a188-be53cdb5c854
	// (2026-08-25), the fleet logged "processed successfully and marked complete"
	// FIFTY-ONE SECONDS before the transaction actually confirmed status=1. A
	// missing state does not make the state stop existing — it makes some other
	// state lie about it.
	//
	// Sits BETWEEN in_process and the terminal states: in_process means the proof
	// cycle is running, settling means it is specifically waiting on the target
	// chain's receipt. NOT terminal and NOT a failure — an intent here is waiting,
	// which is the ordinary case. Phase 7's observation of the real receipt
	// resolves it to complete or failed.
	IntentLifecycleSettling IntentLifecycleStatus = "settling"

	// IntentLifecycleComplete - Phase 9 writeback to Accumulate succeeded
	IntentLifecycleComplete IntentLifecycleStatus = "complete"

	// IntentLifecycleFailed - nothing executed as committed and nothing is owed: a proven revert or absent effect, a
	// non-settlement, an attested refusal. Never an intent whose action executed with its proof still owed (RB6).
	IntentLifecycleFailed IntentLifecycleStatus = "failed"

	// IntentLifecycleExecutedProofPending - every member resolved and at least one EXECUTED on its chain with its proof
	// bundle not produced yet. NOT a failure and NOT terminal: the bundle is recovered automatically, and the intent
	// then completes (RB6, owner decision 2026-10-04).
	IntentLifecycleExecutedProofPending IntentLifecycleStatus = "executed_proof_pending"

	// IntentLifecycleExecutedProofUnavailable - executed, and its proof can never be produced (declared by an operator,
	// with the evidence). Terminal; not a failure of the action.
	IntentLifecycleExecutedProofUnavailable IntentLifecycleStatus = "executed_proof_unavailable"

	// IntentLifecycleRefusedPendingAttestation - refused by name before any chain transaction (the member's refusal
	// names why); the quorum attestation of its non-settlement is pending, after which the intent fails with
	// failure_class refused (RB6-F10).
	IntentLifecycleRefusedPendingAttestation IntentLifecycleStatus = "refused_pending_attestation"
)

// IntentFailureClass is why a failed intent failed, set from typed errors where the failure is recorded
// (RB4-F13; migration 00014). A failed intent recorded before the class existed has none.
type IntentFailureClass string

const (
	// FailureRefused: the intent itself cannot be settled; its bytes are final on Accumulate.
	FailureRefused IntentFailureClass = "refused"
	// FailureNotEntitled: its principal holds no CERTEN entitlement.
	FailureNotEntitled IntentFailureClass = "not_entitled"
	// FailureGovernanceUnsatisfied: its governance proof shows it lacks the authority it needs.
	FailureGovernanceUnsatisfied IntentFailureClass = "governance_unsatisfied"
	// FailureGovernanceUnavailable: its governance proof could not be produced - not a verdict on the intent.
	FailureGovernanceUnavailable IntentFailureClass = "governance_unavailable"
	// FailureSettlementFailed: a chain member did not settle, or was not proven or written back.
	FailureSettlementFailed IntentFailureClass = "settlement_failed"
	// FailureProcessingFailed: CERTEN could not complete processing it.
	FailureProcessingFailed IntentFailureClass = "processing_failed"
)

// IsTerminal returns true if this status represents a final state.
//
// settling is deliberately NOT terminal: it is the one state whose whole purpose
// is to say "the answer is not in yet".
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
	// FailureClass is why a failed intent failed (IntentFailureClass); nil when it has not failed, or failed
	// before the class was recorded.
	FailureClass *string `json:"failure_class,omitempty" db:"failure_class"`
}
