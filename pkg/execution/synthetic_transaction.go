// Copyright 2025 Certen Protocol
//
// Synthetic Transaction Types - Write-back to Accumulate Network
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
//
// These types represent the synthetic transactions created by validators
// to record proof cycle completion on the Accumulate network. This closes
// the cryptographic loop by writing external chain execution results back
// to Accumulate with full attestation proof.

package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// SYNTHETIC TRANSACTION TYPES
// =============================================================================

// SyntheticTransaction represents a transaction created by validators
// to record proof cycle completion on Accumulate
type SyntheticTransaction struct {
	// Transaction identification
	TxID   [32]byte `json:"tx_id"`
	TxHash [32]byte `json:"tx_hash"`
	TxType string   `json:"tx_type"` // "CertenProofResult", "CertenAttestationRecord"

	// Source data
	OriginBundleID [32]byte `json:"origin_bundle_id"` // Original validator block bundle
	ResultHash     [32]byte `json:"result_hash"`      // Hash of external chain result

	// Target Accumulate account
	Principal string `json:"principal"` // Accumulate URL (e.g., "acc://certen.acme/results")

	// Transaction body
	Body *SyntheticTxBody `json:"body"`

	// Signatures from validators
	Signatures []SyntheticSignature `json:"signatures"`

	// Attestation proof
	AttestationProof *AggregatedAttestation `json:"attestation_proof"`

	// Metadata
	CreatedAt   time.Time `json:"created_at"`
	SubmittedAt time.Time `json:"submitted_at,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`

	// Status
	Status    string `json:"status"` // pending, submitted, confirmed, failed
	TxReceipt string `json:"tx_receipt,omitempty"`
}

// SyntheticTxBody contains the body of the synthetic transaction
type SyntheticTxBody struct {
	// Proof cycle completion data
	ProofCycleResult ProofCycleResult `json:"proof_cycle_result"`

	// External chain verification
	ExternalChainProof ExternalChainProofSummary `json:"external_chain_proof"`

	// Accumulate data entry fields
	DataEntry CertenDataEntry `json:"data_entry"`
}

// ProofCycleResult represents the complete proof cycle outcome
type ProofCycleResult struct {
	// Original intent
	IntentHash   [32]byte `json:"intent_hash"`
	IntentBlock  uint64   `json:"intent_block"`
	IntentTxHash string   `json:"intent_tx_hash"`

	// Execution binding
	OperationID   [32]byte `json:"operation_id"`
	BundleID      [32]byte `json:"bundle_id"`
	CommitmentHash [32]byte `json:"commitment_hash"`

	// External chain execution
	TargetChain         string      `json:"target_chain"`
	TargetChainID       int64       `json:"target_chain_id"`
	ExecutionTxHash     common.Hash `json:"execution_tx_hash"`
	ExecutionBlockNumber *big.Int   `json:"execution_block_number"`
	ExecutionBlockHash  common.Hash `json:"execution_block_hash"`
	ExecutionSuccess    bool        `json:"execution_success"`
	ExecutionGasUsed    uint64      `json:"execution_gas_used"`

	// State binding
	StateRoot        common.Hash `json:"state_root"`
	TransactionsRoot common.Hash `json:"transactions_root"`
	ReceiptsRoot     common.Hash `json:"receipts_root"`

	// Attestation summary
	AttestationCount    int      `json:"attestation_count"`
	AttestationPower    *big.Int `json:"attestation_power"`
	AttestationThreshold bool    `json:"attestation_threshold"`

	// Final proof hash
	ProofCycleHash [32]byte `json:"proof_cycle_hash"`
}

// ExternalChainProofSummary contains a summary of the external chain proof
type ExternalChainProofSummary struct {
	// Merkle proof indicators (actual proofs are too large)
	TxInclusionProofValid      bool     `json:"tx_inclusion_proof_valid"`
	ReceiptInclusionProofValid bool     `json:"receipt_inclusion_proof_valid"`
	ProofRootHash              [32]byte `json:"proof_root_hash"`

	// Block finalization
	ConfirmationBlocks int       `json:"confirmation_blocks"`
	FinalizedAt        time.Time `json:"finalized_at"`
}

// CertenDataEntry represents the COMPREHENSIVE data entry format for Accumulate write-back
// This structure contains all fields required for independent audit and verification
// by miners using the proof artifacts stored in PostgreSQL
type CertenDataEntry struct {
	// ==========================================================================
	// ENTRY IDENTIFICATION (Entry 0-2)
	// ==========================================================================
	EntryType string `json:"entry_type"` // "certen:proof_result:v2"
	Version   string `json:"version"`    // "2.0" for enhanced format

	// ==========================================================================
	// INTENT REFERENCE (Entries 3-6) - Links back to original Accumulate intent
	// ==========================================================================
	IntentID       string `json:"intent_id"`        // Intent operation group ID
	IntentHash     string `json:"intent_hash"`      // Hex-encoded intent hash
	IntentTxHash   string `json:"intent_tx_hash"`   // Original Accumulate transaction ID
	IntentBlock    uint64 `json:"intent_block"`     // Accumulate block containing intent

	// ==========================================================================
	// EXECUTION COMMITMENT (Entries 7-12) - Pre-execution cryptographic binding
	// These fields were committed BEFORE execution and verified AFTER
	// ==========================================================================
	OperationID      string `json:"operation_id"`      // Hex-encoded operation ID
	BundleID         string `json:"bundle_id"`         // Hex-encoded bundle ID
	CommitmentHash   string `json:"commitment_hash"`   // SHA256 of execution commitment
	AnchorContract   string `json:"anchor_contract"`   // Anchor contract address (e.g., 0xEb17eBd...)
	FunctionSelector string `json:"function_selector"` // 4-byte selector (e.g., 0x2897eb55)
	ExpectedValue    string `json:"expected_value"`    // Expected msg.value (0 for anchor calls)

	// ==========================================================================
	// 3-STEP TRANSACTION DETAILS (Entries 13-21)
	// Details of the anchor workflow: createAnchor → executeComprehensiveProof → executeWithGovernance
	// ==========================================================================
	// Step 1: createAnchor
	Step1Selector   string `json:"step1_selector"`    // createAnchor selector (0x...)
	Step1Contract   string `json:"step1_contract"`    // Anchor contract address
	Step1IntentHash string `json:"step1_intent_hash"` // Intent hash passed to createAnchor

	// Step 2: executeComprehensiveProof
	Step2Selector string `json:"step2_selector"` // executeComprehensiveProof selector
	Step2Contract string `json:"step2_contract"` // Anchor contract

	// Step 3: executeWithGovernance (final execution)
	Step3Selector    string `json:"step3_selector"`     // executeWithGovernance selector (0x2897eb55)
	Step3Contract    string `json:"step3_contract"`     // Anchor contract
	Step3FinalTarget string `json:"step3_final_target"` // Final recipient (e.g., 0x02841F7Fa...)
	Step3FinalValue  string `json:"step3_final_value"`  // Amount transferred to final target

	// ==========================================================================
	// ACTUAL EXECUTION RESULT (Entries 22-29)
	// ==========================================================================
	ChainName   string `json:"chain_name"`   // "ethereum"
	ChainID     int64  `json:"chain_id"`     // 11155111 (Sepolia)
	TxHash      string `json:"tx_hash"`      // Ethereum transaction hash
	BlockNumber uint64 `json:"block_number"` // Block containing the transaction
	BlockHash   string `json:"block_hash"`   // Block hash for verification
	Success     bool   `json:"success"`      // Transaction success status
	GasUsed     uint64 `json:"gas_used"`     // Gas consumed
	TxFrom      string `json:"tx_from"`      // Executor address (elected validator)

	// ==========================================================================
	// EVENT VERIFICATION (Entries 30-33)
	// Proves the correct events were emitted by the execution
	// ==========================================================================
	EventsHash           string `json:"events_hash"`            // SHA256 of all emitted events
	EventCount           int    `json:"event_count"`            // Number of events emitted
	TransferExecutedHash string `json:"transfer_executed_hash"` // Hash of TransferExecuted event (if present)
	EventsVerified       bool   `json:"events_verified"`        // True if events match expected

	// ==========================================================================
	// STATE BINDING (Entries 34-36) - Cryptographic state roots from Ethereum
	// ==========================================================================
	StateRoot        string `json:"state_root"`        // Ethereum state trie root
	ReceiptsRoot     string `json:"receipts_root"`     // Receipts trie root
	TransactionsRoot string `json:"transactions_root"` // Transactions trie root

	// ==========================================================================
	// GOVERNANCE PROOF (Entries 37-40)
	// ==========================================================================
	ValidatorCount     int    `json:"validator_count"`      // Number of attesting validators
	SignedPower        string `json:"signed_power"`         // Total voting power (string for big.Int)
	GovernanceProofRef string `json:"governance_proof_ref"` // Reference to full governance proof (BLS, ZK)
	ThresholdMet       bool   `json:"threshold_met"`        // True if attestation threshold met

	// ==========================================================================
	// AUDIT REFERENCES (Entries 41-44) - Links for independent verification
	// ==========================================================================
	ProofArtifactID    string `json:"proof_artifact_id"`    // PostgreSQL artifact ID for full proof data
	AnchorProofHash    string `json:"anchor_proof_hash"`    // L3 anchor proof binding
	PreviousResultHash string `json:"previous_result_hash"` // L4 hash chain continuity
	SequenceNumber     uint64 `json:"sequence_number"`      // Position in result sequence

	// ==========================================================================
	// RESULT HASHES (Entries 45-47)
	// ==========================================================================
	ResultHash     string `json:"result_hash"`      // Final result hash (deterministic)
	ProofCycleHash string `json:"proof_cycle_hash"` // Proof cycle hash

	// ==========================================================================
	// FINALIZATION (Entries 48-50)
	// ==========================================================================
	ConfirmationBlocks int   `json:"confirmation_blocks"` // Blocks confirmed (e.g., 12)
	Timestamp          int64 `json:"timestamp"`           // Unix timestamp of write-back
	FinalizedAt        int64 `json:"finalized_at"`        // Unix timestamp of finalization
}

// SyntheticSignature represents a validator's signature on the synthetic tx
type SyntheticSignature struct {
	ValidatorID string `json:"validator_id"`
	PublicKey   []byte `json:"public_key"`
	Signature   []byte `json:"signature"`
	Timestamp   int64  `json:"timestamp"`
}

// =============================================================================
// SYNTHETIC TRANSACTION BUILDER
// =============================================================================

// SyntheticTxBuilder builds synthetic transactions for Accumulate
type SyntheticTxBuilder struct {
	// Principal account for results
	resultsPrincipal string

	// Validator info
	validatorID string

	// Ed25519 signing key (64 bytes = seed + public key)
	signingKey ed25519.PrivateKey

	// Optional prefix for data entries
	entryPrefix string
}

// NewSyntheticTxBuilder creates a new synthetic transaction builder
// signingKey can be either:
// - ed25519.PrivateKey (64 bytes) - used directly
// - []byte of 32 bytes - used as seed to derive Ed25519 key
// - []byte of 64 bytes - used as Ed25519 private key
func NewSyntheticTxBuilder(
	resultsPrincipal string,
	validatorID string,
	signingKey []byte,
) *SyntheticTxBuilder {
	var privateKey ed25519.PrivateKey

	switch len(signingKey) {
	case ed25519.PrivateKeySize: // 64 bytes - full private key
		privateKey = ed25519.PrivateKey(signingKey)
	case ed25519.SeedSize: // 32 bytes - seed
		privateKey = ed25519.NewKeyFromSeed(signingKey)
	default:
		// Derive a key from the provided bytes using SHA256
		seed := sha256.Sum256(signingKey)
		privateKey = ed25519.NewKeyFromSeed(seed[:])
	}

	return &SyntheticTxBuilder{
		resultsPrincipal: resultsPrincipal,
		validatorID:      validatorID,
		signingKey:       privateKey,
		entryPrefix:      "certen:proof_result:v2",
	}
}

// NewSyntheticTxBuilderFromEd25519 creates a builder with an Ed25519 private key
func NewSyntheticTxBuilderFromEd25519(
	resultsPrincipal string,
	validatorID string,
	privateKey ed25519.PrivateKey,
) *SyntheticTxBuilder {
	return &SyntheticTxBuilder{
		resultsPrincipal: resultsPrincipal,
		validatorID:      validatorID,
		signingKey:       privateKey,
		entryPrefix:      "certen:proof_result:v2",
	}
}

// =============================================================================
// COMPREHENSIVE PROOF CONTEXT
// =============================================================================

// ComprehensiveProofContext contains all the data needed for a complete audit-ready write-back
// This is populated during the proof cycle and passed to the builder
type ComprehensiveProofContext struct {
	// Intent reference
	IntentID     string   `json:"intent_id"`
	IntentHash   [32]byte `json:"intent_hash"`
	IntentTxHash string   `json:"intent_tx_hash"`
	IntentBlock  uint64   `json:"intent_block"`

	// Execution commitment (pre-execution binding)
	Commitment *ExecutionCommitment `json:"commitment"`

	// 3-step transaction details (from BFT flow)
	Step1Selector   string `json:"step1_selector"`
	Step1Contract   string `json:"step1_contract"`
	Step1IntentHash string `json:"step1_intent_hash"`
	Step2Selector   string `json:"step2_selector"`
	Step2Contract   string `json:"step2_contract"`
	Step3Selector   string `json:"step3_selector"`
	Step3Contract   string `json:"step3_contract"`
	Step3FinalTarget string `json:"step3_final_target"`
	Step3FinalValue  string `json:"step3_final_value"`

	// Event verification
	EventsHash           [32]byte `json:"events_hash"`
	EventCount           int      `json:"event_count"`
	TransferExecutedHash string   `json:"transfer_executed_hash"`
	EventsVerified       bool     `json:"events_verified"`

	// Governance proof reference
	GovernanceProofRef string `json:"governance_proof_ref"`

	// Audit references
	ProofArtifactID    string   `json:"proof_artifact_id"`
	AnchorProofHash    [32]byte `json:"anchor_proof_hash"`
	PreviousResultHash [32]byte `json:"previous_result_hash"`
	SequenceNumber     uint64   `json:"sequence_number"`
}

// BuildFromBundle creates a synthetic transaction from an attestation bundle
// This is the basic builder - for comprehensive proof data, use BuildFromBundleWithContext
func (b *SyntheticTxBuilder) BuildFromBundle(bundle *AttestationBundle) (*SyntheticTransaction, error) {
	return b.BuildFromBundleWithContext(bundle, nil)
}

// BuildFromBundleWithContext creates a synthetic transaction with comprehensive proof data
// The context parameter contains all the additional data needed for full audit support
func (b *SyntheticTxBuilder) BuildFromBundleWithContext(bundle *AttestationBundle, ctx *ComprehensiveProofContext) (*SyntheticTransaction, error) {
	if bundle == nil {
		return nil, errors.New("attestation bundle is nil")
	}

	if !bundle.IsComplete() {
		return nil, errors.New("attestation bundle is not complete")
	}

	result := bundle.Result
	agg := bundle.Aggregated

	// Build proof cycle result
	proofResult := ProofCycleResult{
		BundleID:             bundle.BundleID,
		TargetChain:          result.Chain,
		TargetChainID:        result.ChainID,
		ExecutionTxHash:      result.TxHash,
		ExecutionBlockNumber: result.BlockNumber,
		ExecutionBlockHash:   result.BlockHash,
		ExecutionSuccess:     result.IsSuccess(),
		ExecutionGasUsed:     result.TxGasUsed,
		StateRoot:            result.StateRoot,
		TransactionsRoot:     result.TransactionsRoot,
		ReceiptsRoot:         result.ReceiptsRoot,
		AttestationCount:     agg.ValidatorCount,
		AttestationPower:     agg.SignedVotingPower,
		AttestationThreshold: agg.ThresholdMet,
	}

	// Compute proof cycle hash
	proofResult.ProofCycleHash = computeProofCycleHash(&proofResult)

	// Build external chain proof summary
	externalProof := ExternalChainProofSummary{
		TxInclusionProofValid:      result.TxInclusionProof != nil && result.TxInclusionProof.Verified,
		ReceiptInclusionProofValid: result.ReceiptInclusionProof != nil && result.ReceiptInclusionProof.Verified,
		ConfirmationBlocks:         result.ConfirmationBlocks,
		FinalizedAt:                result.FinalizedAt,
	}

	// Compute proof root hash
	if result.TxInclusionProof != nil {
		externalProof.ProofRootHash = result.TxInclusionProof.ExpectedRoot
	}

	// Compute events hash from result logs
	eventsHash := computeEventsHash(result.Logs)

	// Build COMPREHENSIVE data entry
	now := time.Now()
	dataEntry := CertenDataEntry{
		// Entry identification
		EntryType: b.entryPrefix,
		Version:   "2.0",

		// Actual execution result
		ChainName:   result.Chain,
		ChainID:     result.ChainID,
		TxHash:      result.TxHash.Hex(),
		BlockNumber: result.BlockNumber.Uint64(),
		BlockHash:   result.BlockHash.Hex(),
		Success:     result.IsSuccess(),
		GasUsed:     result.TxGasUsed,
		TxFrom:      result.TxFrom.Hex(),

		// Event verification
		EventsHash: hex.EncodeToString(eventsHash[:]),
		EventCount: len(result.Logs),

		// State binding
		StateRoot:        result.StateRoot.Hex(),
		ReceiptsRoot:     result.ReceiptsRoot.Hex(),
		TransactionsRoot: result.TransactionsRoot.Hex(),

		// Governance proof
		ValidatorCount: agg.ValidatorCount,
		ThresholdMet:   agg.ThresholdMet,

		// Result hashes
		BundleID:       hex.EncodeToString(bundle.BundleID[:]),
		ResultHash:     hex.EncodeToString(bundle.ResultHash[:]),
		ProofCycleHash: hex.EncodeToString(proofResult.ProofCycleHash[:]),

		// Finalization
		ConfirmationBlocks: result.ConfirmationBlocks,
		Timestamp:          now.Unix(),
		FinalizedAt:        result.FinalizedAt.Unix(),

		// Audit references from result
		AnchorProofHash:    hex.EncodeToString(result.AnchorProofHash[:]),
		PreviousResultHash: hex.EncodeToString(result.PreviousResultHash[:]),
		SequenceNumber:     result.SequenceNumber,
	}

	// Populate signed power
	if agg.SignedVotingPower != nil {
		dataEntry.SignedPower = agg.SignedVotingPower.String()
	}

	// If comprehensive context is provided, populate additional fields
	if ctx != nil {
		// Intent reference
		dataEntry.IntentID = ctx.IntentID
		dataEntry.IntentHash = hex.EncodeToString(ctx.IntentHash[:])
		dataEntry.IntentTxHash = ctx.IntentTxHash
		dataEntry.IntentBlock = ctx.IntentBlock

		// Execution commitment
		if ctx.Commitment != nil {
			dataEntry.OperationID = hex.EncodeToString(ctx.Commitment.OperationID[:])
			dataEntry.CommitmentHash = hex.EncodeToString(ctx.Commitment.CommitmentHash[:])
			dataEntry.AnchorContract = ctx.Commitment.TargetContract.Hex()
			dataEntry.FunctionSelector = hex.EncodeToString(ctx.Commitment.FunctionSelector[:])
			if ctx.Commitment.ExpectedValue != nil {
				dataEntry.ExpectedValue = ctx.Commitment.ExpectedValue.String()
			}
		}

		// 3-step transaction details
		dataEntry.Step1Selector = ctx.Step1Selector
		dataEntry.Step1Contract = ctx.Step1Contract
		dataEntry.Step1IntentHash = ctx.Step1IntentHash
		dataEntry.Step2Selector = ctx.Step2Selector
		dataEntry.Step2Contract = ctx.Step2Contract
		dataEntry.Step3Selector = ctx.Step3Selector
		dataEntry.Step3Contract = ctx.Step3Contract
		dataEntry.Step3FinalTarget = ctx.Step3FinalTarget
		dataEntry.Step3FinalValue = ctx.Step3FinalValue

		// Event verification
		dataEntry.TransferExecutedHash = ctx.TransferExecutedHash
		dataEntry.EventsVerified = ctx.EventsVerified

		// Governance proof reference
		dataEntry.GovernanceProofRef = ctx.GovernanceProofRef

		// Proof artifact ID for PostgreSQL lookup
		dataEntry.ProofArtifactID = ctx.ProofArtifactID
	}

	// Build transaction body
	body := &SyntheticTxBody{
		ProofCycleResult:   proofResult,
		ExternalChainProof: externalProof,
		DataEntry:          dataEntry,
	}

	// Create transaction
	tx := &SyntheticTransaction{
		TxType:           "CertenProofResult",
		OriginBundleID:   bundle.BundleID,
		ResultHash:       bundle.ResultHash,
		Principal:        b.resultsPrincipal,
		Body:             body,
		AttestationProof: agg,
		CreatedAt:        time.Now(),
		Status:           "pending",
	}

	// Compute transaction hash
	tx.TxHash = tx.ComputeTxHash()

	// Generate transaction ID
	tx.TxID = computeTxID(tx.TxHash, time.Now())

	return tx, nil
}

// AddSignature adds a validator signature to the transaction
func (b *SyntheticTxBuilder) AddSignature(tx *SyntheticTransaction) error {
	if tx == nil {
		return errors.New("transaction is nil")
	}

	// Create signature
	signature := b.signTx(tx.TxHash)

	sig := SyntheticSignature{
		ValidatorID: b.validatorID,
		PublicKey:   b.getPublicKey(),
		Signature:   signature,
		Timestamp:   time.Now().Unix(),
	}

	tx.Signatures = append(tx.Signatures, sig)
	return nil
}

// signTx creates an Ed25519 signature over the transaction hash
func (b *SyntheticTxBuilder) signTx(txHash [32]byte) []byte {
	// Sign the transaction hash with Ed25519
	signature := ed25519.Sign(b.signingKey, txHash[:])
	return signature
}

// getPublicKey returns the Ed25519 public key
func (b *SyntheticTxBuilder) getPublicKey() []byte {
	// Extract public key from the Ed25519 private key
	// Ed25519 private key is 64 bytes: 32-byte seed + 32-byte public key
	publicKey := b.signingKey.Public().(ed25519.PublicKey)
	return publicKey
}

// VerifySignature verifies an Ed25519 signature
func (b *SyntheticTxBuilder) VerifySignature(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// computeProofCycleHash computes a deterministic hash of the proof cycle result
func computeProofCycleHash(result *ProofCycleResult) [32]byte {
	data := make([]byte, 0, 256)

	data = append(data, []byte("CERTEN_PROOF_CYCLE_V1")...)
	data = append(data, result.BundleID[:]...)
	data = append(data, []byte(result.TargetChain)...)
	data = append(data, result.ExecutionTxHash.Bytes()...)
	data = append(data, result.ExecutionBlockHash.Bytes()...)
	data = append(data, result.StateRoot.Bytes()...)

	if result.ExecutionSuccess {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	return sha256.Sum256(data)
}

// computeTxID generates a unique transaction ID
func computeTxID(txHash [32]byte, timestamp time.Time) [32]byte {
	data := make([]byte, 0, 40)
	data = append(data, txHash[:]...)

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp.UnixNano()))
	data = append(data, timeBytes...)

	return sha256.Sum256(data)
}

// ComputeTxHash computes the transaction hash
func (tx *SyntheticTransaction) ComputeTxHash() [32]byte {
	data := make([]byte, 0, 256)

	data = append(data, []byte("CERTEN_SYNTHETIC_TX_V1")...)
	data = append(data, []byte(tx.TxType)...)
	data = append(data, tx.OriginBundleID[:]...)
	data = append(data, tx.ResultHash[:]...)
	data = append(data, []byte(tx.Principal)...)

	if tx.Body != nil {
		bodyData, _ := json.Marshal(tx.Body)
		bodyHash := sha256.Sum256(bodyData)
		data = append(data, bodyHash[:]...)
	}

	return sha256.Sum256(data)
}

// ToHex returns a hex representation for logging
func (tx *SyntheticTransaction) ToHex() string {
	return hex.EncodeToString(tx.TxID[:])
}

// =============================================================================
// RESULT WRITE-BACK SERVICE
// =============================================================================

// ResultWriteBack handles writing proof results back to Accumulate
type ResultWriteBack struct {
	mu sync.RWMutex

	// Transaction builder
	builder *SyntheticTxBuilder

	// Accumulate client interface
	accClient AccumulateSubmitter

	// Pending transactions
	pending map[[32]byte]*SyntheticTransaction

	// Submitted transactions waiting for confirmation
	submitted map[[32]byte]*SyntheticTransaction

	// Configuration
	retryInterval   time.Duration
	maxRetries      int
	confirmTimeout  time.Duration

	// Callbacks
	onConfirmed func(*SyntheticTransaction)
	onFailed    func(*SyntheticTransaction, error)
}

// AccumulateSubmitter interface for submitting transactions to Accumulate
type AccumulateSubmitter interface {
	SubmitTransaction(ctx context.Context, tx *SyntheticTransaction) (string, error)
	GetTransactionStatus(ctx context.Context, txHash string) (string, error)
}

// NewResultWriteBack creates a new result write-back service
func NewResultWriteBack(
	builder *SyntheticTxBuilder,
	accClient AccumulateSubmitter,
) *ResultWriteBack {
	return &ResultWriteBack{
		builder:        builder,
		accClient:      accClient,
		pending:        make(map[[32]byte]*SyntheticTransaction),
		submitted:      make(map[[32]byte]*SyntheticTransaction),
		retryInterval:  5 * time.Second,
		maxRetries:     3,
		confirmTimeout: 2 * time.Minute,
	}
}

// SetCallbacks sets the confirmation/failure callbacks
func (w *ResultWriteBack) SetCallbacks(
	onConfirmed func(*SyntheticTransaction),
	onFailed func(*SyntheticTransaction, error),
) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onConfirmed = onConfirmed
	w.onFailed = onFailed
}

// WriteResult creates and submits a synthetic transaction for a proof result
// This is the basic method - for comprehensive proof data, use WriteResultWithContext
func (w *ResultWriteBack) WriteResult(ctx context.Context, bundle *AttestationBundle) error {
	return w.WriteResultWithContext(ctx, bundle, nil)
}

// WriteResultWithContext creates and submits a synthetic transaction with comprehensive proof context
// The proofCtx parameter contains all additional data needed for full audit support (intent refs, commitment, etc.)
func (w *ResultWriteBack) WriteResultWithContext(ctx context.Context, bundle *AttestationBundle, proofCtx *ComprehensiveProofContext) error {
	// Build synthetic transaction with context
	tx, err := w.builder.BuildFromBundleWithContext(bundle, proofCtx)
	if err != nil {
		return fmt.Errorf("build synthetic tx: %w", err)
	}

	// Add our signature
	if err := w.builder.AddSignature(tx); err != nil {
		return fmt.Errorf("add signature: %w", err)
	}

	// Store as pending
	w.mu.Lock()
	w.pending[tx.TxID] = tx
	w.mu.Unlock()

	// Submit transaction
	return w.submitWithRetry(ctx, tx)
}

// submitWithRetry submits a transaction with retries
func (w *ResultWriteBack) submitWithRetry(ctx context.Context, tx *SyntheticTransaction) error {
	var lastErr error

	for attempt := 0; attempt < w.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.retryInterval):
			}
		}

		receipt, err := w.accClient.SubmitTransaction(ctx, tx)
		if err != nil {
			lastErr = err
			continue
		}

		// Success
		w.mu.Lock()
		tx.Status = "submitted"
		tx.SubmittedAt = time.Now()
		tx.TxReceipt = receipt

		delete(w.pending, tx.TxID)
		w.submitted[tx.TxID] = tx
		w.mu.Unlock()

		// Start confirmation watcher
		go w.watchConfirmation(ctx, tx)

		return nil
	}

	// All retries failed
	w.mu.Lock()
	tx.Status = "failed"
	delete(w.pending, tx.TxID)
	w.mu.Unlock()

	if w.onFailed != nil {
		go w.onFailed(tx, lastErr)
	}

	return fmt.Errorf("submit failed after %d attempts: %w", w.maxRetries, lastErr)
}

// watchConfirmation watches for transaction confirmation
func (w *ResultWriteBack) watchConfirmation(ctx context.Context, tx *SyntheticTransaction) {
	timeout := time.After(w.confirmTimeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timeout:
			w.mu.Lock()
			tx.Status = "timeout"
			delete(w.submitted, tx.TxID)
			w.mu.Unlock()

			if w.onFailed != nil {
				w.onFailed(tx, errors.New("confirmation timeout"))
			}
			return

		case <-ticker.C:
			status, err := w.accClient.GetTransactionStatus(ctx, tx.TxReceipt)
			if err != nil {
				continue
			}

			if status == "confirmed" || status == "delivered" {
				w.mu.Lock()
				tx.Status = "confirmed"
				tx.ConfirmedAt = time.Now()
				delete(w.submitted, tx.TxID)
				w.mu.Unlock()

				if w.onConfirmed != nil {
					w.onConfirmed(tx)
				}
				return
			}

			if status == "failed" || status == "rejected" {
				w.mu.Lock()
				tx.Status = "failed"
				delete(w.submitted, tx.TxID)
				w.mu.Unlock()

				if w.onFailed != nil {
					w.onFailed(tx, fmt.Errorf("transaction %s", status))
				}
				return
			}
		}
	}
}

// GetPendingCount returns the number of pending transactions
func (w *ResultWriteBack) GetPendingCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.pending)
}

// GetSubmittedCount returns the number of submitted transactions
func (w *ResultWriteBack) GetSubmittedCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.submitted)
}

// =============================================================================
// PROOF CYCLE COMPLETION
// =============================================================================

// ProofCycleCompletion represents the complete proof cycle from intent to write-back
type ProofCycleCompletion struct {
	// Original intent
	IntentID      string   `json:"intent_id"`
	IntentTxHash  string   `json:"intent_tx_hash"`
	IntentBlock   uint64   `json:"intent_block"`
	IntentHash    [32]byte `json:"intent_hash"`

	// Validator block binding
	ValidatorBlockID string   `json:"validator_block_id"`
	BundleID         [32]byte `json:"bundle_id"`

	// Execution commitment (stored for write-back context)
	Commitment *ExecutionCommitment `json:"commitment,omitempty"`

	// External chain execution
	ExecutionResult *ExternalChainResult `json:"execution_result"`

	// Multi-validator attestation
	Attestation *AggregatedAttestation `json:"attestation"`

	// Write-back transaction
	WriteBackTx *SyntheticTransaction `json:"write_back_tx"`

	// Proof cycle hash (cryptographic binding of everything)
	CycleHash [32]byte `json:"cycle_hash"`

	// Timing
	IntentTime     time.Time `json:"intent_time"`
	ExecutionTime  time.Time `json:"execution_time"`
	AttestationTime time.Time `json:"attestation_time"`
	WriteBackTime  time.Time `json:"write_back_time"`
	TotalDuration  time.Duration `json:"total_duration"`

	// Status
	Complete bool `json:"complete"`
}

// ComputeCycleHash computes the complete proof cycle hash
func (c *ProofCycleCompletion) ComputeCycleHash() [32]byte {
	data := make([]byte, 0, 256)

	data = append(data, []byte("CERTEN_PROOF_CYCLE_COMPLETE_V1")...)
	data = append(data, []byte(c.IntentID)...)
	data = append(data, c.BundleID[:]...)

	if c.ExecutionResult != nil {
		data = append(data, c.ExecutionResult.ResultHash[:]...)
	}

	if c.Attestation != nil {
		aggHash := c.Attestation.ComputeAggregateHash()
		data = append(data, aggHash[:]...)
	}

	if c.WriteBackTx != nil {
		data = append(data, c.WriteBackTx.TxHash[:]...)
	}

	return sha256.Sum256(data)
}

// Finalize marks the proof cycle as complete
func (c *ProofCycleCompletion) Finalize() {
	c.CycleHash = c.ComputeCycleHash()
	c.TotalDuration = c.WriteBackTime.Sub(c.IntentTime)
	c.Complete = true
}

// ToHex returns a hex representation for logging
func (c *ProofCycleCompletion) ToHex() string {
	return hex.EncodeToString(c.CycleHash[:])
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// ComputeSHA256 computes the SHA256 hash of the given data
func ComputeSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// ComputeDoubleHash computes a double SHA256 hash (as used in some Accumulate operations)
func ComputeDoubleHash(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// computeEventsHash computes a deterministic hash of all event logs
// This allows miners to independently verify the events emitted by execution
func computeEventsHash(logs []LogEntry) [32]byte {
	if len(logs) == 0 {
		return sha256.Sum256([]byte("CERTEN_NO_EVENTS"))
	}

	data := make([]byte, 0, 256)
	data = append(data, []byte("CERTEN_EVENTS_V1")...)

	for _, log := range logs {
		// Include: Address, Topics, Data
		data = append(data, log.Address.Bytes()...)
		for _, topic := range log.Topics {
			data = append(data, topic.Bytes()...)
		}
		data = append(data, log.Data...)
	}

	return sha256.Sum256(data)
}
