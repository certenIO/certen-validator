// Copyright 2025 Certen Protocol
//
// External Chain Result Types - Cryptographic proof structures for cross-chain execution
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 7
//
// These types capture the cryptographically verifiable proof that an operation
// was executed on an external chain (e.g., Ethereum) and can be independently verified.

package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// =============================================================================
// EXTERNAL CHAIN RESULT - Cryptographic Proof of Execution
// =============================================================================

// ExternalChainResult contains the complete cryptographic proof that a transaction
// was executed on an external chain and its result is part of the finalized state.
//
// This structure provides everything needed for independent verification:
// - Block headers with state roots
// - Merkle inclusion proofs for transaction and receipt
// - Execution outcome details
// - Hash chain binding for verifiable lineage
// ResultOutcomeNotSettled is the outcome of a member that never settled.
const ResultOutcomeNotSettled = "not_settled"

// ResultOutcomeEffectsNotProven is the outcome of a member whose settlement executed its committed calls
// under its leaf while a committed effect is provably absent (RB3-F67).
const ResultOutcomeEffectsNotProven = "effects_not_proven"

type ExternalChainResult struct {
	// ==========================================================================
	// RESULT IDENTIFICATION (Hash Chain Binding - Phase 2.5)
	// ==========================================================================

	// ResultID is a unique identifier for this result, computed deterministically
	// from chain + block + tx hash for global uniqueness
	ResultID [32]byte `json:"result_id"`

	// PreviousResultHash links to the previous result in the hash chain
	// This creates a verifiable lineage of all execution results
	// For the first result in a chain, this is all zeros
	PreviousResultHash [32]byte `json:"previous_result_hash"`

	// AnchorProofHash binds this Level 4 result to its Level 3: the batch root its member's anchor published
	// (proof_levels.go), zero where that anchor is not established. Per result - results on one chain belong
	// to different intents and anchors (RB3-F106).
	AnchorProofHash [32]byte `json:"anchor_proof_hash"`

	// SequenceNumber is the position in the result hash chain
	SequenceNumber uint64 `json:"sequence_number"`

	// ==========================================================================
	// CHAIN IDENTIFICATION
	// ==========================================================================

	Chain   string `json:"chain"`    // e.g., "ethereum", "sepolia"
	ChainID int64  `json:"chain_id"` // e.g., 11155111 for Sepolia

	// Transaction identification
	TxHash common.Hash `json:"tx_hash"`

	// ==========================================================================
	// NATIVE (NON-EVM) IDENTIFIERS
	// For chains like NEAR that use base58 hashes or account-based addresses
	// ==========================================================================

	NativeTxHash    string `json:"native_tx_hash,omitempty"`    // base58 NEAR tx hash (or other non-hex chain hash)
	NativeBlockHash string `json:"native_block_hash,omitempty"` // base58 NEAR block hash
	NativeTxFrom    string `json:"native_tx_from,omitempty"`    // NEAR account ID (e.g., "certen-kermit-12.acme")

	// ==========================================================================
	// BLOCK INFORMATION
	// ==========================================================================

	BlockNumber *big.Int    `json:"block_number"`
	BlockHash   common.Hash `json:"block_hash"`
	BlockTime   time.Time   `json:"block_time"`

	// Ethereum block state roots (for cryptographic verification)
	TransactionsRoot common.Hash `json:"transactions_root"` // Merkle root of all txs in block
	ReceiptsRoot     common.Hash `json:"receipts_root"`     // Merkle root of all receipts
	StateRoot        common.Hash `json:"state_root"`        // State trie root after block execution

	// ==========================================================================
	// MERKLE INCLUSION PROOFS
	// ==========================================================================

	TxInclusionProof      *MerkleInclusionProof `json:"tx_inclusion_proof"`
	ReceiptInclusionProof *MerkleInclusionProof `json:"receipt_inclusion_proof"`

	// inclusionErr says why the observer built no inclusion proofs (pkg/ethproof's refusal), for the callers that refuse
	// a result without them.
	inclusionErr error

	// RB-5: optional storage-slot state proofs, independently verifiable against StateRoot.
	StateProofs []*StateProof `json:"state_proofs,omitempty"`

	// ==========================================================================
	// TRANSACTION DETAILS
	// ==========================================================================

	TxIndex   uint            `json:"tx_index"`    // Position in block
	TxFrom    common.Address  `json:"tx_from"`     // Sender
	TxTo      *common.Address `json:"tx_to"`       // Recipient (nil for contract creation)
	TxValue   *big.Int        `json:"tx_value"`    // Value transferred
	TxData    []byte          `json:"tx_data"`     // Input data
	TxGasUsed uint64          `json:"tx_gas_used"` // Gas consumed

	// ==========================================================================
	// EXECUTION OUTCOME
	// ==========================================================================

	Status uint64 `json:"status"` // 1=success, 0=revert
	// Outcome is set when the result is not a transaction's: ResultOutcomeNotSettled for a member that
	// never settled (RB3-F49), with OutcomeReason saying why. Empty for a settlement, whose Status says
	// what happened. Not part of ComputeResultHash; the attested result is the non-settlement's own.
	Outcome         string          `json:"outcome,omitempty"`
	OutcomeReason   string          `json:"outcome_reason,omitempty"`
	ContractAddress *common.Address `json:"contract_address,omitempty"` // For contract creation
	Logs            []LogEntry      `json:"logs"`                       // Event logs emitted
	ReturnData      []byte          `json:"return_data,omitempty"`      // Return data (if available)

	// ==========================================================================
	// FINALIZATION PROOF
	// ==========================================================================

	ConfirmationBlocks  int       `json:"confirmation_blocks"` // Blocks since tx (e.g., 12)
	FinalizedAt         time.Time `json:"finalized_at"`
	ObservedByValidator string    `json:"observed_by_validator"`

	// ==========================================================================
	// DETERMINISTIC HASHES
	// ==========================================================================

	// ResultHash is the deterministic hash of this result for attestation signing
	// Computed using RFC8785 canonical JSON for determinism
	ResultHash [32]byte `json:"result_hash"`
}

// LegResult is a lightweight per-leg proof summary for multi-leg intents.
// Uses string types (not common.Hash) for chain-agnostic compatibility
// (EVM hex, Solana base58, NEAR accounts, Aptos hex).
type LegResult struct {
	LegIndex      int      `json:"leg_index"`
	LegID         string   `json:"leg_id,omitempty"`
	Chain         string   `json:"chain"`
	ChainID       int64    `json:"chain_id"`
	TxHash        string   `json:"tx_hash"`
	BlockNumber   uint64   `json:"block_number"`
	BlockHash     string   `json:"block_hash"`
	Status        uint64   `json:"status"` // 1=success, 0=revert
	GasUsed       uint64   `json:"gas_used"`
	TxFrom        string   `json:"tx_from"`
	EventsHash    [32]byte `json:"events_hash"`
	EventCount    int      `json:"event_count"`
	IsFinalized   bool     `json:"is_finalized"`
	Confirmations int      `json:"confirmations"`
}

// ComputeMultiLegResultHash computes a deterministic hash over sorted legs
// using RFC8785 canonical JSON with domain separator "CERTEN_MULTI_LEG_RESULT_V1".
// Legs are sorted by LegIndex before hashing for determinism regardless of input order.
func ComputeMultiLegResultHash(legs []LegResult) [32]byte {
	if len(legs) == 0 {
		return [32]byte{}
	}

	// Sort legs by LegIndex for determinism
	sorted := make([]LegResult, len(legs))
	copy(sorted, legs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LegIndex < sorted[j].LegIndex
	})

	// Build canonical data with domain separator
	data := map[string]interface{}{
		"domain":    "CERTEN_MULTI_LEG_RESULT_V1",
		"leg_count": len(sorted),
		"legs":      sorted,
	}

	canonical := canonicalJSONMarshal(data)
	return sha256.Sum256(canonical)
}

// LogEntry represents an event log from the transaction
type LogEntry struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    []byte         `json:"data"`
	Index   uint           `json:"index"`
}

// MerkleInclusionProof is the Merkle-Patricia inclusion proof of a transaction or a receipt against its block's
// transactionsRoot or receiptsRoot. There is one implementation, pkg/ethproof, shared by the settlement gate and the chain
// strategy's observer (RB5-F16).
type MerkleInclusionProof = ethproof.InclusionProof

// =============================================================================
// RESULT COMPUTATION METHODS (RFC8785 Canonical JSON)
// =============================================================================

// ComputeResultID computes a globally unique identifier for this result
// The ID is deterministic and can be recomputed from chain + block + tx
func (r *ExternalChainResult) ComputeResultID() [32]byte {
	// Use canonical JSON for determinism
	idData := canonicalJSONMarshal(map[string]interface{}{
		"chain":        r.Chain,
		"chain_id":     r.ChainID,
		"block_number": r.BlockNumber.String(),
		"tx_hash":      r.TxHash.Hex(),
	})
	return sha256.Sum256(idData)
}

// ComputeResultHash computes a deterministic hash of the execution result
// This hash is used for attestation signing and verification
// Uses RFC8785 canonical JSON for cross-implementation determinism
func (r *ExternalChainResult) ComputeResultHash() [32]byte {
	// Compute logs hash first
	logsHash := r.computeLogsHash()

	// Build canonical structure with all verification-relevant fields
	canonicalData := canonicalJSONMarshal(map[string]interface{}{
		// Hash chain binding (Level 4 lineage)
		"result_id":            hex.EncodeToString(r.ResultID[:]),
		"previous_result_hash": hex.EncodeToString(r.PreviousResultHash[:]),
		"anchor_proof_hash":    hex.EncodeToString(r.AnchorProofHash[:]),
		"sequence_number":      r.SequenceNumber,

		// Chain identification
		"chain":    r.Chain,
		"chain_id": r.ChainID,

		// Transaction identification
		"tx_hash": r.TxHash.Hex(),

		// Block binding
		"block_number": r.BlockNumber.String(),
		"block_hash":   r.BlockHash.Hex(),

		// State roots (cryptographic binding to block state)
		"transactions_root": r.TransactionsRoot.Hex(),
		"receipts_root":     r.ReceiptsRoot.Hex(),
		"state_root":        r.StateRoot.Hex(),

		// Execution outcome
		"status":      r.Status,
		"tx_index":    r.TxIndex,
		"tx_gas_used": r.TxGasUsed,
		"logs_hash":   hex.EncodeToString(logsHash[:]),
	})

	return sha256.Sum256(canonicalData)
}

// SetHashChainBinding sets the hash chain binding fields
// This must be called before ComputeResultHash() to include chain binding
func (r *ExternalChainResult) SetHashChainBinding(
	previousResultHash [32]byte,
	anchorProofHash [32]byte,
	sequenceNumber uint64,
) {
	r.PreviousResultHash = previousResultHash
	r.AnchorProofHash = anchorProofHash
	r.SequenceNumber = sequenceNumber
	r.ResultID = r.ComputeResultID()
	r.ResultHash = r.ComputeResultHash()
}

// VerifyHashChain verifies that this result correctly chains to the previous
func (r *ExternalChainResult) VerifyHashChain(previousResult *ExternalChainResult) error {
	if previousResult == nil {
		// First in chain - previous hash must be zero
		if r.PreviousResultHash != [32]byte{} {
			return fmt.Errorf("first result must have zero previous hash")
		}
		if r.SequenceNumber != 0 {
			return fmt.Errorf("first result must have sequence number 0, got %d", r.SequenceNumber)
		}
		return nil
	}

	// Verify previous hash matches
	if r.PreviousResultHash != previousResult.ResultHash {
		return fmt.Errorf("previous result hash mismatch: expected %x, got %x",
			previousResult.ResultHash, r.PreviousResultHash)
	}

	// Verify sequence number
	if r.SequenceNumber != previousResult.SequenceNumber+1 {
		return fmt.Errorf("sequence number mismatch: expected %d, got %d",
			previousResult.SequenceNumber+1, r.SequenceNumber)
	}

	return nil
}

// VerifyResultHash recomputes and verifies the result hash
func (r *ExternalChainResult) VerifyResultHash() error {
	expectedHash := r.ComputeResultHash()
	if r.ResultHash != expectedHash {
		return fmt.Errorf("result hash mismatch: stored %x, computed %x",
			r.ResultHash, expectedHash)
	}
	return nil
}

// VerifyResultID recomputes and verifies the result ID
func (r *ExternalChainResult) VerifyResultID() error {
	expectedID := r.ComputeResultID()
	if r.ResultID != expectedID {
		return fmt.Errorf("result ID mismatch: stored %x, computed %x",
			r.ResultID, expectedID)
	}
	return nil
}

// computeLogsHash computes a deterministic hash of all logs
func (r *ExternalChainResult) computeLogsHash() [32]byte {
	if len(r.Logs) == 0 {
		return [32]byte{}
	}

	data := make([]byte, 0, 64*len(r.Logs))
	for _, log := range r.Logs {
		data = append(data, log.Address.Bytes()...)
		for _, topic := range log.Topics {
			data = append(data, topic.Bytes()...)
		}
		data = append(data, log.Data...)
	}

	return sha256.Sum256(data)
}

// IsSuccess returns true if the transaction executed successfully
func (r *ExternalChainResult) IsSuccess() bool {
	return r.Status == 1
}

// IsFinalized returns true if the transaction has enough confirmations
func (r *ExternalChainResult) IsFinalized(requiredConfirmations int) bool {
	return r.ConfirmationBlocks >= requiredConfirmations
}

// GetLogsByTopic returns logs matching a specific event topic
func (r *ExternalChainResult) GetLogsByTopic(topic common.Hash) []LogEntry {
	var matching []LogEntry
	for _, log := range r.Logs {
		if len(log.Topics) > 0 && log.Topics[0] == topic {
			matching = append(matching, log)
		}
	}
	return matching
}

// VerifyInclusionProofs verifies the result's transaction and receipt inclusion proofs against its block's roots, at its
// transaction's index, the transaction proof's leaf being this transaction (pkg/ethproof). A result without them says why
// the observer built none.
func (r *ExternalChainResult) VerifyInclusionProofs() error {
	if r.TxInclusionProof == nil || r.ReceiptInclusionProof == nil {
		if r.inclusionErr != nil {
			return fmt.Errorf("RB-2: no inclusion proofs for %s: %w", r.TxHash.Hex(), r.inclusionErr)
		}
		return fmt.Errorf("RB-2: no inclusion proofs for %s", r.TxHash.Hex())
	}
	leaf, err := ethproof.VerifyInclusion(r.TxInclusionProof, r.TransactionsRoot, uint64(r.TxIndex))
	if err != nil {
		return fmt.Errorf("RB-2: tx inclusion proof of %s: %w", r.TxHash.Hex(), err)
	}
	if got := crypto.Keccak256Hash(leaf); got != r.TxHash {
		return fmt.Errorf("RB-2: the tx inclusion proof proves %s, not %s", got.Hex(), r.TxHash.Hex())
	}
	if _, err := ethproof.VerifyInclusion(r.ReceiptInclusionProof, r.ReceiptsRoot, uint64(r.TxIndex)); err != nil {
		return fmt.Errorf("RB-2: receipt inclusion proof of %s: %w", r.TxHash.Hex(), err)
	}
	return nil
}

// =============================================================================
// CONVERSION HELPERS
// =============================================================================

// FromEthereumReceipt creates an ExternalChainResult from an Ethereum receipt
func FromEthereumReceipt(
	receipt *types.Receipt,
	tx *types.Transaction,
	block *types.Block,
	chainID int64,
	confirmations int,
	validatorID string,
) *ExternalChainResult {

	// Extract sender
	signer := types.LatestSignerForChainID(big.NewInt(chainID))
	from, _ := types.Sender(signer, tx)

	// Convert logs
	logs := make([]LogEntry, len(receipt.Logs))
	for i, log := range receipt.Logs {
		topics := make([]common.Hash, len(log.Topics))
		copy(topics, log.Topics)
		logs[i] = LogEntry{
			Address: log.Address,
			Topics:  topics,
			Data:    log.Data,
			Index:   uint(log.Index),
		}
	}

	result := &ExternalChainResult{
		// Hash chain fields initialized to zero (will be set by SetHashChainBinding)
		ResultID:           [32]byte{},
		PreviousResultHash: [32]byte{},
		AnchorProofHash:    [32]byte{},
		SequenceNumber:     0,

		// Chain identification
		Chain:   "ethereum",
		ChainID: chainID,
		TxHash:  receipt.TxHash,

		// Block information
		BlockNumber:      receipt.BlockNumber,
		BlockHash:        receipt.BlockHash,
		BlockTime:        time.Unix(int64(block.Time()), 0),
		TransactionsRoot: block.TxHash(),
		ReceiptsRoot:     block.ReceiptHash(),
		StateRoot:        block.Root(),

		// Transaction details
		TxIndex:   uint(receipt.TransactionIndex),
		TxFrom:    from,
		TxTo:      tx.To(),
		TxValue:   tx.Value(),
		TxData:    tx.Data(),
		TxGasUsed: receipt.GasUsed,

		// Execution outcome
		Status:          receipt.Status,
		ContractAddress: nil,
		Logs:            logs,

		// Finalization
		ConfirmationBlocks:  confirmations,
		FinalizedAt:         time.Now(),
		ObservedByValidator: validatorID,
	}

	// Set contract address if this was a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		result.ContractAddress = &receipt.ContractAddress
	}

	// Compute ResultID first (doesn't depend on hash chain binding)
	result.ResultID = result.ComputeResultID()

	// Compute result hash (includes all fields)
	// Note: Hash chain binding fields are zero until SetHashChainBinding is called
	result.ResultHash = result.ComputeResultHash()

	return result
}

// ToHex returns a hex representation for logging
func (r *ExternalChainResult) ToHex() string {
	return hex.EncodeToString(r.ResultHash[:])
}

// =============================================================================
// PENDING EXECUTION TRACKING
// =============================================================================

// PendingExecution tracks an execution that's waiting for finalization
type PendingExecution struct {
	// Original intent data
	IntentID         string   `json:"intent_id"`
	OperationID      [32]byte `json:"operation_id"`
	ValidatorBlockID string   `json:"validator_block_id"`

	// Ethereum transaction
	TxHash      common.Hash `json:"tx_hash"`
	SubmittedAt time.Time   `json:"submitted_at"`

	// Expected outcome
	ExpectedTarget common.Address  `json:"expected_target"`
	ExpectedValue  *big.Int        `json:"expected_value"`
	ExpectedEvents []ExpectedEvent `json:"expected_events"`

	// Tracking
	CurrentConfirmations  int       `json:"current_confirmations"`
	RequiredConfirmations int       `json:"required_confirmations"`
	LastCheckedAt         time.Time `json:"last_checked_at"`

	// Status
	Status string `json:"status"` // pending, finalized, failed, timeout
}

// ExpectedEvent defines an event we expect to see in the logs
type ExpectedEvent struct {
	Contract common.Address `json:"contract"`
	Topic0   common.Hash    `json:"topic0"`              // Event signature
	DataHash [32]byte       `json:"data_hash,omitempty"` // Optional: hash of expected data
}

// ExpectedStateSlot is a committed storage-slot effect (RB-5): after execution, the
// contract `Account`'s storage slot `Slot` must hold `Value`, proven against the
// finalized block stateRoot.
type ExpectedStateSlot struct {
	Account common.Address `json:"account"`
	Slot    common.Hash    `json:"slot"`
	Value   common.Hash    `json:"value"`
}

// =============================================================================
// EXECUTION COMMITMENT
// =============================================================================

// ExecutionCommitment is a hash that binds an operation to its expected execution
// This is computed BEFORE execution and verified AFTER
type ExecutionCommitment struct {
	// From ValidatorBlock
	OperationID [32]byte `json:"operation_id"`
	BundleID    [32]byte `json:"bundle_id"`

	// Intent reference from Accumulate (for write-back traceability)
	IntentTxHash string `json:"intent_tx_hash,omitempty"`
	IntentBlock  uint64 `json:"intent_block,omitempty"`

	// Target chain execution details
	TargetChain      string         `json:"target_chain"`
	TargetContract   common.Address `json:"target_contract"`
	FunctionSelector [4]byte        `json:"function_selector"`
	CallDataHash     [32]byte       `json:"call_data_hash"`
	ExpectedValue    *big.Int       `json:"expected_value"`

	// RB-4: contract-call event gate. IsContractCall is true when the leg executes a
	// non-empty inner calldata (target.call{value}(data)). For such legs the validator
	// refuses to attest success unless EVERY ExpectedCallEvent appears in the (inclusion-
	// proven, quorum-attested) receipt logs — non-revert alone is insufficient. Native
	// value transfers leave these unset and keep the exact-value check.
	IsContractCall     bool            `json:"is_contract_call,omitempty"`
	ExpectedCallEvents []ExpectedEvent `json:"expected_call_events,omitempty"`

	// RB-5: optional committed storage-slot effects. When present, the validator refuses
	// to attest unless a state proof shows each slot took the committed value at the
	// finalized stateRoot. Opt-in per intent — the strongest effect proof.
	ExpectedState []ExpectedStateSlot `json:"expected_state,omitempty"`

	// Commitment hash (computed from above)
	CommitmentHash [32]byte `json:"commitment_hash"`
}

// ComputeCommitmentHash computes the deterministic commitment hash
func (c *ExecutionCommitment) ComputeCommitmentHash() [32]byte {
	data := make([]byte, 0, 128)

	data = append(data, c.OperationID[:]...)
	data = append(data, c.BundleID[:]...)
	data = append(data, []byte(c.TargetChain)...)
	data = append(data, c.TargetContract.Bytes()...)
	data = append(data, c.FunctionSelector[:]...)
	data = append(data, c.CallDataHash[:]...)
	if c.ExpectedValue != nil {
		data = append(data, c.ExpectedValue.Bytes()...)
	}

	return sha256.Sum256(data)
}

// =============================================================================
// RB-4: CONTRACT-CALL EVENT GATE
// =============================================================================

// =============================================================================
// CANONICAL JSON MARSHALING (RFC8785)
// =============================================================================

// canonicalJSONMarshal produces RFC8785 compliant canonical JSON
// This ensures deterministic serialization across implementations:
// 1. Object keys are sorted lexicographically
// 2. No insignificant whitespace
// 3. Numbers use minimal representation
// 4. Strings use minimal escape sequences
func canonicalJSONMarshal(v interface{}) []byte {
	// Convert to a map for consistent handling
	data, err := json.Marshal(v)
	if err != nil {
		// Hashing an empty input instead would give every unencodable result the same identity
		// (RB3-F81). Callers pass fixed-shape maps of encodable values; an error here is a defect.
		panic(fmt.Sprintf("canonical JSON of a result: %v", err))
	}

	// Unmarshal and re-marshal with sorted keys
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		// Not an object, return as-is
		return data
	}

	// Recursively sort and marshal
	return marshalCanonical(obj)
}

// marshalCanonical recursively marshals with sorted keys
func marshalCanonical(v interface{}) []byte {
	switch val := v.(type) {
	case map[string]interface{}:
		// Get sorted keys
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Build canonical JSON manually
		var result []byte
		result = append(result, '{')
		for i, k := range keys {
			if i > 0 {
				result = append(result, ',')
			}
			// Key
			keyBytes, _ := json.Marshal(k)
			result = append(result, keyBytes...)
			result = append(result, ':')
			// Value (recursively)
			result = append(result, marshalCanonical(val[k])...)
		}
		result = append(result, '}')
		return result

	case []interface{}:
		var result []byte
		result = append(result, '[')
		for i, item := range val {
			if i > 0 {
				result = append(result, ',')
			}
			result = append(result, marshalCanonical(item)...)
		}
		result = append(result, ']')
		return result

	default:
		// Primitive value - use json.Marshal
		data, _ := json.Marshal(val)
		return data
	}
}

// =============================================================================
// RESULT HASH CHAIN MANAGER
// =============================================================================

// ResultHashChain manages the hash chain of external chain results. It links results in order; each result
// carries its own anchor binding. It used to carry one AnchorProofHash for the whole chain - the first
// cycle's operation commitment - stamped on every later result (RB3-F106).
type ResultHashChain struct {
	ChainID        string   `json:"chain_id"`
	LatestHash     [32]byte `json:"latest_hash"`
	LatestSequence uint64   `json:"latest_sequence"`
}

// NewResultHashChain creates a new hash chain for results
func NewResultHashChain(chainID string) *ResultHashChain {
	return &ResultHashChain{
		ChainID:        chainID,
		LatestHash:     [32]byte{}, // Genesis - all zeros
		LatestSequence: 0,
	}
}

// AddResult links a result into the chain, binding it to its own anchor (anchorProofHash).
func (c *ResultHashChain) AddResult(result *ExternalChainResult, anchorProofHash [32]byte) error {
	// Set hash chain binding
	result.SetHashChainBinding(c.LatestHash, anchorProofHash, c.LatestSequence)

	// Update chain state
	c.LatestHash = result.ResultHash
	c.LatestSequence++

	return nil
}

// VerifyChain verifies a sequence of results form a valid hash chain
func (c *ResultHashChain) VerifyChain(results []*ExternalChainResult) error {
	if len(results) == 0 {
		return nil
	}

	// Verify first result
	if err := results[0].VerifyHashChain(nil); err != nil {
		return fmt.Errorf("first result invalid: %w", err)
	}
	if err := results[0].VerifyResultHash(); err != nil {
		return fmt.Errorf("first result hash invalid: %w", err)
	}

	// Verify chain continuity
	for i := 1; i < len(results); i++ {
		if err := results[i].VerifyHashChain(results[i-1]); err != nil {
			return fmt.Errorf("result %d chain invalid: %w", i, err)
		}
		if err := results[i].VerifyResultHash(); err != nil {
			return fmt.Errorf("result %d hash invalid: %w", i, err)
		}

	}

	return nil
}
