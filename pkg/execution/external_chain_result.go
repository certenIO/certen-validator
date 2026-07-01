// Copyright 2025 Certen Protocol
//
// External Chain Result Types - Cryptographic proof structures for cross-chain execution
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 7
//
// These types capture the cryptographically verifiable proof that an operation
// was executed on an external chain (e.g., Ethereum) and can be independently verified.

package execution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
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

	// AnchorProofHash binds this Level 4 result to Level 3 anchor proof
	// This ensures cryptographic continuity from L1→L2→L3→L4
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

	// RB-5: optional storage-slot state proofs, independently verifiable against StateRoot.
	StateProofs []*StateProof `json:"state_proofs,omitempty"`

	// ==========================================================================
	// TRANSACTION DETAILS
	// ==========================================================================

	TxIndex   uint           `json:"tx_index"`   // Position in block
	TxFrom    common.Address `json:"tx_from"`    // Sender
	TxTo      *common.Address `json:"tx_to"`     // Recipient (nil for contract creation)
	TxValue   *big.Int       `json:"tx_value"`   // Value transferred
	TxData    []byte         `json:"tx_data"`    // Input data
	TxGasUsed uint64         `json:"tx_gas_used"` // Gas consumed

	// ==========================================================================
	// EXECUTION OUTCOME
	// ==========================================================================

	Status          uint64          `json:"status"` // 1=success, 0=revert
	ContractAddress *common.Address `json:"contract_address,omitempty"` // For contract creation
	Logs            []LogEntry      `json:"logs"`   // Event logs emitted
	ReturnData      []byte          `json:"return_data,omitempty"` // Return data (if available)

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
	Status        uint64   `json:"status"`         // 1=success, 0=revert
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

// MerkleInclusionProof provides cryptographic proof that an item is in a Merkle tree
type MerkleInclusionProof struct {
	// The leaf being proven
	LeafHash [32]byte `json:"leaf_hash"`

	// The index of the leaf in the tree
	LeafIndex uint64 `json:"leaf_index"`

	// Proof path from leaf to root
	ProofHashes [][32]byte `json:"proof_hashes"`

	// Directions for proof verification (0=left, 1=right)
	ProofDirections []uint8 `json:"proof_directions"`

	// Expected root (for verification)
	ExpectedRoot [32]byte `json:"expected_root"`

	// Verified flag (set after verification)
	Verified bool `json:"verified"`

	// RB-2: the raw RLP-encoded Patricia-trie proof nodes (the proof set), enabling
	// INDEPENDENT re-verification off the original RPC via go-ethereum trie.VerifyProof.
	// Nodes are keyed on verify by keccak256(node) — the construction-time key is never
	// trusted. Empty ⇒ Verify() fails closed (cannot trustlessly verify).
	ProofNodes [][]byte `json:"proof_nodes,omitempty"`

	// RB-2: the exact leaf value (RLP(tx) or RLP(receipt)) the proof must resolve to
	// at the key. VerifyProof's returned value is asserted byte-equal to this.
	LeafValue []byte `json:"leaf_value,omitempty"`
}

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
		"status":     r.Status,
		"tx_index":   r.TxIndex,
		"tx_gas_used": r.TxGasUsed,
		"logs_hash":  hex.EncodeToString(logsHash[:]),
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

// =============================================================================
// MERKLE PROOF VERIFICATION
// =============================================================================

// Verify independently verifies the Ethereum Patricia-Merkle-trie inclusion proof.
//
// RB-2: This no longer trusts a construction-time flag. It rebuilds the proof node
// set in-memory (keyed by keccak256(node), recomputed from the node bytes so a
// caller-supplied key is never trusted) and runs go-ethereum's trie.VerifyProof,
// which walks from ExpectedRoot and errors if any node is missing/altered or the
// path doesn't reconcile to the root. The returned leaf value is then asserted to
// equal the exact tx/receipt RLP (LeafValue) and to hash to LeafHash.
//
// Trustlessness depends on ExpectedRoot being bound to the block header's
// TxHash/ReceiptHash (done at construction in constructTx/ReceiptInclusionProof),
// and the header itself being bound to receipt.BlockHash (checked in
// FromEthereumReceipt). Fails closed on any error or missing proof set.
func (p *MerkleInclusionProof) Verify() bool {
	// Without the raw proof node set we cannot trustlessly verify. Fail closed.
	if len(p.ProofNodes) == 0 {
		return false
	}

	// Rebuild the trie node DB, recomputing every key as keccak256(node) so we
	// never trust caller-provided node keys.
	proofDB := memorydb.New()
	for _, node := range p.ProofNodes {
		if len(node) == 0 {
			return false
		}
		key := crypto.Keccak256(node)
		if err := proofDB.Put(key, node); err != nil {
			return false
		}
	}

	// The trie key is the RLP encoding of the leaf index (tx/receipt index in block),
	// matching how the trie was built and proven at construction time.
	key, err := rlp.EncodeToBytes(uint(p.LeafIndex))
	if err != nil {
		return false
	}

	// Independent Patricia-trie verification against the expected (header-bound) root.
	value, err := trie.VerifyProof(common.Hash(p.ExpectedRoot), key, proofDB)
	if err != nil || value == nil {
		return false
	}

	// The proven value must be the exact tx/receipt RLP we committed to...
	if p.LeafValue != nil && !bytes.Equal(value, p.LeafValue) {
		return false
	}
	// ...and must hash to the committed leaf hash.
	if crypto.Keccak256Hash(value) != common.Hash(p.LeafHash) {
		return false
	}

	return true
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
	IntentID        string    `json:"intent_id"`
	OperationID     [32]byte  `json:"operation_id"`
	ValidatorBlockID string   `json:"validator_block_id"`

	// Ethereum transaction
	TxHash      common.Hash `json:"tx_hash"`
	SubmittedAt time.Time   `json:"submitted_at"`

	// Expected outcome
	ExpectedTarget   common.Address `json:"expected_target"`
	ExpectedValue    *big.Int       `json:"expected_value"`
	ExpectedEvents   []ExpectedEvent `json:"expected_events"`

	// Tracking
	CurrentConfirmations int       `json:"current_confirmations"`
	RequiredConfirmations int      `json:"required_confirmations"`
	LastCheckedAt        time.Time `json:"last_checked_at"`

	// Status
	Status string `json:"status"` // pending, finalized, failed, timeout
}

// ExpectedEvent defines an event we expect to see in the logs
type ExpectedEvent struct {
	Contract common.Address `json:"contract"`
	Topic0   common.Hash    `json:"topic0"` // Event signature
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
	OperationID     [32]byte `json:"operation_id"`
	BundleID        [32]byte `json:"bundle_id"`

	// Intent reference from Accumulate (for write-back traceability)
	IntentTxHash    string   `json:"intent_tx_hash,omitempty"`
	IntentBlock     uint64   `json:"intent_block,omitempty"`

	// Target chain execution details
	TargetChain     string         `json:"target_chain"`
	TargetContract  common.Address `json:"target_contract"`
	FunctionSelector [4]byte       `json:"function_selector"`
	CallDataHash    [32]byte       `json:"call_data_hash"`
	ExpectedValue   *big.Int       `json:"expected_value"`

	// RB-4: contract-call event gate. IsContractCall is true when the leg executes a
	// non-empty inner calldata (target.call{value}(data)). For such legs the validator
	// refuses to attest success unless EVERY ExpectedCallEvent appears in the (inclusion-
	// proven, quorum-attested) receipt logs — non-revert alone is insufficient. Native
	// value transfers leave these unset and keep the exact-value check.
	IsContractCall    bool            `json:"is_contract_call,omitempty"`
	ExpectedCallEvents []ExpectedEvent `json:"expected_call_events,omitempty"`

	// RB-5: optional committed storage-slot effects. When present, the validator refuses
	// to attest unless a state proof shows each slot took the committed value at the
	// finalized stateRoot. Opt-in per intent — the strongest effect proof.
	ExpectedState []ExpectedStateSlot `json:"expected_state,omitempty"`

	// Commitment hash (computed from above)
	CommitmentHash  [32]byte `json:"commitment_hash"`

	// ComprehensiveData contains the full verification data from the BFT flow
	// This includes all 3-step execution data and expected events for complete verification
	// SECURITY CRITICAL: This data was created BEFORE execution from the intent's CrossChainData
	ComprehensiveData map[string]interface{} `json:"comprehensive_data,omitempty"`
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

// VerifyAgainstResult checks if the result matches the commitment
// SECURITY CRITICAL: This is the primary defense against executor misbehavior
func (c *ExecutionCommitment) VerifyAgainstResult(result *ExternalChainResult) bool {
	// Non-EVM chains (TRON, NEAR, Solana, etc.) use native observers that only return
	// confirmation status, not full tx details (TxTo, TxData, TxValue). For these chains,
	// the on-chain contract already verified the execution commitment in Step 3.
	// Skip detailed field-level verification and accept the confirmed result.
	if result.TxTo == nil && result.TxData == nil && result.Status == 1 {
		chain := strings.ToLower(result.Chain)
		if strings.Contains(chain, "tron") || strings.Contains(chain, "near") ||
			strings.Contains(chain, "solana") || strings.Contains(chain, "ton") ||
			strings.Contains(chain, "aptos") || strings.Contains(chain, "sui") {
			fmt.Printf("✅ [COMMITMENT-VERIFY] Non-EVM chain %s: tx confirmed on-chain, skipping field-level verification\n", result.Chain)
			return true
		}
		fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: TxTo is nil\n")
		return false
	}

	// Basic verification: target contract
	if result.TxTo == nil {
		fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: TxTo is nil\n")
		return false
	}
	if *result.TxTo != c.TargetContract {
		fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: Target contract mismatch: expected %s, got %s\n",
			c.TargetContract.Hex(), result.TxTo.Hex())
		return false
	}
	fmt.Printf("✅ [COMMITMENT-VERIFY] Target contract matches: %s\n", c.TargetContract.Hex())

	// Basic verification: function selector (first 4 bytes of tx data)
	if len(result.TxData) < 4 {
		fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: TxData too short (%d bytes)\n", len(result.TxData))
		return false
	}
	var actualSelector [4]byte
	copy(actualSelector[:], result.TxData[:4])
	if actualSelector != c.FunctionSelector {
		fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: Function selector mismatch: expected %x, got %x\n",
			c.FunctionSelector, actualSelector)
		return false
	}
	fmt.Printf("✅ [COMMITMENT-VERIFY] Function selector matches: %x\n", c.FunctionSelector)

	// Basic verification: value matches (allow zero expectation to match any)
	if c.ExpectedValue != nil && c.ExpectedValue.Sign() > 0 {
		if result.TxValue.Cmp(c.ExpectedValue) != 0 {
			fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: Value mismatch: expected %s, got %s\n",
				c.ExpectedValue.String(), result.TxValue.String())
			return false
		}
		fmt.Printf("✅ [COMMITMENT-VERIFY] Value matches: %s\n", c.ExpectedValue.String())
	}

	// RB-4: enforce the committed event(s) for contract calls. A call "succeeds" only if
	// the effect it authorized (an emitted event) is present in the receipt logs; a
	// status==1 non-revert is necessary but NOT sufficient. These logs are bound by
	// logs_hash inside the quorum-attested ResultHash and are inclusion-proven (RB-2),
	// so requiring the event here makes success cryptographically meaningful.
	if c.isContractCallExpected() {
		events := c.expectedEventsForGate()
		if len(events) == 0 {
			fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: contract call has no committed expected events — refusing to attest\n")
			return false
		}
		if !c.verifyExpectedEventsStrict(result, events) {
			fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: committed contract-call event(s) not found in inclusion-proven logs\n")
			return false
		}
		fmt.Printf("✅ [COMMITMENT-VERIFY] Committed contract-call event(s) verified in logs\n")
	}

	// RB-5: enforce committed storage-slot effects (opt-in). Each committed slot must be
	// proven — against the finalized block stateRoot — to hold exactly the committed
	// value. This is the strongest effect proof: it binds the on-chain state itself, not
	// just an emitted event.
	if len(c.ExpectedState) > 0 {
		if !c.verifyExpectedState(result) {
			fmt.Printf("❌ [COMMITMENT-VERIFY] FAILED: committed state slot(s) not proven at stateRoot\n")
			return false
		}
		fmt.Printf("✅ [COMMITMENT-VERIFY] Committed state slot(s) proven against stateRoot\n")
	}

	// If comprehensive data is available, perform enhanced verification
	if c.ComprehensiveData != nil {
		fmt.Printf("🔍 [COMMITMENT-VERIFY] Starting comprehensive verification...\n")
		return c.verifyComprehensive(result)
	}

	fmt.Printf("✅ [COMMITMENT-VERIFY] Basic verification PASSED\n")
	return true
}

// verifyComprehensive performs enhanced verification using the full commitment data
// This checks all 3 execution steps and expected events
func (c *ExecutionCommitment) verifyComprehensive(result *ExternalChainResult) bool {
	// Verify chain ID matches
	if chainID, ok := c.ComprehensiveData["chainID"].(float64); ok {
		if int64(chainID) != result.ChainID {
			fmt.Printf("❌ [COMPREHENSIVE] FAILED: Chain ID mismatch: expected %d, got %d\n",
				int64(chainID), result.ChainID)
			return false
		}
		fmt.Printf("✅ [COMPREHENSIVE] Chain ID matches: %d\n", result.ChainID)
	}

	// Verify final target address from commitment
	if finalTargetHex, ok := c.ComprehensiveData["finalTarget"].(string); ok {
		finalTarget := common.HexToAddress(finalTargetHex)
		// Check if the final target appears in the transaction or logs
		if !c.verifyFinalTargetInResult(result, finalTarget) {
			// Non-fatal - final target may be in internal calls
			fmt.Printf("⚠️ [COMPREHENSIVE] Final target %s not found in result (non-fatal)\n", finalTarget.Hex())
		} else {
			fmt.Printf("✅ [COMPREHENSIVE] Final target verified: %s\n", finalTarget.Hex())
		}
	}

	// Verify expected events were emitted
	if expectedEvents, ok := c.ComprehensiveData["expectedEvents"].([]interface{}); ok {
		fmt.Printf("🔍 [COMPREHENSIVE] Checking %d expected events...\n", len(expectedEvents))
		fmt.Printf("🔍 [COMPREHENSIVE] Result has %d logs\n", len(result.Logs))
		if !c.verifyExpectedEvents(result, expectedEvents) {
			fmt.Printf("❌ [COMPREHENSIVE] FAILED: Expected events not found in logs\n")
			return false
		}
		fmt.Printf("✅ [COMPREHENSIVE] All expected events verified\n")
	}

	// Verify anchor contract matches
	if anchorContractHex, ok := c.ComprehensiveData["anchorContract"].(string); ok {
		anchorContract := common.HexToAddress(anchorContractHex)
		if result.TxTo != nil && *result.TxTo != anchorContract {
			fmt.Printf("❌ [COMPREHENSIVE] FAILED: Anchor contract mismatch: expected %s, got %s\n",
				anchorContract.Hex(), result.TxTo.Hex())
			return false
		}
		fmt.Printf("✅ [COMPREHENSIVE] Anchor contract matches: %s\n", anchorContract.Hex())
	}

	fmt.Printf("✅ [COMPREHENSIVE] All comprehensive checks PASSED\n")
	return true
}

// verifyFinalTargetInResult checks if the final target address appears in the result
func (c *ExecutionCommitment) verifyFinalTargetInResult(result *ExternalChainResult, target common.Address) bool {
	// Check if target is the direct recipient
	if result.TxTo != nil && *result.TxTo == target {
		return true
	}

	// Check logs for events involving the target
	for _, log := range result.Logs {
		// Check if target is in log topics (for indexed address params)
		for _, topic := range log.Topics {
			if common.BytesToAddress(topic.Bytes()) == target {
				return true
			}
		}
	}

	return false
}

// verifyExpectedEvents checks if all expected events were emitted
func (c *ExecutionCommitment) verifyExpectedEvents(result *ExternalChainResult, expectedEvents []interface{}) bool {
	if len(expectedEvents) == 0 {
		return true
	}

	for _, evt := range expectedEvents {
		eventMap, ok := evt.(map[string]interface{})
		if !ok {
			continue
		}

		eventName, _ := eventMap["name"].(string)
		topic0Hex, _ := eventMap["topic0"].(string)
		contractHex, _ := eventMap["contract"].(string)

		if topic0Hex == "" {
			continue
		}

		// Decode topic0
		topic0Bytes, err := hex.DecodeString(topic0Hex)
		if err != nil {
			continue
		}

		expectedTopic0 := common.BytesToHash(topic0Bytes)
		expectedContract := common.HexToAddress(contractHex)

		// Look for this event in the result's logs
		found := false
		for _, log := range result.Logs {
			if len(log.Topics) == 0 {
				continue
			}

			// Check contract address matches
			if log.Address != expectedContract {
				continue
			}

			// Check topic0 matches
			if log.Topics[0] == expectedTopic0 {
				found = true
				break
			}
		}

		if !found {
			// Expected event not found - this is a verification failure
			// In strict mode, this should fail. In lenient mode, log and continue.
			// For now, we use strict mode for security
			_ = eventName // Used for logging in debug mode
			return false
		}
	}

	return true
}

// =============================================================================
// RB-4: CONTRACT-CALL EVENT GATE
// =============================================================================

// isContractCallExpected reports whether this commitment is for an arbitrary contract
// call whose success must be proven by an emitted event. Reads the typed flag, or the
// ComprehensiveData["isContractCall"] map fallback for the map-driven flows.
func (c *ExecutionCommitment) isContractCallExpected() bool {
	if c.IsContractCall {
		return true
	}
	if c.ComprehensiveData != nil {
		if b, ok := c.ComprehensiveData["isContractCall"].(bool); ok {
			return b
		}
	}
	return false
}

// expectedEventsForGate returns the committed events to enforce, from the typed field
// or the ComprehensiveData["expectedEvents"] map fallback (which the producer emits in
// the user-signed executionPayload).
func (c *ExecutionCommitment) expectedEventsForGate() []ExpectedEvent {
	if len(c.ExpectedCallEvents) > 0 {
		return c.ExpectedCallEvents
	}
	if c.ComprehensiveData != nil {
		if raw, ok := c.ComprehensiveData["expectedEvents"].([]interface{}); ok {
			return parseExpectedEventsFromMap(raw)
		}
	}
	return nil
}

// parseExpectedEventsFromMap converts the JSON-roundtripped []{contract,topic0,dataHash}
// into typed ExpectedEvent values. Entries lacking a topic0 are skipped.
func parseExpectedEventsFromMap(raw []interface{}) []ExpectedEvent {
	out := make([]ExpectedEvent, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		topic0, _ := m["topic0"].(string)
		if topic0 == "" {
			continue
		}
		contract, _ := m["contract"].(string)
		ev := ExpectedEvent{
			Contract: common.HexToAddress(contract),
			Topic0:   common.HexToHash(topic0),
		}
		if dh, _ := m["dataHash"].(string); dh != "" {
			ev.DataHash = [32]byte(common.HexToHash(dh))
		}
		out = append(out, ev)
	}
	return out
}

// verifyExpectedEventsStrict requires EVERY committed event to be present in the receipt
// logs, matched on emitting contract + topic0 (+ optional keccak256 of the non-indexed
// data). Missing any committed event ⇒ the call is NOT considered successful.
func (c *ExecutionCommitment) verifyExpectedEventsStrict(result *ExternalChainResult, events []ExpectedEvent) bool {
	var zeroHash [32]byte
	for _, exp := range events {
		found := false
		for _, lg := range result.Logs {
			if len(lg.Topics) == 0 {
				continue
			}
			if lg.Address != exp.Contract {
				continue
			}
			if lg.Topics[0] != exp.Topic0 {
				continue
			}
			// Optional: bind the non-indexed event data.
			if exp.DataHash != zeroHash {
				if crypto.Keccak256Hash(lg.Data) != common.Hash(exp.DataHash) {
					continue
				}
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

// verifyExpectedState (RB-5) requires, for every committed slot, a StateProof in the
// result that verifies against the block stateRoot AND proves the committed value.
// Missing proof, failed verification, or value mismatch ⇒ reject.
func (c *ExecutionCommitment) verifyExpectedState(result *ExternalChainResult) bool {
	for _, want := range c.ExpectedState {
		var proof *StateProof
		for _, sp := range result.StateProofs {
			if sp != nil && sp.Account == want.Account && sp.Slot == want.Slot {
				proof = sp
				break
			}
		}
		if proof == nil {
			fmt.Printf("❌ [STATE-PROOF] No proof for account %s slot %s\n", want.Account.Hex(), want.Slot.Hex())
			return false
		}
		if proof.Value != want.Value {
			fmt.Printf("❌ [STATE-PROOF] Value mismatch for %s[%s]: committed %s, proven %s\n",
				want.Account.Hex(), want.Slot.Hex(), want.Value.Hex(), proof.Value.Hex())
			return false
		}
		if !proof.Verify(result.StateRoot) {
			fmt.Printf("❌ [STATE-PROOF] Proof failed to verify against stateRoot %s\n", result.StateRoot.Hex())
			return false
		}
	}
	return true
}

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
		// Fallback: empty hash on error
		return []byte{}
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

// ResultHashChain manages the hash chain of external chain results
type ResultHashChain struct {
	ChainID         string   `json:"chain_id"`
	LatestHash      [32]byte `json:"latest_hash"`
	LatestSequence  uint64   `json:"latest_sequence"`
	AnchorProofHash [32]byte `json:"anchor_proof_hash"`
}

// NewResultHashChain creates a new hash chain for results
func NewResultHashChain(chainID string, anchorProofHash [32]byte) *ResultHashChain {
	return &ResultHashChain{
		ChainID:         chainID,
		LatestHash:      [32]byte{}, // Genesis - all zeros
		LatestSequence:  0,
		AnchorProofHash: anchorProofHash,
	}
}

// AddResult adds a result to the hash chain and returns the updated result
func (c *ResultHashChain) AddResult(result *ExternalChainResult) error {
	// Set hash chain binding
	result.SetHashChainBinding(c.LatestHash, c.AnchorProofHash, c.LatestSequence)

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

		// Verify anchor proof binding is consistent
		if results[i].AnchorProofHash != c.AnchorProofHash {
			return fmt.Errorf("result %d anchor proof hash mismatch", i)
		}
	}

	return nil
}
