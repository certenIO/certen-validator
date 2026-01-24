package verification

import (
	"context"
	"time"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
)

// ValidatorBlockMetadata is a "sanitized" view of the committed ValidatorBlock
// that the target-chain anchoring system needs. It deliberately lives in the
// verification package so we don't have a consensus <-> verification import cycle.
type ValidatorBlockMetadata struct {
	RoundID  string
	IntentID string

	// Height of the VB chain at which this block was committed.
	Height int64

	// Canonical operation commitment hash for this VB (e.g. 32-byte digest).
	OperationCommitment []byte

	// Optional: chain ID, partition, etc.
	ChainID string

	// ============ PROOF DATA FOR ANCHOR CREATION ============
	// These fields are CRITICAL for CertenAnchorV3.createAnchor() to receive
	// real values instead of empty bytes. Without these, the contract stores
	// merkleRoot = keccak256(opCommitment || 0x00 || 0x00) which cannot be verified.

	// BPTRoot from Accumulate lite client proof - used for CrossChainCommitment
	// This is the Binary Patricia Trie root that proves account state inclusion.
	BPTRoot []byte

	// CrossChainCommitment computed from the ValidatorBlock's CrossChainProof
	// If BPTRoot is available, this is derived from BPTRoot; otherwise from CC legs.
	CrossChainCommitment []byte

	// BLSAggregateSignature from governance proof - used to compute GovernanceRoot
	// This is the hex-encoded BLS12-381 aggregate signature from validator attestations.
	BLSAggregateSignature string

	// GovernanceRoot computed from the ValidatorBlock's GovernanceProof
	// This is the Merkle root of authorization leaves signed by validators.
	GovernanceRoot []byte

	// TransactionHash from the original Accumulate transaction
	TransactionHash string

	// AccountURL from the intent
	AccountURL string

	// SourceBlockHeight is the Accumulate block height where the intent was found
	// This is distinct from the CometBFT Height which is the validator chain height.
	SourceBlockHeight uint64

	// ============ COMPLETE PROOF FOR MERKLE VERIFICATION ============
	// LiteClientProof contains the complete Merkle proof chain from the lite client.
	// CRITICAL: This is required for extractMerkleProofHashes() to extract the
	// actual Merkle proof path (proofHashes[]) for on-chain verification.
	// Without this, the contract's merkleVerified check will fail.
	LiteClientProof *lcproof.CompleteProof
}

// BFTExecutionMetadata describes what CometBFT told us about the commit.
// Again, we keep this here to avoid importing consensus from verification.
type BFTExecutionMetadata struct {
	Height      int64
	TxHash      []byte
	BlockHash   []byte
	CommittedAt time.Time
}

// AnchorExecutionResult summarises what happened on the target chain(s).
// Enhanced to track all 3 transactions in the Ethereum anchor workflow:
//   Step 1: CreateAnchor - stores anchor data on-chain
//   Step 2: ExecuteComprehensiveProof - submits BLS proof for verification
//   Step 3: ExecuteWithGovernance - executes the actual value transfer
type AnchorExecutionResult struct {
	AnchorTxID  string // Primary tx (createAnchor) for backwards compatibility
	Network     string
	Height      uint64
	ConfirmedAt time.Time

	// Enhanced: All 3 transaction hashes from the anchor workflow
	CreateTxHash     string // Step 1: createAnchor tx hash
	VerifyTxHash     string // Step 2: executeComprehensiveProof tx hash
	GovernanceTxHash string // Step 3: executeWithGovernance tx hash

	// Block numbers for each transaction
	CreateBlockNumber     uint64
	VerifyBlockNumber     uint64
	GovernanceBlockNumber uint64

	// All transactions confirmed successfully
	AllTransactionsConfirmed bool
}

// TargetChainExecutor is strictly responsible for the
// "AnchorManager.createAnchor() → TargetChain.notify() → TargetChain receipts"
// part of the pipeline, AFTER the ValidatorBlock has been committed.
type TargetChainExecutor interface {
	SubmitAnchorFromValidatorBlock(
		ctx context.Context,
		vb *ValidatorBlockMetadata,
		bft *BFTExecutionMetadata,
	) (*AnchorExecutionResult, error)
}