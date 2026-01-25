// Copyright 2025 Certen Protocol
//
// Chain Execution Strategy Interface - Multi-Chain Anchor Operations
// Supports EVM, CosmWasm, Solana, Move, TON, NEAR and future platforms
//
// Per Unified Multi-Chain Architecture:
// - Common interface for all blockchain platforms
// - Enables pluggable chain execution
// - Supports 3-step anchor workflow (Create → Verify → Governance)

package strategy

import (
	"context"
	"time"

	"github.com/google/uuid"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
)

// =============================================================================
// CHAIN PLATFORM IDENTIFIERS
// =============================================================================

// ChainPlatform identifies the blockchain platform type
type ChainPlatform string

const (
	// ChainPlatformEVM for Ethereum and EVM-compatible chains
	// Ethereum, Arbitrum, Optimism, Base, Polygon, Avalanche, BSC, TRON
	ChainPlatformEVM ChainPlatform = "evm"

	// ChainPlatformCosmWasm for Cosmos SDK chains with CosmWasm
	// Osmosis, Neutron, Injective
	ChainPlatformCosmWasm ChainPlatform = "cosmwasm"

	// ChainPlatformSolana for Solana and SVM chains
	ChainPlatformSolana ChainPlatform = "solana"

	// ChainPlatformMove for Move-based chains
	// Aptos, Sui
	ChainPlatformMove ChainPlatform = "move"

	// ChainPlatformTON for TON blockchain
	ChainPlatformTON ChainPlatform = "ton"

	// ChainPlatformNEAR for NEAR Protocol
	ChainPlatformNEAR ChainPlatform = "near"
)

// String returns the string representation of the platform
func (p ChainPlatform) String() string {
	return string(p)
}

// IsValid checks if the platform is a known valid platform
func (p ChainPlatform) IsValid() bool {
	switch p {
	case ChainPlatformEVM, ChainPlatformCosmWasm, ChainPlatformSolana,
		ChainPlatformMove, ChainPlatformTON, ChainPlatformNEAR:
		return true
	default:
		return false
	}
}

// DefaultAttestationScheme returns the default attestation scheme for the platform
func (p ChainPlatform) DefaultAttestationScheme() attestation.AttestationScheme {
	switch p {
	case ChainPlatformEVM:
		// BLS for EVM - ZK-verified on-chain
		return attestation.AttestationSchemeBLS12381
	case ChainPlatformCosmWasm, ChainPlatformSolana, ChainPlatformMove,
		ChainPlatformTON, ChainPlatformNEAR:
		// Ed25519 - native support, low cost
		return attestation.AttestationSchemeEd25519
	default:
		return attestation.AttestationSchemeEd25519
	}
}

// =============================================================================
// CHAIN CONFIGURATION
// =============================================================================

// ChainConfig holds configuration for a specific chain
type ChainConfig struct {
	// Platform is the blockchain platform type
	Platform ChainPlatform `json:"platform"`

	// ChainID is the chain identifier
	// EVM: numeric chain ID as string (e.g., "1" for mainnet)
	// Others: native chain ID format
	ChainID string `json:"chain_id"`

	// NetworkName is the human-readable network name
	// e.g., "ethereum-mainnet", "sepolia", "arbitrum-one"
	NetworkName string `json:"network_name"`

	// RPC is the primary RPC endpoint URL
	RPC string `json:"rpc"`

	// RPCBackup is an optional backup RPC endpoint
	RPCBackup string `json:"rpc_backup,omitempty"`

	// ContractAddress is the Certen anchor contract address
	ContractAddress string `json:"contract_address"`

	// RequiredConfirmations is blocks needed for finality
	// EVM mainnet: 12, Sepolia: 2, Solana: 32 slots
	RequiredConfirmations int `json:"required_confirmations"`

	// AttestationScheme overrides the platform default if set
	AttestationScheme attestation.AttestationScheme `json:"attestation_scheme,omitempty"`

	// PlatformConfig holds platform-specific configuration
	PlatformConfig map[string]interface{} `json:"platform_config,omitempty"`

	// GasConfig holds gas/fee configuration
	GasConfig *GasConfig `json:"gas_config,omitempty"`

	// Enabled indicates if the chain is active
	Enabled bool `json:"enabled"`
}

// GetAttestationScheme returns the attestation scheme for this chain
func (c *ChainConfig) GetAttestationScheme() attestation.AttestationScheme {
	if c.AttestationScheme != "" {
		return c.AttestationScheme
	}
	return c.Platform.DefaultAttestationScheme()
}

// GasConfig holds gas/fee configuration for a chain
type GasConfig struct {
	// MaxGasPrice is the maximum gas price to pay (in native units)
	MaxGasPrice string `json:"max_gas_price,omitempty"`

	// GasLimit is the gas limit for transactions
	GasLimit uint64 `json:"gas_limit,omitempty"`

	// PriorityFee for EIP-1559 transactions (EVM)
	PriorityFee string `json:"priority_fee,omitempty"`

	// ComputeUnits for Solana
	ComputeUnits uint32 `json:"compute_units,omitempty"`
}

// =============================================================================
// ANCHOR REQUEST/RESULT
// =============================================================================

// AnchorRequest is the chain-agnostic request to create an anchor
type AnchorRequest struct {
	// RequestID is a unique identifier for this request
	RequestID uuid.UUID `json:"request_id"`

	// IntentID is the intent being anchored
	IntentID string `json:"intent_id"`

	// BundleID is the operation bundle identifier
	BundleID [32]byte `json:"bundle_id"`

	// MerkleRoot is the root of the transaction merkle tree
	MerkleRoot [32]byte `json:"merkle_root"`

	// OperationCommitment is the L3 operation commitment
	OperationCommitment [32]byte `json:"operation_commitment"`

	// CrossChainCommitment is the BPT root from Accumulate
	CrossChainCommitment [32]byte `json:"cross_chain_commitment"`

	// GovernanceRoot is the governance proof root
	GovernanceRoot [32]byte `json:"governance_root"`

	// Timestamp is the Unix timestamp for the anchor
	Timestamp int64 `json:"timestamp"`

	// AccumulateHeight is the Accumulate block height
	AccumulateHeight int64 `json:"accumulate_height,omitempty"`

	// AccumulateHash is the Accumulate block hash
	AccumulateHash string `json:"accumulate_hash,omitempty"`

	// ValidatorID is the creating validator
	ValidatorID string `json:"validator_id"`

	// BatchID if this is a batch anchor
	BatchID *uuid.UUID `json:"batch_id,omitempty"`

	// TxCount for batch anchors
	TxCount int `json:"tx_count,omitempty"`

	// ProofClass indicates on_demand or on_cadence
	ProofClass string `json:"proof_class,omitempty"`
}

// AnchorResult is the chain-agnostic result of an anchor operation
type AnchorResult struct {
	// TxHash is the transaction hash on the target chain
	TxHash string `json:"tx_hash"`

	// BlockNumber is the block where the tx was included
	BlockNumber uint64 `json:"block_number"`

	// BlockHash is the block hash
	BlockHash string `json:"block_hash"`

	// BlockTimestamp is the block timestamp
	BlockTimestamp time.Time `json:"block_timestamp,omitempty"`

	// GasUsed is the gas/compute units consumed
	GasUsed uint64 `json:"gas_used"`

	// GasCost is the total cost in native token (wei, lamports, etc.)
	GasCost string `json:"gas_cost,omitempty"`

	// Status is the transaction status
	// 0 = pending, 1 = success, 2 = failed
	Status uint8 `json:"status"`

	// Timestamp when the result was created
	Timestamp time.Time `json:"timestamp"`

	// AnchorID is the anchor identifier on-chain (if returned)
	AnchorID [32]byte `json:"anchor_id,omitempty"`

	// ContractAddress is the contract that processed the tx
	ContractAddress string `json:"contract_address,omitempty"`

	// Logs contains relevant event logs
	Logs []EventLog `json:"logs,omitempty"`
}

// EventLog represents an event log from transaction execution
type EventLog struct {
	// Address is the contract that emitted the event
	Address string `json:"address"`

	// Topics are the indexed event parameters
	Topics []string `json:"topics"`

	// Data is the non-indexed event data
	Data []byte `json:"data"`

	// LogIndex within the transaction
	LogIndex uint `json:"log_index"`
}

// =============================================================================
// PROOF SUBMISSION
// =============================================================================

// ProofSubmission contains proof data for on-chain verification (Step 2)
type ProofSubmission struct {
	// AnchorID references the anchor from Step 1
	AnchorID [32]byte `json:"anchor_id"`

	// BLSSignature is the aggregated BLS signature
	BLSSignature []byte `json:"bls_signature,omitempty"`

	// BLSPublicKey is the aggregated BLS public key
	BLSPublicKey []byte `json:"bls_public_key,omitempty"`

	// Ed25519Signatures for non-aggregatable schemes
	Ed25519Signatures []ValidatorSignature `json:"ed25519_signatures,omitempty"`

	// MerkleProof for transaction inclusion
	MerkleProof []byte `json:"merkle_proof,omitempty"`

	// ProofHashes are intermediate proof hashes
	ProofHashes [][32]byte `json:"proof_hashes,omitempty"`

	// LeafHash is the transaction leaf hash
	LeafHash [32]byte `json:"leaf_hash,omitempty"`

	// Timestamp of proof submission
	Timestamp int64 `json:"timestamp"`
}

// ValidatorSignature pairs a validator with their signature
type ValidatorSignature struct {
	ValidatorID string `json:"validator_id"`
	PublicKey   []byte `json:"public_key"`
	Signature   []byte `json:"signature"`
}

// =============================================================================
// EXECUTION PARAMETERS
// =============================================================================

// ExecutionParams holds parameters for governance-verified execution (Step 3)
type ExecutionParams struct {
	// AnchorID references the anchor from Step 1
	AnchorID [32]byte `json:"anchor_id"`

	// GovernanceProof is the governance verification proof
	GovernanceProof []byte `json:"governance_proof,omitempty"`

	// GovernanceLevel is G0, G1, or G2
	GovernanceLevel string `json:"governance_level,omitempty"`

	// ExecutionPayload is chain-specific execution data
	ExecutionPayload []byte `json:"execution_payload,omitempty"`

	// Timestamp of execution request
	Timestamp int64 `json:"timestamp"`
}

// =============================================================================
// OBSERVATION RESULT
// =============================================================================

// ObservationResult is the chain-agnostic observation result
type ObservationResult struct {
	// TxHash of the observed transaction
	TxHash string `json:"tx_hash"`

	// BlockNumber where the transaction was included
	BlockNumber uint64 `json:"block_number"`

	// BlockHash of the block
	BlockHash string `json:"block_hash"`

	// BlockTimestamp when the block was created
	BlockTimestamp time.Time `json:"block_timestamp"`

	// Status of the transaction (0=pending, 1=success, 2=failed)
	Status uint8 `json:"status"`

	// Confirmations is the current confirmation count
	Confirmations int `json:"confirmations"`

	// RequiredConfirmations needed for finality
	RequiredConfirmations int `json:"required_confirmations"`

	// IsFinalized indicates if transaction has reached finality
	IsFinalized bool `json:"is_finalized"`

	// ResultHash is the hash of the execution result
	ResultHash [32]byte `json:"result_hash"`

	// MerkleProof for transaction inclusion (chain-specific)
	MerkleProof []byte `json:"merkle_proof,omitempty"`

	// ReceiptProof for receipt inclusion (EVM-specific)
	ReceiptProof []byte `json:"receipt_proof,omitempty"`

	// StateRoot from the block (for state proofs)
	StateRoot [32]byte `json:"state_root,omitempty"`

	// TransactionsRoot from the block
	TransactionsRoot [32]byte `json:"transactions_root,omitempty"`

	// ReceiptsRoot from the block (EVM)
	ReceiptsRoot [32]byte `json:"receipts_root,omitempty"`

	// RawReceipt is the raw transaction receipt
	RawReceipt []byte `json:"raw_receipt,omitempty"`

	// Logs from transaction execution
	Logs []EventLog `json:"logs,omitempty"`

	// GasUsed by the transaction
	GasUsed uint64 `json:"gas_used,omitempty"`

	// ObservedAt is when observation completed
	ObservedAt time.Time `json:"observed_at"`

	// ObserverValidatorID is the validator who observed
	ObserverValidatorID string `json:"observer_validator_id,omitempty"`
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE
// =============================================================================

// ChainExecutionStrategy defines the interface for chain-specific operations
// Implementations must be thread-safe
type ChainExecutionStrategy interface {
	// Platform returns the chain platform identifier
	Platform() ChainPlatform

	// ChainID returns the specific chain ID
	ChainID() string

	// NetworkName returns the human-readable network name
	NetworkName() string

	// CreateAnchor creates an anchor transaction on the chain (Step 1)
	// Returns the transaction result after submission
	CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error)

	// SubmitProof submits proof for on-chain verification (Step 2)
	// Verifies the proof cryptographically on-chain
	SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error)

	// ExecuteWithGovernance executes with governance verification (Step 3)
	// Final step that completes the anchor workflow
	ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error)

	// ObserveTransaction watches a transaction until finalization
	// Blocking call that returns when tx is finalized or times out
	ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error)

	// ObserveTransactionAsync starts async observation with callbacks
	ObserveTransactionAsync(ctx context.Context, txHash string,
		onFinalized func(*ObservationResult),
		onFailed func(error)) error

	// GetRequiredConfirmations returns confirmations needed for finality
	GetRequiredConfirmations() int

	// GetCurrentBlock returns the current block number
	GetCurrentBlock(ctx context.Context) (uint64, error)

	// GetTransactionReceipt retrieves a transaction receipt
	GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error)

	// EstimateGas estimates gas for an anchor operation
	EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error)

	// HealthCheck verifies connectivity to the chain
	HealthCheck(ctx context.Context) error

	// Config returns the chain configuration
	Config() *ChainConfig
}

// =============================================================================
// ANCHOR WORKFLOW MANAGER
// =============================================================================

// AnchorWorkflowState tracks the 3-step anchor workflow
type AnchorWorkflowState struct {
	// RequestID uniquely identifies the workflow
	RequestID uuid.UUID `json:"request_id"`

	// AnchorID from Step 1
	AnchorID [32]byte `json:"anchor_id"`

	// Step1 (Create) result
	Step1TxHash string       `json:"step1_tx_hash,omitempty"`
	Step1Result *AnchorResult `json:"step1_result,omitempty"`
	Step1Done   bool          `json:"step1_done"`

	// Step2 (Verify) result
	Step2TxHash string       `json:"step2_tx_hash,omitempty"`
	Step2Result *AnchorResult `json:"step2_result,omitempty"`
	Step2Done   bool          `json:"step2_done"`

	// Step3 (Governance) result
	Step3TxHash string       `json:"step3_tx_hash,omitempty"`
	Step3Result *AnchorResult `json:"step3_result,omitempty"`
	Step3Done   bool          `json:"step3_done"`

	// Workflow status
	Started    time.Time `json:"started"`
	Completed  *time.Time `json:"completed,omitempty"`
	Failed     bool       `json:"failed"`
	FailReason string     `json:"fail_reason,omitempty"`
}

// IsComplete returns true if all 3 steps are done
func (s *AnchorWorkflowState) IsComplete() bool {
	return s.Step1Done && s.Step2Done && s.Step3Done
}

// =============================================================================
// SUPPORTED CHAINS REGISTRY
// =============================================================================

// SupportedChain maps chain identifiers to their platforms
var SupportedChains = map[string]ChainPlatform{
	// EVM Chains
	"ethereum":         ChainPlatformEVM,
	"ethereum-mainnet": ChainPlatformEVM,
	"sepolia":          ChainPlatformEVM,
	"goerli":           ChainPlatformEVM,
	"arbitrum":         ChainPlatformEVM,
	"arbitrum-one":     ChainPlatformEVM,
	"optimism":         ChainPlatformEVM,
	"base":             ChainPlatformEVM,
	"polygon":          ChainPlatformEVM,
	"avalanche":        ChainPlatformEVM,
	"bsc":              ChainPlatformEVM,
	"tron":             ChainPlatformEVM,

	// CosmWasm Chains
	"osmosis":    ChainPlatformCosmWasm,
	"neutron":    ChainPlatformCosmWasm,
	"injective":  ChainPlatformCosmWasm,
	"cosmoshub":  ChainPlatformCosmWasm,
	"juno":       ChainPlatformCosmWasm,

	// Solana
	"solana":         ChainPlatformSolana,
	"solana-mainnet": ChainPlatformSolana,
	"solana-devnet":  ChainPlatformSolana,

	// Move Chains
	"aptos":       ChainPlatformMove,
	"sui":         ChainPlatformMove,
	"aptos-mainnet": ChainPlatformMove,
	"sui-mainnet":   ChainPlatformMove,

	// TON
	"ton":         ChainPlatformTON,
	"ton-mainnet": ChainPlatformTON,

	// NEAR
	"near":         ChainPlatformNEAR,
	"near-mainnet": ChainPlatformNEAR,
}

// GetPlatformForChain returns the platform for a chain identifier
func GetPlatformForChain(chainID string) (ChainPlatform, bool) {
	platform, ok := SupportedChains[chainID]
	return platform, ok
}
