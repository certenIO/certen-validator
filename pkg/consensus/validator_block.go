// Copyright 2025 Certen Protocol
//
// ValidatorBlock - Production-grade canonical proof bundle structure
// Implements deterministic JSON encoding and commitment computation

package consensus

import (
	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

// ValidatorBlock represents the canonical proof bundle stored in the validator CometBFT chain.
type ValidatorBlock struct {
	// === CORE METADATA ===
	BlockHeight   uint64 `json:"block_height"`        // [DERIVED]
	Timestamp     string `json:"timestamp"`           // [DERIVED] - RFC3339 format
	ValidatorID   string `json:"validator_id"`        // [CONFIG]
	BundleID      string `json:"bundle_id"`           // [DERIVED] - commitment.ComputeBundleID(GovernanceProof, CrossChainProof)

	// Reference to the Accumulate anchor the intent originated from.
	AccumulateAnchorReference AccumulateAnchorReference `json:"accumulate_anchor_reference"`

	// === COMMITMENTS ===
	OperationCommitment string `json:"operation_commitment"`  // [DERIVED] - Final commitment hash

	// === GOVERNANCE PROOF ===
	GovernanceProof GovernanceProof `json:"governance_proof"`

	// === CROSS-CHAIN PROOF ===
	CrossChainProof CrossChainProof `json:"cross_chain_proof"`

	// === EXECUTION PROOF ===
	ExecutionProof ExecutionProof `json:"execution_proof"`

	// === SYNTHETIC TRANSACTIONS ===
	SyntheticTransactions []SyntheticTx `json:"synthetic_transactions"` // [DERIVED]

	// === RESULT ATTESTATIONS ===
	ResultAttestations []ResultAttestation `json:"result_attestations"` // [DERIVED + OBSERVED]

	// === LITE CLIENT PROOF ===
	// Complete cryptographic proof chain from account state to network consensus
	// via the Accumulate lite client - provides L1-L4 validation
	LiteClientProof *lcproof.CompleteProof `json:"lite_client_proof,omitempty"`
}

// GovernanceProof represents the governance verification and authorization
// Per CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0:
// - G0: Inclusion & Finality (transaction existence proven via L1-L4)
// - G1: Authority Validated (key page authority, signature threshold)
// - G2: Outcome Binding (payload verification, effect verification)
type GovernanceProof struct {
	// === LEGACY FIELDS (backward compatibility) ===
	OrganizationADI       string              `json:"organization_adi"`         // [INTENT]
	MerkleRoot            string              `json:"merkle_root"`              // [DERIVED] - Merkle root of authorization leaves
	MerkleBranches        []MerkleBranch      `json:"merkle_branches"`          // [DERIVED] - Merkle inclusion proofs
	AuthorizationLeaves   []AuthorizationLeaf `json:"authorization_leaves"`     // [DERIVED] - From keybook lookups
	BLSAggregateSignature string              `json:"bls_aggregate_signature"`  // [DERIVED] - BLS signature aggregation
	BLSValidatorSetPubKey string              `json:"bls_validator_set_pubkey"` // [CONFIG] - Validator set public key

	// === FULL GOVERNANCE PROOF ARTIFACTS (G0/G1/G2) ===
	// These are the complete governance proofs per CERTEN spec v3-governance-kpsw-exec-4.0
	// They are populated AFTER L1-L4 lite client proof completes (dependency chain)

	// G0: Inclusion & Finality - Proves transaction exists and is finalized
	// Uses L1-L4 artifacts as cryptographic foundation
	G0Proof *govproof.G0Result `json:"g0_proof,omitempty"`

	// G1: Authority Validated - Proves authorization was correct at execution time
	// Uses G0 artifacts + validates key page authority and signature threshold
	G1Proof *govproof.G1Result `json:"g1_proof,omitempty"`

	// G2: Outcome Binding - Proves Accumulate intent payload authenticity and effect verification
	// Uses G1 artifacts + verifies the Accumulate intent's payload and transaction effects
	// NOTE: G2 is about the Accumulate intent authorship, NOT external chain execution
	G2Proof *govproof.G2Result `json:"g2_proof,omitempty"`

	// GovernanceLevel indicates the highest governance proof level achieved
	// "G0" = inclusion only, "G1" = authority validated, "G2" = outcome binding
	GovernanceLevel string `json:"governance_level,omitempty"`

	// SpecVersion is the CERTEN governance spec version used for proof generation
	SpecVersion string `json:"spec_version,omitempty"`
}

// CrossChainProof represents the cross-chain operation verification
type CrossChainProof struct {
	OperationID          string        `json:"operation_id"`            // [DERIVED] - Hash of 4 intent blobs
	ChainTargets         []ChainTarget `json:"chain_targets"`           // [INTENT + DERIVED] - Per-leg operations
	CrossChainCommitment string        `json:"cross_chain_commitment"`  // [DERIVED] - Hash of operation + commitments
}

// ExecutionProof represents the execution stage and results
type ExecutionProof struct {
	Stage               string                `json:"stage"`                            // [DERIVED] - one of "", ExecutionStagePre, ExecutionStagePost
	ValidatorSignatures []string              `json:"validator_signatures,omitempty"`  // [DERIVED] - Consensus signatures
	ExternalChainResults []ExternalChainResult `json:"external_chain_results,omitempty"` // [OBSERVED] - External execution results

	// CRITICAL: ProofClass routing per FIRST_PRINCIPLES 2.5 - on-demand vs on-cadence never interchangeable
	ProofClass          string                `json:"proof_class,omitempty"`            // [CANONICAL] - "on_demand" | "on_cadence" from IntentData
}

// AuthorizationLeaf represents a single authorization in the governance proof
type AuthorizationLeaf struct {
	KeyPage   string `json:"key_page"`
	KeyHash   string `json:"key_hash"`
	Role      string `json:"role"`
	Signature string `json:"signature"`
}

// MerkleBranch represents a branch in the Merkle tree proof
type MerkleBranch struct {
	LeafIndex uint64   `json:"leaf"`
	Branch    []string `json:"branch"`
}

// ChainTarget represents a target blockchain for cross-chain operations
type ChainTarget struct {
	Chain            string `json:"chain"`              // [INTENT] - "ethereum"
	ChainID          uint64 `json:"chain_id"`           // [INTENT] - 11155111 for Sepolia
	ContractAddress  string `json:"contract_address"`   // [INTENT] - Anchor contract address
	FunctionSelector string `json:"function_selector"`  // [INTENT] - Function selector
	EncodedCallData  string `json:"encoded_call_data"`  // [DERIVED] - ABI encoded call data
	Commitment       string `json:"commitment"`         // [DERIVED] - Per-leg commitment hash
	Expiry           string `json:"expiry"`             // [DERIVED FROM INTENT] - RFC3339 from ReplayData.ExpiresAt
}

// ExternalChainResult represents the result of an external chain operation
type ExternalChainResult struct {
	Chain        string      `json:"chain"`
	TxHash       string      `json:"tx_hash"`
	BlockHash    string      `json:"block_hash"`
	BlockNumber  uint64      `json:"block_number"`
	LogsRoot     string      `json:"logs_root"`
	InclusionProof []string  `json:"proof_of_inclusion"`
	Status       interface{} `json:"status,omitempty"` // Can be string, int, or bool
}

// SyntheticTx represents a synthetic transaction generated during validation
type SyntheticTx struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// ResultAttestation represents the final attestation of operation results
type ResultAttestation struct {
	OperationID         string   `json:"operation_id"`
	Chain               string   `json:"chain"`
	ObservedTxHash      string   `json:"observed_tx_hash"`
	ExecutionStatus     string   `json:"execution_status"`
	Timestamp           string   `json:"timestamp"`
	ValidatorSignatures []string `json:"validator_signatures"`
}

// Execution stage constants - use these everywhere instead of hard-coded strings
const (
	ExecutionStagePre  = "pre-execution"
	ExecutionStagePost = "post-execution"
)
