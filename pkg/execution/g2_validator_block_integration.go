// Copyright 2025 Certen Protocol
//
// G2 ValidatorBlock Integration - Connects G2 Outcome Binding with ValidatorBlockBuilder
// Per CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0
//
// This integration provides:
// - Enhanced BuilderInputs with G2 proof support
// - Methods to incorporate G2 outcome binding into ValidatorBlock
// - Orchestration of complete proof generation with G2 binding

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// ENHANCED VALIDATOR BLOCK BUILDER INPUTS
// =============================================================================

// G2EnhancedBuilderInputs extends the standard BuilderInputs with G2 outcome binding
type G2EnhancedBuilderInputs struct {
	// Standard builder inputs (from consensus package)
	IntentID          string `json:"intent_id"`
	TransactionHash   string `json:"transaction_hash"`
	AccountURL        string `json:"account_url"`
	OrganizationADI   string `json:"organization_adi"`

	// Cross-chain target details
	TargetChain     string         `json:"target_chain"`
	TargetChainID   int64          `json:"target_chain_id"`
	TargetContract  common.Address `json:"target_contract"`
	FunctionSelector [4]byte       `json:"function_selector"`
	EncodedCallData []byte         `json:"encoded_call_data"`
	Value           *big.Int       `json:"value"`

	// Governance proofs
	G1Proof *proof.G1Result `json:"g1_proof,omitempty"`
	G2Proof *proof.G2Result `json:"g2_proof,omitempty"`

	// G2 Outcome Binding
	OutcomeBinding *G2BindingResult `json:"outcome_binding,omitempty"`

	// External chain execution result
	ExecutionResult *ExternalChainResult `json:"execution_result,omitempty"`

	// Expected effects for verification
	ExpectedEffects []ExpectedEffect `json:"expected_effects,omitempty"`

	// Attestations
	Attestations *AggregatedAttestation `json:"attestations,omitempty"`

	// Block metadata
	BlockHeight uint64    `json:"block_height"`
	Timestamp   time.Time `json:"timestamp"`
	ValidatorID string    `json:"validator_id"`
}

// =============================================================================
// G2 ENHANCED VALIDATOR BLOCK
// =============================================================================

// G2EnhancedValidatorBlock extends ValidatorBlock with G2 outcome binding proof
type G2EnhancedValidatorBlock struct {
	// Standard ValidatorBlock fields (represented as embedded interface)
	BlockHeight         uint64 `json:"block_height"`
	Timestamp           string `json:"timestamp"`
	ValidatorID         string `json:"validator_id"`
	BundleID            string `json:"bundle_id"`
	OperationCommitment string `json:"operation_commitment"`

	// G2 Enhanced Governance Proof
	G2GovernanceProof *G2GovernanceProofBlock `json:"g2_governance_proof"`

	// Cross-Chain Proof
	CrossChainProof *G2CrossChainProof `json:"cross_chain_proof"`

	// Execution Proof with G2 binding
	ExecutionProof *G2ExecutionProof `json:"execution_proof"`

	// Outcome Binding (G2 specific)
	OutcomeBinding *G2OutcomeBindingBlock `json:"outcome_binding"`

	// Result Attestations
	ResultAttestations *AggregatedAttestation `json:"result_attestations,omitempty"`

	// Computed hashes
	BlockHash        [32]byte `json:"block_hash"`
	OutcomeLeafHash  [32]byte `json:"outcome_leaf_hash"`
	G2BindingHash    [32]byte `json:"g2_binding_hash"`
}

// G2GovernanceProofBlock contains governance proof at G2 level
type G2GovernanceProofBlock struct {
	// G2 proof result
	Level       string `json:"level"` // "G2"
	SpecVersion string `json:"spec_version"`

	// Core G1 fields
	OrganizationADI     string `json:"organization_adi"`
	KeyBookURL          string `json:"key_book_url"`
	ThresholdSatisfied  bool   `json:"threshold_satisfied"`
	UniqueValidKeys     int    `json:"unique_valid_keys"`
	RequiredThreshold   uint64 `json:"required_threshold"`

	// G2 specific fields
	PayloadVerified     bool   `json:"payload_verified"`
	EffectVerified      bool   `json:"effect_verified"`
	G2ProofComplete     bool   `json:"g2_proof_complete"`
	SecurityLevel       string `json:"security_level"`

	// Merkle root of authorization leaves
	MerkleRoot          string `json:"merkle_root"`

	// BLS aggregate signature
	BLSAggregateSignature string `json:"bls_aggregate_signature"`

	// Full proof reference (hash)
	ProofHash           [32]byte `json:"proof_hash"`
}

// G2CrossChainProof contains cross-chain proof with outcome binding
type G2CrossChainProof struct {
	OperationID          string        `json:"operation_id"`
	CrossChainCommitment string        `json:"cross_chain_commitment"`
	ChainTargets         []G2ChainTarget `json:"chain_targets"`

	// Outcome binding extension
	OutcomeCommitment    [32]byte `json:"outcome_commitment"`
}

// G2ChainTarget extends ChainTarget with outcome verification
type G2ChainTarget struct {
	Chain            string         `json:"chain"`
	ChainID          uint64         `json:"chain_id"`
	ContractAddress  common.Address `json:"contract_address"`
	FunctionSelector [4]byte        `json:"function_selector"`
	EncodedCallData  string         `json:"encoded_call_data"`
	Commitment       string         `json:"commitment"`
	Expiry           string         `json:"expiry"`

	// G2 outcome verification
	PayloadVerified bool     `json:"payload_verified"`
	EffectVerified  bool     `json:"effect_verified"`
	ExecutionTxHash string   `json:"execution_tx_hash,omitempty"`
	ExecutionBlock  uint64   `json:"execution_block,omitempty"`
}

// G2ExecutionProof contains execution proof with G2 outcome binding
type G2ExecutionProof struct {
	Stage      string `json:"stage"` // "pre-execution" or "post-execution"
	ProofClass string `json:"proof_class"`

	// Pre-execution validator signatures
	ValidatorSignatures []string `json:"validator_signatures,omitempty"`

	// Post-execution external chain results
	ExternalChainResults []*ExternalChainResult `json:"external_chain_results,omitempty"`

	// G2 outcome verification
	OutcomeLeaf *proof.OutcomeLeaf `json:"outcome_leaf,omitempty"`
	G2Verified  bool               `json:"g2_verified"`
}

// G2OutcomeBindingBlock contains the G2 outcome binding proof
type G2OutcomeBindingBlock struct {
	// Binding verification status
	BindingComplete bool `json:"binding_complete"`

	// Individual verifications
	PayloadVerification *proof.PayloadVerification `json:"payload_verification"`
	EffectVerification  *proof.EffectVerification  `json:"effect_verification"`
	ReceiptBinding      *proof.VerificationResult  `json:"receipt_binding"`
	WitnessConsistency  *proof.VerificationResult  `json:"witness_consistency"`

	// Outcome leaf
	OutcomeLeaf *proof.OutcomeLeaf `json:"outcome_leaf"`

	// Cryptographic binding
	BindingHash     [32]byte  `json:"binding_hash"`
	VerifiedAt      time.Time `json:"verified_at"`
	VerificationMs  int64     `json:"verification_ms"`
}

// =============================================================================
// G2 ENHANCED VALIDATOR BLOCK BUILDER
// =============================================================================

// G2EnhancedBlockBuilder builds G2-enhanced ValidatorBlocks
type G2EnhancedBlockBuilder struct {
	// G2 outcome binding service
	g2Service *G2OutcomeBindingService

	// Configuration
	config *G2BlockBuilderConfig

	// Logging
	logger Logger
}

// G2BlockBuilderConfig contains configuration for the G2 block builder
type G2BlockBuilderConfig struct {
	ValidatorID           string
	BLSValidatorSetPubKey string

	// G2 verification settings
	RequireG2Verification bool
	StrictOutcomeBinding  bool
}

// NewG2EnhancedBlockBuilder creates a new G2-enhanced block builder
func NewG2EnhancedBlockBuilder(
	g2Service *G2OutcomeBindingService,
	config *G2BlockBuilderConfig,
	logger Logger,
) *G2EnhancedBlockBuilder {
	return &G2EnhancedBlockBuilder{
		g2Service: g2Service,
		config:    config,
		logger:    logger,
	}
}

// BuildG2EnhancedBlock builds a G2-enhanced ValidatorBlock
func (b *G2EnhancedBlockBuilder) BuildG2EnhancedBlock(
	ctx context.Context,
	inputs *G2EnhancedBuilderInputs,
) (*G2EnhancedValidatorBlock, error) {

	b.logger.Printf("🏗️ [G2-BUILDER] Building G2-enhanced ValidatorBlock for intent: %s", inputs.IntentID)

	// Step 1: Validate inputs
	if err := b.validateInputs(inputs); err != nil {
		return nil, fmt.Errorf("validate inputs: %w", err)
	}

	// Step 2: Perform G2 outcome binding if execution result available
	var outcomeBinding *G2BindingResult
	if inputs.ExecutionResult != nil && inputs.G1Proof != nil {
		b.logger.Printf("🔐 [G2-BUILDER] Performing G2 outcome binding verification")

		bindingRequest := &G2BindingRequest{
			Intent: BuildIntentOutcomeData(
				inputs.IntentID,
				inputs.TransactionHash,
				inputs.TargetChain,
				inputs.TargetChainID,
				inputs.TargetContract,
				inputs.FunctionSelector,
				inputs.EncodedCallData,
				inputs.Value,
				inputs.OrganizationADI,
				"", // key book URL
			),
			G1Proof:         inputs.G1Proof,
			ExecutionResult: inputs.ExecutionResult,
			Commitment:      nil, // Can be provided if available
			ExpectedEffects: inputs.ExpectedEffects,
		}

		var err error
		outcomeBinding, err = b.g2Service.VerifyOutcomeBinding(ctx, bindingRequest)
		if err != nil {
			if b.config.StrictOutcomeBinding {
				return nil, fmt.Errorf("G2 outcome binding failed: %w", err)
			}
			b.logger.Printf("⚠️ [G2-BUILDER] G2 outcome binding error (non-strict): %v", err)
		}
	}

	// Step 3: Build operation commitment
	operationCommitment := b.computeOperationCommitment(inputs)

	// Step 4: Build cross-chain proof with outcome binding
	crossChainProof := b.buildG2CrossChainProof(inputs, outcomeBinding)

	// Step 5: Build governance proof block
	govProofBlock := b.buildG2GovernanceProofBlock(inputs, outcomeBinding)

	// Step 6: Build execution proof
	execProof := b.buildG2ExecutionProof(inputs, outcomeBinding)

	// Step 7: Build outcome binding block
	outcomeBindingBlock := b.buildG2OutcomeBindingBlock(outcomeBinding)

	// Step 8: Compute bundle ID
	bundleID := b.computeBundleID(govProofBlock, crossChainProof)

	// Step 9: Assemble the enhanced block
	block := &G2EnhancedValidatorBlock{
		BlockHeight:         inputs.BlockHeight,
		Timestamp:           inputs.Timestamp.Format(time.RFC3339),
		ValidatorID:         inputs.ValidatorID,
		BundleID:            bundleID,
		OperationCommitment: operationCommitment,
		G2GovernanceProof:   govProofBlock,
		CrossChainProof:     crossChainProof,
		ExecutionProof:      execProof,
		OutcomeBinding:      outcomeBindingBlock,
		ResultAttestations:  inputs.Attestations,
	}

	// Step 10: Compute block hashes
	block.BlockHash = b.computeBlockHash(block)
	if outcomeBinding != nil && outcomeBinding.OutcomeLeaf != nil {
		block.OutcomeLeafHash = b.computeOutcomeLeafHash(outcomeBinding.OutcomeLeaf)
		block.G2BindingHash = outcomeBinding.BindingHash
	}

	b.logger.Printf("✅ [G2-BUILDER] G2-enhanced ValidatorBlock built successfully")
	b.logger.Printf("   Bundle ID: %s", bundleID[:16])
	b.logger.Printf("   G2 Complete: %v", govProofBlock.G2ProofComplete)

	return block, nil
}

// =============================================================================
// BUILDER HELPER METHODS
// =============================================================================

// validateInputs validates the builder inputs
func (b *G2EnhancedBlockBuilder) validateInputs(inputs *G2EnhancedBuilderInputs) error {
	if inputs.IntentID == "" {
		return fmt.Errorf("intent ID required")
	}
	if inputs.OrganizationADI == "" {
		return fmt.Errorf("organization ADI required")
	}
	if b.config.RequireG2Verification {
		if inputs.G1Proof == nil {
			return fmt.Errorf("G1 proof required for G2 verification")
		}
	}
	return nil
}

// computeOperationCommitment computes the operation commitment hash
func (b *G2EnhancedBlockBuilder) computeOperationCommitment(inputs *G2EnhancedBuilderInputs) string {
	data := make([]byte, 0, 256)

	data = append(data, []byte(inputs.IntentID)...)
	data = append(data, []byte(inputs.TransactionHash)...)
	data = append(data, []byte(inputs.AccountURL)...)
	data = append(data, []byte(inputs.OrganizationADI)...)

	hash := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// buildG2CrossChainProof builds cross-chain proof with outcome binding
func (b *G2EnhancedBlockBuilder) buildG2CrossChainProof(
	inputs *G2EnhancedBuilderInputs,
	outcomeBinding *G2BindingResult,
) *G2CrossChainProof {

	target := G2ChainTarget{
		Chain:            inputs.TargetChain,
		ChainID:          uint64(inputs.TargetChainID),
		ContractAddress:  inputs.TargetContract,
		FunctionSelector: inputs.FunctionSelector,
		EncodedCallData:  hex.EncodeToString(inputs.EncodedCallData),
		Commitment:       "",
		Expiry:           "",
	}

	if outcomeBinding != nil && outcomeBinding.PayloadVerification != nil {
		target.PayloadVerified = outcomeBinding.PayloadVerification.Verified
	}
	if outcomeBinding != nil && outcomeBinding.EffectVerification != nil {
		target.EffectVerified = outcomeBinding.EffectVerification.Verified
	}
	if inputs.ExecutionResult != nil {
		target.ExecutionTxHash = inputs.ExecutionResult.TxHash.Hex()
		target.ExecutionBlock = inputs.ExecutionResult.BlockNumber.Uint64()
	}

	// Compute cross-chain commitment
	ccData := map[string]interface{}{
		"chain":    inputs.TargetChain,
		"chain_id": inputs.TargetChainID,
		"contract": inputs.TargetContract.Hex(),
	}
	ccBytes, _ := json.Marshal(ccData)
	ccHash := sha256.Sum256(ccBytes)

	var outcomeCommitment [32]byte
	if outcomeBinding != nil {
		outcomeCommitment = outcomeBinding.BindingHash
	}

	return &G2CrossChainProof{
		OperationID:          inputs.IntentID,
		CrossChainCommitment: "0x" + hex.EncodeToString(ccHash[:]),
		ChainTargets:         []G2ChainTarget{target},
		OutcomeCommitment:    outcomeCommitment,
	}
}

// buildG2GovernanceProofBlock builds governance proof block
func (b *G2EnhancedBlockBuilder) buildG2GovernanceProofBlock(
	inputs *G2EnhancedBuilderInputs,
	outcomeBinding *G2BindingResult,
) *G2GovernanceProofBlock {

	block := &G2GovernanceProofBlock{
		Level:               "G2",
		SpecVersion:         proof.GovernanceSpecVersion,
		OrganizationADI:     inputs.OrganizationADI,
		BLSAggregateSignature: b.config.BLSValidatorSetPubKey,
	}

	// Copy G1 fields if available
	if inputs.G1Proof != nil {
		block.ThresholdSatisfied = inputs.G1Proof.ThresholdSatisfied
		block.UniqueValidKeys = inputs.G1Proof.UniqueValidKeys
		block.RequiredThreshold = inputs.G1Proof.RequiredThreshold
	}

	// Add G2 fields from outcome binding
	if outcomeBinding != nil {
		if outcomeBinding.PayloadVerification != nil {
			block.PayloadVerified = outcomeBinding.PayloadVerification.Verified
		}
		if outcomeBinding.EffectVerification != nil {
			block.EffectVerified = outcomeBinding.EffectVerification.Verified
		}
		block.G2ProofComplete = outcomeBinding.Success
		if outcomeBinding.G2Proof != nil {
			block.SecurityLevel = outcomeBinding.G2Proof.SecurityLevel
		}
	}

	// Compute proof hash
	proofData, _ := json.Marshal(block)
	block.ProofHash = sha256.Sum256(proofData)

	return block
}

// buildG2ExecutionProof builds execution proof with G2 binding
func (b *G2EnhancedBlockBuilder) buildG2ExecutionProof(
	inputs *G2EnhancedBuilderInputs,
	outcomeBinding *G2BindingResult,
) *G2ExecutionProof {

	execProof := &G2ExecutionProof{
		Stage:      "post-execution",
		ProofClass: "on_demand",
	}

	if inputs.ExecutionResult != nil {
		execProof.ExternalChainResults = []*ExternalChainResult{inputs.ExecutionResult}
	}

	if outcomeBinding != nil {
		execProof.OutcomeLeaf = outcomeBinding.OutcomeLeaf
		execProof.G2Verified = outcomeBinding.Success
	}

	return execProof
}

// buildG2OutcomeBindingBlock builds the outcome binding block
func (b *G2EnhancedBlockBuilder) buildG2OutcomeBindingBlock(
	outcomeBinding *G2BindingResult,
) *G2OutcomeBindingBlock {

	if outcomeBinding == nil {
		return &G2OutcomeBindingBlock{
			BindingComplete: false,
		}
	}

	return &G2OutcomeBindingBlock{
		BindingComplete:     outcomeBinding.Success,
		PayloadVerification: outcomeBinding.PayloadVerification,
		EffectVerification:  outcomeBinding.EffectVerification,
		ReceiptBinding:      outcomeBinding.ReceiptBinding,
		WitnessConsistency:  outcomeBinding.WitnessConsistency,
		OutcomeLeaf:         outcomeBinding.OutcomeLeaf,
		BindingHash:         outcomeBinding.BindingHash,
		VerifiedAt:          outcomeBinding.VerifiedAt,
		VerificationMs:      outcomeBinding.VerificationMs,
	}
}

// computeBundleID computes the bundle ID
func (b *G2EnhancedBlockBuilder) computeBundleID(
	govProof *G2GovernanceProofBlock,
	ccProof *G2CrossChainProof,
) string {
	data := make([]byte, 0, 128)

	data = append(data, govProof.ProofHash[:]...)
	data = append(data, []byte(ccProof.CrossChainCommitment)...)
	data = append(data, ccProof.OutcomeCommitment[:]...)

	hash := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// computeBlockHash computes the block hash
func (b *G2EnhancedBlockBuilder) computeBlockHash(block *G2EnhancedValidatorBlock) [32]byte {
	data, _ := json.Marshal(block)
	return sha256.Sum256(data)
}

// computeOutcomeLeafHash computes the outcome leaf hash
func (b *G2EnhancedBlockBuilder) computeOutcomeLeafHash(leaf *proof.OutcomeLeaf) [32]byte {
	data, _ := json.Marshal(leaf)
	return sha256.Sum256(data)
}

// =============================================================================
// SERIALIZATION
// =============================================================================

// ToJSON serializes G2EnhancedValidatorBlock to JSON
func (b *G2EnhancedValidatorBlock) ToJSON() ([]byte, error) {
	return json.Marshal(b)
}

// ToHex returns a hex representation of the block hash
func (b *G2EnhancedValidatorBlock) ToHex() string {
	return hex.EncodeToString(b.BlockHash[:])
}

// IsG2Complete returns whether G2 verification is complete
func (b *G2EnhancedValidatorBlock) IsG2Complete() bool {
	return b.G2GovernanceProof != nil && b.G2GovernanceProof.G2ProofComplete
}
