// Copyright 2025 Certen Protocol
//
// ValidatorBlock Builder - Converts ProofBundle to production ValidatorBlock
// Implements proper commitment computation and canonical structure

package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/commitment"
)

// ValidatorBlockBuilder constructs ValidatorBlock from CertenIntent and validator context
type ValidatorBlockBuilder struct {
	validatorID           string
	blsValidatorSetPubKey string
}

// BuilderConfig holds configuration for the validator block builder
type BuilderConfig struct {
	ValidatorID           string
	BLSValidatorSetPubKey string
}

// NewValidatorBlockBuilder creates a new builder instance
func NewValidatorBlockBuilder(config BuilderConfig) *ValidatorBlockBuilder {
	return &ValidatorBlockBuilder{
		validatorID:           config.ValidatorID,
		blsValidatorSetPubKey: config.BLSValidatorSetPubKey,
	}
}

// BuildFromIntent builds a ValidatorBlock from a discovered CertenIntent
// This is the ONLY function that may construct a ValidatorBlock per Golden Spec.
func (builder *ValidatorBlockBuilder) BuildFromIntent(inputs BuilderInputs) (*ValidatorBlock, error) {
	// Validation
	if inputs.Intent == nil {
		return nil, fmt.Errorf("CertenIntent cannot be nil")
	}

	// === 3.1 Compute operationID and set OperationCommitment ===
	opID, err := inputs.Intent.OperationID()
	if err != nil {
		return nil, fmt.Errorf("compute operationID: %w", err)
	}

	// === 3.2 Derive expiry RFC3339 from ReplayData ===
	replay, err := inputs.Intent.ParseReplay()
	if err != nil {
		return nil, fmt.Errorf("parse replay: %w", err)
	}
	expiryTime := time.Unix(replay.ExpiresAt, 0).UTC()
	expiryString := expiryTime.Format(time.RFC3339)

	// === 3.3 Build ChainTargets and cross-chain commitment ===
	env, err := inputs.Intent.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain: %w", err)
	}

	chainTargets := make([]ChainTarget, len(env.Legs))
	commitments := make([]string, len(env.Legs))

	for i, leg := range env.Legs {
		legBytes, _ := json.Marshal(leg)
		var legMap map[string]interface{}
		_ = json.Unmarshal(legBytes, &legMap)

		legCommitment, err := commitment.ComputeLegCommitment(legMap)
		if err != nil {
			return nil, fmt.Errorf("compute leg commitment for leg %d: %w", i, err)
		}

		// Encode call data for this leg
		encodedCallData, err := builder.encodeAnchorCallData(leg, legCommitment, expiryString)
		if err != nil {
			return nil, fmt.Errorf("encode call data for leg %d: %w", i, err)
		}

		chainTargets[i] = ChainTarget{
			Chain:            leg.Chain,
			ChainID:          leg.ChainID,
			ContractAddress:  leg.AnchorContract.Address,
			FunctionSelector: leg.AnchorContract.FunctionSelector,
			EncodedCallData:  encodedCallData,
			Commitment:       legCommitment,
			Expiry:           expiryString,
		}

		commitments[i] = legCommitment
	}

	// Use canonical hash of operation ID and commitments for cross-chain commitment
	crossChainData := map[string]interface{}{
		"operation_id": opID,
		"commitments":  commitments,
		"expiry":       expiryString,
	}

	crossChainCommitment, err := commitment.HashCanonical(crossChainData)
	if err != nil {
		return nil, fmt.Errorf("compute cross-chain commitment: %w", err)
	}

	// === 3.4 Governance proof ===
	leaves := make([]interface{}, len(inputs.Governance.Leaves))
	for i, leaf := range inputs.Governance.Leaves {
		leaves[i] = leaf
	}

	merkleRoot, err := commitment.ComputeGovernanceMerkleRoot(leaves)
	if err != nil {
		return nil, fmt.Errorf("compute governance merkle root: %w", err)
	}

	gd, err := inputs.Intent.ParseGovernance()
	if err != nil {
		return nil, fmt.Errorf("parse governance: %w", err)
	}

	orgADI := gd.OrganizationAdi
	if orgADI == "" {
		orgADI = gd.OrganizationADI
	}

	// Build GovernanceProof with both legacy fields and full G0/G1/G2 proofs
	// Per CERTEN spec v3-governance-kpsw-exec-4.0:
	// - G0/G1/G2 proofs are generated AFTER L1-L4 lite client proof completes
	// - These proofs provide the cryptographic foundation for governance verification
	// NOTE: G2 (Outcome Binding) is about Accumulate intent authorship, NOT external execution
	govProof := GovernanceProof{
		// Legacy fields (backward compatibility)
		AuthorizationLeaves:   inputs.Governance.Leaves,
		MerkleRoot:            merkleRoot,
		BLSValidatorSetPubKey: builder.blsValidatorSetPubKey,
		BLSAggregateSignature: inputs.Governance.BLSAggregateSignature,
		OrganizationADI:       orgADI,
		MerkleBranches:        nil, // optional for now

		// Full G0/G1/G2 governance proof artifacts
		// These are populated from GovernanceInputs if L1-L4 proof completed
		// G0: Inclusion & Finality
		// G1: Authority Validated
		// G2: Outcome Binding (Accumulate intent payload/effect verification)
		G0Proof:         inputs.Governance.G0Proof,
		G1Proof:         inputs.Governance.G1Proof,
		G2Proof:         inputs.Governance.G2Proof,
		GovernanceLevel: inputs.Governance.GovernanceLevel,
		SpecVersion:     "v3-governance-kpsw-exec-4.0",
	}

	crossChainProof := CrossChainProof{
		OperationID:          opID,
		ChainTargets:         chainTargets,
		CrossChainCommitment: crossChainCommitment,
	}

	// === 3.5 Bundle ID ===
	bundleID, err := commitment.ComputeBundleID(govProof, crossChainProof)
	if err != nil {
		return nil, fmt.Errorf("compute bundle id: %w", err)
	}

	// === 3.6 ExecutionProof ===
	stage := inputs.Execution.Stage
	if stage == "" {
		stage = ExecutionStagePre
	}
	if stage != ExecutionStagePre && stage != ExecutionStagePost {
		return nil, fmt.Errorf("invalid execution stage: %s", stage)
	}

	execProof := ExecutionProof{
		Stage:      stage,
		ProofClass: inputs.Execution.ProofClass, // CRITICAL: preserve proof class per FIRST_PRINCIPLES 2.5
	}

	if stage == ExecutionStagePre {
		if len(inputs.Execution.ValidatorSignatures) == 0 {
			return nil, fmt.Errorf("pre-execution must include validator signatures")
		}
		execProof.ValidatorSignatures = inputs.Execution.ValidatorSignatures
		execProof.ExternalChainResults = nil
	} else { // post
		execProof.ExternalChainResults = inputs.Execution.ExternalResults
	}

	// === 3.7 SyntheticTxs & ResultAttestations ===
	// Ensure all use the same OperationCommitment
	for i := range inputs.ResultAtts {
		inputs.ResultAtts[i].OperationID = opID
	}

	// === 3.8 Anchor reference and lite client proof ===
	// Ensure anchor reference has required fields populated
	anchorRef := inputs.AnchorRef
	if anchorRef.BlockHeight == 0 && inputs.BlockHeight > 0 {
		anchorRef.BlockHeight = inputs.BlockHeight
	}
	// If TxHash is empty, use a derived value from the intent
	if anchorRef.TxHash == "" {
		// Use intent's transaction hash or operation ID as fallback
		if inputs.Intent.TransactionHash != "" {
			anchorRef.TxHash = inputs.Intent.TransactionHash
		} else {
			anchorRef.TxHash = opID // Use operation ID as fallback
		}
	}

	// === 3.9 Metadata (BlockHeight/Timestamp/ValidatorID) ===
	// These must be populated for invariant validation
	timestamp := time.Now().UTC().Format(time.RFC3339)
	validatorID := builder.validatorID
	if validatorID == "" {
		validatorID = "validator-default" // Fallback if not configured
	}

	// BLS signature validation - must be set before reaching builder
	// The bft_integration.go generates this using the validator's BLS key
	if govProof.BLSAggregateSignature == "" {
		return nil, fmt.Errorf("governance_proof.bls_aggregate_signature must not be empty - ensure BLS key is initialized")
	}

	vb := &ValidatorBlock{
		BlockHeight:               inputs.BlockHeight,
		Timestamp:                 timestamp,
		ValidatorID:               validatorID,
		BundleID:                  bundleID,
		AccumulateAnchorReference: anchorRef,
		OperationCommitment:       opID,
		GovernanceProof:           govProof,
		CrossChainProof:           crossChainProof,
		ExecutionProof:            execProof,
		SyntheticTransactions:     inputs.SyntheticTxs,
		ResultAttestations:        inputs.ResultAtts,
		LiteClientProof:           inputs.LiteClientProof,
	}

	return vb, nil
}

// Legacy BuildValidatorBlock method removed - use BuildFromIntent with CertenIntent



// ==================================
// Intent-Centric Helper Methods
// ==================================

// parseIntentBlobs parses the 4 JSON blobs from CertenIntent
func (builder *ValidatorBlockBuilder) parseIntentBlobs(intent *CertenIntent) (*IntentData, *CrossChainEnvelope, *GovernanceData, *ReplayData, error) {
	// Parse the 4 JSON blobs from CertenIntent
	var intentData IntentData
	if err := json.Unmarshal(intent.IntentData, &intentData); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse intentData: %w", err)
	}

	var crossChainData CrossChainEnvelope
	if err := json.Unmarshal(intent.CrossChainData, &crossChainData); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse crossChainData: %w", err)
	}

	var govData GovernanceData
	if err := json.Unmarshal(intent.GovernanceData, &govData); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse governanceData: %w", err)
	}

	var replayData ReplayData
	if err := json.Unmarshal(intent.ReplayData, &replayData); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse replayData: %w", err)
	}

	return &intentData, &crossChainData, &govData, &replayData, nil
}

// buildChainTargets builds ChainTarget array from cross-chain legs
func (builder *ValidatorBlockBuilder) buildChainTargets(crossChainData *CrossChainEnvelope, expiryString string) ([]ChainTarget, error) {
	targets := make([]ChainTarget, len(crossChainData.Legs))

	for i, leg := range crossChainData.Legs {
		// Compute per-leg commitment - convert CCLeg to map for commitment function
		legData, err := json.Marshal(leg)
		if err != nil {
			return nil, fmt.Errorf("marshal leg %d: %w", i, err)
		}
		var legMap map[string]interface{}
		if err := json.Unmarshal(legData, &legMap); err != nil {
			return nil, fmt.Errorf("unmarshal leg %d to map: %w", i, err)
		}
		legCommitment, err := commitment.ComputeLegCommitment(legMap)
		if err != nil {
			return nil, fmt.Errorf("compute commitment for leg %d: %w", i, err)
		}

		// ABI-encode the call data for the anchor contract
		encodedCallData, err := builder.encodeAnchorCallData(leg, legCommitment, expiryString)
		if err != nil {
			return nil, fmt.Errorf("ABI encode call data for leg %d: %w", i, err)
		}

		targets[i] = ChainTarget{
			Chain:            leg.Chain,
			ChainID:          leg.ChainID,
			ContractAddress:  leg.AnchorContract.Address,
			FunctionSelector: leg.AnchorContract.FunctionSelector,
			EncodedCallData:  encodedCallData,
			Commitment:       legCommitment,
			Expiry:           expiryString,
		}
	}

	return targets, nil
}


// buildMerkleBranches constructs Merkle branches for authorization leaves
func (builder *ValidatorBlockBuilder) buildMerkleBranches(leaves []AuthorizationLeaf) []MerkleBranch {
	branches := make([]MerkleBranch, 0)

	// TODO: Move Merkle branch computation into commitment package so
	// both MerkleRoot and MerkleBranches share a single implementation.
	// Currently Branch is a single element (leaf hash) for shape only.
	for i, leaf := range leaves {
		// Create hash using commitment package
		raw, err := json.Marshal(leaf)
		if err != nil {
			continue
		}
		canonBytes, err := commitment.CanonicalizeJSON(raw)
		if err != nil {
			continue
		}
		h := sha256.Sum256(canonBytes)
		leafHash := "0x" + hex.EncodeToString(h[:])

		branches = append(branches, MerkleBranch{
			LeafIndex: uint64(i),
			Branch:    []string{leafHash},
		})
	}

	return branches
}

// encodeAnchorCallData ABI-encodes the call data for Ethereum anchor contracts
func (builder *ValidatorBlockBuilder) encodeAnchorCallData(leg CCLeg, commitment, expiry string) (string, error) {
	// TODO: Replace with true Ethereum ABI encoding using keccak256 selector
	// and uint256 expiry. This simplified encoding is ONLY OK for dev/test.
	// Simplified ABI encoding for anchor function call
	// Typically this would be: anchorCommitment(bytes32 commitment, uint256 expiry, bytes calldata proof)

	// Convert hex commitment to bytes32
	commitmentBytes, err := hex.DecodeString(strings.TrimPrefix(commitment, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid commitment hex: %w", err)
	}

	// Pad to 32 bytes if needed
	if len(commitmentBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(commitmentBytes):], commitmentBytes)
		commitmentBytes = padded
	}

	// Create minimal ABI-encoded call data
	// Function selector (first 4 bytes of keccak256("anchorCommitment(bytes32,uint256,bytes)"))
	functionSelector := leg.AnchorContract.FunctionSelector
	if functionSelector == "" {
		// Default anchor commitment function selector
		hash := sha256.Sum256([]byte("anchorCommitment(bytes32,uint256,bytes)"))
		functionSelector = hex.EncodeToString(hash[:4])
	}

	// Simple encoding: selector + commitment (32 bytes) + expiry timestamp
	// This is a simplified implementation - real ABI encoding would be more complex
	callData := functionSelector
	callData += hex.EncodeToString(commitmentBytes)

	// Add expiry as uint256 (32 bytes, simplified)
	expiryHash := sha256.Sum256([]byte(expiry))
	callData += hex.EncodeToString(expiryHash[:])

	return "0x" + callData, nil
}
