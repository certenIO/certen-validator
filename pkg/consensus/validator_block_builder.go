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
	"github.com/ethereum/go-ethereum/common"
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

	// === HIGH-004: Enforce G2 for value-moving operations ===
	// Parse cross-chain data to check if any leg transfers value.
	// If so, require G2 governance level which provides full payload binding.
	// G0 (inclusion only) and G1 (authority only) do NOT bind execution semantics.
	if env, parseErr := inputs.Intent.ParseCrossChain(); parseErr == nil && env != nil {
		hasValueOps := false
		for _, leg := range env.Legs {
			if leg.AmountWei != "" && leg.AmountWei != "0" {
				hasValueOps = true
				break
			}
		}
		if hasValueOps && inputs.Governance.GovernanceLevel != "G2" {
			return nil, fmt.Errorf(
				"HIGH-004: G2 governance required for value-moving operations, got %s",
				inputs.Governance.GovernanceLevel,
			)
		}
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

		// What will execute for this leg: its chain's anchor, called with createBatchAnchor - the leg's
		// declaration, which admission has already held to the chain's live anchor (declared_anchor.go).
		// No call data: the batch anchor's carries the batch root, which does not exist until the batch
		// closes; it was made up here from sha256 (RB4-F9).
		target, err := legChainTarget(leg)
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		target.Commitment = legCommitment
		target.Expiry = expiryString
		chainTargets[i] = target

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
	// The anchor reference is the proof's, whole. A missing height used to become the CometBFT height and
	// a missing transaction the intent's hash or the operation ID (RB3-F88).
	anchorRef := inputs.AnchorRef
	if anchorRef.BlockHash == "" || anchorRef.BlockHeight == 0 || anchorRef.TxHash == "" {
		return nil, fmt.Errorf("accumulate anchor reference is incomplete (block hash %q, height %d, tx %q)",
			anchorRef.BlockHash, anchorRef.BlockHeight, anchorRef.TxHash)
	}

	// === 3.9 Metadata (BlockHeight/Timestamp/ValidatorID) ===
	// These must be populated for invariant validation
	// The intent's own Accumulate block time: the same on every validator and on every retry, so a
	// resubmitted block is the same transaction and a late commit is found by its hash. It was
	// time.Now(), so each retry proposed new bytes and one intent could commit twice (RB3-F99). The
	// committed block's timestamp is the ABCI block time either way (applyCommitMetadata).
	if inputs.Intent.BlockTime.IsZero() {
		return nil, fmt.Errorf("intent %s carries no Accumulate block time; a validator block is not stamped with a local clock", inputs.Intent.IntentID)
	}
	timestamp := inputs.Intent.BlockTime.UTC().Format(time.RFC3339)
	validatorID := builder.validatorID
	if validatorID == "" {
		return nil, fmt.Errorf("validator block builder has no validator ID")
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
		EntitlementEvidence:       inputs.EntitlementEvidence,
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

// legChainTarget is the call a leg's chain will execute: the anchor the leg declares (an EVM address;
// its type string was put here when it had none, "so invariant doesn't fail") with the selector of the
// call it declares.
func legChainTarget(leg CCLeg) (ChainTarget, error) {
	addr := strings.TrimSpace(leg.AnchorContract.Address)
	if !common.IsHexAddress(addr) {
		return ChainTarget{}, fmt.Errorf("chain %d: the leg declares no anchor address (%q)", leg.ChainID, addr)
	}
	sel, err := DeclaredSelector(leg.AnchorContract.FunctionSelector)
	if err != nil {
		return ChainTarget{}, fmt.Errorf("chain %d: %w", leg.ChainID, err)
	}
	return ChainTarget{
		Chain:            leg.Chain,
		ChainID:          leg.ChainID,
		ContractAddress:  common.HexToAddress(addr).Hex(),
		FunctionSelector: "0x" + hex.EncodeToString(sel[:]),
	}, nil
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
