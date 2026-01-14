// Copyright 2025 Certen Protocol
//
// ExecutionCommitmentBuilder - Cryptographic binding of intent to expected execution
//
// This module creates ExecutionCommitments BEFORE execution that specify exactly
// what the executor is expected to do. After execution, validators verify the
// actual transaction matches the commitment - ensuring the executor didn't
// substitute a different transaction.
//
// SECURITY CRITICAL: This is the mechanism that prevents a malicious executor
// from executing arbitrary transactions instead of the intended operation.

package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// EXECUTION COMMITMENT BUILDER
// =============================================================================

// ExecutionCommitmentBuilder creates ExecutionCommitments from intent data
// It extracts expected execution parameters and creates cryptographic commitments
// that can be verified after execution.
type ExecutionCommitmentBuilder struct {
	// Known function selectors for Certen contracts
	functionSelectors map[string][4]byte

	// Known event signatures for verification
	eventSignatures map[string]common.Hash
}

// NewExecutionCommitmentBuilder creates a new commitment builder
func NewExecutionCommitmentBuilder() *ExecutionCommitmentBuilder {
	builder := &ExecutionCommitmentBuilder{
		functionSelectors: make(map[string][4]byte),
		eventSignatures:   make(map[string]common.Hash),
	}

	// Pre-compute known function selectors for CertenAnchorV3
	// createAnchor(bytes32,bytes32,bytes32,bytes32,uint256)
	builder.functionSelectors["createAnchor"] = computeFunctionSelector("createAnchor(bytes32,bytes32,bytes32,bytes32,uint256)")
	// executeComprehensiveProof(bytes32,uint256[8],uint256[2],uint256[2][2],uint256[2],bytes32[],uint8[],bytes)
	builder.functionSelectors["executeComprehensiveProof"] = computeFunctionSelector("executeComprehensiveProof(bytes32,uint256[8],uint256[2],uint256[2][2],uint256[2],bytes32[],uint8[],bytes)")
	// executeWithGovernance(bytes32,address,uint256,bytes)
	builder.functionSelectors["executeWithGovernance"] = computeFunctionSelector("executeWithGovernance(bytes32,address,uint256,bytes)")

	// Pre-compute known event signatures
	// AnchorCreated(bytes32 indexed bundleId, bytes32 intentHash, bytes32 stateRoot, bytes32 operationCommitment, uint256 timestamp)
	builder.eventSignatures["AnchorCreated"] = crypto.Keccak256Hash([]byte("AnchorCreated(bytes32,bytes32,bytes32,bytes32,uint256)"))
	// ProofVerified(bytes32 indexed bundleId, bool success, uint256 timestamp)
	builder.eventSignatures["ProofVerified"] = crypto.Keccak256Hash([]byte("ProofVerified(bytes32,bool,uint256)"))
	// GovernanceExecuted(bytes32 indexed bundleId, address target, uint256 value, bool success)
	builder.eventSignatures["GovernanceExecuted"] = crypto.Keccak256Hash([]byte("GovernanceExecuted(bytes32,address,uint256,bool)"))

	return builder
}

// computeFunctionSelector computes the 4-byte function selector from signature
func computeFunctionSelector(signature string) [4]byte {
	hash := crypto.Keccak256([]byte(signature))
	var selector [4]byte
	copy(selector[:], hash[:4])
	return selector
}

// =============================================================================
// INTENT PARSING TYPES
// =============================================================================

// ParsedCrossChainData represents parsed cross-chain data from intent
type ParsedCrossChainData struct {
	Protocol         string            `json:"protocol"`
	Version          string            `json:"version"`
	OperationGroupID string            `json:"operationGroupId"`
	Legs             []ParsedCCLeg     `json:"legs"`
}

// ParsedCCLeg represents a parsed cross-chain leg
type ParsedCCLeg struct {
	LegID          string `json:"legId"`
	Chain          string `json:"chain"`
	ChainID        uint64 `json:"chainId"`
	From           string `json:"from"`
	To             string `json:"to"`
	AmountWei      string `json:"amountWei"`
	AnchorContract struct {
		Address          string `json:"address"`
		FunctionSelector string `json:"functionSelector"`
	} `json:"anchorContract"`
}

// =============================================================================
// COMMITMENT BUILDING
// =============================================================================

// FullExecutionCommitment contains all data needed to verify execution
type FullExecutionCommitment struct {
	// Identity
	IntentID    string   `json:"intent_id"`
	BundleID    [32]byte `json:"bundle_id"`
	OperationID [32]byte `json:"operation_id"`

	// Target chain info
	TargetChain string `json:"target_chain"`
	ChainID     int64  `json:"chain_id"`

	// Step 1: createAnchor commitment
	CreateAnchorCommitment *StepCommitment `json:"create_anchor"`

	// Step 2: executeComprehensiveProof commitment
	ExecuteProofCommitment *StepCommitment `json:"execute_proof"`

	// Step 3: executeWithGovernance commitment
	ExecuteGovernanceCommitment *StepCommitment `json:"execute_governance"`

	// Expected events
	ExpectedEvents []ExpectedEventCommitment `json:"expected_events"`

	// Final target (where ETH/tokens actually go)
	FinalTarget     common.Address `json:"final_target"`
	FinalValue      *big.Int       `json:"final_value"`
	FinalCallData   []byte         `json:"final_call_data"`

	// Commitment hash (computed from all above)
	CommitmentHash [32]byte `json:"commitment_hash"`
}

// StepCommitment represents commitment for a single execution step
type StepCommitment struct {
	StepNumber       int            `json:"step_number"`
	StepName         string         `json:"step_name"`
	TargetContract   common.Address `json:"target_contract"`
	FunctionSelector [4]byte        `json:"function_selector"`
	ExpectedValue    *big.Int       `json:"expected_value"`
	CallDataHash     [32]byte       `json:"call_data_hash"`
}

// ExpectedEventCommitment represents an expected event
type ExpectedEventCommitment struct {
	Contract   common.Address `json:"contract"`
	EventName  string         `json:"event_name"`
	Topic0     common.Hash    `json:"topic0"`
	// Indexed parameters to verify
	IndexedParams []common.Hash `json:"indexed_params,omitempty"`
}

// BuildFromIntent creates a FullExecutionCommitment from intent data
func (b *ExecutionCommitmentBuilder) BuildFromIntent(
	intentID string,
	bundleID [32]byte,
	crossChainDataJSON []byte,
	anchorContractAddress string,
) (*FullExecutionCommitment, error) {

	// Parse cross-chain data
	var crossChainData ParsedCrossChainData
	if err := json.Unmarshal(crossChainDataJSON, &crossChainData); err != nil {
		return nil, fmt.Errorf("parse crossChainData: %w", err)
	}

	if len(crossChainData.Legs) == 0 {
		return nil, fmt.Errorf("no legs in crossChainData")
	}

	// Use first leg for now (multi-leg support can be added later)
	leg := crossChainData.Legs[0]

	// Parse addresses
	anchorContract := common.HexToAddress(anchorContractAddress)
	if anchorContractAddress == "" && leg.AnchorContract.Address != "" {
		anchorContract = common.HexToAddress(leg.AnchorContract.Address)
	}

	finalTarget := common.HexToAddress(leg.To)

	// Parse value
	finalValue := big.NewInt(0)
	if leg.AmountWei != "" {
		var ok bool
		// Handle both string and scientific notation
		amountStr := strings.TrimSpace(leg.AmountWei)
		finalValue, ok = new(big.Int).SetString(amountStr, 10)
		if !ok {
			// Try parsing as float for scientific notation
			f, _, err := big.ParseFloat(amountStr, 10, 256, big.ToNearestEven)
			if err == nil {
				finalValue, _ = f.Int(nil)
			}
		}
	}

	commitment := &FullExecutionCommitment{
		IntentID:    intentID,
		BundleID:    bundleID,
		TargetChain: leg.Chain,
		ChainID:     int64(leg.ChainID),
		FinalTarget: finalTarget,
		FinalValue:  finalValue,
	}

	// Build Step 1: createAnchor commitment
	commitment.CreateAnchorCommitment = &StepCommitment{
		StepNumber:       1,
		StepName:         "createAnchor",
		TargetContract:   anchorContract,
		FunctionSelector: b.functionSelectors["createAnchor"],
		ExpectedValue:    big.NewInt(0), // createAnchor doesn't transfer ETH
	}

	// Build Step 2: executeComprehensiveProof commitment
	commitment.ExecuteProofCommitment = &StepCommitment{
		StepNumber:       2,
		StepName:         "executeComprehensiveProof",
		TargetContract:   anchorContract,
		FunctionSelector: b.functionSelectors["executeComprehensiveProof"],
		ExpectedValue:    big.NewInt(0), // proof verification doesn't transfer ETH
	}

	// Build Step 3: executeWithGovernance commitment
	commitment.ExecuteGovernanceCommitment = &StepCommitment{
		StepNumber:       3,
		StepName:         "executeWithGovernance",
		TargetContract:   anchorContract,
		FunctionSelector: b.functionSelectors["executeWithGovernance"],
		ExpectedValue:    finalValue, // This is where ETH is forwarded
	}

	// Build expected events
	commitment.ExpectedEvents = []ExpectedEventCommitment{
		{
			Contract:  anchorContract,
			EventName: "AnchorCreated",
			Topic0:    b.eventSignatures["AnchorCreated"],
			IndexedParams: []common.Hash{
				common.BytesToHash(bundleID[:]), // bundleId is indexed
			},
		},
		{
			Contract:  anchorContract,
			EventName: "ProofVerified",
			Topic0:    b.eventSignatures["ProofVerified"],
			IndexedParams: []common.Hash{
				common.BytesToHash(bundleID[:]), // bundleId is indexed
			},
		},
		{
			Contract:  anchorContract,
			EventName: "GovernanceExecuted",
			Topic0:    b.eventSignatures["GovernanceExecuted"],
			IndexedParams: []common.Hash{
				common.BytesToHash(bundleID[:]), // bundleId is indexed
			},
		},
	}

	// Compute commitment hash
	commitment.CommitmentHash = commitment.ComputeCommitmentHash()

	return commitment, nil
}

// ComputeCommitmentHash computes deterministic hash of the commitment
func (c *FullExecutionCommitment) ComputeCommitmentHash() [32]byte {
	data := make([]byte, 0, 512)

	// Version prefix for future compatibility
	data = append(data, []byte("CERTEN_EXEC_COMMITMENT_V1")...)

	// Identity
	data = append(data, []byte(c.IntentID)...)
	data = append(data, c.BundleID[:]...)

	// Target chain
	data = append(data, []byte(c.TargetChain)...)
	data = append(data, big.NewInt(c.ChainID).Bytes()...)

	// Step commitments
	if c.CreateAnchorCommitment != nil {
		hash := c.CreateAnchorCommitment.Hash()
		data = append(data, hash[:]...)
	}
	if c.ExecuteProofCommitment != nil {
		hash := c.ExecuteProofCommitment.Hash()
		data = append(data, hash[:]...)
	}
	if c.ExecuteGovernanceCommitment != nil {
		hash := c.ExecuteGovernanceCommitment.Hash()
		data = append(data, hash[:]...)
	}

	// Final target
	data = append(data, c.FinalTarget.Bytes()...)
	if c.FinalValue != nil {
		data = append(data, c.FinalValue.Bytes()...)
	}

	// Events
	for _, evt := range c.ExpectedEvents {
		data = append(data, evt.Contract.Bytes()...)
		data = append(data, evt.Topic0.Bytes()...)
	}

	return sha256.Sum256(data)
}

// Hash computes the hash of a step commitment
func (s *StepCommitment) Hash() [32]byte {
	data := make([]byte, 0, 128)
	data = append(data, byte(s.StepNumber))
	data = append(data, []byte(s.StepName)...)
	data = append(data, s.TargetContract.Bytes()...)
	data = append(data, s.FunctionSelector[:]...)
	if s.ExpectedValue != nil {
		data = append(data, s.ExpectedValue.Bytes()...)
	}
	data = append(data, s.CallDataHash[:]...)
	return sha256.Sum256(data)
}

// =============================================================================
// COMMITMENT VERIFICATION
// =============================================================================

// VerificationResult contains the result of commitment verification
type VerificationResult struct {
	Verified       bool                    `json:"verified"`
	Step1Verified  bool                    `json:"step1_verified"`
	Step2Verified  bool                    `json:"step2_verified"`
	Step3Verified  bool                    `json:"step3_verified"`
	EventsVerified bool                    `json:"events_verified"`
	Errors         []string                `json:"errors,omitempty"`
	Details        map[string]interface{}  `json:"details"`
}

// VerifyAgainstResults verifies the commitment against actual execution results
func (c *FullExecutionCommitment) VerifyAgainstResults(results []*ExternalChainResult) *VerificationResult {
	vr := &VerificationResult{
		Verified: true,
		Details:  make(map[string]interface{}),
	}

	if len(results) == 0 {
		vr.Verified = false
		vr.Errors = append(vr.Errors, "no execution results provided")
		return vr
	}

	// We expect 3 results for the 3-step workflow
	// But we may only have 1 result if using batched execution

	for _, result := range results {
		// Check chain ID matches
		if result.ChainID != c.ChainID {
			vr.Verified = false
			vr.Errors = append(vr.Errors, fmt.Sprintf("chain ID mismatch: expected %d, got %d", c.ChainID, result.ChainID))
		}

		// Check transaction succeeded
		if !result.IsSuccess() {
			vr.Verified = false
			vr.Errors = append(vr.Errors, fmt.Sprintf("transaction %s failed", result.TxHash.Hex()))
			continue
		}

		// Verify based on function selector
		if len(result.TxData) >= 4 {
			var actualSelector [4]byte
			copy(actualSelector[:], result.TxData[:4])

			// Check which step this result corresponds to
			if c.CreateAnchorCommitment != nil && actualSelector == c.CreateAnchorCommitment.FunctionSelector {
				vr.Step1Verified = c.verifyStep(result, c.CreateAnchorCommitment, vr)
			} else if c.ExecuteProofCommitment != nil && actualSelector == c.ExecuteProofCommitment.FunctionSelector {
				vr.Step2Verified = c.verifyStep(result, c.ExecuteProofCommitment, vr)
			} else if c.ExecuteGovernanceCommitment != nil && actualSelector == c.ExecuteGovernanceCommitment.FunctionSelector {
				vr.Step3Verified = c.verifyStep(result, c.ExecuteGovernanceCommitment, vr)

				// For governance step, also verify final target
				// The calldata should contain the target address
				if len(result.TxData) >= 68 { // 4 (selector) + 32 (bundleId) + 32 (address)
					// Extract target address from calldata (second parameter after bundleId)
					targetFromCalldata := common.BytesToAddress(result.TxData[36:68])
					if targetFromCalldata != c.FinalTarget {
						vr.Verified = false
						vr.Errors = append(vr.Errors, fmt.Sprintf("final target mismatch: expected %s, got %s",
							c.FinalTarget.Hex(), targetFromCalldata.Hex()))
					}
				}
			}
		}

		// Verify events
		vr.EventsVerified = c.verifyEvents(result, vr)
	}

	// Final verification status
	if !vr.Step1Verified || !vr.Step2Verified || !vr.Step3Verified {
		vr.Verified = false
	}

	return vr
}

// verifyStep verifies a single execution step
func (c *FullExecutionCommitment) verifyStep(result *ExternalChainResult, step *StepCommitment, vr *VerificationResult) bool {
	// Verify target contract
	if result.TxTo == nil || *result.TxTo != step.TargetContract {
		vr.Errors = append(vr.Errors, fmt.Sprintf("step %d: target contract mismatch", step.StepNumber))
		return false
	}

	// Verify function selector
	if len(result.TxData) < 4 {
		vr.Errors = append(vr.Errors, fmt.Sprintf("step %d: no function selector in tx data", step.StepNumber))
		return false
	}
	var actualSelector [4]byte
	copy(actualSelector[:], result.TxData[:4])
	if actualSelector != step.FunctionSelector {
		vr.Errors = append(vr.Errors, fmt.Sprintf("step %d: function selector mismatch: expected %x, got %x",
			step.StepNumber, step.FunctionSelector, actualSelector))
		return false
	}

	vr.Details[fmt.Sprintf("step%d_contract", step.StepNumber)] = step.TargetContract.Hex()
	vr.Details[fmt.Sprintf("step%d_selector", step.StepNumber)] = hex.EncodeToString(actualSelector[:])

	return true
}

// verifyEvents verifies expected events were emitted
func (c *FullExecutionCommitment) verifyEvents(result *ExternalChainResult, vr *VerificationResult) bool {
	if len(c.ExpectedEvents) == 0 {
		return true
	}

	eventsFound := make(map[string]bool)

	for _, log := range result.Logs {
		if len(log.Topics) == 0 {
			continue
		}

		// Check if this log matches any expected event
		for _, expected := range c.ExpectedEvents {
			if log.Address == expected.Contract && log.Topics[0] == expected.Topic0 {
				// Verify indexed parameters if specified
				if len(expected.IndexedParams) > 0 {
					allMatch := true
					for i, expectedParam := range expected.IndexedParams {
						if i+1 >= len(log.Topics) {
							allMatch = false
							break
						}
						if log.Topics[i+1] != expectedParam {
							allMatch = false
							break
						}
					}
					if allMatch {
						eventsFound[expected.EventName] = true
					}
				} else {
					eventsFound[expected.EventName] = true
				}
			}
		}
	}

	// Check all expected events were found
	allFound := true
	for _, expected := range c.ExpectedEvents {
		if !eventsFound[expected.EventName] {
			allFound = false
			vr.Errors = append(vr.Errors, fmt.Sprintf("expected event %s not found", expected.EventName))
		}
	}

	vr.Details["events_found"] = eventsFound
	return allFound
}

// =============================================================================
// CONVERSION TO LEGACY COMMITMENT
// =============================================================================

// ToLegacyCommitment converts to the legacy ExecutionCommitment format
// for backward compatibility with existing code
func (c *FullExecutionCommitment) ToLegacyCommitment() *ExecutionCommitment {
	legacy := &ExecutionCommitment{
		BundleID:    c.BundleID,
		TargetChain: c.TargetChain,
	}

	// Use the governance step as the primary commitment (it's the most important)
	if c.ExecuteGovernanceCommitment != nil {
		legacy.TargetContract = c.ExecuteGovernanceCommitment.TargetContract
		legacy.FunctionSelector = c.ExecuteGovernanceCommitment.FunctionSelector
		legacy.ExpectedValue = c.FinalValue
	}

	legacy.CommitmentHash = legacy.ComputeCommitmentHash()
	return legacy
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// GetFunctionSelector returns the function selector for a known function
func (b *ExecutionCommitmentBuilder) GetFunctionSelector(functionName string) ([4]byte, bool) {
	selector, ok := b.functionSelectors[functionName]
	return selector, ok
}

// GetEventSignature returns the event signature for a known event
func (b *ExecutionCommitmentBuilder) GetEventSignature(eventName string) (common.Hash, bool) {
	sig, ok := b.eventSignatures[eventName]
	return sig, ok
}
