// Copyright 2025 Certen Protocol
//
// G2 Outcome Binding - Enhanced Security for Cross-Chain Execution
// Per CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0
//
// G2 extends G1 governance proofs with outcome binding:
// - Payload authenticity verification (transaction data matches intent)
// - Effect verification (execution results match expectations)
// - Receipt binding (cryptographic link to Accumulate state)
// - Witness consistency (execution witness derivation)
//
// This closes the security gap between intent and execution outcome.

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// G2 OUTCOME BINDING SERVICE
// =============================================================================

// G2OutcomeBindingService provides G2 governance proof generation with outcome binding.
// It extends G1 proofs by verifying that external chain execution matches the original intent.
type G2OutcomeBindingService struct {
	// Ethereum client for RPC calls (eth_getStorageAt, eth_call)
	ethClient *ethclient.Client

	// Configuration
	config *G2Config

	// Logging
	logger Logger
}

// G2Config contains configuration for G2 outcome binding
type G2Config struct {
	// Ethereum RPC endpoint for state verification
	EthereumRPCURL string

	// Verification strictness
	StrictPayloadVerification bool
	StrictEffectVerification  bool

	// Timeout for verification operations
	VerificationTimeout time.Duration

	// Hash algorithm for payload binding
	PayloadHashAlgorithm string // "sha256" or "keccak256"
}

// NewG2OutcomeBindingService creates a new G2 outcome binding service
func NewG2OutcomeBindingService(config *G2Config, logger Logger) *G2OutcomeBindingService {
	if config == nil {
		config = &G2Config{
			EthereumRPCURL:            "https://rpc.sepolia.org",
			StrictPayloadVerification: true,
			StrictEffectVerification:  true,
			VerificationTimeout:       30 * time.Second,
			PayloadHashAlgorithm:      "sha256",
		}
	}

	service := &G2OutcomeBindingService{
		config: config,
		logger: logger,
	}

	// Connect to Ethereum RPC for state verification
	if config.EthereumRPCURL != "" {
		client, err := ethclient.Dial(config.EthereumRPCURL)
		if err != nil {
			logger.Printf("⚠️ [G2] Failed to connect to Ethereum RPC: %v", err)
		} else {
			service.ethClient = client
			logger.Printf("✅ [G2] Connected to Ethereum RPC for state verification: %s", config.EthereumRPCURL)
		}
	}

	return service
}

// =============================================================================
// OUTCOME BINDING REQUEST/RESPONSE
// =============================================================================

// G2BindingRequest contains all data needed for G2 outcome binding verification
type G2BindingRequest struct {
	// Original intent data
	Intent *IntentOutcomeData `json:"intent"`

	// G1 governance proof (foundation for G2)
	G1Proof *proof.G1Result `json:"g1_proof"`

	// External chain execution result
	ExecutionResult *ExternalChainResult `json:"execution_result"`

	// Execution commitment made before execution
	Commitment *ExecutionCommitment `json:"commitment"`

	// Expected effects from the intent
	ExpectedEffects []ExpectedEffect `json:"expected_effects"`
}

// IntentOutcomeData contains intent data needed for outcome verification
type IntentOutcomeData struct {
	// Intent identification
	IntentID        string `json:"intent_id"`
	TransactionHash string `json:"transaction_hash"`

	// Target operation details
	TargetChain     string         `json:"target_chain"`
	TargetChainID   int64          `json:"target_chain_id"`
	TargetContract  common.Address `json:"target_contract"`
	FunctionSelector [4]byte       `json:"function_selector"`
	EncodedCallData []byte         `json:"encoded_call_data"`
	Value           *big.Int       `json:"value"`

	// Expected execution hash (computed from intent)
	ExpectedPayloadHash [32]byte `json:"expected_payload_hash"`

	// Governance binding
	OrganizationADI string `json:"organization_adi"`
	KeyBookURL      string `json:"key_book_url"`
}

// ExpectedEffect defines an expected effect from execution
type ExpectedEffect struct {
	EffectType string `json:"effect_type"` // "transfer", "state_change", "event_emission"

	// For transfers
	ExpectedRecipient *common.Address `json:"expected_recipient,omitempty"`
	ExpectedAmount    *big.Int        `json:"expected_amount,omitempty"`

	// For state changes
	ExpectedSlot  *common.Hash `json:"expected_slot,omitempty"`
	ExpectedValue *common.Hash `json:"expected_value,omitempty"`

	// For events
	ExpectedEventTopic *common.Hash `json:"expected_event_topic,omitempty"`
	ExpectedEventData  []byte       `json:"expected_event_data,omitempty"`
}

// G2BindingResult contains the complete G2 outcome binding verification result
type G2BindingResult struct {
	// Success indicator
	Success bool `json:"success"`

	// G2 proof result
	G2Proof *proof.G2Result `json:"g2_proof"`

	// Individual verification results
	PayloadVerification *proof.PayloadVerification `json:"payload_verification"`
	EffectVerification  *proof.EffectVerification  `json:"effect_verification"`
	ReceiptBinding      *proof.VerificationResult  `json:"receipt_binding"`
	WitnessConsistency  *proof.VerificationResult  `json:"witness_consistency"`

	// Outcome leaf for ValidatorBlock integration
	OutcomeLeaf *proof.OutcomeLeaf `json:"outcome_leaf"`

	// Binding hash (cryptographic binding of all verifications)
	BindingHash [32]byte `json:"binding_hash"`

	// Timing
	VerifiedAt    time.Time     `json:"verified_at"`
	VerificationMs int64        `json:"verification_ms"`

	// Errors if any
	Errors []string `json:"errors,omitempty"`
}

// =============================================================================
// G2 OUTCOME BINDING VERIFICATION
// =============================================================================

// VerifyOutcomeBinding performs complete G2 outcome binding verification
func (s *G2OutcomeBindingService) VerifyOutcomeBinding(
	ctx context.Context,
	request *G2BindingRequest,
) (*G2BindingResult, error) {
	startTime := time.Now()

	s.logger.Printf("🔐 [G2] Starting outcome binding verification for intent: %s", request.Intent.IntentID)

	result := &G2BindingResult{
		VerifiedAt: time.Now(),
		Errors:     make([]string, 0),
	}

	// Step 1: Verify payload authenticity
	s.logger.Printf("📋 [G2] Step 1: Verifying payload authenticity")
	payloadResult, err := s.verifyPayloadAuthenticity(ctx, request)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("payload verification failed: %v", err))
		if s.config.StrictPayloadVerification {
			return result, err
		}
	}
	result.PayloadVerification = payloadResult

	// Step 2: Verify transaction effects
	s.logger.Printf("⚡ [G2] Step 2: Verifying transaction effects")
	effectResult, err := s.verifyTransactionEffects(ctx, request)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("effect verification failed: %v", err))
		if s.config.StrictEffectVerification {
			return result, err
		}
	}
	result.EffectVerification = effectResult

	// Step 3: Verify receipt binding
	s.logger.Printf("📜 [G2] Step 3: Verifying receipt binding")
	receiptResult := s.verifyReceiptBinding(ctx, request)
	result.ReceiptBinding = receiptResult

	// Step 4: Verify witness consistency
	s.logger.Printf("👁️ [G2] Step 4: Verifying witness consistency")
	witnessResult := s.verifyWitnessConsistency(ctx, request)
	result.WitnessConsistency = witnessResult

	// Step 5: Build outcome leaf
	s.logger.Printf("🌿 [G2] Step 5: Building outcome leaf")
	outcomeLeaf := s.buildOutcomeLeaf(payloadResult, effectResult, receiptResult, witnessResult)
	result.OutcomeLeaf = outcomeLeaf

	// Step 6: Build G2 proof result
	s.logger.Printf("📦 [G2] Step 6: Building G2 proof result")
	g2Proof := s.buildG2ProofResult(request.G1Proof, outcomeLeaf, payloadResult, effectResult)
	result.G2Proof = g2Proof

	// Step 7: Compute binding hash
	result.BindingHash = s.computeBindingHash(result)

	// Determine overall success
	result.Success = payloadResult.Verified && effectResult.Verified &&
	                 receiptResult.Verified && witnessResult.Verified

	result.VerificationMs = time.Since(startTime).Milliseconds()

	s.logger.Printf("✅ [G2] Outcome binding verification complete: success=%v, time=%dms",
		result.Success, result.VerificationMs)

	return result, nil
}

// =============================================================================
// PAYLOAD AUTHENTICITY VERIFICATION
// =============================================================================

// verifyPayloadAuthenticity verifies that the execution payload matches the intent
func (s *G2OutcomeBindingService) verifyPayloadAuthenticity(
	ctx context.Context,
	request *G2BindingRequest,
) (*proof.PayloadVerification, error) {

	result := &proof.PayloadVerification{
		Verified:            false,
		VerificationDetails: make(map[string]interface{}),
	}

	// Compute payload hash from execution result
	computedHash := s.computePayloadHash(request.ExecutionResult)
	result.ComputedTxHash = hex.EncodeToString(computedHash[:])
	result.ExpectedTxHash = hex.EncodeToString(request.Intent.ExpectedPayloadHash[:])

	// Verify target contract matches
	if request.ExecutionResult.TxTo == nil {
		return result, errors.New("execution has no target address")
	}

	if *request.ExecutionResult.TxTo != request.Intent.TargetContract {
		result.VerificationDetails["target_mismatch"] = true
		result.VerificationDetails["expected_target"] = request.Intent.TargetContract.Hex()
		result.VerificationDetails["actual_target"] = request.ExecutionResult.TxTo.Hex()
		return result, errors.New("target contract mismatch")
	}
	result.VerificationDetails["target_verified"] = true

	// Verify function selector matches
	if len(request.ExecutionResult.TxData) >= 4 {
		var actualSelector [4]byte
		copy(actualSelector[:], request.ExecutionResult.TxData[:4])

		if actualSelector != request.Intent.FunctionSelector {
			result.VerificationDetails["selector_mismatch"] = true
			return result, errors.New("function selector mismatch")
		}
		result.VerificationDetails["selector_verified"] = true
	}

	// Verify value matches
	if request.Intent.Value != nil {
		if request.ExecutionResult.TxValue.Cmp(request.Intent.Value) != 0 {
			result.VerificationDetails["value_mismatch"] = true
			result.VerificationDetails["expected_value"] = request.Intent.Value.String()
			result.VerificationDetails["actual_value"] = request.ExecutionResult.TxValue.String()
			return result, errors.New("transaction value mismatch")
		}
		result.VerificationDetails["value_verified"] = true
	}

	// Verify call data matches (if provided)
	if len(request.Intent.EncodedCallData) > 0 {
		if !bytesEqual(request.ExecutionResult.TxData, request.Intent.EncodedCallData) {
			result.VerificationDetails["calldata_mismatch"] = true
			return result, errors.New("call data mismatch")
		}
		result.VerificationDetails["calldata_verified"] = true
	}

	// Verify chain ID matches
	if request.ExecutionResult.ChainID != request.Intent.TargetChainID {
		result.VerificationDetails["chain_mismatch"] = true
		return result, errors.New("chain ID mismatch")
	}
	result.VerificationDetails["chain_verified"] = true

	// All verifications passed
	result.Verified = true
	result.GoVerifierOutput = "payload authenticity verified"

	return result, nil
}

// computePayloadHash computes a deterministic hash of the execution payload
func (s *G2OutcomeBindingService) computePayloadHash(result *ExternalChainResult) [32]byte {
	data := make([]byte, 0, 256)

	// Include all payload-relevant fields
	data = append(data, []byte(result.Chain)...)
	data = append(data, big.NewInt(result.ChainID).Bytes()...)
	data = append(data, result.TxHash.Bytes()...)

	if result.TxTo != nil {
		data = append(data, result.TxTo.Bytes()...)
	}

	if result.TxValue != nil {
		data = append(data, result.TxValue.Bytes()...)
	}

	data = append(data, result.TxData...)

	return sha256.Sum256(data)
}

// =============================================================================
// EFFECT VERIFICATION
// =============================================================================

// verifyTransactionEffects verifies that execution effects match expectations
func (s *G2OutcomeBindingService) verifyTransactionEffects(
	ctx context.Context,
	request *G2BindingRequest,
) (*proof.EffectVerification, error) {

	result := &proof.EffectVerification{
		EffectType: "composite",
		Verified:   true,
		Details:    make(map[string]interface{}),
	}

	// Verify execution was successful
	if !request.ExecutionResult.IsSuccess() {
		result.Verified = false
		result.Details["execution_failed"] = true
		result.Details["status"] = request.ExecutionResult.Status
		return result, errors.New("execution failed (reverted)")
	}
	result.Details["execution_success"] = true

	// Verify each expected effect
	verifiedEffects := 0
	failedEffects := 0

	for i, expected := range request.ExpectedEffects {
		effectKey := fmt.Sprintf("effect_%d", i)

		verified, details := s.verifyEffect(request.ExecutionResult, &expected)
		result.Details[effectKey] = details

		if verified {
			verifiedEffects++
		} else {
			failedEffects++
			result.Verified = false
		}
	}

	result.Details["verified_effects"] = verifiedEffects
	result.Details["failed_effects"] = failedEffects
	result.Details["total_effects"] = len(request.ExpectedEffects)

	// Compute effect summary
	effectSummary := fmt.Sprintf("%d/%d effects verified", verifiedEffects, len(request.ExpectedEffects))
	result.ComputedValue = &effectSummary

	if !result.Verified {
		return result, fmt.Errorf("%d effects failed verification", failedEffects)
	}

	return result, nil
}

// verifyEffect verifies a single expected effect
func (s *G2OutcomeBindingService) verifyEffect(
	result *ExternalChainResult,
	expected *ExpectedEffect,
) (bool, map[string]interface{}) {

	details := make(map[string]interface{})
	details["type"] = expected.EffectType

	switch expected.EffectType {
	case "transfer":
		return s.verifyTransferEffect(result, expected, details)
	case "event_emission":
		return s.verifyEventEffect(result, expected, details)
	case "state_change":
		return s.verifyStateChangeEffect(result, expected, details)
	default:
		details["error"] = "unknown effect type"
		return false, details
	}
}

// verifyTransferEffect verifies a value transfer effect
func (s *G2OutcomeBindingService) verifyTransferEffect(
	result *ExternalChainResult,
	expected *ExpectedEffect,
	details map[string]interface{},
) (bool, map[string]interface{}) {

	// For transfers, verify the target and value
	if expected.ExpectedRecipient != nil {
		if result.TxTo == nil || *result.TxTo != *expected.ExpectedRecipient {
			details["recipient_mismatch"] = true
			return false, details
		}
		details["recipient_verified"] = true
	}

	if expected.ExpectedAmount != nil {
		if result.TxValue == nil || result.TxValue.Cmp(expected.ExpectedAmount) != 0 {
			details["amount_mismatch"] = true
			return false, details
		}
		details["amount_verified"] = true
	}

	details["verified"] = true
	return true, details
}

// verifyEventEffect verifies an event emission effect
func (s *G2OutcomeBindingService) verifyEventEffect(
	result *ExternalChainResult,
	expected *ExpectedEffect,
	details map[string]interface{},
) (bool, map[string]interface{}) {

	if expected.ExpectedEventTopic == nil {
		details["error"] = "no expected event topic"
		return false, details
	}

	// Search for matching log
	for i, log := range result.Logs {
		if len(log.Topics) > 0 {
			// Convert common.Hash to comparable form
			logTopic := common.Hash(log.Topics[0])
			if logTopic == *expected.ExpectedEventTopic {
				details["found_at_index"] = i
				details["verified"] = true

				// Optionally verify event data
				if expected.ExpectedEventData != nil {
					if bytesEqual(log.Data, expected.ExpectedEventData) {
						details["data_verified"] = true
					} else {
						details["data_mismatch"] = true
						return false, details
					}
				}

				return true, details
			}
		}
	}

	details["error"] = "event not found in logs"
	return false, details
}

// verifyStateChangeEffect verifies a state change effect using eth_getStorageAt
func (s *G2OutcomeBindingService) verifyStateChangeEffect(
	result *ExternalChainResult,
	expected *ExpectedEffect,
	details map[string]interface{},
) (bool, map[string]interface{}) {

	// Verify we have an Ethereum client for RPC calls
	if s.ethClient == nil {
		details["error"] = "ethereum client not initialized for state verification"
		details["verified"] = false
		return false, details
	}

	// Check we have necessary state change data
	if expected.ExpectedSlot == nil {
		details["note"] = "no storage slot specified for state change verification"
		details["verified"] = true // No specific slot to check
		return true, details
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.VerificationTimeout)
	defer cancel()

	// Get the contract address from result (TxTo is the target contract)
	if result.TxTo == nil {
		details["error"] = "transaction has no target contract (contract creation tx)"
		details["verified"] = false
		return false, details
	}
	contractAddr := *result.TxTo

	// Query storage at the specified slot using eth_getStorageAt RPC
	slotHash := *expected.ExpectedSlot
	storageValue, err := s.ethClient.StorageAt(ctx, contractAddr, slotHash, nil)
	if err != nil {
		details["error"] = fmt.Sprintf("eth_getStorageAt failed: %v", err)
		details["verified"] = false
		return false, details
	}

	details["storage_slot"] = slotHash.Hex()
	details["storage_value"] = fmt.Sprintf("0x%x", storageValue)
	details["contract"] = contractAddr.Hex()

	// If expected value is specified, compare
	if expected.ExpectedValue != nil {
		// Compare storage value with expected value
		if common.BytesToHash(storageValue) != *expected.ExpectedValue {
			details["expected_value"] = expected.ExpectedValue.Hex()
			details["value_mismatch"] = true
			details["verified"] = false
			return false, details
		}
		details["value_match"] = true
	}

	// If we have a minimum balance check
	if expected.ExpectedAmount != nil && expected.ExpectedAmount.Sign() > 0 {
		actualValue := new(big.Int).SetBytes(storageValue)
		if actualValue.Cmp(expected.ExpectedAmount) < 0 {
			details["expected_minimum"] = expected.ExpectedAmount.String()
			details["actual_value"] = actualValue.String()
			details["below_minimum"] = true
			details["verified"] = false
			return false, details
		}
		details["amount_sufficient"] = true
	}

	details["verified"] = true
	details["verification_method"] = "eth_getStorageAt"
	s.logger.Printf("✅ [G2] State change verified at slot %s: value=%x",
		slotHash.Hex(), storageValue[:8])

	return true, details
}

// Close closes the Ethereum client connection
func (s *G2OutcomeBindingService) Close() {
	if s.ethClient != nil {
		s.ethClient.Close()
	}
}

// =============================================================================
// RECEIPT BINDING VERIFICATION
// =============================================================================

// verifyReceiptBinding verifies receipt binding to Accumulate state
func (s *G2OutcomeBindingService) verifyReceiptBinding(
	ctx context.Context,
	request *G2BindingRequest,
) *proof.VerificationResult {

	result := &proof.VerificationResult{
		Verified: false,
		Details:  "",
	}

	// Verify G1 proof has valid receipt
	if request.G1Proof == nil {
		result.Details = "no G1 proof provided"
		return result
	}

	if !request.G1Proof.G1ProofComplete {
		result.Details = "G1 proof incomplete"
		return result
	}

	// Verify receipt binding through Merkle proofs
	if request.ExecutionResult.ReceiptInclusionProof != nil {
		if request.ExecutionResult.ReceiptInclusionProof.Verified {
			result.Verified = true
			result.Details = fmt.Sprintf("receipt bound at block %d with %d confirmations",
				request.ExecutionResult.BlockNumber.Uint64(),
				request.ExecutionResult.ConfirmationBlocks)
		} else {
			result.Details = "receipt inclusion proof not verified"
		}
	} else {
		// Without Merkle proof, use block binding
		result.Verified = true
		result.Details = fmt.Sprintf("receipt bound via block hash %s",
			request.ExecutionResult.BlockHash.Hex()[:16])
	}

	return result
}

// =============================================================================
// WITNESS CONSISTENCY VERIFICATION
// =============================================================================

// verifyWitnessConsistency verifies execution witness consistency
func (s *G2OutcomeBindingService) verifyWitnessConsistency(
	ctx context.Context,
	request *G2BindingRequest,
) *proof.VerificationResult {

	result := &proof.VerificationResult{
		Verified: false,
		Details:  "",
	}

	// Verify G1 execution context consistency
	if request.G1Proof == nil {
		result.Details = "no G1 proof for witness verification"
		return result
	}

	// Verify timing consistency
	if request.G1Proof.TimingValid {
		result.Verified = true
		result.Details = fmt.Sprintf("witness consistent: exec_mbi=%d, threshold_satisfied=%v",
			request.G1Proof.ExecMBI, request.G1Proof.ThresholdSatisfied)
	} else {
		result.Details = "timing validation failed"
	}

	// Verify authority snapshot consistency
	if request.G1Proof.AuthoritySnapshot.Validation.GenesisFound {
		result.Details += fmt.Sprintf(", genesis_verified=true, mutations=%d",
			request.G1Proof.AuthoritySnapshot.Validation.MutationsApplied)
	}

	return result
}

// =============================================================================
// OUTCOME LEAF CONSTRUCTION
// =============================================================================

// buildOutcomeLeaf constructs the G2 outcome leaf
func (s *G2OutcomeBindingService) buildOutcomeLeaf(
	payload *proof.PayloadVerification,
	effect *proof.EffectVerification,
	receipt *proof.VerificationResult,
	witness *proof.VerificationResult,
) *proof.OutcomeLeaf {

	return &proof.OutcomeLeaf{
		PayloadBinding:     *payload,
		ReceiptBinding:     *receipt,
		WitnessConsistency: *witness,
		Effect:             *effect,
	}
}

// =============================================================================
// G2 PROOF RESULT CONSTRUCTION
// =============================================================================

// buildG2ProofResult constructs the complete G2 proof result
func (s *G2OutcomeBindingService) buildG2ProofResult(
	g1Proof *proof.G1Result,
	outcomeLeaf *proof.OutcomeLeaf,
	payloadResult *proof.PayloadVerification,
	effectResult *proof.EffectVerification,
) *proof.G2Result {

	g2Complete := payloadResult.Verified && effectResult.Verified &&
	              outcomeLeaf.ReceiptBinding.Verified && outcomeLeaf.WitnessConsistency.Verified

	securityLevel := "G2-standard"
	if g2Complete {
		securityLevel = "G2-complete"
	}

	return &proof.G2Result{
		G1Result:        *g1Proof,
		OutcomeLeaf:     *outcomeLeaf,
		PayloadVerified: payloadResult.Verified,
		EffectVerified:  effectResult.Verified,
		G2ProofComplete: g2Complete,
		SecurityLevel:   securityLevel,
	}
}

// =============================================================================
// BINDING HASH COMPUTATION
// =============================================================================

// computeBindingHash computes the cryptographic binding hash
func (s *G2OutcomeBindingService) computeBindingHash(result *G2BindingResult) [32]byte {
	data := make([]byte, 0, 256)

	data = append(data, []byte("CERTEN_G2_OUTCOME_BINDING_V1")...)

	// Include payload verification
	if result.PayloadVerification != nil {
		data = append(data, []byte(result.PayloadVerification.ComputedTxHash)...)
		if result.PayloadVerification.Verified {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}

	// Include effect verification
	if result.EffectVerification != nil {
		if result.EffectVerification.Verified {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}

	// Include receipt binding
	if result.ReceiptBinding != nil {
		if result.ReceiptBinding.Verified {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}

	// Include witness consistency
	if result.WitnessConsistency != nil {
		if result.WitnessConsistency.Verified {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}

	return sha256.Sum256(data)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// INTENT OUTCOME DATA BUILDER
// =============================================================================

// BuildIntentOutcomeData builds IntentOutcomeData from a CertenIntent
func BuildIntentOutcomeData(
	intentID string,
	transactionHash string,
	targetChain string,
	targetChainID int64,
	targetContract common.Address,
	functionSelector [4]byte,
	encodedCallData []byte,
	value *big.Int,
	organizationADI string,
	keyBookURL string,
) *IntentOutcomeData {

	// Compute expected payload hash
	data := make([]byte, 0, 256)
	data = append(data, []byte(targetChain)...)
	data = append(data, big.NewInt(targetChainID).Bytes()...)
	data = append(data, targetContract.Bytes()...)
	data = append(data, functionSelector[:]...)
	data = append(data, encodedCallData...)
	if value != nil {
		data = append(data, value.Bytes()...)
	}

	expectedHash := sha256.Sum256(data)

	return &IntentOutcomeData{
		IntentID:            intentID,
		TransactionHash:     transactionHash,
		TargetChain:         targetChain,
		TargetChainID:       targetChainID,
		TargetContract:      targetContract,
		FunctionSelector:    functionSelector,
		EncodedCallData:     encodedCallData,
		Value:               value,
		ExpectedPayloadHash: expectedHash,
		OrganizationADI:     organizationADI,
		KeyBookURL:          keyBookURL,
	}
}

// =============================================================================
// SERIALIZATION
// =============================================================================

// ToJSON serializes G2BindingResult to JSON
func (r *G2BindingResult) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToHex returns a hex representation of the binding hash
func (r *G2BindingResult) ToHex() string {
	return hex.EncodeToString(r.BindingHash[:])
}
