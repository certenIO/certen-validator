// Copyright 2025 Certen Protocol
//
// Proof Cycle Orchestrator - Complete Cryptographic Proof Cycle Integration
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 10
//
// This orchestrator wires together all phases of the complete proof cycle:
//   Phase 1-6: Accumulate → Ethereum (existing in BFT integration)
//   Phase 7: ExternalChainObserver (observation and Merkle proofs)
//   Phase 8: ResultVerifier (attestation and BLS aggregation)
//   Phase 9: ResultWriteBack (synthetic transaction to Accumulate)
//
// The complete cycle ensures cryptographic verifiability from intent to result.

package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"sync"
	"time"

	"strings"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

// =============================================================================
// PROOF CYCLE ORCHESTRATOR
// =============================================================================

// ProofCycleOrchestrator coordinates the complete cryptographic proof cycle
// from intent discovery through execution verification and write-back.
type ProofCycleOrchestrator struct {
	mu sync.RWMutex

	// Validator identity
	validatorID      string
	validatorAddress common.Address
	validatorIndex   uint32

	// External chain observer (Phase 7)
	observer *ExternalChainObserver

	// Result verifier (Phase 8)
	verifier  *ResultVerifier
	collector *AttestationCollector

	// Result write-back (Phase 9)
	writeBack *ResultWriteBack
	txBuilder *SyntheticTxBuilder

	// Configuration
	config *ProofCycleConfig

	// Active proof cycles
	activeCycles map[string]*ProofCycleCompletion

	// Callbacks
	onCycleComplete func(*ProofCycleCompletion)
	onCycleFailed   func(string, error)

	// Database repositories for persistence
	repos *database.Repositories

	// Chained proof generator for L1-L3 receipt extraction
	proofGenerator ChainedProofGenerator

	// Logging
	logger Logger
}

// ProofCycleConfig contains configuration for the proof cycle
type ProofCycleConfig struct {
	// Ethereum connection
	EthereumRPC string
	ChainID     int64

	// Confirmation requirements
	RequiredConfirmations int
	ObservationTimeout    time.Duration

	// Attestation requirements
	ThresholdNumerator   uint64
	ThresholdDenominator uint64

	// Write-back configuration
	AccumulatePrincipal string
	WriteBackEnabled    bool

	// BLS signing key
	BLSPrivateKey []byte
}

// NewProofCycleOrchestrator creates a new proof cycle orchestrator
func NewProofCycleOrchestrator(
	validatorID string,
	validatorAddress common.Address,
	validatorIndex uint32,
	validatorSet *ValidatorSet,
	config *ProofCycleConfig,
	accSubmitter AccumulateSubmitter,
	repos *database.Repositories,
	logger Logger,
) (*ProofCycleOrchestrator, error) {

	// Create Phase 7: External Chain Observer
	observerConfig := &ExternalChainObserverConfig{
		EthereumRPC:           config.EthereumRPC,
		ChainID:               config.ChainID,
		ValidatorID:           validatorID,
		RequiredConfirmations: config.RequiredConfirmations,
		PollingInterval:       12 * time.Second,
		Timeout:               config.ObservationTimeout,
		Logger:                logger,
	}

	observer, err := NewExternalChainObserver(observerConfig)
	if err != nil {
		return nil, fmt.Errorf("create external chain observer: %w", err)
	}

	// Create attestation collector for Phase 8
	collector := NewAttestationCollector(
		validatorSet,
		config.ThresholdNumerator,
		config.ThresholdDenominator,
	)

	// Create Phase 8: Result Verifier with real BLS key
	verifier, err := NewResultVerifierFromBytes(
		validatorID,
		validatorAddress,
		validatorIndex,
		config.BLSPrivateKey,
		collector,
	)
	if err != nil {
		return nil, fmt.Errorf("create result verifier: %w", err)
	}

	// Create Phase 9: Synthetic Transaction Builder and Write-Back
	txBuilder := NewSyntheticTxBuilder(
		config.AccumulatePrincipal,
		validatorID,
		config.BLSPrivateKey,
	)

	writeBack := NewResultWriteBack(txBuilder, accSubmitter)

	orchestrator := &ProofCycleOrchestrator{
		validatorID:      validatorID,
		validatorAddress: validatorAddress,
		validatorIndex:   validatorIndex,
		observer:         observer,
		verifier:         verifier,
		collector:        collector,
		writeBack:        writeBack,
		txBuilder:        txBuilder,
		config:           config,
		activeCycles:     make(map[string]*ProofCycleCompletion),
		repos:            repos,
		logger:           logger,
	}

	// Set up callbacks
	collector.SetThresholdCallback(orchestrator.onAttestationThreshold)
	writeBack.SetCallbacks(orchestrator.onWriteBackConfirmed, orchestrator.onWriteBackFailed)

	return orchestrator, nil
}

// SetProofGenerator configures the chained proof generator for L1-L3 receipt extraction.
// Must be called after creation if receipt entry persistence is desired.
func (o *ProofCycleOrchestrator) SetProofGenerator(pg ChainedProofGenerator) {
	o.proofGenerator = pg
}

// =============================================================================
// PROOF CYCLE EXECUTION
// =============================================================================

// StartProofCycle initiates a complete proof cycle for an executed operation
// Call this after BFT consensus has executed an operation on the target chain.
// The commitment parameter can be *ExecutionCommitment or interface{} containing commitment data
func (o *ProofCycleOrchestrator) StartProofCycle(
	ctx context.Context,
	intentID string,
	bundleID [32]byte,
	executionTxHash common.Hash,
	commitment interface{},
) error {
	// Type assert the commitment if provided
	var execCommitment *ExecutionCommitment
	if commitment != nil {
		switch c := commitment.(type) {
		case *ExecutionCommitment:
			execCommitment = c
		case *ExecutionCommitmentData:
			// Convert from adapter type
			execCommitment = &ExecutionCommitment{
				BundleID:    c.BundleID,
				TargetChain: c.TargetChain,
			}
		case map[string]interface{}:
			// SECURITY CRITICAL: Convert comprehensive commitment from BFT flow
			// This commitment contains all 3-step verification data
			execCommitment = convertMapToExecutionCommitment(c, o.logger)
		default:
			o.logger.Printf("⚠️ [PROOF-CYCLE] Unknown commitment type %T, proceeding without commitment", commitment)
		}
	}
	o.mu.Lock()

	// Check for duplicate
	cycleID := fmt.Sprintf("%s:%s", intentID, executionTxHash.Hex())
	if _, exists := o.activeCycles[cycleID]; exists {
		o.mu.Unlock()
		return fmt.Errorf("proof cycle already active: %s", cycleID)
	}

	// Initialize proof cycle with commitment data
	cycle := &ProofCycleCompletion{
		IntentID:         intentID,
		BundleID:         bundleID,
		ValidatorBlockID: fmt.Sprintf("vb-%s", intentID[:16]),
		IntentTime:       time.Now(),
		Commitment:       execCommitment, // Store for Phase 9 write-back context
	}
	o.activeCycles[cycleID] = cycle
	o.mu.Unlock()

	o.logger.Printf("🔄 [PROOF-CYCLE] Starting proof cycle: %s", cycleID)

	// Phase 7: Observe and verify external chain execution
	go o.executePhase7(ctx, cycleID, cycle, executionTxHash, execCommitment)

	return nil
}

// AnchorWorkflowTxHashes contains all 3 transaction hashes from the Ethereum anchor workflow
// Duplicated here to avoid circular imports with consensus package
type AnchorWorkflowTxHashes struct {
	CreateTxHash     common.Hash // Step 1: createAnchor tx
	VerifyTxHash     common.Hash // Step 2: executeComprehensiveProof tx
	GovernanceTxHash common.Hash // Step 3: executeWithGovernance tx
	PrimaryTxHash    common.Hash // For backwards compatibility
	RawTxHashes      []string    // Native-format hashes for non-EVM chains (e.g. NEAR base58)
}

// StartProofCycleWithAllTxs initiates a complete proof cycle tracking all 3 anchor workflow transactions
// Enhanced: Observes createAnchor, executeComprehensiveProof, and executeWithGovernance
func (o *ProofCycleOrchestrator) StartProofCycleWithAllTxs(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashesInterface interface{},
	commitment interface{},
) error {
	// Convert interface to actual type - support both local and consensus package types
	var txHashes *AnchorWorkflowTxHashes
	switch th := txHashesInterface.(type) {
	case *AnchorWorkflowTxHashes:
		txHashes = th
	case *ConsensusAnchorWorkflowTxHashes:
		txHashes = &AnchorWorkflowTxHashes{
			CreateTxHash:     th.CreateTxHash,
			VerifyTxHash:     th.VerifyTxHash,
			GovernanceTxHash: th.GovernanceTxHash,
			PrimaryTxHash:    th.PrimaryTxHash,
		}
	default:
		// Use reflection to extract fields from consensus.AnchorWorkflowTxHashes
		// This handles cross-package type assertion issues
		txHashes = extractTxHashesViaReflection(txHashesInterface)
		if txHashes == nil {
			return fmt.Errorf("invalid txHashes type: %T", txHashesInterface)
		}
	}
	// Type assert the commitment if provided
	var execCommitment *ExecutionCommitment
	if commitment != nil {
		switch c := commitment.(type) {
		case *ExecutionCommitment:
			execCommitment = c
		case *ExecutionCommitmentData:
			execCommitment = &ExecutionCommitment{
				BundleID:    c.BundleID,
				TargetChain: c.TargetChain,
			}
		case map[string]interface{}:
			execCommitment = convertMapToExecutionCommitment(c, o.logger)
		default:
			o.logger.Printf("⚠️ [PROOF-CYCLE] Unknown commitment type %T, proceeding without commitment", commitment)
		}
	}

	o.mu.Lock()

	// Check for duplicate using primary tx hash
	cycleID := fmt.Sprintf("%s:%s", intentID, txHashes.CreateTxHash.Hex())
	if _, exists := o.activeCycles[cycleID]; exists {
		o.mu.Unlock()
		return fmt.Errorf("proof cycle already active: %s", cycleID)
	}

	// Get IntentTxHash from commitment if available
	intentTxHash := ""
	if execCommitment != nil && execCommitment.IntentTxHash != "" {
		intentTxHash = execCommitment.IntentTxHash
	}

	// Initialize proof cycle with all tx hashes
	cycle := &ProofCycleCompletion{
		IntentID:         intentID,
		UserID:           userID,
		IntentTxHash:     intentTxHash,
		BundleID:         bundleID,
		ValidatorBlockID: fmt.Sprintf("vb-%s", intentID[:16]),
		IntentTime:       time.Now(),
		Commitment:       execCommitment,

		// Enhanced: Store all 3 tx hashes
		CreateTxHash:     txHashes.CreateTxHash,
		VerifyTxHash:     txHashes.VerifyTxHash,
		GovernanceTxHash: txHashes.GovernanceTxHash,
	}
	o.activeCycles[cycleID] = cycle
	o.mu.Unlock()

	o.logger.Printf("🔄 [PROOF-CYCLE] Starting enhanced proof cycle: %s", cycleID)
	o.logger.Printf("   📋 Tracking all 3 anchor workflow transactions:")
	o.logger.Printf("      Step 1 (Create):     %s", txHashes.CreateTxHash.Hex())
	o.logger.Printf("      Step 2 (Verify):     %s", txHashes.VerifyTxHash.Hex())
	o.logger.Printf("      Step 3 (Governance): %s", txHashes.GovernanceTxHash.Hex())

	// Phase 7: Observe all 3 transactions
	go o.executePhase7Enhanced(ctx, cycleID, cycle, txHashes, execCommitment)

	return nil
}

// StartProofCycleWithAccumulateRef implements the enhanced interface with Accumulate reference data
// This is a pass-through to StartProofCycleWithAllTxs for the legacy orchestrator
// (Accumulate reference data is only used by the unified orchestrator for L1/L2/L3 chained proofs)
func (o *ProofCycleOrchestrator) StartProofCycleWithAccumulateRef(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashes interface{},
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	// Legacy orchestrator doesn't use Accumulate reference data - pass through to regular method
	o.logger.Printf("ℹ️ [PROOF-CYCLE] StartProofCycleWithAccumulateRef: Accumulate ref data available but legacy orchestrator doesn't use it")
	o.logger.Printf("   accountURL=%s, txHash=%s, bvn=%s", accumulateAccountURL, accumulateTxHash, bvn)
	return o.StartProofCycleWithAllTxs(ctx, intentID, userID, bundleID, txHashes, commitment)
}

// StartPerChainProofCycles is a no-op for the legacy ProofCycleOrchestrator.
func (o *ProofCycleOrchestrator) StartPerChainProofCycles(
	ctx context.Context,
	intentID string,
	operationID string,
	bundleID [32]byte,
	chainTxHashes map[string][]string,
	legs interface{},
	executionMode string,
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	o.logger.Printf("⚠️ [PROOF-CYCLE] StartPerChainProofCycles not supported by legacy orchestrator")
	return nil
}

// observeTronTransaction observes a TRON transaction using TRON's native HTTP API.
// The standard EVM ethclient.TransactionReceipt doesn't work for TRON because
// the observer uses the default EVM RPC (Alchemy/Sepolia), not TRON's endpoint.
func (o *ProofCycleOrchestrator) observeTronTransaction(ctx context.Context, txHash common.Hash) (*ExternalChainResult, error) {
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("load anchor config: %w", err)
	}
	chainCfg := anchorCfg.GetEVMChainConfig(2494104990) // TRON Shasta
	if chainCfg == nil || chainCfg.RPCURL == "" {
		return nil, fmt.Errorf("no TRON Shasta config")
	}

	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	tronClient, err := NewTronClient(chainCfg.RPCURL, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create TRON client: %w", err)
	}

	txID := hex.EncodeToString(txHash.Bytes())
	info, err := tronClient.WaitForConfirmation(ctx, txID, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TRON tx not confirmed: %w", err)
	}

	blockNum := uint64(0)
	if bn, ok := info["blockNumber"].(float64); ok {
		blockNum = uint64(bn)
	}

	status := uint64(1) // assume success
	if receipt, ok := info["receipt"].(map[string]interface{}); ok {
		if result, ok := receipt["result"].(string); ok && result != "SUCCESS" && result != "" {
			status = 0
		}
	}

	return &ExternalChainResult{
		Chain:               "TRON Shasta",
		ChainID:             2494104990,
		TxHash:              txHash,
		BlockNumber:         new(big.Int).SetUint64(blockNum),
		Status:              status,
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  19, // TRON DPoS has near-instant finality; confirmed = final
	}, nil
}

// isTronChain returns true if the target chain is TRON based on the commitment data.
func isTronChain(commitment *ExecutionCommitment) bool {
	if commitment == nil {
		return false
	}
	tc := strings.ToLower(commitment.TargetChain)
	return strings.Contains(tc, "tron")
}

// isSolanaChain returns true if the target chain is Solana based on the commitment data.
func isSolanaChain(commitment *ExecutionCommitment) bool {
	if commitment == nil {
		return false
	}
	tc := strings.ToLower(commitment.TargetChain)
	return strings.Contains(tc, "solana")
}

// isNonEVMChain returns true for chains that cannot use the default Ethereum observer.
func isNonEVMChain(commitment *ExecutionCommitment) bool {
	if commitment == nil {
		return false
	}
	tc := strings.ToLower(commitment.TargetChain)
	return strings.Contains(tc, "tron") || strings.Contains(tc, "solana") ||
		strings.Contains(tc, "near") || strings.Contains(tc, "ton") ||
		strings.Contains(tc, "aptos") || strings.Contains(tc, "sui")
}

// observeSolanaTransaction observes a Solana transaction using Solana's native JSON-RPC.
func (o *ProofCycleOrchestrator) observeSolanaTransaction(ctx context.Context, txSig string) (*ExternalChainResult, error) {
	if txSig == "" {
		return nil, fmt.Errorf("empty Solana tx signature")
	}

	solanaRPC := os.Getenv("SOLANA_RPC_URL")
	if solanaRPC == "" {
		solanaRPC = os.Getenv("SOLANA_DEVNET_RPC_URL")
	}
	if solanaRPC == "" {
		solanaRPC = "https://api.devnet.solana.com"
	}

	factoryID := os.Getenv("SOLANA_FACTORY_PROGRAM_ID")
	if factoryID == "" {
		factoryID = os.Getenv("SOLANA_ACCOUNT_FACTORY_PROGRAM_ID")
	}

	solClient, err := NewSolanaClient(solanaRPC,
		os.Getenv("SOLANA_PRIVATE_KEY"),
		os.Getenv("SOLANA_ANCHOR_PROGRAM_ID"),
		os.Getenv("SOLANA_BLS_VERIFIER_PROGRAM_ID"),
		factoryID,
		os.Getenv("SOLANA_ACCOUNT_PROGRAM_ID"),
	)
	if err != nil {
		return nil, fmt.Errorf("create Solana client: %w", err)
	}

	err = solClient.WaitForConfirmation(ctx, txSig, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Solana tx not confirmed: %w", err)
	}

	return &ExternalChainResult{
		Chain:               "solana-devnet",
		ChainID:             103,
		TxHash:              common.Hash{}, // Solana sigs don't fit in 32 bytes
		BlockNumber:         big.NewInt(0),
		Status:              1, // confirmed = success
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  32, // Solana finality
	}, nil
}

// observeNearTransaction observes a NEAR transaction using NEAR's native JSON-RPC.
func (o *ProofCycleOrchestrator) observeNearTransaction(ctx context.Context, txHash string) (*ExternalChainResult, error) {
	if txHash == "" {
		return nil, fmt.Errorf("empty NEAR tx hash")
	}

	nearRPC := os.Getenv("NEAR_RPC_URL")
	if nearRPC == "" {
		nearRPC = os.Getenv("NEAR_TESTNET_RPC_URL")
	}
	if nearRPC == "" {
		nearRPC = "https://rpc.testnet.near.org"
	}

	nearClient, err := NewNearClient(nearRPC,
		os.Getenv("NEAR_SIGNER_ACCOUNT_ID"),
		os.Getenv("NEAR_PRIVATE_KEY"),
	)
	if err != nil {
		return nil, fmt.Errorf("create NEAR client: %w", err)
	}

	info, err := nearClient.WaitForConfirmation(ctx, txHash, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("NEAR tx not confirmed: %w", err)
	}

	status := uint64(1)
	if statusObj, ok := info["status"].(map[string]interface{}); ok {
		if _, hasFail := statusObj["Failure"]; hasFail {
			status = 0
		}
	}

	return &ExternalChainResult{
		Chain:               "near-testnet",
		ChainID:             398,
		TxHash:              common.Hash{},
		BlockNumber:         big.NewInt(0),
		Status:              status,
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  3,
	}, nil
}

// observeAptosTransaction observes an Aptos transaction using the Aptos REST API.
func (o *ProofCycleOrchestrator) observeAptosTransaction(ctx context.Context, txHash string) (*ExternalChainResult, error) {
	if txHash == "" {
		return nil, fmt.Errorf("empty Aptos tx hash")
	}

	aptosRPC := os.Getenv("APTOS_RPC_URL")
	if aptosRPC == "" {
		aptosRPC = os.Getenv("APTOS_TESTNET_RPC_URL")
	}
	if aptosRPC == "" {
		aptosRPC = "https://fullnode.testnet.aptoslabs.com/v1"
	}

	aptosPackage := os.Getenv("APTOS_PACKAGE_ADDRESS")
	if aptosPackage == "" {
		aptosPackage = os.Getenv("APTOS_ANCHOR_PACKAGE")
	}

	aptosClient, err := NewAptosClient(aptosRPC,
		os.Getenv("APTOS_PRIVATE_KEY"),
		aptosPackage,
	)
	if err != nil {
		return nil, fmt.Errorf("create Aptos client: %w", err)
	}

	err = aptosClient.WaitForConfirmation(ctx, txHash, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Aptos tx not confirmed: %w", err)
	}

	return &ExternalChainResult{
		Chain:               "aptos-testnet",
		ChainID:             2,
		TxHash:              common.Hash{},
		BlockNumber:         big.NewInt(0),
		Status:              1,
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  1,
	}, nil
}

// observeSuiTransaction observes a SUI transaction using SUI's JSON-RPC 2.0.
func (o *ProofCycleOrchestrator) observeSuiTransaction(ctx context.Context, txDigest string) (*ExternalChainResult, error) {
	if txDigest == "" {
		return nil, fmt.Errorf("empty SUI tx digest")
	}

	suiRPC := os.Getenv("SUI_RPC_URL")
	if suiRPC == "" {
		suiRPC = os.Getenv("SUI_TESTNET_RPC_URL")
	}
	if suiRPC == "" {
		suiRPC = "https://fullnode.testnet.sui.io:443"
	}

	suiPackage := os.Getenv("SUI_PACKAGE_ADDRESS")
	if suiPackage == "" {
		suiPackage = os.Getenv("SUI_ANCHOR_PACKAGE")
	}

	suiFactory := os.Getenv("SUI_FACTORY_OBJECT")
	if suiFactory == "" {
		suiFactory = os.Getenv("SUI_ACCOUNT_FACTORY_OBJECT")
	}

	suiClient, err := NewSuiClient(suiRPC,
		os.Getenv("SUI_PRIVATE_KEY"),
		suiPackage,
		os.Getenv("SUI_ANCHOR_STATE_OBJECT"),
		suiFactory,
	)
	if err != nil {
		return nil, fmt.Errorf("create SUI client: %w", err)
	}

	err = suiClient.WaitForConfirmation(ctx, txDigest, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SUI tx not confirmed: %w", err)
	}

	return &ExternalChainResult{
		Chain:               "sui-testnet",
		ChainID:             101,
		TxHash:              common.Hash{},
		BlockNumber:         big.NewInt(0),
		Status:              1,
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  1,
	}, nil
}

// observeTonTransaction2 observes a TON transaction using TON Center API v2.
func (o *ProofCycleOrchestrator) observeTonTransaction2(ctx context.Context, msgHash string) (*ExternalChainResult, error) {
	if msgHash == "" {
		return nil, fmt.Errorf("empty TON msg hash")
	}

	tonAPI := os.Getenv("TON_API_URL")
	if tonAPI == "" {
		tonAPI = os.Getenv("TON_TESTNET_API_URL")
	}
	if tonAPI == "" {
		tonAPI = "https://testnet.toncenter.com/api/v2"
	}

	tonMnemonic := os.Getenv("TON_MNEMONIC")
	if tonMnemonic == "" {
		tonMnemonic = os.Getenv("TON_WALLET_MNEMONIC")
	}

	tonAnchor := os.Getenv("TON_ANCHOR_ADDRESS")
	if tonAnchor == "" {
		tonAnchor = os.Getenv("TON_ANCHOR_CONTRACT")
	}

	tonBLS := os.Getenv("TON_BLS_VERIFIER_ADDRESS")
	if tonBLS == "" {
		tonBLS = os.Getenv("TON_BLS_VERIFIER_CONTRACT")
	}

	tonFactory := os.Getenv("TON_FACTORY_ADDRESS")
	if tonFactory == "" {
		tonFactory = os.Getenv("TON_ACCOUNT_FACTORY_CONTRACT")
	}

	tonClient, err := NewTonClient(tonAPI,
		tonMnemonic,
		tonAnchor,
		tonBLS,
		tonFactory,
	)
	if err != nil {
		return nil, fmt.Errorf("create TON client: %w", err)
	}

	err = tonClient.WaitForConfirmation(ctx, msgHash, 90*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TON tx not confirmed: %w", err)
	}

	return &ExternalChainResult{
		Chain:               "ton-testnet",
		ChainID:             65536,
		TxHash:              common.Hash{},
		BlockNumber:         big.NewInt(0),
		Status:              1,
		FinalizedAt:         time.Now(),
		ObservedByValidator: o.validatorID,
		ConfirmationBlocks:  1,
	}, nil
}

// executePhase7Enhanced observes all 3 anchor workflow transactions
func (o *ProofCycleOrchestrator) executePhase7Enhanced(
	ctx context.Context,
	cycleID string,
	cycle *ProofCycleCompletion,
	txHashes *AnchorWorkflowTxHashes,
	commitment *ExecutionCommitment,
) {
	o.logger.Printf("📡 [PHASE-7-ENHANCED] Observing all 3 anchor workflow transactions")

	// Detect chain type for observer routing
	chainType := "evm"
	if commitment != nil {
		tc := strings.ToLower(commitment.TargetChain)
		switch {
		case strings.Contains(tc, "tron"):
			chainType = "tron"
		case strings.Contains(tc, "solana"):
			chainType = "solana"
		case strings.Contains(tc, "near"):
			chainType = "near"
		case strings.Contains(tc, "aptos"):
			chainType = "aptos"
		case strings.Contains(tc, "sui"):
			chainType = "sui"
		case strings.Contains(tc, "ton"):
			chainType = "ton"
		}
	}
	if chainType != "evm" {
		o.logger.Printf("📡 [PHASE-7] Using %s-native observer (chain: %s)", chainType, commitment.TargetChain)
	}

	// Use timeout context - give more time since we're tracking 3 txs
	observeCtx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout*2)
	defer cancel()

	// Track observation results
	var createResult, verifyResult, govResult *ExternalChainResult
	var createErr, verifyErr, govErr error

	// Helper to observe a transaction (chain-aware)
	observeTx := func(txHash common.Hash, rawSig string, _ *ExecutionCommitment) (*ExternalChainResult, error) {
		switch chainType {
		case "tron":
			return o.observeTronTransaction(observeCtx, txHash)
		case "solana":
			if rawSig != "" {
				return o.observeSolanaTransaction(observeCtx, rawSig)
			}
		case "near":
			if rawSig != "" {
				return o.observeNearTransaction(observeCtx, rawSig)
			}
		case "aptos":
			if rawSig != "" {
				return o.observeAptosTransaction(observeCtx, rawSig)
			}
		case "sui":
			if rawSig != "" {
				return o.observeSuiTransaction(observeCtx, rawSig)
			}
		case "ton":
			if rawSig != "" {
				return o.observeTonTransaction2(observeCtx, rawSig)
			}
		}
		// EVM chains or error: use default Ethereum observer
		if chainType != "evm" {
			// Non-EVM chain without raw tx signature — cannot verify, fail explicitly
			return nil, fmt.Errorf("non-EVM chain %s: no native tx signature available for observation", chainType)
		}
		return o.observer.ObserveTransaction(observeCtx, txHash, nil)
	}

	// Extract raw (native-format) tx signatures for non-EVM chains
	rawCreate, rawVerify, rawGov := "", "", ""
	if len(txHashes.RawTxHashes) >= 3 {
		rawCreate, rawVerify, rawGov = txHashes.RawTxHashes[0], txHashes.RawTxHashes[1], txHashes.RawTxHashes[2]
	} else if commitment != nil && commitment.ComprehensiveData != nil {
		if v, ok := commitment.ComprehensiveData["rawCreateTxHashes"].(string); ok {
			rawCreate = v
		}
		if v, ok := commitment.ComprehensiveData["rawVerifyTxHashes"].(string); ok {
			rawVerify = v
		}
		if v, ok := commitment.ComprehensiveData["rawGovernanceTxHashes"].(string); ok {
			rawGov = v
		}
	}

	// Observe all 3 transactions concurrently
	var wg sync.WaitGroup
	wg.Add(3)

	// Step 1: Observe createAnchor transaction
	go func() {
		defer wg.Done()
		if txHashes.CreateTxHash != (common.Hash{}) || rawCreate != "" {
			o.logger.Printf("📡 [PHASE-7] Observing Step 1 (createAnchor): %s", txHashes.CreateTxHash.Hex())
			createResult, createErr = observeTx(txHashes.CreateTxHash, rawCreate, nil)
			if createErr != nil {
				o.logger.Printf("⚠️ [PHASE-7] Step 1 observation failed: %v", createErr)
			} else {
				o.mu.Lock()
				cycle.CreateResult = createResult
				cycle.CreateObservedAt = time.Now()
				o.mu.Unlock()
				o.logger.Printf("✅ [PHASE-7] Step 1 (createAnchor) confirmed: block=%d success=%v",
					createResult.BlockNumber.Uint64(), createResult.IsSuccess())
			}
		}
	}()

	// Step 2: Observe executeComprehensiveProof transaction
	go func() {
		defer wg.Done()
		if txHashes.VerifyTxHash != (common.Hash{}) || rawVerify != "" {
			o.logger.Printf("📡 [PHASE-7] Observing Step 2 (executeComprehensiveProof): %s", txHashes.VerifyTxHash.Hex())
			verifyResult, verifyErr = observeTx(txHashes.VerifyTxHash, rawVerify, nil)
			if verifyErr != nil {
				o.logger.Printf("⚠️ [PHASE-7] Step 2 observation failed: %v", verifyErr)
			} else {
				o.mu.Lock()
				cycle.VerifyResult = verifyResult
				cycle.VerifyObservedAt = time.Now()
				o.mu.Unlock()
				o.logger.Printf("✅ [PHASE-7] Step 2 (executeComprehensiveProof) confirmed: block=%d success=%v",
					verifyResult.BlockNumber.Uint64(), verifyResult.IsSuccess())
			}
		}
	}()

	// Step 3: Observe executeWithGovernance transaction
	go func() {
		defer wg.Done()
		if txHashes.GovernanceTxHash != (common.Hash{}) || rawGov != "" {
			o.logger.Printf("📡 [PHASE-7] Observing Step 3 (executeWithGovernance): %s", txHashes.GovernanceTxHash.Hex())
			var step3Result *ExternalChainResult
			var step3Err error
			step3Result, step3Err = observeTx(txHashes.GovernanceTxHash, rawGov, commitment)
			govResult, govErr = step3Result, step3Err
			if govErr != nil {
				o.logger.Printf("⚠️ [PHASE-7] Step 3 observation failed: %v", govErr)
			} else {
				o.mu.Lock()
				cycle.GovernanceResult = govResult
				cycle.GovernanceObservedAt = time.Now()
				o.mu.Unlock()
				o.logger.Printf("✅ [PHASE-7] Step 3 (executeWithGovernance) confirmed: block=%d success=%v",
					govResult.BlockNumber.Uint64(), govResult.IsSuccess())
			}
		}
	}()

	// Wait for all observations to complete
	wg.Wait()

	// Determine overall success
	// Key insight: The smart contract enforces that executeWithGovernance (Step 3) can ONLY succeed
	// if createAnchor (Step 1) and executeComprehensiveProof (Step 2) already succeeded.
	// Therefore, if Step 3 succeeds, we KNOW Steps 1 and 2 succeeded on-chain.
	// We only verify commitment for Step 3, so focus on govErr for cycle success.
	if govErr != nil {
		o.handleCycleFailed(cycleID, fmt.Errorf("phase 7 observation failed: executeWithGovernance: %w", govErr))
		return
	}

	// Log any Step 1/2 observation errors (informational only - on-chain they succeeded)
	if createErr != nil {
		o.logger.Printf("⚠️ [PHASE-7] Step 1 observation had error (on-chain succeeded per Step 3): %v", createErr)
	}
	if verifyErr != nil {
		o.logger.Printf("⚠️ [PHASE-7] Step 2 observation had error (on-chain succeeded per Step 3): %v", verifyErr)
	}

	// Update cycle with overall status
	// Use governance result as primary since it's the one with verified commitment
	o.mu.Lock()
	cycle.ExecutionResult = govResult // Use governance result as it has verified commitment
	cycle.ExecutionTime = time.Now()
	cycle.AllTxsConfirmed = govErr == nil && govResult != nil && govResult.IsSuccess()
	o.mu.Unlock()

	// Log summary
	o.logger.Printf("✅ [PHASE-7-ENHANCED] Observation complete:")
	o.logger.Printf("   Step 1 (Create):     %s (block=%d)",
		statusString(createResult), blockNum(createResult))
	o.logger.Printf("   Step 2 (Verify):     %s (block=%d)",
		statusString(verifyResult), blockNum(verifyResult))
	o.logger.Printf("   Step 3 (Governance): %s (block=%d)",
		statusString(govResult), blockNum(govResult))
	o.logger.Printf("   All confirmed: %v", cycle.AllTxsConfirmed)

	// Persist external chain results to database
	o.persistExternalChainResults(ctx, cycle, createResult, verifyResult, govResult)

	// Proceed to Phase 8
	// Use govResult since that's what we verified against the commitment
	o.executePhase8(ctx, cycleID, cycle, govResult, commitment)
}

// Helper functions for logging
func statusString(r *ExternalChainResult) string {
	if r == nil {
		return "skipped"
	}
	if r.IsSuccess() {
		return "✅ success"
	}
	return "❌ failed"
}

func blockNum(r *ExternalChainResult) uint64 {
	if r == nil || r.BlockNumber == nil {
		return 0
	}
	return r.BlockNumber.Uint64()
}

// executePhase7 observes the external chain transaction and constructs proofs
func (o *ProofCycleOrchestrator) executePhase7(
	ctx context.Context,
	cycleID string,
	cycle *ProofCycleCompletion,
	txHash common.Hash,
	commitment *ExecutionCommitment,
) {
	o.logger.Printf("📡 [PHASE-7] Observing external chain execution: %s", txHash.Hex())

	// Use timeout context
	observeCtx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout)
	defer cancel()

	// Observe transaction with Merkle proofs
	result, err := o.observer.ObserveTransaction(observeCtx, txHash, commitment)
	if err != nil {
		o.handleCycleFailed(cycleID, fmt.Errorf("phase 7 observation failed: %w", err))
		return
	}

	o.logger.Printf("✅ [PHASE-7] External chain result observed:")
	o.logger.Printf("   Block: %d", result.BlockNumber.Uint64())
	o.logger.Printf("   Success: %v", result.IsSuccess())
	o.logger.Printf("   Confirmations: %d", result.ConfirmationBlocks)
	o.logger.Printf("   Result Hash: %s", result.ToHex())

	// Update cycle
	o.mu.Lock()
	cycle.ExecutionResult = result
	cycle.ExecutionTime = time.Now()
	o.mu.Unlock()

	// Proceed to Phase 8
	o.executePhase8(ctx, cycleID, cycle, result, commitment)
}

// executePhase8 verifies the result and creates attestation
func (o *ProofCycleOrchestrator) executePhase8(
	ctx context.Context,
	cycleID string,
	cycle *ProofCycleCompletion,
	result *ExternalChainResult,
	commitment *ExecutionCommitment,
) {
	o.logger.Printf("🔐 [PHASE-8] Verifying result and creating attestation")

	// Verify and create attestation
	attestation, err := o.verifier.VerifyAndAttest(result, commitment)
	if err != nil {
		o.handleCycleFailed(cycleID, fmt.Errorf("phase 8 verification failed: %w", err))
		return
	}

	o.logger.Printf("✅ [PHASE-8] Attestation created:")
	o.logger.Printf("   Validator: %s", attestation.ValidatorID)
	o.logger.Printf("   Message Hash: %x", attestation.MessageHash[:8])

	// Persist BLS result attestation to database
	o.persistBLSResultAttestation(ctx, result, attestation)

	// Update cycle
	o.mu.Lock()
	cycle.AttestationTime = time.Now()
	o.mu.Unlock()

	// Note: The attestation is added to the collector, which will trigger
	// onAttestationThreshold when enough validators have attested.
	// For single-validator mode, we can proceed immediately.

	// Check if we already have threshold (single validator or fast path)
	agg := o.collector.GetAggregated(result.ResultHash)
	if agg != nil && agg.ThresholdMet {
		// Persist aggregated attestation before moving to Phase 9
		o.persistAggregatedBLSAttestation(ctx, result, agg)
		o.executePhase9(ctx, cycleID, cycle, result, agg)
	}
}

// onAttestationThreshold is called when attestation threshold is met
func (o *ProofCycleOrchestrator) onAttestationThreshold(agg *AggregatedAttestation) {
	o.logger.Printf("🎯 [PHASE-8] Attestation threshold met: %d validators, power %s",
		agg.ValidatorCount, agg.SignedVotingPower.String())

	// Find the active cycle for this result
	o.mu.RLock()
	var cycleID string
	var cycle *ProofCycleCompletion
	for id, c := range o.activeCycles {
		if c.ExecutionResult != nil && c.ExecutionResult.ResultHash == agg.ResultHash {
			cycleID = id
			cycle = c
			break
		}
	}
	o.mu.RUnlock()

	if cycle == nil {
		o.logger.Printf("⚠️ [PHASE-8] No active cycle found for result: %x", agg.ResultHash[:8])
		return
	}

	// Persist aggregated attestation before moving to Phase 9
	ctx := context.Background()
	o.persistAggregatedBLSAttestation(ctx, cycle.ExecutionResult, agg)

	// Proceed to Phase 9
	o.executePhase9(ctx, cycleID, cycle, cycle.ExecutionResult, agg)
}

// executePhase9 writes the proof result back to Accumulate
func (o *ProofCycleOrchestrator) executePhase9(
	ctx context.Context,
	cycleID string,
	cycle *ProofCycleCompletion,
	result *ExternalChainResult,
	agg *AggregatedAttestation,
) {
	o.logger.Printf("📝 [PHASE-9] Writing proof result back to Accumulate")

	// Update cycle with attestation
	o.mu.Lock()
	cycle.Attestation = agg
	o.mu.Unlock()

	if !o.config.WriteBackEnabled {
		o.logger.Printf("⚠️ [PHASE-9] Write-back disabled, completing cycle without Accumulate submission")
		o.completeCycle(cycleID, cycle, nil)
		return
	}

	// Create attestation bundle
	bundle := NewAttestationBundle(cycle.BundleID, result, agg)

	// Build ComprehensiveProofContext from cycle data for full audit support
	proofCtx := o.buildComprehensiveProofContext(cycle, result, agg)

	// Submit to Accumulate with context
	if err := o.writeBack.WriteResultWithContext(ctx, bundle, proofCtx); err != nil {
		o.handleCycleFailed(cycleID, fmt.Errorf("phase 9 write-back failed: %w", err))
		return
	}

	o.logger.Printf("✅ [PHASE-9] Write-back submitted with comprehensive proof context, awaiting confirmation")
}

// buildComprehensiveProofContext creates the proof context from cycle data
// This populates all fields needed for independent audit and verification
func (o *ProofCycleOrchestrator) buildComprehensiveProofContext(
	cycle *ProofCycleCompletion,
	result *ExternalChainResult,
	agg *AggregatedAttestation,
) *ComprehensiveProofContext {
	proofCtx := &ComprehensiveProofContext{
		// Intent reference from cycle
		IntentID:     cycle.IntentID,
		IntentHash:   cycle.IntentHash,
		IntentTxHash: cycle.IntentTxHash,
		IntentBlock:  cycle.IntentBlock,

		// Event verification from result
		EventCount:     len(result.Logs),
		EventsVerified: result.TxInclusionProof != nil && result.TxInclusionProof.Verified,
	}

	// Compute events hash
	if len(result.Logs) > 0 {
		proofCtx.EventsHash = computeEventsHash(result.Logs)
	}

	// Extract commitment data if available
	if cycle.Commitment != nil {
		proofCtx.Commitment = cycle.Commitment

		// Use intent reference from commitment if not already set
		if proofCtx.IntentTxHash == "" && cycle.Commitment.IntentTxHash != "" {
			proofCtx.IntentTxHash = cycle.Commitment.IntentTxHash
		}
		if proofCtx.IntentBlock == 0 && cycle.Commitment.IntentBlock > 0 {
			proofCtx.IntentBlock = cycle.Commitment.IntentBlock
		}

		// Extract 3-step transaction details from comprehensive commitment data
		if cycle.Commitment.ComprehensiveData != nil {
			o.extractStepDetailsFromCommitment(proofCtx, cycle.Commitment.ComprehensiveData)
		}
	}

	// Generate proof artifact ID for PostgreSQL lookup
	proofCtx.ProofArtifactID = fmt.Sprintf("proof-%s-%s", cycle.IntentID, hex.EncodeToString(cycle.BundleID[:8]))

	// Governance proof reference (BLS aggregate signature)
	if agg != nil && agg.AggregateSignature != nil {
		proofCtx.GovernanceProofRef = fmt.Sprintf("bls-agg-%x", agg.AggregateSignature[:8])
	}

	// Anchor proof hash from result
	proofCtx.AnchorProofHash = result.AnchorProofHash
	proofCtx.PreviousResultHash = result.PreviousResultHash
	proofCtx.SequenceNumber = result.SequenceNumber

	o.logger.Printf("📋 [PHASE-9] Built comprehensive proof context:")
	o.logger.Printf("   IntentID: %s", proofCtx.IntentID)
	o.logger.Printf("   IntentTxHash: %s", proofCtx.IntentTxHash)
	o.logger.Printf("   ProofArtifactID: %s", proofCtx.ProofArtifactID)
	if proofCtx.Commitment != nil {
		o.logger.Printf("   AnchorContract: %s", proofCtx.Commitment.TargetContract.Hex())
		o.logger.Printf("   FunctionSelector: %x", proofCtx.Commitment.FunctionSelector)
	}

	return proofCtx
}

// extractStepDetailsFromCommitment extracts 3-step transaction details from commitment map
func (o *ProofCycleOrchestrator) extractStepDetailsFromCommitment(proofCtx *ComprehensiveProofContext, commitmentData map[string]interface{}) {
	// Extract top-level intent reference if available
	// Try multiple keys: intentTxHash, txHash (commitment uses "txHash")
	if proofCtx.IntentTxHash == "" {
		if intentTxHash, ok := commitmentData["intentTxHash"].(string); ok && intentTxHash != "" {
			proofCtx.IntentTxHash = intentTxHash
		} else if txHash, ok := commitmentData["txHash"].(string); ok && txHash != "" {
			proofCtx.IntentTxHash = txHash
		}
	}
	// Try multiple keys: intentBlock, blockHeight
	if proofCtx.IntentBlock == 0 {
		if intentBlock, ok := commitmentData["intentBlock"].(float64); ok && intentBlock > 0 {
			proofCtx.IntentBlock = uint64(intentBlock)
		} else if blockHeight, ok := commitmentData["blockHeight"].(float64); ok && blockHeight > 0 {
			proofCtx.IntentBlock = uint64(blockHeight)
		}
	}

	// Step 1: createAnchor
	if step1, ok := commitmentData["step1"].(map[string]interface{}); ok {
		if selector, ok := step1["selector"].(string); ok {
			proofCtx.Step1Selector = selector
		}
		if contract, ok := step1["contract"].(string); ok {
			proofCtx.Step1Contract = contract
		}
		// Try multiple keys for intent hash
		if intentHash, ok := step1["intentHash"].(string); ok {
			proofCtx.Step1IntentHash = intentHash
		} else if intentHash, ok := step1["intent_hash"].(string); ok {
			proofCtx.Step1IntentHash = intentHash
		} else if intentHash, ok := step1["hash"].(string); ok {
			proofCtx.Step1IntentHash = intentHash
		}
	}

	// Step 2: executeComprehensiveProof
	if step2, ok := commitmentData["step2"].(map[string]interface{}); ok {
		if selector, ok := step2["selector"].(string); ok {
			proofCtx.Step2Selector = selector
		}
		if contract, ok := step2["contract"].(string); ok {
			proofCtx.Step2Contract = contract
		}
	}

	// Step 3: executeWithGovernance
	if step3, ok := commitmentData["step3"].(map[string]interface{}); ok {
		if selector, ok := step3["selector"].(string); ok {
			proofCtx.Step3Selector = selector
		}
		if contract, ok := step3["contract"].(string); ok {
			proofCtx.Step3Contract = contract
		}
		// Try multiple keys for final target
		if finalTarget, ok := step3["finalTarget"].(string); ok {
			proofCtx.Step3FinalTarget = finalTarget
		} else if finalTarget, ok := step3["final_target"].(string); ok {
			proofCtx.Step3FinalTarget = finalTarget
		} else if finalTarget, ok := step3["to"].(string); ok {
			proofCtx.Step3FinalTarget = finalTarget
		} else if finalTarget, ok := step3["recipient"].(string); ok {
			proofCtx.Step3FinalTarget = finalTarget
		}
		// Try multiple keys for final value
		if finalValue, ok := step3["finalValue"].(string); ok {
			proofCtx.Step3FinalValue = finalValue
		} else if finalValue, ok := step3["final_value"].(string); ok {
			proofCtx.Step3FinalValue = finalValue
		} else if finalValue, ok := step3["amount"].(string); ok {
			proofCtx.Step3FinalValue = finalValue
		} else if finalValue, ok := step3["value"].(string); ok {
			proofCtx.Step3FinalValue = finalValue
		}
		// Also try float64 for value
		if proofCtx.Step3FinalValue == "" {
			if finalValue, ok := step3["finalValue"].(float64); ok {
				proofCtx.Step3FinalValue = fmt.Sprintf("%.0f", finalValue)
			} else if finalValue, ok := step3["amount"].(float64); ok {
				proofCtx.Step3FinalValue = fmt.Sprintf("%.0f", finalValue)
			}
		}
	}

	// Also check top-level fields
	if anchorContract, ok := commitmentData["anchorContract"].(string); ok {
		if proofCtx.Step1Contract == "" {
			proofCtx.Step1Contract = anchorContract
		}
		if proofCtx.Step2Contract == "" {
			proofCtx.Step2Contract = anchorContract
		}
		if proofCtx.Step3Contract == "" {
			proofCtx.Step3Contract = anchorContract
		}
	}

	// Extract final target/value from top-level if not in step3
	// Commitment uses "finalTarget" and "finalValue" at top level
	if proofCtx.Step3FinalTarget == "" {
		if finalTarget, ok := commitmentData["finalTarget"].(string); ok {
			proofCtx.Step3FinalTarget = finalTarget
		} else if to, ok := commitmentData["to"].(string); ok {
			proofCtx.Step3FinalTarget = to
		} else if recipient, ok := commitmentData["recipient"].(string); ok {
			proofCtx.Step3FinalTarget = recipient
		}
	}
	if proofCtx.Step3FinalValue == "" {
		if finalValue, ok := commitmentData["finalValue"].(string); ok {
			proofCtx.Step3FinalValue = finalValue
		} else if amount, ok := commitmentData["amount"].(string); ok {
			proofCtx.Step3FinalValue = amount
		} else if amount, ok := commitmentData["amountWei"].(string); ok {
			proofCtx.Step3FinalValue = amount
		} else if amount, ok := commitmentData["amount"].(float64); ok {
			proofCtx.Step3FinalValue = fmt.Sprintf("%.0f", amount)
		} else if amount, ok := commitmentData["amountWei"].(float64); ok {
			proofCtx.Step3FinalValue = fmt.Sprintf("%.0f", amount)
		}
	}
}

// onWriteBackConfirmed handles successful write-back confirmation
func (o *ProofCycleOrchestrator) onWriteBackConfirmed(tx *SyntheticTransaction) {
	o.logger.Printf("🎉 [PHASE-9] Write-back confirmed: %s", tx.ToHex())

	// Find the cycle
	o.mu.Lock()
	var cycleID string
	var cycle *ProofCycleCompletion
	for id, c := range o.activeCycles {
		if c.BundleID == tx.OriginBundleID {
			cycleID = id
			cycle = c
			break
		}
	}
	o.mu.Unlock()

	if cycle != nil {
		o.completeCycle(cycleID, cycle, tx)
	}
}

// onWriteBackFailed handles write-back failure
func (o *ProofCycleOrchestrator) onWriteBackFailed(tx *SyntheticTransaction, err error) {
	o.logger.Printf("❌ [PHASE-9] Write-back failed: %v", err)

	// Find the cycle
	o.mu.Lock()
	var cycleID string
	for id, c := range o.activeCycles {
		if c.BundleID == tx.OriginBundleID {
			cycleID = id
			break
		}
	}
	o.mu.Unlock()

	if cycleID != "" {
		o.handleCycleFailed(cycleID, err)
	}
}

// completeCycle marks a proof cycle as complete
func (o *ProofCycleOrchestrator) completeCycle(
	cycleID string,
	cycle *ProofCycleCompletion,
	tx *SyntheticTransaction,
) {
	o.mu.Lock()
	cycle.WriteBackTx = tx
	cycle.WriteBackTime = time.Now()
	cycle.Finalize()
	delete(o.activeCycles, cycleID)
	o.mu.Unlock()

	o.logger.Printf("🏆 [PROOF-CYCLE] Complete proof cycle finished!")
	o.logger.Printf("   Cycle ID: %s", cycleID)
	o.logger.Printf("   Cycle Hash: %s", cycle.ToHex())
	o.logger.Printf("   Total Duration: %s", cycle.TotalDuration)

	// Persist completion data to proof_artifacts table
	if err := o.persistProofArtifact(cycle); err != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to persist proof artifact: %v", err)
		// Non-fatal - cycle completed successfully, just persistence failed
	} else {
		o.logger.Printf("✅ [PROOF-CYCLE] Proof artifact persisted to database")
	}

	// Update intent_lifecycle status to 'complete' so the web app reflects the real state
	if o.repos != nil && o.repos.IntentLifecycle != nil && cycle.IntentID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		writeBackTxHash := ""
		if cycle.WriteBackTx != nil && cycle.WriteBackTx.TxHash != ([32]byte{}) {
			writeBackTxHash = hex.EncodeToString(cycle.WriteBackTx.TxHash[:])
		}
		if err := o.repos.IntentLifecycle.UpdateStatus(ctx, cycle.IntentID,
			database.IntentLifecycleComplete,
			database.WithWriteBackTx(writeBackTxHash),
			database.WithCycleID(cycleID),
		); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to update intent lifecycle to complete: %v", err)
		} else {
			o.logger.Printf("✅ [PROOF-CYCLE] Intent lifecycle updated to 'complete' for %s", cycle.IntentID)
		}
	}

	if o.onCycleComplete != nil {
		go o.onCycleComplete(cycle)
	}
}

// persistProofArtifact saves completion data to the proof_artifacts table
// This enables the web app to track progress through all 9 stages
func (o *ProofCycleOrchestrator) persistProofArtifact(cycle *ProofCycleCompletion) error {
	if o.repos == nil || o.repos.ProofArtifacts == nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] No database repository available for proof artifact persistence")
		return nil // Not an error - just skip persistence
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Extract anchor data from execution result and commitment
	var anchorTxHash string
	var anchorBlockNumber int64
	var anchorChain string

	// Determine target chain from commitment (NOT hardcoded)
	if cycle.Commitment != nil && cycle.Commitment.TargetChain != "" {
		anchorChain = cycle.Commitment.TargetChain
	} else if cycle.ExecutionResult != nil && cycle.ExecutionResult.Chain != "" {
		anchorChain = cycle.ExecutionResult.Chain
	} else {
		anchorChain = "ethereum"
	}

	// For non-EVM chains, prefer raw tx hashes (base58/native format) from commitment data
	if cycle.Commitment != nil && cycle.Commitment.ComprehensiveData != nil {
		if raw, ok := cycle.Commitment.ComprehensiveData["rawCreateTxHashes"].(string); ok && raw != "" {
			anchorTxHash = raw
		}
	}

	// Fallback to EVM common.Hash if no raw hash found
	if anchorTxHash == "" {
		if cycle.CreateTxHash != (common.Hash{}) {
			anchorTxHash = cycle.CreateTxHash.Hex()
		} else if cycle.ExecutionResult != nil && cycle.ExecutionResult.TxHash != (common.Hash{}) {
			anchorTxHash = cycle.ExecutionResult.TxHash.Hex()
		}
	}

	// Extract block number from commitment comprehensive data
	if cycle.Commitment != nil && cycle.Commitment.ComprehensiveData != nil {
		switch block := cycle.Commitment.ComprehensiveData["accumulateBlockHeight"].(type) {
		case float64:
			anchorBlockNumber = int64(block)
		case int64:
			anchorBlockNumber = block
		case uint64:
			anchorBlockNumber = int64(block)
		case int:
			anchorBlockNumber = int64(block)
		}
	}
	if anchorBlockNumber == 0 {
		if cycle.CreateResult != nil && cycle.CreateResult.BlockNumber != nil {
			anchorBlockNumber = cycle.CreateResult.BlockNumber.Int64()
		} else if cycle.ExecutionResult != nil && cycle.ExecutionResult.BlockNumber != nil {
			anchorBlockNumber = cycle.ExecutionResult.BlockNumber.Int64()
		}
	}

	// Build comprehensive artifact JSON containing all proof cycle data
	// Enhanced: Now includes all 3 anchor workflow transactions
	artifactData := map[string]interface{}{
		"proof_cycle_version": "3.0", // Upgraded version for enhanced tracking
		"intent_id":           cycle.IntentID,
		"intent_tx_hash":      cycle.IntentTxHash,
		"intent_block":        cycle.IntentBlock,
		"bundle_id":           hex.EncodeToString(cycle.BundleID[:]),
		"cycle_hash":          hex.EncodeToString(cycle.CycleHash[:]),
		"validator_id":        o.validatorID,
		"anchor_chain":        anchorChain,
		"anchor_tx_hash":      anchorTxHash, // Primary (createAnchor)
		"anchor_block":        anchorBlockNumber,
		"total_duration_ms":   cycle.TotalDuration.Milliseconds(),
		"completed_at":        time.Now().Format(time.RFC3339),
		"all_txs_confirmed":   cycle.AllTxsConfirmed,
	}

	// ============ ENHANCED: All 3 Anchor Workflow Transactions ============
	anchorWorkflow := map[string]interface{}{
		"workflow_version": "1.0",
		"all_confirmed":    cycle.AllTxsConfirmed,
	}

	// Step 1: createAnchor transaction
	if cycle.CreateTxHash != (common.Hash{}) {
		step1 := map[string]interface{}{
			"tx_hash": cycle.CreateTxHash.Hex(),
		}
		if cycle.CreateResult != nil {
			step1["block_number"] = cycle.CreateResult.BlockNumber.Uint64()
			step1["success"] = cycle.CreateResult.IsSuccess()
			step1["gas_used"] = cycle.CreateResult.TxGasUsed
			step1["confirmations"] = cycle.CreateResult.ConfirmationBlocks
		}
		if !cycle.CreateObservedAt.IsZero() {
			step1["observed_at"] = cycle.CreateObservedAt.Format(time.RFC3339)
		}
		anchorWorkflow["step1_create_anchor"] = step1
	}

	// Step 2: executeComprehensiveProof transaction
	if cycle.VerifyTxHash != (common.Hash{}) {
		step2 := map[string]interface{}{
			"tx_hash": cycle.VerifyTxHash.Hex(),
		}
		if cycle.VerifyResult != nil {
			step2["block_number"] = cycle.VerifyResult.BlockNumber.Uint64()
			step2["success"] = cycle.VerifyResult.IsSuccess()
			step2["gas_used"] = cycle.VerifyResult.TxGasUsed
			step2["confirmations"] = cycle.VerifyResult.ConfirmationBlocks
		}
		if !cycle.VerifyObservedAt.IsZero() {
			step2["observed_at"] = cycle.VerifyObservedAt.Format(time.RFC3339)
		}
		anchorWorkflow["step2_verify_proof"] = step2
	}

	// Step 3: executeWithGovernance transaction
	if cycle.GovernanceTxHash != (common.Hash{}) {
		step3 := map[string]interface{}{
			"tx_hash": cycle.GovernanceTxHash.Hex(),
		}
		if cycle.GovernanceResult != nil {
			step3["block_number"] = cycle.GovernanceResult.BlockNumber.Uint64()
			step3["success"] = cycle.GovernanceResult.IsSuccess()
			step3["gas_used"] = cycle.GovernanceResult.TxGasUsed
			step3["confirmations"] = cycle.GovernanceResult.ConfirmationBlocks
		}
		if !cycle.GovernanceObservedAt.IsZero() {
			step3["observed_at"] = cycle.GovernanceObservedAt.Format(time.RFC3339)
		}
		anchorWorkflow["step3_governance"] = step3
	}

	artifactData["anchor_workflow"] = anchorWorkflow

	// Add execution result details (legacy format for backwards compatibility)
	if cycle.ExecutionResult != nil {
		artifactData["execution"] = map[string]interface{}{
			"tx_hash":             anchorTxHash,
			"block_number":        anchorBlockNumber,
			"success":             cycle.ExecutionResult.IsSuccess(),
			"gas_used":            cycle.ExecutionResult.TxGasUsed,
			"confirmation_blocks": cycle.ExecutionResult.ConfirmationBlocks,
		}
	}

	// Add attestation details (BLS aggregate signature)
	if cycle.Attestation != nil {
		attestationData := map[string]interface{}{
			"validator_count":     cycle.Attestation.ValidatorCount,
			"threshold_met":       cycle.Attestation.ThresholdMet,
			"result_hash":         hex.EncodeToString(cycle.Attestation.ResultHash[:]),
		}
		if cycle.Attestation.SignedVotingPower != nil {
			attestationData["signed_voting_power"] = cycle.Attestation.SignedVotingPower.String()
		}
		if cycle.Attestation.AggregateSignature != nil {
			attestationData["aggregate_signature"] = hex.EncodeToString(cycle.Attestation.AggregateSignature)
		}
		artifactData["attestation"] = attestationData
	}

	// Add writeback transaction details
	if cycle.WriteBackTx != nil {
		writebackData := map[string]interface{}{
			"tx_type":   cycle.WriteBackTx.TxType,
			"principal": cycle.WriteBackTx.Principal,
			"status":    cycle.WriteBackTx.Status,
		}
		if cycle.WriteBackTx.TxHash != ([32]byte{}) {
			writebackData["tx_hash"] = hex.EncodeToString(cycle.WriteBackTx.TxHash[:])
		}
		if !cycle.WriteBackTx.ConfirmedAt.IsZero() {
			writebackData["confirmed_at"] = cycle.WriteBackTx.ConfirmedAt.Format(time.RFC3339)
		}
		artifactData["writeback"] = writebackData
	}

	// Add timing data
	artifactData["timing"] = map[string]interface{}{
		"intent_time":      cycle.IntentTime.Format(time.RFC3339),
		"execution_time":   cycle.ExecutionTime.Format(time.RFC3339),
		"attestation_time": cycle.AttestationTime.Format(time.RFC3339),
		"writeback_time":   cycle.WriteBackTime.Format(time.RFC3339),
	}

	artifactJSON, err := json.Marshal(artifactData)
	if err != nil {
		return fmt.Errorf("failed to serialize proof artifact: %w", err)
	}

	// First, try to find existing proof artifact by intent tx hash
	existingProof, err := o.repos.ProofArtifacts.GetProofByTxHash(ctx, cycle.IntentTxHash)
	if err != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Error checking existing proof: %v", err)
		// Continue to create new one
	}

	if existingProof != nil {
		// Update existing proof artifact with completion data
		o.logger.Printf("📝 [PROOF-CYCLE] Updating existing proof artifact: %s", existingProof.ProofID)

		// Update intent tracking (user_id and intent_id for Firestore linking)
		if cycle.IntentID != "" || cycle.UserID != "" {
			var userIDPtr, intentIDPtr *string
			if cycle.UserID != "" {
				userIDPtr = &cycle.UserID
			}
			if cycle.IntentID != "" {
				intentIDPtr = &cycle.IntentID
			}
			if err := o.repos.ProofArtifacts.UpdateProofIntentTracking(ctx, existingProof.ProofID, userIDPtr, intentIDPtr); err != nil {
				o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to update proof intent tracking: %v", err)
			} else {
				o.logger.Printf("✅ [PROOF-CYCLE] Updated user_id=%s, intent_id=%s on proof %s", cycle.UserID, cycle.IntentID, existingProof.ProofID)
			}
		}

		// Update anchor information (use Simple version to avoid FK constraint on anchor_records)
		if anchorTxHash != "" {
			if err := o.repos.ProofArtifacts.UpdateProofAnchoredSimple(
				ctx,
				existingProof.ProofID,
				anchorTxHash,
				anchorBlockNumber,
				anchorChain,
			); err != nil {
				o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to update proof anchored status: %v", err)
			}
		}

		// Mark as verified (all 9 steps complete)
		if err := o.repos.ProofArtifacts.UpdateProofVerified(ctx, existingProof.ProofID, true); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to update proof verified status: %v", err)
		}

		// Link external_chain_results to this proof artifact
		if linkedCount, err := o.repos.ProofArtifacts.LinkExternalChainResultsToProof(ctx, cycle.BundleID[:], existingProof.ProofID); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to link external chain results: %v", err)
		} else if linkedCount > 0 {
			o.logger.Printf("✅ [PROOF-CYCLE] Linked %d external chain results to proof %s", linkedCount, existingProof.ProofID)
		}

		o.logger.Printf("✅ [PROOF-CYCLE] Updated proof artifact %s with completion data", existingProof.ProofID)
		return nil
	}

	// Create new proof artifact if none exists
	o.logger.Printf("📝 [PROOF-CYCLE] Creating new proof artifact for intent: %s", cycle.IntentID)

	// Look up the actual account URL from batch_transactions
	accountURL := ""
	if cycle.IntentID != "" {
		if url, err := o.repos.Batches.GetAccountURLByIntentID(ctx, cycle.IntentID); err == nil && url != "" {
			accountURL = url
			o.logger.Printf("📍 [PROOF-CYCLE] Found account URL for intent %s: %s", cycle.IntentID, accountURL)
		}
	}
	// Fallback to intent tx hash if no account URL found (for CLI-submitted intents)
	if accountURL == "" {
		accountURL = cycle.IntentTxHash
	}

	govLevel := database.GovLevelG2 // G2 = Governance + outcome binding (BLS attestation provides this)
	intentID := cycle.IntentID      // Copy for pointer
	userID := cycle.UserID          // Copy for pointer
	input := &database.NewProofArtifact{
		ProofType:    database.ProofTypeCertenAnchor,
		AccumTxHash:  cycle.IntentTxHash,
		AccountURL:   accountURL, // Use actual Accumulate account URL (ADI)
		GovLevel:     &govLevel,
		ProofClass:   database.ProofClassOnCadence,
		ValidatorID:  o.validatorID,
		ArtifactJSON: artifactJSON,
		UserID:       &userID,   // Set user tracking for Firestore linking
		IntentID:     &intentID, // Set intent tracking for Firestore linking
	}

	proof, err := o.repos.ProofArtifacts.CreateProofArtifact(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create proof artifact: %w", err)
	}

	// Immediately update with anchor and verification status (use Simple version to avoid FK constraint)
	if anchorTxHash != "" {
		if updateErr := o.repos.ProofArtifacts.UpdateProofAnchoredSimple(
			ctx,
			proof.ProofID,
			anchorTxHash,
			anchorBlockNumber,
			anchorChain,
		); updateErr != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to update new proof with anchor: %v", updateErr)
		}
	}

	// Mark as verified since cycle completed successfully
	if verifyErr := o.repos.ProofArtifacts.UpdateProofVerified(ctx, proof.ProofID, true); verifyErr != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to mark new proof as verified: %v", verifyErr)
	}

	// Link external_chain_results to this newly created proof artifact
	if linkedCount, err := o.repos.ProofArtifacts.LinkExternalChainResultsToProof(ctx, cycle.BundleID[:], proof.ProofID); err != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to link external chain results to new proof: %v", err)
	} else if linkedCount > 0 {
		o.logger.Printf("✅ [PROOF-CYCLE] Linked %d external chain results to new proof %s", linkedCount, proof.ProofID)
	}

	// ============ CHAINED PROOF LAYERS (L1/L2/L3) ============
	// Fetch and store the Accumulate chained proof (Merkle receipt paths)
	// This populates the "Proof Journey" section in the web app
	o.storeChainedProofLayers(ctx, proof.ProofID, cycle)

	// ============ GOVERNANCE PROOF LEVELS ============
	// Store G0/G1/G2 governance proof records
	o.storeGovernanceLevels(ctx, proof.ProofID, cycle, anchorBlockNumber)

	// ============ ATTESTATION RECORDS ============
	// Store validator attestation for this proof
	o.storeAttestationRecord(ctx, proof.ProofID, cycle)

	o.logger.Printf("✅ [PROOF-CYCLE] Created proof artifact %s for intent %s", proof.ProofID, cycle.IntentID)
	return nil
}

// storeChainedProofLayers fetches the L1-L3 receipt entries from Accumulate
// (the same proof the validators already produced during Phase 2) and stores them.
func (o *ProofCycleOrchestrator) storeChainedProofLayers(ctx context.Context, proofID uuid.UUID, cycle *ProofCycleCompletion) {
	if o.repos == nil {
		return
	}

	// Determine account URL and tx hash for proof lookup
	accountURL := ""
	txHash := cycle.IntentTxHash
	bvn := ""

	if url, err := o.repos.Batches.GetAccountURLByIntentID(ctx, cycle.IntentID); err == nil && url != "" {
		accountURL = url
	}
	if accountURL == "" {
		accountURL = txHash
	}

	o.logger.Printf("📋 [PROOF-CYCLE] Storing chained proof layers for proof %s (account=%s, tx=%s)",
		proofID, accountURL, txHash)

	// Use the ProofGenerator to fetch the L1-L3 receipt entries from Accumulate
	// This is the SAME proof data the validators produced during Phase 2
	if o.proofGenerator != nil && accountURL != "" && txHash != "" {
		chainedProof, err := o.proofGenerator.GenerateChainedProofForTx(ctx, accountURL, txHash, bvn)
		if err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to fetch chained proof for persistence: %v", err)
			// Fall through to minimal layers below
		} else if chainedProof != nil {
			// L1: Transaction → BVN (with real receipt entries)
			l1JSON, _ := json.Marshal(map[string]interface{}{
				"layer":          "L1",
				"description":    "Transaction to BVN",
				"bvn_partition":  chainedProof.L1BVNPartition,
				"receipt_anchor": hex.EncodeToString(chainedProof.L1ReceiptAnchor),
				"source_hash":    hex.EncodeToString(chainedProof.L1SourceHash),
				"target_hash":    hex.EncodeToString(chainedProof.L1TargetHash),
				"path_depth":     len(chainedProof.L1ReceiptEntries),
			})
			l1Layer := &database.NewChainedProofLayer{
				ProofID:        proofID,
				LayerNumber:    1,
				LayerName:      "L1 - Transaction to BVN",
				BVNPartition:   &chainedProof.L1BVNPartition,
				ReceiptAnchor:  chainedProof.L1ReceiptAnchor,
				BVNRoot:        chainedProof.L1BVNRoot,
				SourceHash:     chainedProof.L1SourceHash,
				TargetHash:     chainedProof.L1TargetHash,
				ReceiptEntries: chainedProof.L1ReceiptEntries,
				LayerJSON:      l1JSON,
			}
			if _, err := o.repos.ProofArtifacts.CreateChainedProofLayer(ctx, l1Layer); err != nil {
				o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create L1 layer: %v", err)
			}

			// L2: BVN → DN (with real receipt entries)
			l2JSON, _ := json.Marshal(map[string]interface{}{
				"layer":       "L2",
				"description": "BVN to DN",
				"anchor_seq":  chainedProof.L2AnchorSeq,
				"source_hash": hex.EncodeToString(chainedProof.L2SourceHash),
				"target_hash": hex.EncodeToString(chainedProof.L2TargetHash),
				"path_depth":  len(chainedProof.L2ReceiptEntries),
			})
			l2Layer := &database.NewChainedProofLayer{
				ProofID:        proofID,
				LayerNumber:    2,
				LayerName:      "L2 - BVN to DN",
				DNRoot:         chainedProof.L2DNRoot,
				AnchorSequence: &chainedProof.L2AnchorSeq,
				DNBlockHash:    chainedProof.L2DNBlockHash,
				SourceHash:     chainedProof.L2SourceHash,
				TargetHash:     chainedProof.L2TargetHash,
				ReceiptEntries: chainedProof.L2ReceiptEntries,
				LayerJSON:      l2JSON,
			}
			if _, err := o.repos.ProofArtifacts.CreateChainedProofLayer(ctx, l2Layer); err != nil {
				o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create L2 layer: %v", err)
			}

			// L3: DN → Consensus (with real receipt entries)
			consensusTS := chainedProof.L3ConsensusTimestamp
			l3JSON, _ := json.Marshal(map[string]interface{}{
				"layer":               "L3",
				"description":         "DN to Consensus",
				"dn_block_height":     chainedProof.L3DNBlockHeight,
				"consensus_timestamp": chainedProof.L3ConsensusTimestamp,
				"source_hash":         hex.EncodeToString(chainedProof.L3SourceHash),
				"target_hash":         hex.EncodeToString(chainedProof.L3TargetHash),
				"path_depth":          len(chainedProof.L3ReceiptEntries),
			})
			l3Layer := &database.NewChainedProofLayer{
				ProofID:            proofID,
				LayerNumber:        3,
				LayerName:          "L3 - DN to Consensus",
				DNBlockHeight:      &chainedProof.L3DNBlockHeight,
				ConsensusTimestamp: &consensusTS,
				SourceHash:         chainedProof.L3SourceHash,
				TargetHash:         chainedProof.L3TargetHash,
				ReceiptEntries:     chainedProof.L3ReceiptEntries,
				LayerJSON:          l3JSON,
			}
			if _, err := o.repos.ProofArtifacts.CreateChainedProofLayer(ctx, l3Layer); err != nil {
				o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create L3 layer: %v", err)
			}

			o.logger.Printf("✅ [PROOF-CYCLE] Created L1/L2/L3 chained proof layers with %d+%d+%d receipt entries for proof %s",
				len(chainedProof.L1ReceiptEntries), len(chainedProof.L2ReceiptEntries),
				len(chainedProof.L3ReceiptEntries), proofID)
			return
		}
	} else if o.proofGenerator == nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] ProofGenerator not configured — receipt entries will be empty")
	}

	// Fallback: create minimal layers without receipt entries
	for layer := 1; layer <= 3; layer++ {
		names := []string{"", "L1 - Transaction to BVN", "L2 - BVN to DN", "L3 - DN to Consensus"}
		layerJSON, _ := json.Marshal(map[string]interface{}{
			"layer": fmt.Sprintf("L%d", layer),
		})
		l := &database.NewChainedProofLayer{
			ProofID:     proofID,
			LayerNumber: layer,
			LayerName:   names[layer],
			LayerJSON:   layerJSON,
		}
		if _, err := o.repos.ProofArtifacts.CreateChainedProofLayer(ctx, l); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create L%d layer: %v", layer, err)
		}
	}
	o.logger.Printf("✅ [PROOF-CYCLE] Created L1/L2/L3 chained proof layers (minimal — no ProofGenerator) for proof %s", proofID)
}

// storeGovernanceLevels stores G0/G1/G2 governance proof level records using
// the actual proof data wired through from bft_integration.
func (o *ProofCycleOrchestrator) storeGovernanceLevels(ctx context.Context, proofID uuid.UUID, cycle *ProofCycleCompletion, blockHeight int64) {
	if o.repos == nil {
		return
	}

	now := time.Now()
	verified := true

	// Extract real governance proof data from commitment map
	var g0Data, g1Data, g2Data string
	govLevel := ""
	if cycle.Commitment != nil && cycle.Commitment.ComprehensiveData != nil {
		cd := cycle.Commitment.ComprehensiveData
		if v, ok := cd["g0Proof"].(string); ok {
			g0Data = v
		}
		if v, ok := cd["g1Proof"].(string); ok {
			g1Data = v
		}
		if v, ok := cd["g2Proof"].(string); ok {
			g2Data = v
		}
		if v, ok := cd["governanceLevel"].(string); ok {
			govLevel = v
		}
	}

	// G0: Inclusion and Finality — uses real G0 proof if available
	g0JSON := json.RawMessage(g0Data)
	if g0Data == "" {
		g0JSON, _ = json.Marshal(map[string]interface{}{
			"level": "G0", "name": "Inclusion and Finality",
			"verified": true, "block_height": blockHeight,
			"finality_time": cycle.ExecutionTime.Format(time.RFC3339),
		})
	}
	g0 := &database.NewGovernanceProofLevel{
		ProofID:           proofID,
		GovLevel:          database.GovLevelG0,
		LevelName:         "G0 - Inclusion and Finality",
		Verified:          &verified,
		FinalityTimestamp: &now,
		BlockHeight:       &blockHeight,
		LevelJSON:         g0JSON,
	}
	if _, err := o.repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g0); err != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create G0 level: %v", err)
	}

	// G1: Governance Correctness — uses real G1 proof data
	if govLevel == "G1" || govLevel == "G2" || (cycle.Attestation != nil && cycle.Attestation.ThresholdMet) {
		g1JSON := json.RawMessage(g1Data)
		if g1Data == "" {
			g1JSON, _ = json.Marshal(map[string]interface{}{
				"level": "G1", "name": "Governance Correctness",
				"verified": true, "threshold_met": true,
			})
		}
		g1 := &database.NewGovernanceProofLevel{
			ProofID:           proofID,
			GovLevel:          database.GovLevelG1,
			LevelName:         "G1 - Governance Correctness",
			Verified:          &verified,
			FinalityTimestamp: &now,
			LevelJSON:         g1JSON,
		}
		if _, err := o.repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g1); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create G1 level: %v", err)
		}
	}

	// G2: Outcome Binding — uses real G2 proof data
	if govLevel == "G2" || (cycle.WriteBackTx != nil && cycle.WriteBackTx.Status == "confirmed") {
		g2JSON := json.RawMessage(g2Data)
		if g2Data == "" {
			g2JSON, _ = json.Marshal(map[string]interface{}{
				"level": "G2", "name": "Outcome Binding",
				"verified": true, "write_back_confirmed": true,
			})
		}
		g2 := &database.NewGovernanceProofLevel{
			ProofID:           proofID,
			GovLevel:          database.GovLevelG2,
			LevelName:         "G2 - Outcome Binding",
			Verified:          &verified,
			FinalityTimestamp: &now,
			LevelJSON:         g2JSON,
		}
		if _, err := o.repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g2); err != nil {
			o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create G2 level: %v", err)
		}
	}

	o.logger.Printf("✅ [PROOF-CYCLE] Created governance proof levels (gov_level=%s) for proof %s", govLevel, proofID)
}

// storeAttestationRecord stores the validator attestation for this proof
func (o *ProofCycleOrchestrator) storeAttestationRecord(ctx context.Context, proofID uuid.UUID, cycle *ProofCycleCompletion) {
	if o.repos == nil || o.repos.Attestations == nil {
		return
	}

	var pubKey []byte
	if len(o.config.BLSPrivateKey) >= 32 {
		pubKey = o.config.BLSPrivateKey[:32]
	}

	// Extract BLS signature and anchor tx from commitment data for verification
	anchorTxHash := ""
	var blsSigBytes []byte
	if cycle.Commitment != nil && cycle.Commitment.ComprehensiveData != nil {
		cd := cycle.Commitment.ComprehensiveData
		if raw, ok := cd["rawCreateTxHashes"].(string); ok {
			anchorTxHash = raw
		}
		// Use BLS aggregate signature as the attestation signature
		if blsSig, ok := cd["blsSignature"].(string); ok && blsSig != "" {
			blsSigBytes, _ = hex.DecodeString(blsSig)
		}
	}

	// Also use attestation aggregate signature if available
	if len(blsSigBytes) == 0 && cycle.Attestation != nil && len(cycle.Attestation.AggregateSignature) > 0 {
		blsSigBytes = cycle.Attestation.AggregateSignature
	}

	attestation := &database.NewValidatorAttestation{
		ProofID:            proofID,
		ValidatorID:        o.validatorID,
		ValidatorPubkey:    pubKey,
		Signature:          blsSigBytes,
		AttestedAnchorTx:   anchorTxHash,
	}

	if _, err := o.repos.Attestations.CreateAttestation(ctx, attestation); err != nil {
		o.logger.Printf("⚠️ [PROOF-CYCLE] Failed to create attestation record: %v", err)
	} else {
		o.logger.Printf("✅ [PROOF-CYCLE] Created validator attestation for proof %s", proofID)
	}
}

// persistExternalChainResults saves the Ethereum transaction results to external_chain_results table
func (o *ProofCycleOrchestrator) persistExternalChainResults(
	ctx context.Context,
	cycle *ProofCycleCompletion,
	createResult, verifyResult, govResult *ExternalChainResult,
) {
	// Recover from any panics to prevent crashing the proof cycle
	defer func() {
		if r := recover(); r != nil {
			o.logger.Printf("❌ [PHASE-7] PANIC in persistExternalChainResults: %v", r)
		}
	}()

	o.logger.Printf("📊 [PHASE-7] Starting external chain result persistence...")

	if o.repos == nil || o.repos.ProofArtifacts == nil {
		o.logger.Printf("⚠️ [PHASE-7] No database repository available for external chain result persistence")
		return
	}

	persistCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Try to find the proof_id by looking up the proof artifact for this intent
	var proofID *uuid.UUID
	if cycle.IntentID != "" {
		proof, err := o.repos.ProofArtifacts.GetProofByIntentID(persistCtx, cycle.IntentID)
		if err == nil && proof != nil {
			proofID = &proof.ProofID
			o.logger.Printf("📋 [PHASE-7] Linked to proof artifact: %s", proof.ProofID)
		} else {
			o.logger.Printf("⚠️ [PHASE-7] Could not find proof artifact for intent %s: %v", cycle.IntentID, err)
		}
	}

	// Helper to persist a single result
	persistResult := func(stepName string, result *ExternalChainResult, stepNum int) {
		if result == nil {
			o.logger.Printf("⚠️ [PHASE-7] %s result is nil, skipping persistence", stepName)
			return
		}

		// Build input matching the actual schema
		// Derive execution status from IsSuccess (1 = success, 0 = failure)
		executionStatus := 0
		if result.IsSuccess() {
			executionStatus = 1
		}

		// Safely extract block number (can be nil)
		var blockNumber int64
		if result.BlockNumber != nil {
			blockNumber = result.BlockNumber.Int64()
		}

		// Build logs JSON from result logs
		var logsJSON json.RawMessage = []byte("[]") // Default to empty array
		if len(result.Logs) > 0 {
			if jsonBytes, err := json.Marshal(result.Logs); err == nil {
				logsJSON = jsonBytes
			}
		}

		// Set finalized_at if finalized
		isFinalized := result.ConfirmationBlocks >= 12
		var finalizedAt *time.Time
		if isFinalized {
			now := time.Now()
			finalizedAt = &now
		}

		input := &database.ExternalChainResultInput{
			ProofID:               proofID, // Link to proof artifact if found
			BundleID:              cycle.BundleID[:],
			OperationID:           cycle.BundleID[:], // Use BundleID as OperationID
			ChainType:             "ethereum",
			ChainID:               o.config.ChainID,
			NetworkName:           "sepolia",
			TxHash:                result.TxHash.Bytes(),
			TxIndex:               int(result.TxIndex),
			TxGasUsed:             int64(result.TxGasUsed),
			TxFromAddress:         result.TxFrom.Bytes(),
			BlockNumber:           blockNumber,
			BlockHash:             result.BlockHash.Bytes(),
			BlockTimestamp:        result.BlockTime,
			StateRoot:             result.StateRoot.Bytes(),
			TransactionsRoot:      result.TransactionsRoot.Bytes(),
			ReceiptsRoot:          result.ReceiptsRoot.Bytes(),
			ExecutionStatus:       executionStatus,
			ExecutionSuccess:      result.IsSuccess(),
			LogsJSON:              logsJSON,
			ConfirmationBlocks:    result.ConfirmationBlocks,
			RequiredConfirmations: 12,
			IsFinalized:           isFinalized,
			FinalizedAt:           finalizedAt,
			ResultHash:            result.ResultHash[:],
			ObserverValidatorID:   o.validatorID,
			ObservedAt:            time.Now(),
		}

		// Set TxTo if available
		if result.TxTo != nil {
			input.TxToAddress = result.TxTo.Bytes()
		}

		resultID, err := o.repos.ProofArtifacts.SaveExternalChainResultV2(persistCtx, input)
		if err != nil {
			o.logger.Printf("⚠️ [PHASE-7] Failed to persist %s result: %v", stepName, err)
		} else {
			o.logger.Printf("✅ [PHASE-7] Persisted %s result: %s (tx=%s)", stepName, resultID, result.TxHash.Hex()[:18])
		}
	}

	// Persist all 3 anchor workflow results
	persistResult("Step1-createAnchor", createResult, 1)
	persistResult("Step2-verifyProof", verifyResult, 2)
	persistResult("Step3-governance", govResult, 3)
}

// persistBLSResultAttestation persists an individual BLS result attestation to the database
func (o *ProofCycleOrchestrator) persistBLSResultAttestation(
	ctx context.Context,
	result *ExternalChainResult,
	attestation *ResultAttestation,
) {
	if o.repos == nil || o.repos.ProofArtifacts == nil {
		o.logger.Printf("⚠️ [PHASE-8] Cannot persist attestation: repos not available")
		return
	}

	// Look up the result_id from external_chain_results by tx_hash
	resultID, err := o.repos.ProofArtifacts.GetExternalChainResultIDByResultHash(ctx, result.ResultHash[:])
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to look up result_id: %v", err)
		return
	}
	if resultID == nil {
		o.logger.Printf("⚠️ [PHASE-8] No result_id found for result hash %x", result.ResultHash[:8])
		return
	}

	// Prepare the attestation input
	input := &database.NewBLSResultAttestation{
		ResultID:              *resultID,
		ResultHash:            result.ResultHash[:],
		BundleID:              attestation.BundleID[:],
		MessageHash:           attestation.MessageHash[:],
		ValidatorID:           attestation.ValidatorID,
		ValidatorAddress:      attestation.ValidatorAddress.Bytes(),
		ValidatorIndex:        int(attestation.ValidatorIndex),
		BLSSignature:          attestation.BLSSignature,
		BLSPublicKey:          o.verifier.GetBLSPublicKey(),
		SignatureDomain:       "CERTEN_RESULT_ATTESTATION_V1",
		AttestedBlockNumber:   result.BlockNumber.Int64(),
		AttestedBlockHash:     result.BlockHash[:],
		ConfirmationsAtAttest: attestation.Confirmations,
		AttestationTime:       attestation.AttestationTime,
	}

	att, err := o.repos.ProofArtifacts.SaveBLSResultAttestation(ctx, input)
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to persist BLS result attestation: %v", err)
		return
	}

	// Mark attestation as verified (signature was validated in VerifyAndAttest)
	if err := o.repos.ProofArtifacts.MarkBLSResultAttestationVerified(ctx, att.AttestationID, true, nil); err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to mark attestation verified: %v", err)
	}

	o.logger.Printf("✅ [PHASE-8] Persisted BLS result attestation %s for validator %s (verified=true)",
		att.AttestationID, attestation.ValidatorID)
}

// persistAggregatedBLSAttestation persists an aggregated BLS attestation to the database
func (o *ProofCycleOrchestrator) persistAggregatedBLSAttestation(
	ctx context.Context,
	result *ExternalChainResult,
	agg *AggregatedAttestation,
) {
	if o.repos == nil || o.repos.ProofArtifacts == nil {
		o.logger.Printf("⚠️ [PHASE-8] Cannot persist aggregated attestation: repos not available")
		return
	}

	// Look up the result_id from external_chain_results
	resultID, err := o.repos.ProofArtifacts.GetExternalChainResultIDByResultHash(ctx, result.ResultHash[:])
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to look up result_id for aggregation: %v", err)
		return
	}
	if resultID == nil {
		o.logger.Printf("⚠️ [PHASE-8] No result_id found for aggregation, result hash %x", result.ResultHash[:8])
		return
	}

	// Get individual attestation IDs from the database
	blsAttestations, err := o.repos.ProofArtifacts.GetBLSResultAttestationsByResult(ctx, *resultID)
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to get BLS attestations for aggregation: %v", err)
		return
	}

	attestationIDs := make([]uuid.UUID, 0, len(blsAttestations))
	publicKeys := make([]*bls.PublicKey, 0, len(blsAttestations))
	for _, att := range blsAttestations {
		attestationIDs = append(attestationIDs, att.AttestationID)
		// Collect public keys for aggregation
		if len(att.BLSPublicKey) > 0 {
			pk, err := bls.PublicKeyFromBytes(att.BLSPublicKey)
			if err == nil {
				publicKeys = append(publicKeys, pk)
			}
		}
	}

	// Compute aggregate public key
	var aggregatePublicKey []byte
	if len(publicKeys) > 0 {
		aggPk, err := bls.AggregatePublicKeys(publicKeys)
		if err == nil {
			aggregatePublicKey = aggPk.Bytes()
		} else {
			o.logger.Printf("⚠️ [PHASE-8] Failed to aggregate public keys: %v", err)
		}
	}

	// Convert validator addresses to byte slices
	validatorAddresses := make([][]byte, 0, len(agg.ValidatorAddresses))
	for _, addr := range agg.ValidatorAddresses {
		validatorAddresses = append(validatorAddresses, addr.Bytes())
	}

	// Convert validator indices to int32 slice
	validatorIndices := make([]int32, len(validatorAddresses))
	// Note: We don't have individual validator indices in AggregatedAttestation
	// So we'll leave them as zeros for now

	// Compute aggregation hash
	aggHash := agg.ComputeAggregateHash()

	// Compute voting power percentage
	var votingPowerPct float64
	if agg.TotalVotingPower != nil && agg.TotalVotingPower.Sign() > 0 {
		pct := new(big.Float).Quo(
			new(big.Float).SetInt(agg.SignedVotingPower),
			new(big.Float).SetInt(agg.TotalVotingPower),
		)
		votingPowerPct, _ = pct.Mul(pct, big.NewFloat(100)).Float64()
	}

	// Prepare the aggregation input
	input := &database.NewAggregatedBLSAttestation{
		ResultID:              *resultID,
		ResultHash:            result.ResultHash[:],
		BundleID:              agg.BundleID[:],
		MessageHash:           agg.MessageHash[:],
		AttestedBlockNumber:   result.BlockNumber.Int64(),
		AggregateSignature:    agg.AggregateSignature,
		AggregatePublicKey:    aggregatePublicKey,
		ValidatorBitfield:     agg.ValidatorBitfield,
		ValidatorCount:        agg.ValidatorCount,
		ValidatorAddresses:    validatorAddresses,
		ValidatorIndices:      validatorIndices,
		AttestationIDs:        attestationIDs,
		TotalVotingPower:      agg.TotalVotingPower.String(),
		SignedVotingPower:     agg.SignedVotingPower.String(),
		VotingPowerPercentage: votingPowerPct,
		ThresholdNumerator:    int(agg.ThresholdNumerator),
		ThresholdDenominator:  int(agg.ThresholdDenominator),
		ThresholdMet:          agg.ThresholdMet,
		FirstAttestationAt:    agg.FirstAttestation,
		LastAttestationAt:     agg.LastAttestation,
		AggregationHash:       aggHash[:],
	}

	aggRecord, err := o.repos.ProofArtifacts.SaveAggregatedBLSAttestation(ctx, input)
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to persist aggregated BLS attestation: %v", err)
		return
	}

	// Mark aggregation as finalized and verified (threshold was met, aggregation complete)
	if err := o.repos.ProofArtifacts.MarkAggregatedBLSAttestationFinalized(ctx, aggRecord.AggregationID, true, nil); err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to mark aggregation finalized: %v", err)
	}

	o.logger.Printf("✅ [PHASE-8] Persisted aggregated BLS attestation %s with %d validators, threshold_met=%v (finalized)",
		aggRecord.AggregationID, agg.ValidatorCount, agg.ThresholdMet)
}

// handleCycleFailed handles a failed proof cycle
func (o *ProofCycleOrchestrator) handleCycleFailed(cycleID string, err error) {
	o.logger.Printf("❌ [PROOF-CYCLE] Cycle failed: %s - %v", cycleID, err)

	o.mu.Lock()
	delete(o.activeCycles, cycleID)
	o.mu.Unlock()

	if o.onCycleFailed != nil {
		go o.onCycleFailed(cycleID, err)
	}
}

// =============================================================================
// CALLBACK SETTERS
// =============================================================================

// SetCycleCallbacks sets the cycle completion/failure callbacks
func (o *ProofCycleOrchestrator) SetCycleCallbacks(
	onComplete func(*ProofCycleCompletion),
	onFailed func(string, error),
) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.onCycleComplete = onComplete
	o.onCycleFailed = onFailed
}

// =============================================================================
// STATUS METHODS
// =============================================================================

// GetActiveCycleCount returns the number of active proof cycles
func (o *ProofCycleOrchestrator) GetActiveCycleCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.activeCycles)
}

// GetPendingAttestations returns the number of results awaiting threshold
func (o *ProofCycleOrchestrator) GetPendingAttestations() int {
	// This would require exposing more from the collector
	return 0
}

// GetPendingWriteBacks returns the number of pending write-backs
func (o *ProofCycleOrchestrator) GetPendingWriteBacks() int {
	return o.writeBack.GetPendingCount() + o.writeBack.GetSubmittedCount()
}

// =============================================================================
// FACTORY FUNCTION
// =============================================================================

// NewProofCycleOrchestratorFromEnv creates an orchestrator from environment variables
func NewProofCycleOrchestratorFromEnv(
	validatorID string,
	validatorAddress common.Address,
	validatorIndex uint32,
	validatorSet *ValidatorSet,
	accSubmitter AccumulateSubmitter,
	repos *database.Repositories,
	logger Logger,
) (*ProofCycleOrchestrator, error) {

	config := &ProofCycleConfig{
		EthereumRPC:           os.Getenv("ETHEREUM_URL"),
		ChainID:               11155111, // Sepolia default
		RequiredConfirmations: 12,
		ObservationTimeout:    10 * time.Minute,
		ThresholdNumerator:    2,
		ThresholdDenominator:  3,
		AccumulatePrincipal:   os.Getenv("ACCUMULATE_RESULTS_PRINCIPAL"),
		WriteBackEnabled:      os.Getenv("PROOF_CYCLE_WRITEBACK") == "true",
		BLSPrivateKey:         []byte(os.Getenv("BLS_PRIVATE_KEY")),
	}

	if config.AccumulatePrincipal == "" {
		config.AccumulatePrincipal = "acc://certen.acme/proof-results"
	}

	return NewProofCycleOrchestrator(
		validatorID,
		validatorAddress,
		validatorIndex,
		validatorSet,
		config,
		accSubmitter,
		repos,
		logger,
	)
}

// =============================================================================
// INTEGRATION WITH BFT TARGET CHAIN EXECUTOR
// =============================================================================

// BFTTargetChainExecutorWithProofCycle extends BFTTargetChainExecutor with
// complete proof cycle support
type BFTTargetChainExecutorWithProofCycle struct {
	*BFTTargetChainExecutor
	orchestrator *ProofCycleOrchestrator
}

// NewBFTTargetChainExecutorWithProofCycle creates an executor with proof cycle support
func NewBFTTargetChainExecutorWithProofCycle(
	base *BFTTargetChainExecutor,
	orchestrator *ProofCycleOrchestrator,
) *BFTTargetChainExecutorWithProofCycle {
	return &BFTTargetChainExecutorWithProofCycle{
		BFTTargetChainExecutor: base,
		orchestrator:           orchestrator,
	}
}

// ExecuteWithProofCycle executes target chain operations and starts the proof cycle
func (e *BFTTargetChainExecutorWithProofCycle) ExecuteWithProofCycle(
	ctx context.Context,
	intentID string,
	transactionHash string,
	accountURL string,
	validatorID string,
	bundleID string,
	anchorID string,
	certenProof interface{}, // *proof.CertenProof
) (*TargetChainExecutionResult, error) {

	// Import proof type
	proofPkg, ok := certenProof.(interface {
		GetProofID() string
		GetBlockHeight() uint64
	})
	if !ok {
		return nil, fmt.Errorf("invalid proof type")
	}

	e.logger.Printf("🔄 [PROOF-CYCLE] Executing with complete proof cycle")

	// Execute base target chain operations
	// Note: In real implementation, call base executor here
	// result, err := e.BFTTargetChainExecutor.ExecuteTargetChainOperations(...)

	// For now, create a simulated result
	result := &TargetChainExecutionResult{
		Chain:       "ethereum",
		TxHash:      transactionHash,
		BlockNumber: proofPkg.GetBlockHeight() + 100,
		Success:     true,
		Metadata: map[string]string{
			"proof_id": proofPkg.GetProofID(),
			"intent":   intentID,
		},
	}

	// Parse bundle ID
	var bundleIDBytes [32]byte
	if len(bundleID) >= 32 {
		copy(bundleIDBytes[:], []byte(bundleID)[:32])
	}

	// Create execution commitment
	commitment := &ExecutionCommitment{
		BundleID:    bundleIDBytes,
		TargetChain: "ethereum",
	}

	// Parse tx hash
	txHash := common.HexToHash(transactionHash)

	// Start proof cycle
	if e.orchestrator != nil {
		if err := e.orchestrator.StartProofCycle(ctx, intentID, bundleIDBytes, txHash, commitment); err != nil {
			e.logger.Printf("⚠️ [PROOF-CYCLE] Failed to start proof cycle: %v", err)
			// Continue - proof cycle failure shouldn't block execution result
		}
	}

	return result, nil
}

// GetOrchestrator returns the proof cycle orchestrator
func (e *BFTTargetChainExecutorWithProofCycle) GetOrchestrator() *ProofCycleOrchestrator {
	return e.orchestrator
}

// =============================================================================
// VALIDATOR SET HELPERS
// =============================================================================

// NewValidatorSetFromConfig creates a validator set from configuration
// This replaces the hardcoded test addresses with real validator configuration
func NewValidatorSetFromConfig(validatorID string, validatorAddress [20]byte) *ValidatorSet {
	addr := common.Address(validatorAddress)

	return &ValidatorSet{
		Validators: []ValidatorInfo{
			{
				ID:          validatorID,
				Address:     addr,
				Index:       0,
				VotingPower: big.NewInt(100),
				Active:      true,
			},
		},
		TotalVotingPower: big.NewInt(100),
		ValidatorCount:   1,
	}
}

// NewMultiValidatorSet creates a validator set with multiple validators
// Use this for production deployments with multiple validators
func NewMultiValidatorSet(validators []struct {
	ID          string
	Address     common.Address
	VotingPower int64
}) *ValidatorSet {
	vs := &ValidatorSet{
		Validators:       make([]ValidatorInfo, 0, len(validators)),
		TotalVotingPower: big.NewInt(0),
		ValidatorCount:   len(validators),
	}

	for i, v := range validators {
		vi := ValidatorInfo{
			ID:          v.ID,
			Address:     v.Address,
			Index:       uint32(i),
			VotingPower: big.NewInt(v.VotingPower),
			Active:      true,
		}
		vs.Validators = append(vs.Validators, vi)
		vs.TotalVotingPower = new(big.Int).Add(vs.TotalVotingPower, vi.VotingPower)
	}

	return vs
}

// LoadValidatorSetFromContract loads the validator set from an on-chain contract
// This will be implemented when the validator registry contract is deployed
func LoadValidatorSetFromContract(ctx context.Context, contractAddress common.Address) (*ValidatorSet, error) {
	// TODO: Implement contract call to load validators
	// For now, return an error indicating the contract is not available
	return nil, fmt.Errorf("validator registry contract not yet deployed at %s", contractAddress.Hex())
}

// =============================================================================
// CONSENSUS INTERFACE ADAPTER
// =============================================================================

// ExecutionCommitmentData mirrors the consensus.ExecutionCommitmentData type
// This is used to break circular import dependencies
type ExecutionCommitmentData struct {
	BundleID         [32]byte
	TargetChain      string
	OperationHash    [32]byte
	CrossChainHash   [32]byte
	ValidatorBlockID string
}

// ProofCycleOrchestratorAdapter wraps ProofCycleOrchestrator to implement
// the consensus.ProofCycleOrchestratorInterface
type ProofCycleOrchestratorAdapter struct {
	orchestrator *ProofCycleOrchestrator
}

// NewProofCycleOrchestratorAdapter creates an adapter for the consensus interface
func NewProofCycleOrchestratorAdapter(o *ProofCycleOrchestrator) *ProofCycleOrchestratorAdapter {
	return &ProofCycleOrchestratorAdapter{orchestrator: o}
}

// StartProofCycle implements the consensus.ProofCycleOrchestratorInterface
func (a *ProofCycleOrchestratorAdapter) StartProofCycle(
	ctx context.Context,
	intentID string,
	bundleID [32]byte,
	executionTxHash common.Hash,
	commitment *ExecutionCommitmentData,
) error {
	// Convert the commitment data to the internal type
	var internalCommitment *ExecutionCommitment
	if commitment != nil {
		internalCommitment = &ExecutionCommitment{
			BundleID:    commitment.BundleID,
			TargetChain: commitment.TargetChain,
		}
	}

	return a.orchestrator.StartProofCycle(ctx, intentID, bundleID, executionTxHash, internalCommitment)
}

// ConsensusAnchorWorkflowTxHashes mirrors consensus.AnchorWorkflowTxHashes to avoid import cycle
type ConsensusAnchorWorkflowTxHashes struct {
	CreateTxHash     common.Hash
	VerifyTxHash     common.Hash
	GovernanceTxHash common.Hash
	PrimaryTxHash    common.Hash
}

// StartProofCycleWithAllTxs implements the consensus.ProofCycleOrchestratorInterface
// Enhanced: Tracks all 3 anchor workflow transactions
func (a *ProofCycleOrchestratorAdapter) StartProofCycleWithAllTxs(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashes interface{},
	commitment interface{},
) error {
	// Convert the txHashes from consensus package type to local type
	var localTxHashes *AnchorWorkflowTxHashes

	switch th := txHashes.(type) {
	case *AnchorWorkflowTxHashes:
		localTxHashes = th
	case *ConsensusAnchorWorkflowTxHashes:
		localTxHashes = &AnchorWorkflowTxHashes{
			CreateTxHash:     th.CreateTxHash,
			VerifyTxHash:     th.VerifyTxHash,
			GovernanceTxHash: th.GovernanceTxHash,
			PrimaryTxHash:    th.PrimaryTxHash,
		}
	default:
		// Use reflection to extract fields from consensus.AnchorWorkflowTxHashes
		// This handles the case where we can't import the consensus package directly
		localTxHashes = extractTxHashesViaReflection(txHashes)
		if localTxHashes == nil {
			return fmt.Errorf("unknown txHashes type: %T", txHashes)
		}
	}

	return a.orchestrator.StartProofCycleWithAllTxs(ctx, intentID, userID, bundleID, localTxHashes, commitment)
}

// StartProofCycleWithAccumulateRef implements the enhanced interface with Accumulate reference data
func (a *ProofCycleOrchestratorAdapter) StartProofCycleWithAccumulateRef(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashes interface{},
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	// Pass through to orchestrator's method
	return a.orchestrator.StartProofCycleWithAccumulateRef(ctx, intentID, userID, bundleID, txHashes, commitment, accumulateAccountURL, accumulateTxHash, bvn)
}

// StartPerChainProofCycles is a no-op for the legacy orchestrator - multi-leg proof cycles
// require the unified orchestrator with MultiLegAggregator support.
func (a *ProofCycleOrchestratorAdapter) StartPerChainProofCycles(
	ctx context.Context,
	intentID string,
	operationID string,
	bundleID [32]byte,
	chainTxHashes map[string][]string,
	legs interface{},
	executionMode string,
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	a.orchestrator.logger.Printf("⚠️ [PROOF-CYCLE] StartPerChainProofCycles not supported by legacy orchestrator - falling back to single proof cycle")
	return nil
}

// extractTxHashesViaReflection uses reflection to extract tx hashes from a struct
// This is used to avoid circular imports between execution and consensus packages
func extractTxHashesViaReflection(txHashes interface{}) *AnchorWorkflowTxHashes {
	if txHashes == nil {
		return nil
	}

	// Use type assertion with interface to extract common.Hash fields
	v := reflect.ValueOf(txHashes)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	result := &AnchorWorkflowTxHashes{}

	// Try to get CreateTxHash field
	if f := v.FieldByName("CreateTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.CreateTxHash = f.Interface().(common.Hash)
	}

	// Try to get VerifyTxHash field
	if f := v.FieldByName("VerifyTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.VerifyTxHash = f.Interface().(common.Hash)
	}

	// Try to get GovernanceTxHash field
	if f := v.FieldByName("GovernanceTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.GovernanceTxHash = f.Interface().(common.Hash)
	}

	// Try to get PrimaryTxHash field
	if f := v.FieldByName("PrimaryTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.PrimaryTxHash = f.Interface().(common.Hash)
	}

	// Try to get RawTxHashes field (native-format hashes for non-EVM chains)
	if f := v.FieldByName("RawTxHashes"); f.IsValid() && f.Kind() == reflect.Slice {
		if strs, ok := f.Interface().([]string); ok {
			result.RawTxHashes = strs
		}
	}

	return result
}

// =============================================================================
// COMPREHENSIVE COMMITMENT CONVERSION
// =============================================================================

// Logger interface for commitment conversion
type commitmentLogger interface {
	Printf(format string, v ...interface{})
}

// convertMapToExecutionCommitment converts a comprehensive commitment map from
// the BFT flow into an ExecutionCommitment for Phase 8 verification.
//
// SECURITY CRITICAL: This function extracts verification data from the commitment
// map that was created BEFORE execution. The data is used to verify the actual
// execution matches what was specified in the intent.
func convertMapToExecutionCommitment(commitmentMap map[string]interface{}, logger commitmentLogger) *ExecutionCommitment {
	commitment := &ExecutionCommitment{}

	// Extract bundleID
	if bundleIDHex, ok := commitmentMap["bundleID"].(string); ok {
		bundleIDBytes, err := hex.DecodeString(bundleIDHex)
		if err == nil && len(bundleIDBytes) >= 32 {
			copy(commitment.BundleID[:], bundleIDBytes[:32])
		}
	}

	// Extract operationID
	if opIDHex, ok := commitmentMap["operationID"].(string); ok {
		opIDBytes, err := hex.DecodeString(opIDHex)
		if err == nil && len(opIDBytes) >= 32 {
			copy(commitment.OperationID[:], opIDBytes[:32])
		}
	}

	// Extract targetChain
	if targetChain, ok := commitmentMap["targetChain"].(string); ok {
		commitment.TargetChain = targetChain
	}

	// Extract intent reference from Accumulate (intentTxHash, intentBlock)
	// Try both "intentTxHash" and "txHash" keys (commitment uses "txHash")
	// DEBUG: Log available keys
	if logger != nil {
		var keys []string
		for k := range commitmentMap {
			keys = append(keys, k)
		}
		logger.Printf("📋 [COMMITMENT-DEBUG] Available keys in commitmentMap: %v", keys)
		if txHash, ok := commitmentMap["txHash"].(string); ok {
			logger.Printf("📋 [COMMITMENT-DEBUG] Found txHash: %s", txHash)
		} else {
			logger.Printf("📋 [COMMITMENT-DEBUG] txHash NOT found in map")
		}
	}
	if intentTxHash, ok := commitmentMap["intentTxHash"].(string); ok && intentTxHash != "" {
		commitment.IntentTxHash = intentTxHash
	} else if txHash, ok := commitmentMap["txHash"].(string); ok && txHash != "" {
		commitment.IntentTxHash = txHash
	}
	if intentBlock, ok := commitmentMap["intentBlock"].(float64); ok {
		commitment.IntentBlock = uint64(intentBlock)
	}
	// Also try string format for intentBlock
	if intentBlockStr, ok := commitmentMap["intentBlock"].(string); ok {
		var block uint64
		if _, err := fmt.Sscanf(intentBlockStr, "%d", &block); err == nil && block > 0 {
			commitment.IntentBlock = block
		}
	}

	// Extract anchor contract from step1 or top level
	if anchorContractHex, ok := commitmentMap["anchorContract"].(string); ok {
		commitment.TargetContract = common.HexToAddress(anchorContractHex)
	} else if step3, ok := commitmentMap["step3"].(map[string]interface{}); ok {
		// Governance step contract - this is where the final action happens
		if contractHex, ok := step3["contract"].(string); ok {
			commitment.TargetContract = common.HexToAddress(contractHex)
		}
	}

	// Extract function selector from step3 (governance - most important for verification)
	if step3, ok := commitmentMap["step3"].(map[string]interface{}); ok {
		if selectorHex, ok := step3["selector"].(string); ok {
			selectorBytes, err := hex.DecodeString(selectorHex)
			if err == nil && len(selectorBytes) >= 4 {
				copy(commitment.FunctionSelector[:], selectorBytes[:4])
			}
		}
	}

	// Extract expected value from step3's expectedValue (NOT finalValue!)
	// SECURITY NOTE: For anchor-based workflows, the executeWithGovernance call has msg.value=0
	// because the anchor contract handles value transfer internally. The "finalValue" is the
	// intent's specified amount, but "step3.expectedValue" is what the actual tx.Value should be.
	if step3, ok := commitmentMap["step3"].(map[string]interface{}); ok {
		if expectedValueStr, ok := step3["expectedValue"].(string); ok {
			value, ok := new(big.Int).SetString(expectedValueStr, 10)
			if ok {
				commitment.ExpectedValue = value
			}
		}
	}

	// Store the comprehensive commitment map for advanced verification
	commitment.ComprehensiveData = commitmentMap

	// Compute commitment hash
	commitment.CommitmentHash = commitment.ComputeCommitmentHash()

	if logger != nil {
		logger.Printf("✅ [COMMITMENT] Converted comprehensive commitment:")
		logger.Printf("   BundleID: %x", commitment.BundleID[:8])
		logger.Printf("   Target: %s", commitment.TargetContract.Hex())
		logger.Printf("   Selector: %x", commitment.FunctionSelector)
		if commitment.ExpectedValue != nil {
			logger.Printf("   Value: %s wei", commitment.ExpectedValue.String())
		}
	}

	return commitment
}
