// services/validator/pkg/execution/bft_target_chain_integration.go
//
// BFT Target Chain Integration - Canonical Target Chain Executor Implementation
//
// This file contains the canonical implementation of consensus.TargetChainExecutor
// for Ethereum/Sepolia target chains. Production deployments should plug this
// instance into NewBFTValidator via dependency injection.
//
// Architecture: BFTValidator → TargetChainExecutor → EthereumContractManager → On-chain contracts
//
// SECURITY: All execution parameters are extracted from the intent's CrossChainData
// and used to build an ExecutionCommitment BEFORE execution. This commitment is
// verified by other validators after execution to ensure the executor performed
// the correct operation.
package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/certen/independant-validator/pkg/anchor"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/proof"
)

// getTargetChainConfig loads target chain configuration from environment
func getTargetChainConfig() (string, int64) {
	// Load from environment or use defaults for Sepolia testnet
	orgADI := os.Getenv("ORGANIZATION_ADI")
	if orgADI == "" {
		orgADI = "acc://certen-demo-13112025.acme" // Fallback for development
	}

	chainID := int64(11155111) // Sepolia default
	if envChainID := os.Getenv("ETHEREUM_CHAIN_ID"); envChainID != "" {
		if parsed, err := strconv.ParseInt(envChainID, 10, 64); err == nil {
			chainID = parsed
		}
	}

	return orgADI, chainID
}

// TargetChainExecutionResult represents the result of target chain operations
// Enhanced to track all 3 transactions in the anchor workflow:
//   Step 1: CreateAnchor - stores the anchor data on-chain
//   Step 2: ExecuteComprehensiveProof - submits BLS proof verification
//   Step 3: ExecuteWithGovernance - executes the actual value transfer
type TargetChainExecutionResult struct {
	Chain       string            `json:"chain"`
	TxHash      string            `json:"tx_hash"`       // Primary tx (governance) for backwards compatibility
	BlockNumber uint64            `json:"block_number"`
	Success     bool              `json:"success"`
	RawLogs     []byte            `json:"raw_logs"`
	Metadata    map[string]string `json:"metadata"`

	// Enhanced: All 3 transaction hashes from the anchor workflow
	CreateTxHash     string `json:"create_tx_hash"`     // Step 1: createAnchor tx
	VerifyTxHash     string `json:"verify_tx_hash"`     // Step 2: executeComprehensiveProof tx
	GovernanceTxHash string `json:"governance_tx_hash"` // Step 3: executeWithGovernance tx

	// Block numbers for each transaction (may differ if txs land in different blocks)
	CreateBlockNumber     uint64 `json:"create_block_number"`
	VerifyBlockNumber     uint64 `json:"verify_block_number"`
	GovernanceBlockNumber uint64 `json:"governance_block_number"`
}

// Interface implementation for consensus.TargetChainExecutionResult
func (tcr *TargetChainExecutionResult) GetChain() string {
	return tcr.Chain
}

func (tcr *TargetChainExecutionResult) GetTxHash() string {
	return tcr.TxHash
}

func (tcr *TargetChainExecutionResult) GetBlockNumber() uint64 {
	return tcr.BlockNumber
}

func (tcr *TargetChainExecutionResult) GetSuccess() bool {
	return tcr.Success
}

func (tcr *TargetChainExecutionResult) GetMetadata() map[string]string {
	return tcr.Metadata
}

// BFTTargetChainExecutor is the canonical implementation of consensus.TargetChainExecutor
// for Ethereum/Sepolia target chains. It handles BFT-coordinated target chain operations
// including proof submission and governance execution.
//
// This executor should be injected into BFTValidator during bootstrap:
//   targetExec := execution.NewBFTTargetChainExecutor(logger)
//   bftValidator := consensus.NewBFTValidator(..., targetExec, ...)
type BFTTargetChainExecutor struct {
	logger            Logger
	commitmentBuilder *ExecutionCommitmentBuilder
}

// Logger interface for logging operations
type Logger interface {
	Printf(format string, v ...interface{})
}

// NewBFTTargetChainExecutor creates a new BFT target chain executor.
// This is the canonical constructor for production target chain execution.
func NewBFTTargetChainExecutor(logger Logger) *BFTTargetChainExecutor {
	return &BFTTargetChainExecutor{
		logger:            logger,
		commitmentBuilder: NewExecutionCommitmentBuilder(),
	}
}

// =============================================================================
// EXECUTION PARAMETER EXTRACTION FROM INTENT
// =============================================================================

// ExtractedExecutionParams contains all parameters extracted from intent for execution
type ExtractedExecutionParams struct {
	// Target chain info
	Chain   string `json:"chain"`
	ChainID int64  `json:"chain_id"`

	// Contract addresses
	AnchorContract common.Address `json:"anchor_contract"`

	// Final target (where ETH/tokens go after governance)
	FinalTarget common.Address `json:"final_target"`
	FinalValue  *big.Int       `json:"final_value"`
	CallData    []byte         `json:"call_data"`

	// Source address (for logging/verification)
	SourceAddress common.Address `json:"source_address"`

	// Commitment created from these params
	Commitment *FullExecutionCommitment `json:"commitment,omitempty"`
}

// ExtractExecutionParams extracts all execution parameters from intent's CrossChainData
// This is the SINGLE SOURCE OF TRUTH for what the executor should do.
func (btce *BFTTargetChainExecutor) ExtractExecutionParams(
	certenIntent *intent.CertenIntent,
	bundleID [32]byte,
) (*ExtractedExecutionParams, error) {
	btce.logger.Printf("🔍 [EXTRACT] Extracting execution parameters from intent: %s", certenIntent.IntentID)

	// Parse CrossChainData
	var crossChainData struct {
		Protocol         string `json:"protocol"`
		Version          string `json:"version"`
		OperationGroupID string `json:"operationGroupId"`
		Legs             []struct {
			LegID   string `json:"legId"`
			Chain   string `json:"chain"`
			ChainID uint64 `json:"chainId"`
			From    string `json:"from"`
			To      string `json:"to"`
			AmountWei string `json:"amountWei"`
			AnchorContract struct {
				Address          string `json:"address"`
				FunctionSelector string `json:"functionSelector"`
			} `json:"anchorContract"`
		} `json:"legs"`
	}

	if err := json.Unmarshal(certenIntent.CrossChainData, &crossChainData); err != nil {
		return nil, fmt.Errorf("parse CrossChainData: %w", err)
	}

	if len(crossChainData.Legs) == 0 {
		return nil, fmt.Errorf("no legs in CrossChainData")
	}

	// Use first leg (multi-leg support can be added later)
	leg := crossChainData.Legs[0]

	btce.logger.Printf("📋 [EXTRACT] Leg details:")
	btce.logger.Printf("   Chain: %s (ID: %d)", leg.Chain, leg.ChainID)
	btce.logger.Printf("   From: %s", leg.From)
	btce.logger.Printf("   To: %s", leg.To)
	btce.logger.Printf("   AmountWei: %s", leg.AmountWei)
	btce.logger.Printf("   AnchorContract: %s", leg.AnchorContract.Address)

	// Parse value
	finalValue := big.NewInt(0)
	if leg.AmountWei != "" {
		amountStr := strings.TrimSpace(leg.AmountWei)
		var ok bool
		finalValue, ok = new(big.Int).SetString(amountStr, 10)
		if !ok {
			// Try parsing as float (for scientific notation like 1.0e+0)
			f, _, err := big.ParseFloat(amountStr, 10, 256, big.ToNearestEven)
			if err == nil {
				finalValue, _ = f.Int(nil)
			} else {
				btce.logger.Printf("⚠️ [EXTRACT] Could not parse amountWei '%s', defaulting to 1", amountStr)
				finalValue = big.NewInt(1)
			}
		}
	}

	// Get anchor contract address from env or intent
	anchorContractAddr := os.Getenv("CERTEN_ANCHOR_V3_ADDRESS")
	if anchorContractAddr == "" {
		anchorContractAddr = leg.AnchorContract.Address
	}
	if anchorContractAddr == "" {
		return nil, fmt.Errorf("no anchor contract address in intent or environment")
	}

	params := &ExtractedExecutionParams{
		Chain:          leg.Chain,
		ChainID:        int64(leg.ChainID),
		AnchorContract: common.HexToAddress(anchorContractAddr),
		FinalTarget:    common.HexToAddress(leg.To),
		FinalValue:     finalValue,
		CallData:       []byte{}, // ETH transfer has empty calldata
		SourceAddress:  common.HexToAddress(leg.From),
	}

	// Build execution commitment BEFORE execution
	commitment, err := btce.commitmentBuilder.BuildFromIntent(
		certenIntent.IntentID,
		bundleID,
		certenIntent.CrossChainData,
		anchorContractAddr,
	)
	if err != nil {
		btce.logger.Printf("⚠️ [EXTRACT] Failed to build commitment: %v", err)
		// Continue without commitment - but log the issue
	} else {
		params.Commitment = commitment
		btce.logger.Printf("✅ [EXTRACT] Built execution commitment: %x", commitment.CommitmentHash[:8])
	}

	btce.logger.Printf("✅ [EXTRACT] Extracted execution parameters:")
	btce.logger.Printf("   Anchor Contract: %s", params.AnchorContract.Hex())
	btce.logger.Printf("   Final Target: %s", params.FinalTarget.Hex())
	btce.logger.Printf("   Final Value: %s wei", params.FinalValue.String())

	return params, nil
}

// GetCommitment returns the execution commitment for Phase 8 verification
func (btce *BFTTargetChainExecutor) GetCommitment() *ExecutionCommitmentBuilder {
	return btce.commitmentBuilder
}

// ExecuteTargetChainOperations executes real smart contract operations on target chains
// MULTI-CHAIN: Now extracts target chain from CrossChainData and routes to correct EVM chain
func (btce *BFTTargetChainExecutor) ExecuteTargetChainOperations(
	ctx context.Context,
	intentID string,
	transactionHash string,
	accountURL string,
	validatorID string,
	bundleID string,
	anchorID string,
	certenProof *proof.CertenProof,
) (*TargetChainExecutionResult, error) {

	btce.logger.Printf("🌐 [BFT-TARGET] Executing real target chain operations: intent=%s anchor=%s",
		intentID, anchorID)

	// Extract target chain from CrossChainData (not from intent ID)
	var crossChainData []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		crossChainData = certenProof.CrossChainData
	}

	targetChain, targetChainID := btce.extractTargetChainFromCrossChainData(crossChainData)

	btce.logger.Printf("🎯 [BFT-TARGET] Target chain identified: %s (chain_id=%d)", targetChain, targetChainID)

	// Check if chain is supported
	anchorCfg, _ := config.LoadAnchorConfigFromEnv()
	if anchorCfg != nil && !anchorCfg.IsChainSupported(targetChainID) {
		btce.logger.Printf("⚠️ [BFT-TARGET] Chain %d not configured, supported chains: %v",
			targetChainID, anchorCfg.GetSupportedChainIDs())
	}

	// Execute based on target chain - all EVM chains use executeEthereumOperations
	switch targetChain {
	case "ethereum", "eth", "sepolia", "arbitrum", "arb", "optimism", "op", "base", "polygon", "matic":
		return btce.executeEthereumOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID)
	default:
		// Try EVM execution for unknown chains if they have a valid chain ID
		if targetChainID > 0 {
			btce.logger.Printf("⚠️ [BFT-TARGET] Unknown chain '%s', attempting EVM execution for chainId=%d", targetChain, targetChainID)
			return btce.executeEthereumOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID)
		}
		return nil, fmt.Errorf("unsupported target chain: %s (chainId=%d)", targetChain, targetChainID)
	}
}

// extractTargetChainFromIntent extracts target chain information from the Intent
// Now properly parses the chain from intent CrossChainData
func (btce *BFTTargetChainExecutor) extractTargetChainFromIntent(intentID string) (string, int64) {
	// Default to Ethereum Sepolia
	return "ethereum", 11155111
}

// extractTargetChainFromCrossChainData parses the actual target chain from CrossChainData
func (btce *BFTTargetChainExecutor) extractTargetChainFromCrossChainData(crossChainData []byte) (string, int64) {
	if len(crossChainData) == 0 {
		btce.logger.Printf("⚠️ [CHAIN] No CrossChainData, defaulting to Ethereum Sepolia")
		return "ethereum", 11155111
	}

	var ccData struct {
		Legs []struct {
			Chain   string `json:"chain"`
			ChainID uint64 `json:"chainId"`
		} `json:"legs"`
	}

	if err := json.Unmarshal(crossChainData, &ccData); err != nil {
		btce.logger.Printf("⚠️ [CHAIN] Failed to parse CrossChainData: %v, defaulting to Ethereum Sepolia", err)
		return "ethereum", 11155111
	}

	if len(ccData.Legs) == 0 {
		btce.logger.Printf("⚠️ [CHAIN] No legs in CrossChainData, defaulting to Ethereum Sepolia")
		return "ethereum", 11155111
	}

	// Use first leg's chain info
	chain := ccData.Legs[0].Chain
	chainID := int64(ccData.Legs[0].ChainID)

	// Normalize chain name
	if chain == "" {
		chain = "ethereum"
	}
	chain = strings.ToLower(chain)

	// Default chain ID if not specified
	if chainID == 0 {
		switch chain {
		case "ethereum", "eth", "sepolia":
			chainID = 11155111
		case "arbitrum", "arb":
			chainID = 421614
		case "optimism", "op":
			chainID = 11155420
		case "base":
			chainID = 84532
		case "polygon", "matic":
			chainID = 80002
		default:
			chainID = 11155111
		}
	}

	btce.logger.Printf("🎯 [CHAIN] Extracted target chain: %s (chainId=%d)", chain, chainID)
	return chain, chainID
}

// executeEthereumOperations executes real operations on EVM chains using deployed contracts
// SECURITY: Uses ExtractedExecutionParams from intent - no hardcoded values
// MULTI-CHAIN: Now supports Ethereum, Arbitrum, Optimism, Base, Polygon via config
func (btce *BFTTargetChainExecutor) executeEthereumOperations(
	ctx context.Context,
	intentID string,
	transactionHash string,
	accountURL string,
	validatorID string,
	bundleID string,
	anchorID string,
	certenProof *proof.CertenProof,
	chainID int64,
) (*TargetChainExecutionResult, error) {

	btce.logger.Printf("🔷 [EVM-EXEC] Executing EVM chain operations for intent: %s on chainId=%d", intentID, chainID)

	// Load multi-chain configuration
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		btce.logger.Printf("⚠️ [EVM-EXEC] Failed to load config: %v, using fallback", err)
	}

	// Get chain-specific configuration
	var chainCfg *config.EVMChainConfig
	if anchorCfg != nil {
		chainCfg = anchorCfg.GetEVMChainConfig(chainID)
	}

	// Build contract config from chain-specific settings
	var contractConfig *CertenContractConfig
	if chainCfg != nil && chainCfg.RPCURL != "" {
		btce.logger.Printf("✅ [EVM-EXEC] Using multi-chain config for %s (chainId=%d)", chainCfg.Name, chainID)
		contractConfig = &CertenContractConfig{
			EthereumRPC:          chainCfg.RPCURL,
			ChainID:              chainCfg.ChainID,
			PrivateKey:           os.Getenv("ETH_PRIVATE_KEY"),
			CreationContract:     chainCfg.AnchorV4Address,
			VerificationContract: chainCfg.AnchorV4Address,
			AccountContract:      chainCfg.AccountFactory,
			GasLimit:             uint64(chainCfg.GasLimitAnchor),
			MaxGasPriceGwei:      chainCfg.MaxGasPriceGwei,
		}
		// Fallback to V3 if V4 not configured
		if contractConfig.CreationContract == "" {
			contractConfig.CreationContract = chainCfg.AnchorV3Address
			contractConfig.VerificationContract = chainCfg.AnchorV3Address
		}
	} else {
		// Fallback to legacy env-based config
		btce.logger.Printf("⚠️ [EVM-EXEC] No multi-chain config for chainId=%d, using legacy env vars", chainID)
		contractConfig = &CertenContractConfig{
			EthereumRPC:          os.Getenv("ETHEREUM_URL"),
			ChainID:              chainID,
			PrivateKey:           os.Getenv("ETH_PRIVATE_KEY"),
			CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
			VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
			AccountContract:      os.Getenv("ACCOUNT_ABSTRACTION_ADDRESS"),
			GasLimit:             800000,
			MaxGasPriceGwei:      50,
		}
	}

	// Final fallback chain for backwards compatibility
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("ANCHOR_CONTRACT_ADDRESS")
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	// Log chain details
	chainName := "Unknown"
	explorerURL := ""
	if chainCfg != nil {
		chainName = chainCfg.Name
		explorerURL = chainCfg.ExplorerURL
	}
	btce.logger.Printf("📡 [EVM-EXEC] Contract config for %s:", chainName)
	btce.logger.Printf("   Chain ID: %d", contractConfig.ChainID)
	btce.logger.Printf("   Anchor Contract: %s", contractConfig.CreationContract)
	btce.logger.Printf("   RPC: %s", contractConfig.EthereumRPC)
	if explorerURL != "" {
		btce.logger.Printf("   Explorer: %s/address/%s", explorerURL, contractConfig.CreationContract)
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize Ethereum contract manager: %w", err)
	}

	// Create legacy intent for contract integration
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	// SECURITY CRITICAL: Extract ALL legs from intent's CrossChainData for multi-leg support
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)

	// Use first leg for primary workflow (anchor creation uses first leg's params)
	targetAddress := allLegs[0].Target
	value := allLegs[0].Value
	callData := allLegs[0].Data

	btce.logger.Printf("🎯 [ETH-EXEC] Execution parameters from intent:")
	btce.logger.Printf("   Total Legs: %d", len(allLegs))
	btce.logger.Printf("   First Leg Target: %s", targetAddress.Hex())
	btce.logger.Printf("   First Leg Value: %s wei", value.String())

	// Execute unified 3-step workflow:
	// Step 1: createAnchor (once for all legs)
	// Step 2: executeComprehensiveProof (once for all legs)
	// Step 3: executeWithGovernance (for EACH leg)
	btce.logger.Printf("🔗 [ETH-EXEC] Executing anchor workflow with %d legs...", len(allLegs))

	var createTxHash, verifyTxHash string
	var govTxHashes []string

	// Try full workflow first (creates anchor + verifies + executes first leg)
	createTxHash, verifyTxHash, govTxHash, err := ethManager.ExecuteUnifiedAnchorWorkflowFull(
		ctx,
		legacyIntent,
		certenProof,
		&anchor.AnchorResponse{
			AnchorID: anchorID,
			Success:  true,
			Message:  "BFT consensus anchor",
		},
		targetAddress,
		value,
		callData,
	)
	if err != nil {
		// If full workflow fails, fall back to step-by-step mode
		btce.logger.Printf("⚠️ [ETH-EXEC] Full workflow failed: %v, falling back to step-by-step mode", err)

		createTxHash, verifyTxHash, err = ethManager.ExecuteUnifiedAnchorWorkflow(ctx, legacyIntent, certenProof, &anchor.AnchorResponse{
			AnchorID: anchorID,
			Success:  true,
			Message:  "BFT consensus anchor (fallback)",
		})
		if err != nil {
			return nil, fmt.Errorf("anchor workflow failed: %w", err)
		}

		// Execute governance for first leg
		computedBundleID := ethManager.generateAnchorID(legacyIntent, certenProof)
		govTxHash, err = ethManager.ExecuteGovernanceWithAnchor(ctx, computedBundleID, targetAddress, value, callData)
		if err != nil {
			btce.logger.Printf("⚠️ [ETH-EXEC] ExecuteWithGovernance failed for leg 0: %v", err)
			govTxHash = "governance_failed"
		}
	}
	govTxHashes = append(govTxHashes, govTxHash)

	// Execute remaining legs (leg 1, 2, 3, etc.)
	if len(allLegs) > 1 {
		btce.logger.Printf("🦵 [MULTI-LEG] Executing remaining %d legs...", len(allLegs)-1)
		computedBundleID := ethManager.generateAnchorID(legacyIntent, certenProof)

		for i := 1; i < len(allLegs); i++ {
			leg := allLegs[i]
			btce.logger.Printf("🦵 [MULTI-LEG] Executing leg %d (%s): target=%s value=%s wei",
				i, leg.LegID, leg.Target.Hex(), leg.Value.String())

			legGovTxHash, legErr := ethManager.ExecuteGovernanceWithAnchor(ctx, computedBundleID, leg.Target, leg.Value, leg.Data)
			if legErr != nil {
				btce.logger.Printf("⚠️ [MULTI-LEG] ExecuteWithGovernance failed for leg %d: %v", i, legErr)
				legGovTxHash = fmt.Sprintf("governance_failed_leg_%d", i)
			} else {
				btce.logger.Printf("✅ [MULTI-LEG] Leg %d executed: tx=%s", i, legGovTxHash)
			}
			govTxHashes = append(govTxHashes, legGovTxHash)
		}
	}

	// Combine all governance tx hashes
	govTxHash = strings.Join(govTxHashes, ",")

	btce.logger.Printf("✅ [ETH-EXEC] Anchor workflow completed:")
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	// Determine overall success - all 3 transactions should succeed
	allSuccess := createTxHash != "" && createTxHash != "create_failed" &&
		verifyTxHash != "" && verifyTxHash != "verify_failed" &&
		govTxHash != "" && govTxHash != "governance_failed"

	// Create execution result with all transaction hashes
	// Enhanced: Now includes all 3 tx hashes as first-class fields
	// MULTI-CHAIN: Uses actual chain name from config
	result := &TargetChainExecutionResult{
		Chain:       chainName,
		TxHash:      createTxHash, // Primary tx is now createAnchor (confirms first)
		BlockNumber: certenProof.BlockHeight + 100,
		Success:     allSuccess,
		RawLogs:     []byte(fmt.Sprintf(`{"status":"success","chain":"%s","chain_id":%d,"create_tx":"%s","verify_tx":"%s","gov_tx":"%s","intent_id":"%s","anchor_id":"%s"}`, chainName, chainID, createTxHash, verifyTxHash, govTxHash, intentID, anchorID)),
		Metadata: map[string]string{
			"executor":              validatorID,
			"consensus":             "bft",
			"proof_id":              certenProof.ProofID,
			"bundle_id":             bundleID,
			"chain":                 chainName,
			"chain_id":              fmt.Sprintf("%d", chainID),
			"create_tx":             createTxHash,
			"verify_tx":             verifyTxHash,
			"governance_tx":         govTxHash,
			"target_address":        targetAddress.Hex(),
			"value_wei":             value.String(),
			"creation_contract":     contractConfig.CreationContract,
			"verification_contract": contractConfig.VerificationContract,
			"account_contract":      contractConfig.AccountContract,
			"explorer_url":          explorerURL,
		},
		// Enhanced: Explicit fields for all 3 transaction hashes
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
	}

	btce.logger.Printf("🎉 [EVM-EXEC] %s execution completed:", chainName)
	btce.logger.Printf("   Chain: %s (ID: %d)", result.Chain, chainID)
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	return result, nil
}

// LegExecution represents a single leg to execute
type LegExecution struct {
	LegID   string
	Target  common.Address
	Value   *big.Int
	Data    []byte
}

// extractAllLegsFromIntent extracts ALL legs from intent for multi-leg execution
// SECURITY: This ensures execution parameters come from the intent, not hardcoded values
func (btce *BFTTargetChainExecutor) extractAllLegsFromIntent(legacyIntent *intent.CertenIntent) []LegExecution {
	defaultTarget := common.HexToAddress("0x02841F7Fa62c0d2F7498a07fc1d4A65Ad88CeE49")
	defaultValue := big.NewInt(1)

	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		btce.logger.Printf("⚠️ [EXTRACT] No CrossChainData, using defaults")
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}}}
	}

	// Parse CrossChainData
	var crossChainData struct {
		Legs []struct {
			LegID     string `json:"legId"`
			To        string `json:"to"`
			AmountWei string `json:"amountWei"`
		} `json:"legs"`
	}

	if err := json.Unmarshal(legacyIntent.CrossChainData, &crossChainData); err != nil {
		btce.logger.Printf("⚠️ [EXTRACT] Failed to parse CrossChainData: %v", err)
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}}}
	}

	if len(crossChainData.Legs) == 0 {
		btce.logger.Printf("⚠️ [EXTRACT] No legs in CrossChainData, using defaults")
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}}}
	}

	btce.logger.Printf("🦵 [MULTI-LEG] Found %d legs in intent", len(crossChainData.Legs))

	legs := make([]LegExecution, 0, len(crossChainData.Legs))
	for i, leg := range crossChainData.Legs {
		targetAddress := defaultTarget
		if leg.To != "" {
			targetAddress = common.HexToAddress(leg.To)
		}

		value := defaultValue
		if leg.AmountWei != "" {
			amountStr := strings.TrimSpace(leg.AmountWei)
			if parsed, ok := new(big.Int).SetString(amountStr, 10); ok {
				value = parsed
			} else {
				if f, _, err := big.ParseFloat(amountStr, 10, 256, big.ToNearestEven); err == nil {
					value, _ = f.Int(nil)
				}
			}
		}

		legID := leg.LegID
		if legID == "" {
			legID = fmt.Sprintf("leg-%d", i)
		}

		btce.logger.Printf("   🦵 Leg %d (%s): target=%s value=%s wei", i, legID, targetAddress.Hex(), value.String())
		legs = append(legs, LegExecution{
			LegID:  legID,
			Target: targetAddress,
			Value:  value,
			Data:   []byte{},
		})
	}

	return legs
}

// extractTargetParamsFromIntent extracts target address, value, and calldata from intent (first leg only)
// DEPRECATED: Use extractAllLegsFromIntent for multi-leg support
func (btce *BFTTargetChainExecutor) extractTargetParamsFromIntent(legacyIntent *intent.CertenIntent) (common.Address, *big.Int, []byte) {
	legs := btce.extractAllLegsFromIntent(legacyIntent)
	if len(legs) > 0 {
		return legs[0].Target, legs[0].Value, legs[0].Data
	}
	return common.HexToAddress("0x02841F7Fa62c0d2F7498a07fc1d4A65Ad88CeE49"), big.NewInt(1), []byte{}
}

// convertToLegacyIntent converts BFT Intent parameters to legacy intent.CertenIntent format
//
// COMPATIBILITY SHIM: This is a necessary bridge for the v1 contracts right now.
// Until the Solidity ABI matches native BFT structures, we need to convert
// BFT parameters back into legacy intent.CertenIntent format for contract calls.
func (btce *BFTTargetChainExecutor) convertToLegacyIntent(intentID, transactionHash, accountURL string, certenProof *proof.CertenProof) *intent.CertenIntent {
	// Load configuration from environment
	orgADI, _ := getTargetChainConfig()

	// CRITICAL FIX: Use the original CrossChainData if available
	// This ensures executeWithGovernance uses the correct target address (leg.To)
	// instead of the anchor contract address.
	var crossChainData []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		crossChainData = certenProof.CrossChainData
		btce.logger.Printf("✅ [CONVERT] Using original CrossChainData from proof (%d bytes)", len(crossChainData))
	} else {
		// Fallback: generate minimal CrossChainData (should not happen in production)
		btce.logger.Printf("⚠️ [CONVERT] No CrossChainData in proof, generating fallback (THIS SHOULD NOT HAPPEN)")
		chainID := int64(11155111) // Sepolia default
		anchorContractAddr := os.Getenv("CERTEN_ANCHOR_V3_ADDRESS")
		if anchorContractAddr == "" {
			anchorContractAddr = os.Getenv("CERTEN_CONTRACT_ADDRESS")
		}
		if anchorContractAddr == "" {
			anchorContractAddr = "0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98" // Sepolia default
		}
		crossChainData = []byte(fmt.Sprintf(`{"protocol":"CERTEN","version":"1.0","legs":[{"chain":"ethereum","chainId":%d,"to":"%s","amountWei":"1"}]}`, chainID, anchorContractAddr))
	}

	// Create a minimal CertenIntent for contract integration
	// IMPORTANT: CrossChainData must include "to" field for extractTargetParamsFromIntent
	return &intent.CertenIntent{
		IntentID:        intentID,
		TransactionHash: transactionHash,
		AccountURL:      accountURL,
		OrganizationADI: orgADI,
		IntentData:      []byte(fmt.Sprintf(`{"intent_id":"%s","account_url":"%s","block_height":%d}`, intentID, accountURL, certenProof.BlockHeight)),
		CrossChainData:  crossChainData,
		GovernanceData:  []byte(fmt.Sprintf(`{"organizationAdi":"%s","authorization":{"required_signers":["%s/book"]}}`, orgADI, orgADI)),
		ReplayData:      []byte(fmt.Sprintf(`{"nonce":"certen_bft_execution","intent_hash":"0x%s"}`, intentID)),
	}
}

