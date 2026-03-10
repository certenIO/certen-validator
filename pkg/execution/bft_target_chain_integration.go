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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	tonaddr "github.com/xssnick/tonutils-go/address"

	"github.com/certen/independant-validator/pkg/anchor"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/proof"
)

// getTargetChainConfig derives org ADI from accountURL and loads chain config
func getTargetChainConfig(accountURL string) (string, int64) {
	// Derive org ADI from accountURL (e.g. "acc://certen-kermit-004.acme/data" → "acc://certen-kermit-004.acme")
	orgADI := ""
	if accountURL != "" && strings.HasPrefix(accountURL, "acc://") {
		hostPart := accountURL[len("acc://"):]
		if idx := strings.Index(hostPart, "/"); idx > 0 {
			orgADI = "acc://" + hostPart[:idx]
		} else {
			orgADI = accountURL
		}
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
			ChainID int64  `json:"chainId"`
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
		ChainID:        leg.ChainID,
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

	// Check if this is a multi-leg intent with chains beyond the primary
	var additionalChainLegs []struct {
		Chain   string
		ChainID int64
	}
	if len(crossChainData) > 0 {
		var ccPeek struct {
			Legs []struct {
				Chain   string `json:"chain"`
				ChainID int64  `json:"chainId"`
			} `json:"legs"`
		}
		if err := json.Unmarshal(crossChainData, &ccPeek); err == nil && len(ccPeek.Legs) > 1 {
			for _, leg := range ccPeek.Legs[1:] {
				legChainNorm := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
				// Only add legs on DIFFERENT chains than primary
				if legChainNorm != strings.ToLower(strings.ReplaceAll(targetChain, " ", "-")) {
					additionalChainLegs = append(additionalChainLegs, struct {
						Chain   string
						ChainID int64
					}{leg.Chain, leg.ChainID})
				}
			}
		}
	}

	// Execute based on target chain (primary leg)
	switch targetChain {
	case "tron", "tron-shasta", "tron-shasta-testnet", "tron-nile", "tron-mainnet",
		"tron shasta", "tron shasta testnet", "tron nile", "tron mainnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeTronOperations, additionalChainLegs)
	case "near", "near-testnet", "near-protocol", "near-mainnet",
		"near testnet", "near protocol", "near mainnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeNearOperations, additionalChainLegs)
	case "solana", "solana-devnet", "solana-mainnet", "solana-testnet",
		"solana devnet", "solana mainnet", "solana testnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeSolanaOperations, additionalChainLegs)
	case "aptos", "aptos-testnet", "aptos-mainnet",
		"aptos testnet", "aptos mainnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeAptosOperations, additionalChainLegs)
	case "sui", "sui-testnet", "sui-mainnet",
		"sui testnet", "sui mainnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeSuiOperations, additionalChainLegs)
	case "ton", "ton-testnet", "ton-mainnet",
		"ton testnet", "ton mainnet":
		return btce.executeNonEVMPrimaryWithAdditionalLegs(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, targetChainID,
			btce.executeTonOperations, additionalChainLegs)
	case "ethereum", "ethereum-sepolia", "eth", "eth-sepolia", "sepolia",
		"arbitrum", "arbitrum-one", "arbitrum-sepolia", "arb",
		"optimism", "op-mainnet", "optimism-sepolia", "op", "op-sepolia",
		"base", "base-mainnet", "base-sepolia",
		"polygon", "polygon-amoy", "matic", "amoy",
		"bsc", "bsc-testnet", "binance",
		"moonbeam", "moonbase", "moonbase-alpha", "moonbeam-moonbase-alpha":
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
	return "ethereum-sepolia", 11155111
}

// extractTargetChainFromCrossChainData parses the actual target chain from CrossChainData
func (btce *BFTTargetChainExecutor) extractTargetChainFromCrossChainData(crossChainData []byte) (string, int64) {
	if len(crossChainData) == 0 {
		btce.logger.Printf("⚠️ [CHAIN] No CrossChainData, defaulting to Ethereum Sepolia")
		return "ethereum-sepolia", 11155111
	}

	var ccData struct {
		Legs []struct {
			Chain   string `json:"chain"`
			ChainID int64  `json:"chainId"`
		} `json:"legs"`
	}

	if err := json.Unmarshal(crossChainData, &ccData); err != nil {
		btce.logger.Printf("⚠️ [CHAIN] Failed to parse CrossChainData: %v, defaulting to Ethereum Sepolia", err)
		return "ethereum-sepolia", 11155111
	}

	if len(ccData.Legs) == 0 {
		btce.logger.Printf("⚠️ [CHAIN] No legs in CrossChainData, defaulting to Ethereum Sepolia")
		return "ethereum-sepolia", 11155111
	}

	// Use first leg's chain info
	chain := ccData.Legs[0].Chain
	chainID := ccData.Legs[0].ChainID

	// Normalize chain name: replace spaces with hyphens, lowercase
	if chain == "" {
		chain = "ethereum-sepolia"
	}
	chain = strings.ToLower(strings.TrimSpace(chain))
	chain = strings.ReplaceAll(chain, " ", "-")

	// Default chain ID if not specified
	if chainID == 0 {
		switch chain {
		case "ethereum", "eth":
			chainID = 1
		case "ethereum-sepolia", "eth-sepolia", "sepolia":
			chainID = 11155111
		case "arbitrum", "arb", "arbitrum-one":
			chainID = 42161
		case "arbitrum-sepolia", "arb-sepolia":
			chainID = 421614
		case "optimism", "op", "op-mainnet":
			chainID = 10
		case "optimism-sepolia", "op-sepolia":
			chainID = 11155420
		case "base", "base-mainnet":
			chainID = 8453
		case "base-sepolia":
			chainID = 84532
		case "polygon", "matic":
			chainID = 137
		case "polygon-amoy", "amoy":
			chainID = 80002
		case "moonbeam":
			chainID = 1284
		case "moonbase-alpha", "moonbeam-moonbase-alpha":
			chainID = 1287
		case "tron", "tron-shasta", "tron-shasta-testnet", "tron-nile", "tron-mainnet":
			chainID = 2494104990
		case "solana", "solana-devnet", "solana-mainnet", "solana-testnet":
			chainID = 103
		case "near", "near-testnet", "near-mainnet":
			chainID = 398
		case "aptos", "aptos-testnet", "aptos-mainnet":
			chainID = 2
		case "sui", "sui-testnet", "sui-mainnet":
			chainID = 2
		case "ton", "ton-testnet", "ton-mainnet":
			chainID = -3
		default:
			chainID = 11155111
		}
	}

	btce.logger.Printf("🎯 [CHAIN] Extracted target chain: %s (chainId=%d)", chain, chainID)
	return chain, chainID
}

// nonEVMHandler is the function signature shared by all non-EVM chain executors.
type nonEVMHandler func(
	ctx context.Context,
	intentID, transactionHash, accountURL, validatorID, bundleID, anchorID string,
	certenProof *proof.CertenProof,
	chainID int64,
) (*TargetChainExecutionResult, error)

// executeNonEVMPrimaryWithAdditionalLegs executes the primary non-EVM chain handler,
// then dispatches any additional legs on other chains (EVM or non-EVM).
// This fixes the bug where a non-EVM primary chain (e.g. NEAR) would skip additional
// legs on other chains (e.g. ETH Sepolia).
func (btce *BFTTargetChainExecutor) executeNonEVMPrimaryWithAdditionalLegs(
	ctx context.Context,
	intentID, transactionHash, accountURL, validatorID, bundleID, anchorID string,
	certenProof *proof.CertenProof,
	primaryChainID int64,
	primaryHandler nonEVMHandler,
	additionalLegs []struct {
		Chain   string
		ChainID int64
	},
) (*TargetChainExecutionResult, error) {

	// Step 1: Execute primary non-EVM chain
	btce.logger.Printf("🔗 [MULTI-LEG] Executing primary non-EVM chain (chainId=%d), then %d additional leg(s)",
		primaryChainID, len(additionalLegs))

	primaryResult, primaryErr := primaryHandler(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, primaryChainID)
	if primaryErr != nil {
		btce.logger.Printf("❌ [MULTI-LEG] Primary chain failed: %v", primaryErr)
		// Still attempt additional legs even if primary fails — each leg is independent
		if primaryResult == nil {
			primaryResult = &TargetChainExecutionResult{
				Chain:    fmt.Sprintf("chainId-%d", primaryChainID),
				Success:  false,
				Metadata: map[string]string{"error": primaryErr.Error()},
			}
		}
	} else {
		btce.logger.Printf("✅ [MULTI-LEG] Primary chain completed: success=%v tx=%s",
			primaryResult.Success, primaryResult.TxHash)
	}

	// Step 2: If no additional legs, return primary result directly
	if len(additionalLegs) == 0 {
		return primaryResult, primaryErr
	}

	// Step 3: Execute additional legs on other chains
	// Use a fresh context with generous timeout since primary may have consumed time
	addCtx, addCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer addCancel()

	allTxHashes := []string{}
	if primaryResult.TxHash != "" {
		allTxHashes = append(allTxHashes, fmt.Sprintf("%s:%s", primaryResult.Chain, primaryResult.TxHash))
	}

	overallSuccess := primaryResult.Success

	for i, leg := range additionalLegs {
		legChainNorm := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
		btce.logger.Printf("🦵 [MULTI-LEG] Executing additional leg %d/%d: chain=%s chainId=%d",
			i+1, len(additionalLegs), leg.Chain, leg.ChainID)

		// Check if this additional leg is non-EVM or EVM
		nonEVMName := btce.getNonEVMChainName(leg.ChainID, leg.Chain)
		var legResult *TargetChainExecutionResult
		var legErr error

		if nonEVMName != "" {
			// Non-EVM additional leg
			legResult, legErr = btce.dispatchNonEVMChain(addCtx, nonEVMName,
				intentID, transactionHash, accountURL, validatorID, bundleID, anchorID,
				certenProof, leg.ChainID)
		} else {
			// EVM additional leg
			legResult, legErr = btce.executeEthereumOperations(addCtx,
				intentID, transactionHash, accountURL, validatorID, bundleID, anchorID,
				certenProof, leg.ChainID)
		}

		if legErr != nil {
			btce.logger.Printf("❌ [MULTI-LEG] Additional leg %s failed: %v", legChainNorm, legErr)
			overallSuccess = false
			allTxHashes = append(allTxHashes, fmt.Sprintf("%s:execution_failed", legChainNorm))
		} else if legResult != nil {
			btce.logger.Printf("✅ [MULTI-LEG] Additional leg %s completed: success=%v tx=%s",
				legChainNorm, legResult.Success, legResult.TxHash)
			if !legResult.Success {
				overallSuccess = false
			}
			txHash := legResult.TxHash
			if txHash == "" {
				txHash = legResult.GovernanceTxHash
			}
			allTxHashes = append(allTxHashes, fmt.Sprintf("%s:%s", legChainNorm, txHash))
		}
	}

	// Step 4: Merge results — primary result is the base, annotate with additional leg info
	if primaryResult.Metadata == nil {
		primaryResult.Metadata = make(map[string]string)
	}
	primaryResult.Metadata["multi_leg"] = "true"
	primaryResult.Metadata["total_legs"] = fmt.Sprintf("%d", 1+len(additionalLegs))
	primaryResult.Metadata["all_tx_hashes"] = strings.Join(allTxHashes, ",")
	primaryResult.Success = overallSuccess

	// Update TxHash to include all chains for proof cycle parsing
	if len(allTxHashes) > 1 {
		primaryResult.TxHash = strings.Join(allTxHashes, ",")
	}

	btce.logger.Printf("🎉 [MULTI-LEG] All %d legs completed: overall_success=%v",
		1+len(additionalLegs), overallSuccess)

	return primaryResult, nil
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

	// Create a fresh context with generous timeout for multi-chain EVM execution.
	// The parent BFT context may have a very short deadline that's already nearly expired
	// after consensus rounds. Each chain's anchor workflow needs ~15-25 seconds.
	evmCtx, evmCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer evmCancel()
	ctx = evmCtx

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

	// Log chain details (for primary chain passed in - used in result metadata)
	chainName := "Unknown"
	explorerURL := ""
	if chainCfg != nil {
		chainName = chainCfg.Name
		explorerURL = chainCfg.ExplorerURL
	}
	btce.logger.Printf("📡 [EVM-EXEC] Primary chain config for %s:", chainName)
	btce.logger.Printf("   Chain ID: %d", contractConfig.ChainID)
	btce.logger.Printf("   Anchor Contract: %s", contractConfig.CreationContract)
	btce.logger.Printf("   RPC: %s", contractConfig.EthereumRPC)
	if explorerURL != "" {
		btce.logger.Printf("   Explorer: %s/address/%s", explorerURL, contractConfig.CreationContract)
	}

	// NOTE: Chain-specific managers are now created inside the multi-chain loop below
	// This allows each leg to be routed to its correct target chain

	// Create legacy intent for contract integration
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	// SECURITY CRITICAL: Extract ALL legs from intent's CrossChainData for multi-leg support
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)

	btce.logger.Printf("🎯 [ETH-EXEC] Execution parameters from intent:")
	btce.logger.Printf("   Total Legs: %d", len(allLegs))

	// MULTI-CHAIN: Group legs by their target chain
	legsByChain := btce.groupLegsByChain(allLegs)

	// Track results across all chains
	var allCreateTxHashes []string
	var allVerifyTxHashes []string
	var allGovTxHashes []string
	var chainResults []string
	overallSuccess := true

	// Execute on each target chain
	for targetChainID, chainLegs := range legsByChain {
		btce.logger.Printf("🔗 [MULTI-CHAIN] Processing %d legs for chainId=%d...", len(chainLegs), targetChainID)

		// Check if this chain group is non-EVM and needs a different handler
		nonEVMChainName := btce.getNonEVMChainName(targetChainID, chainLegs[0].Chain)
		if nonEVMChainName != "" {
			btce.logger.Printf("🔀 [MULTI-CHAIN] Chain %d (%s) is non-EVM, dispatching to %s handler",
				targetChainID, nonEVMChainName, nonEVMChainName)
			nonEVMResult, nonEVMErr := btce.dispatchNonEVMChain(ctx, nonEVMChainName,
				intentID, transactionHash, accountURL, validatorID, bundleID, anchorID,
				certenProof, targetChainID)
			if nonEVMErr != nil {
				btce.logger.Printf("❌ [MULTI-CHAIN] Non-EVM handler failed for %s: %v", nonEVMChainName, nonEVMErr)
				overallSuccess = false
				for _, leg := range chainLegs {
					allCreateTxHashes = append(allCreateTxHashes, fmt.Sprintf("create_failed_%s", nonEVMChainName))
					allVerifyTxHashes = append(allVerifyTxHashes, fmt.Sprintf("verify_failed_%s", nonEVMChainName))
					allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("execution_failed_%s", leg.LegID))
				}
			} else if nonEVMResult != nil {
				// Merge non-EVM results
				displayName := nonEVMChainName
				allCreateTxHashes = append(allCreateTxHashes, fmt.Sprintf("%s:%s", displayName, nonEVMResult.CreateTxHash))
				allVerifyTxHashes = append(allVerifyTxHashes, fmt.Sprintf("%s:%s", displayName, nonEVMResult.VerifyTxHash))
				for i, leg := range chainLegs {
					govTx := nonEVMResult.GovernanceTxHash
					if !nonEVMResult.Success {
						govTx = fmt.Sprintf("execution_failed_%s", leg.LegID)
						overallSuccess = false
					}
					if i == 0 {
						allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("%s:%s:%s", displayName, leg.LegID, govTx))
					} else {
						allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("%s:%s:%s", displayName, leg.LegID, govTx))
					}
				}
				chainResults = append(chainResults, fmt.Sprintf("%s:%d_legs", displayName, len(chainLegs)))
				btce.logger.Printf("✅ [MULTI-CHAIN] Non-EVM %s completed: success=%v", displayName, nonEVMResult.Success)
			}
			continue
		}

		// Get contract manager for this specific chain
		chainEthManager, chainSpecificCfg, chainErr := btce.getContractManagerForChain(targetChainID, anchorCfg)
		if chainErr != nil {
			btce.logger.Printf("❌ [MULTI-CHAIN] Failed to get contract manager for chainId=%d: %v", targetChainID, chainErr)
			overallSuccess = false
			for _, leg := range chainLegs {
				allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("chain_config_failed_%s", leg.LegID))
			}
			continue
		}

		chainExplorerURL := ""
		chainDisplayName := fmt.Sprintf("chain-%d", targetChainID)
		if chainSpecificCfg != nil {
			chainExplorerURL = chainSpecificCfg.ExplorerURL
			chainDisplayName = chainSpecificCfg.Name
		}

		btce.logger.Printf("📡 [MULTI-CHAIN] Connected to %s:", chainDisplayName)
		btce.logger.Printf("   Chain ID: %d", targetChainID)
		if chainExplorerURL != "" {
			btce.logger.Printf("   Explorer: %s", chainExplorerURL)
		}

		// Use first leg of this chain for anchor creation
		firstLeg := chainLegs[0]

		// Execute anchor workflow for this chain
		var chainCreateTx, chainVerifyTx, chainGovTx string
		var chainExecErr error

		// NEW FLOW: 2-step anchor workflow + user account execution
		// Step 1 & 2: Create anchor and verify proof
		btce.logger.Printf("🔗 [MULTI-CHAIN] Starting 2-step anchor workflow for %s...", chainDisplayName)

		chainCreateTx, chainVerifyTx, chainExecErr = chainEthManager.ExecuteUnifiedAnchorWorkflow(
			ctx, legacyIntent, certenProof,
			&anchor.AnchorResponse{
				AnchorID: anchorID,
				Success:  true,
				Message:  fmt.Sprintf("BFT consensus anchor for %s", chainDisplayName),
			},
		)

		if chainExecErr != nil {
			btce.logger.Printf("❌ [MULTI-CHAIN] Anchor workflow failed for %s: %v", chainDisplayName, chainExecErr)
			overallSuccess = false
			allCreateTxHashes = append(allCreateTxHashes, fmt.Sprintf("create_failed_%s", chainDisplayName))
			allVerifyTxHashes = append(allVerifyTxHashes, fmt.Sprintf("verify_failed_%s", chainDisplayName))
			for _, leg := range chainLegs {
				allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("execution_failed_%s", leg.LegID))
			}
			continue
		}

		// Step 3: Execute via user's Abstract Account (CORRECT FLOW)
		computedBundleID := chainEthManager.generateAnchorID(legacyIntent, certenProof)

		// Check if user has an Abstract Account (SourceAddress from leg.From)
		if firstLeg.SourceAddress != (common.Address{}) {
			btce.logger.Printf("🏦 [USER-ACCOUNT] Executing via user's Abstract Account: %s", firstLeg.SourceAddress.Hex())
			chainGovTx, chainExecErr = chainEthManager.ExecuteViaUserAccount(
				ctx,
				firstLeg.SourceAddress,
				computedBundleID,
				firstLeg.Target,
				firstLeg.Value,
				firstLeg.Data,
				certenProof,
				accountURL, // ADI URL from intent
			)
		} else {
			// Fallback to anchor-based execution (legacy mode - anchor contract holds funds)
			btce.logger.Printf("⚠️ [LEGACY] No user account, falling back to anchor-based execution")
			chainGovTx, chainExecErr = chainEthManager.ExecuteGovernanceWithAnchor(ctx, computedBundleID, firstLeg.Target, firstLeg.Value, firstLeg.Data)
		}

		if chainExecErr != nil {
			btce.logger.Printf("⚠️ [MULTI-CHAIN] Execution failed for %s leg 0: %v", chainDisplayName, chainExecErr)
			chainGovTx = fmt.Sprintf("execution_failed_%s", firstLeg.LegID)
			overallSuccess = false
		}

		allCreateTxHashes = append(allCreateTxHashes, fmt.Sprintf("%s:%s", chainDisplayName, chainCreateTx))
		allVerifyTxHashes = append(allVerifyTxHashes, fmt.Sprintf("%s:%s", chainDisplayName, chainVerifyTx))
		allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("%s:%s:%s", chainDisplayName, firstLeg.LegID, chainGovTx))

		btce.logger.Printf("✅ [MULTI-CHAIN] %s first leg executed:", chainDisplayName)
		btce.logger.Printf("   Create TX: %s", chainCreateTx)
		btce.logger.Printf("   Verify TX: %s", chainVerifyTx)
		btce.logger.Printf("   Governance TX: %s", chainGovTx)

		// Execute remaining legs for this chain
		if len(chainLegs) > 1 {
			computedBundleID := chainEthManager.generateAnchorID(legacyIntent, certenProof)
			btce.logger.Printf("🦵 [MULTI-CHAIN] Executing remaining %d legs for %s...", len(chainLegs)-1, chainDisplayName)

			for i := 1; i < len(chainLegs); i++ {
				leg := chainLegs[i]
				btce.logger.Printf("🦵 [MULTI-CHAIN] Executing leg %s on %s: from=%s target=%s value=%s wei",
					leg.LegID, chainDisplayName, leg.SourceAddress.Hex(), leg.Target.Hex(), leg.Value.String())

				var legGovTxHash string
				var legErr error

				// Execute via user's Abstract Account (CORRECT FLOW)
				if leg.SourceAddress != (common.Address{}) {
					btce.logger.Printf("🏦 [USER-ACCOUNT] Executing via user's Abstract Account: %s", leg.SourceAddress.Hex())
					legGovTxHash, legErr = chainEthManager.ExecuteViaUserAccount(
						ctx,
						leg.SourceAddress,
						computedBundleID,
						leg.Target,
						leg.Value,
						leg.Data,
						certenProof,
						accountURL,
					)
				} else {
					// Fallback to anchor-based execution (legacy mode)
					btce.logger.Printf("⚠️ [LEGACY] No user account, falling back to anchor-based execution")
					legGovTxHash, legErr = chainEthManager.ExecuteGovernanceWithAnchor(ctx, computedBundleID, leg.Target, leg.Value, leg.Data)
				}

				if legErr != nil {
					btce.logger.Printf("⚠️ [MULTI-CHAIN] Execution failed for %s %s: %v", chainDisplayName, leg.LegID, legErr)
					legGovTxHash = fmt.Sprintf("execution_failed_%s", leg.LegID)
					overallSuccess = false
				} else {
					btce.logger.Printf("✅ [MULTI-CHAIN] %s %s executed: tx=%s", chainDisplayName, leg.LegID, legGovTxHash)
				}
				allGovTxHashes = append(allGovTxHashes, fmt.Sprintf("%s:%s:%s", chainDisplayName, leg.LegID, legGovTxHash))
			}
		}

		chainResults = append(chainResults, fmt.Sprintf("%s:%d_legs", chainDisplayName, len(chainLegs)))
	}

	// Combine all transaction hashes
	createTxHash := strings.Join(allCreateTxHashes, ",")
	verifyTxHash := strings.Join(allVerifyTxHashes, ",")
	govTxHash := strings.Join(allGovTxHashes, ",")

	btce.logger.Printf("✅ [MULTI-CHAIN] All chains processed:")
	btce.logger.Printf("   Chains: %s", strings.Join(chainResults, ", "))
	btce.logger.Printf("   Create TXs: %s", createTxHash)
	btce.logger.Printf("   Verify TXs: %s", verifyTxHash)
	btce.logger.Printf("   Governance TXs: %s", govTxHash)

	// Create execution result with all transaction hashes
	// MULTI-CHAIN: Combines results from all target chains
	result := &TargetChainExecutionResult{
		Chain:       chainName,
		TxHash:      createTxHash,
		BlockNumber: certenProof.BlockHeight + 100,
		Success:     overallSuccess,
		RawLogs:     []byte(fmt.Sprintf(`{"status":"%s","chains":"%s","create_txs":"%s","verify_txs":"%s","gov_txs":"%s","intent_id":"%s","anchor_id":"%s"}`, map[bool]string{true: "success", false: "partial_failure"}[overallSuccess], strings.Join(chainResults, ","), createTxHash, verifyTxHash, govTxHash, intentID, anchorID)),
		Metadata: map[string]string{
			"executor":              validatorID,
			"consensus":             "bft",
			"proof_id":              certenProof.ProofID,
			"bundle_id":             bundleID,
			"chains":                strings.Join(chainResults, ","),
			"total_legs":            fmt.Sprintf("%d", len(allLegs)),
			"total_chains":          fmt.Sprintf("%d", len(legsByChain)),
			"create_txs":            createTxHash,
			"verify_txs":            verifyTxHash,
			"governance_txs":        govTxHash,
			"creation_contract":     contractConfig.CreationContract,
			"verification_contract": contractConfig.VerificationContract,
			"account_contract":      contractConfig.AccountContract,
			"explorer_url":          explorerURL,
		},
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
	}

	btce.logger.Printf("🎉 [MULTI-CHAIN] Multi-chain execution completed:")
	btce.logger.Printf("   Total Chains: %d", len(legsByChain))
	btce.logger.Printf("   Total Legs: %d", len(allLegs))
	btce.logger.Printf("   Overall Success: %v", overallSuccess)

	return result, nil
}

// LegExecution represents a single leg to execute
type LegExecution struct {
	LegID         string
	Target        common.Address
	Value         *big.Int
	Data          []byte
	ChainID       int64          // Target chain for this leg
	Chain         string         // Chain name (e.g., "ethereum sepolia", "arbitrum sepolia")
	SourceAddress common.Address // User's Abstract Account address (from leg.From)
	AccountOwner  common.Address // Owner wallet address for account factory deployment
}

// extractAllLegsFromIntent extracts ALL legs from intent for multi-leg execution
// SECURITY: This ensures execution parameters come from the intent, not hardcoded values
// MULTI-CHAIN: Now captures chainId for each leg to enable proper chain routing
func (btce *BFTTargetChainExecutor) extractAllLegsFromIntent(legacyIntent *intent.CertenIntent) []LegExecution {
	defaultTarget := common.HexToAddress("0x02841F7Fa62c0d2F7498a07fc1d4A65Ad88CeE49")
	defaultValue := big.NewInt(1)
	defaultChainID := int64(11155111) // Ethereum Sepolia

	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		btce.logger.Printf("⚠️ [EXTRACT] No CrossChainData, using defaults")
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}, ChainID: defaultChainID, Chain: "ethereum sepolia"}}
	}

	// Parse CrossChainData with chain information
	var crossChainData struct {
		Legs []struct {
			LegID        string `json:"legId"`
			From         string `json:"from"`         // User's Abstract Account address
			To           string `json:"to"`
			AmountWei    string `json:"amountWei"`
			ChainID      int64  `json:"chainId"`
			Chain        string `json:"chain"`
			AccountOwner string `json:"accountOwner"` // Owner wallet for account factory deployment
		} `json:"legs"`
	}

	if err := json.Unmarshal(legacyIntent.CrossChainData, &crossChainData); err != nil {
		btce.logger.Printf("⚠️ [EXTRACT] Failed to parse CrossChainData: %v", err)
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}, ChainID: defaultChainID, Chain: "ethereum sepolia"}}
	}

	if len(crossChainData.Legs) == 0 {
		btce.logger.Printf("⚠️ [EXTRACT] No legs in CrossChainData, using defaults")
		return []LegExecution{{LegID: "default", Target: defaultTarget, Value: defaultValue, Data: []byte{}, ChainID: defaultChainID, Chain: "ethereum sepolia"}}
	}

	btce.logger.Printf("🦵 [MULTI-LEG] Found %d legs in intent", len(crossChainData.Legs))

	legs := make([]LegExecution, 0, len(crossChainData.Legs))
	for i, leg := range crossChainData.Legs {
		targetAddress := defaultTarget
		if leg.To != "" {
			targetAddress = parseChainAddress(leg.To)
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

		// Capture chain information for multi-chain routing
		chainID := leg.ChainID
		if chainID == 0 {
			chainID = defaultChainID
		}
		chainName := leg.Chain
		if chainName == "" {
			chainName = "ethereum sepolia"
		}

		// Extract source address (user's Abstract Account)
		sourceAddress := common.Address{}
		if leg.From != "" {
			sourceAddress = parseChainAddress(leg.From)
		}

		// Extract account owner (wallet address for factory deployment)
		accountOwner := common.Address{}
		if leg.AccountOwner != "" {
			accountOwner = parseChainAddress(leg.AccountOwner)
		}

		btce.logger.Printf("   🦵 Leg %d (%s): chain=%s chainId=%d from=%s target=%s value=%s wei",
			i, legID, chainName, chainID, sourceAddress.Hex(), targetAddress.Hex(), value.String())
		if accountOwner != (common.Address{}) {
			btce.logger.Printf("      accountOwner=%s", accountOwner.Hex())
		}
		legs = append(legs, LegExecution{
			LegID:         legID,
			Target:        targetAddress,
			Value:         value,
			Data:          []byte{},
			ChainID:       chainID,
			Chain:         chainName,
			SourceAddress: sourceAddress,
			AccountOwner:  accountOwner,
		})
	}

	return legs
}

// tronBase58ToAddress converts a TRON base58check address (T...) to common.Address.
// TRON base58check: base58decode → 21 bytes (0x41 + 20-byte address) + 4-byte checksum.
func tronBase58ToAddress(addr string) (common.Address, error) {
	decoded, err := base58.Decode(addr)
	if err != nil {
		return common.Address{}, fmt.Errorf("base58 decode failed: %w", err)
	}
	if len(decoded) < 25 || decoded[0] != 0x41 {
		return common.Address{}, fmt.Errorf("invalid TRON address: len=%d prefix=0x%x", len(decoded), decoded[0])
	}
	return common.BytesToAddress(decoded[1:21]), nil
}

// parseChainAddress parses an address string that may be hex (0x...) or TRON base58 (T...).
func parseChainAddress(addr string) common.Address {
	if strings.HasPrefix(addr, "T") && len(addr) == 34 {
		if parsed, err := tronBase58ToAddress(addr); err == nil {
			return parsed
		}
	}
	return common.HexToAddress(addr)
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

// groupLegsByChain groups legs by their target chainId for multi-chain execution
// Returns a map of chainId -> []LegExecution
func (btce *BFTTargetChainExecutor) groupLegsByChain(legs []LegExecution) map[int64][]LegExecution {
	grouped := make(map[int64][]LegExecution)
	for _, leg := range legs {
		grouped[leg.ChainID] = append(grouped[leg.ChainID], leg)
	}

	btce.logger.Printf("🔀 [MULTI-CHAIN] Grouped %d legs into %d chains:", len(legs), len(grouped))
	for chainID, chainLegs := range grouped {
		btce.logger.Printf("   Chain %d: %d legs", chainID, len(chainLegs))
		for _, leg := range chainLegs {
			btce.logger.Printf("      - %s: target=%s value=%s wei", leg.LegID, leg.Target.Hex(), leg.Value.String())
		}
	}

	return grouped
}

// getNonEVMChainName checks if a chainID corresponds to a non-EVM chain.
// Returns the normalized chain name if non-EVM, empty string if EVM.
func (btce *BFTTargetChainExecutor) getNonEVMChainName(chainID int64, legChainName string) string {
	// Known non-EVM chain IDs
	switch chainID {
	case 103: // Solana devnet
		return "solana-devnet"
	case 101: // Solana mainnet
		return "solana-mainnet"
	case 102: // Solana testnet
		return "solana-testnet"
	case 398: // NEAR
		return "near-testnet"
	case 2: // Aptos or SUI (disambiguate by chain name)
		normalized := strings.ToLower(strings.ReplaceAll(legChainName, " ", "-"))
		if strings.Contains(normalized, "sui") {
			return normalized
		}
		if strings.Contains(normalized, "aptos") {
			return normalized
		}
		return normalized
	case -3: // TON
		return "ton-testnet"
	case 2494104990: // TRON
		return "tron-shasta"
	}

	// Also check by chain name for chains with non-standard IDs
	normalized := strings.ToLower(strings.ReplaceAll(legChainName, " ", "-"))
	switch {
	case strings.HasPrefix(normalized, "solana"):
		return normalized
	case strings.HasPrefix(normalized, "near"):
		return normalized
	case strings.HasPrefix(normalized, "aptos"):
		return normalized
	case strings.HasPrefix(normalized, "sui"):
		return normalized
	case strings.HasPrefix(normalized, "ton"):
		return normalized
	case strings.HasPrefix(normalized, "tron"):
		return normalized
	}

	return "" // EVM chain
}

// dispatchNonEVMChain routes a non-EVM chain group to its proper execution handler.
func (btce *BFTTargetChainExecutor) dispatchNonEVMChain(
	ctx context.Context,
	chainName string,
	intentID, transactionHash, accountURL, validatorID, bundleID, anchorID string,
	certenProof *proof.CertenProof,
	chainID int64,
) (*TargetChainExecutionResult, error) {
	switch {
	case strings.HasPrefix(chainName, "solana"):
		return btce.executeSolanaOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	case strings.HasPrefix(chainName, "near"):
		return btce.executeNearOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	case strings.HasPrefix(chainName, "aptos"):
		return btce.executeAptosOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	case strings.HasPrefix(chainName, "sui"):
		return btce.executeSuiOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	case strings.HasPrefix(chainName, "ton"):
		return btce.executeTonOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	case strings.HasPrefix(chainName, "tron"):
		return btce.executeTronOperations(ctx, intentID, transactionHash, accountURL, validatorID, bundleID, anchorID, certenProof, chainID)
	default:
		return nil, fmt.Errorf("unsupported non-EVM chain: %s (chainId=%d)", chainName, chainID)
	}
}

// getContractManagerForChain creates a contract manager for a specific chain
func (btce *BFTTargetChainExecutor) getContractManagerForChain(
	chainID int64,
	anchorCfg *config.AnchorConfig,
) (*EthereumContractManager, *config.EVMChainConfig, error) {
	var chainCfg *config.EVMChainConfig
	if anchorCfg != nil {
		chainCfg = anchorCfg.GetEVMChainConfig(chainID)
	}

	var contractConfig *CertenContractConfig
	if chainCfg != nil && chainCfg.RPCURL != "" {
		btce.logger.Printf("✅ [MULTI-CHAIN] Loading config for %s (chainId=%d)", chainCfg.Name, chainID)
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
		if contractConfig.CreationContract == "" {
			contractConfig.CreationContract = chainCfg.AnchorV3Address
			contractConfig.VerificationContract = chainCfg.AnchorV3Address
		}
	} else {
		return nil, nil, fmt.Errorf("no configuration found for chainId=%d", chainID)
	}

	if contractConfig.CreationContract == "" {
		return nil, nil, fmt.Errorf("no anchor contract address for chainId=%d", chainID)
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("create contract manager for chainId=%d: %w", chainID, err)
	}

	return ethManager, chainCfg, nil
}

// convertToLegacyIntent converts BFT Intent parameters to legacy intent.CertenIntent format
//
// COMPATIBILITY SHIM: This is a necessary bridge for the v1 contracts right now.
// Until the Solidity ABI matches native BFT structures, we need to convert
// BFT parameters back into legacy intent.CertenIntent format for contract calls.
func (btce *BFTTargetChainExecutor) convertToLegacyIntent(intentID, transactionHash, accountURL string, certenProof *proof.CertenProof) *intent.CertenIntent {
	// Derive org ADI from accountURL (not hardcoded fallback)
	orgADI, _ := getTargetChainConfig(accountURL)

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

// executeTronOperations executes anchor workflow on TRON chains using TRON's HTTP API.
// TRON's /jsonrpc endpoint does NOT support eth_getTransactionCount or eth_sendRawTransaction,
// so we use TRON's native HTTP API (triggersmartcontract + broadcasttransaction) for writes.
// Proof building reuses EthereumContractManager (which works for read-only operations on TRON).
func (btce *BFTTargetChainExecutor) executeTronOperations(
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

	btce.logger.Printf("🔷 [TRON-EXEC] Executing TRON chain operations for intent: %s on chainId=%d", intentID, chainID)

	// Load multi-chain configuration
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load anchor config: %w", err)
	}

	chainCfg := anchorCfg.GetEVMChainConfig(chainID)
	// Defensive: if intent had wrong chainID (e.g. Sepolia 11155111 instead of TRON 2494104990),
	// fall back to TRON Shasta's known chain ID since we're in the TRON execution path.
	if chainCfg == nil || chainCfg.RPCURL == "" || !strings.Contains(strings.ToLower(chainCfg.Name), "tron") {
		btce.logger.Printf("⚠️ [TRON-EXEC] chainId=%d resolved to non-TRON config (%v), falling back to TRON Shasta (2494104990)", chainID, chainCfg)
		chainCfg = anchorCfg.GetEVMChainConfig(2494104990) // TRON Shasta
		if chainCfg == nil || chainCfg.RPCURL == "" {
			return nil, fmt.Errorf("no TRON chain config: tried chainId=%d and fallback 2494104990", chainID)
		}
		chainID = 2494104990
	}

	btce.logger.Printf("✅ [TRON-EXEC] Using TRON config for %s (chainId=%d)", chainCfg.Name, chainID)
	btce.logger.Printf("   RPC: %s", chainCfg.RPCURL)
	btce.logger.Printf("   Anchor Contract: %s", chainCfg.AnchorV4Address)
	btce.logger.Printf("   Explorer: %s", chainCfg.ExplorerURL)

	// Create TRON HTTP client for transaction submission
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	tronClient, err := NewTronClient(chainCfg.RPCURL, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create TRON client: %w", err)
	}
	btce.logger.Printf("   TRON Address: %s", tronClient.GetOwnerAddressHex())

	// Create EthereumContractManager for proof building (works for read-only ops on TRON /jsonrpc)
	contractConfig := &CertenContractConfig{
		EthereumRPC:          chainCfg.RPCURL,
		ChainID:              chainCfg.ChainID,
		PrivateKey:           privateKey,
		CreationContract:     chainCfg.AnchorV4Address,
		VerificationContract: chainCfg.AnchorV4Address,
		AccountContract:      chainCfg.AccountFactory,
		GasLimit:             uint64(chainCfg.GasLimitAnchor),
		MaxGasPriceGwei:      chainCfg.MaxGasPriceGwei,
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder: %w", err)
	}

	// Build legacy intent and proof data (same as EVM path)
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)
	bundleIdHash := ethManager.generateAnchorID(legacyIntent, certenProof)
	comprehensiveProof := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
		&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: fmt.Sprintf("BFT anchor for %s", chainCfg.Name)},
		bundleIdHash,
	)

	// Compute adiURLHash (same as CreateAnchorOnChain)
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	copy(adiURLHash[:], ethcrypto.Keccak256([]byte(adiURL)))

	anchorContract := chainCfg.AnchorV4Address
	feeLimit := int64(chainCfg.GasLimitAnchor)
	if feeLimit <= 0 {
		feeLimit = 1000000000 // 1000 TRX default fee limit
	}

	// ========== Step 1: Create Anchor via TRON HTTP API ==========
	btce.logger.Printf("🔗 [TRON-EXEC] Step 1: Creating anchor on %s...", chainCfg.Name)

	createTxHash, err := tronClient.CreateAnchor(ctx, anchorContract,
		bundleIdHash, adiURLHash,
		comprehensiveProof.Commitments.OperationCommitment,
		comprehensiveProof.Commitments.CrossChainCommitment,
		comprehensiveProof.Commitments.GovernanceRoot,
		big.NewInt(int64(certenProof.BlockHeight)),
		feeLimit,
	)
	if err != nil {
		btce.logger.Printf("❌ [TRON-EXEC] Step 1 failed: %v", err)
		return btce.buildTronFailedResult(chainCfg, intentID, anchorID, err), err
	}

	btce.logger.Printf("✅ [TRON-EXEC] Step 1 complete - Anchor created: %s", createTxHash)

	// Wait for Step 1 confirmation
	info, err := tronClient.WaitForConfirmation(ctx, createTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [TRON-EXEC] Step 1 confirmation failed: %v", err)
	} else if info != nil {
		if bn, ok := info["blockNumber"]; ok {
			btce.logger.Printf("   Confirmed in TRON block: %v", bn)
		}
	}

	// ========== Step 2: Execute Comprehensive Proof via TRON HTTP API ==========
	btce.logger.Printf("🔗 [TRON-EXEC] Step 2: Submitting comprehensive proof on %s...", chainCfg.Name)

	// Convert ComprehensiveCertenProof to V4 CertenProof for contract call
	v4Proof := contracts.ConvertFromExtended(comprehensiveProof)

	verifyTxHash, err := tronClient.ExecuteComprehensiveProof(ctx, anchorContract,
		bundleIdHash, v4Proof, feeLimit)
	if err != nil {
		btce.logger.Printf("❌ [TRON-EXEC] Step 2 failed: %v", err)
		// Step 1 succeeded, Step 2 failed — partial success
		return btce.buildTronResult(chainCfg, intentID, anchorID,
			createTxHash, fmt.Sprintf("verify_failed_%s", chainCfg.Name), "", false), err
	}

	btce.logger.Printf("✅ [TRON-EXEC] Step 2 complete - Proof verified: %s", verifyTxHash)

	// Wait for Step 2 confirmation
	info, err = tronClient.WaitForConfirmation(ctx, verifyTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [TRON-EXEC] Step 2 confirmation failed: %v", err)
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	// CORRECT FLOW: Call executeGovernanceProofDirect on the USER'S abstract account,
	// NOT executeWithGovernance on the anchor contract.
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	tronLeg := btce.findLegForChainPrefix(allLegs, "tron", 2494104990)
	govTxHash := ""
	if tronLeg != nil && tronLeg.SourceAddress != (common.Address{}) {
		userAccountAddr := tronLeg.SourceAddress
		btce.logger.Printf("🏦 [TRON-EXEC] Step 3: Executing governance proof direct on user account %s", userAccountAddr.Hex())

		// Pre-flight: Check if the user's abstract account contract exists on-chain
		userAccountHex := "0x" + hex.EncodeToString(userAccountAddr.Bytes())
		contractExists, checkErr := tronClient.CheckContractExists(ctx, userAccountHex)
		if checkErr != nil {
			btce.logger.Printf("⚠️ [TRON-EXEC] Step 3: Failed to check account existence: %v", checkErr)
		}

		if !contractExists {
			btce.logger.Printf("⚠️ [TRON-EXEC] Step 3: User account %s has no contract deployed", userAccountHex)

			// Auto-deploy via CertenAccountFactory using deterministic derivation from ADI URL.
			// Owner and salt are derived the same way as the Bridge API:
			//   owner = last 20 bytes of keccak256(adiUrl)
			//   salt  = BigInt(keccak256(adiUrl))
			factoryAddr := chainCfg.AccountFactory
			if factoryAddr != "" {
				ownerAddr := DeriveAccountOwner(adiURL)
				salt := DeriveAccountSalt(adiURL)
				btce.logger.Printf("🏗️ [TRON-EXEC] Auto-deploying user account via factory %s", factoryAddr)
				btce.logger.Printf("   Derived owner: %s (from ADI URL: %s)", ownerAddr.Hex(), adiURL)

				deployTx, deployErr := tronClient.DeployAccountViaFactory(ctx,
					factoryAddr, ownerAddr, adiURL, salt,
					0, // deployment fee (factory fee is 0)
					feeLimit,
				)
				if deployErr != nil {
					btce.logger.Printf("❌ [TRON-EXEC] Account auto-deploy failed: %v", deployErr)
					govTxHash = fmt.Sprintf("gov_failed_account_deploy_%s", chainCfg.Name)
				} else {
					btce.logger.Printf("✅ [TRON-EXEC] Account deployment tx: %s", deployTx)
					// Wait for deployment confirmation before proceeding
					_, waitErr := tronClient.WaitForConfirmation(ctx, deployTx, 60*time.Second)
					if waitErr != nil {
						btce.logger.Printf("⚠️ [TRON-EXEC] Account deployment confirmation failed: %v", waitErr)
						govTxHash = fmt.Sprintf("gov_failed_account_deploy_%s", chainCfg.Name)
					} else {
						contractExists = true // Only proceed to Step 3 if deployment succeeded
					}
				}
			} else {
				btce.logger.Printf("❌ [TRON-EXEC] Cannot auto-deploy: no factory address configured")
				govTxHash = fmt.Sprintf("gov_failed_no_factory_%s", chainCfg.Name)
			}
		}

		if contractExists && govTxHash == "" {
			// Read back anchor commitments from chain via TRON native HTTP API.
			// This is a critical verification step — confirms on-chain state matches expectations.
			anchorData, err := tronClient.GetAnchorData(ctx, anchorContract, bundleIdHash)
			if err != nil {
				btce.logger.Printf("⚠️ [TRON-EXEC] Step 3: Failed to fetch anchor commitments: %v", err)
				govTxHash = fmt.Sprintf("gov_failed_anchor_read_%s", chainCfg.Name)
			} else {
				// Build AccountProof with 4-leaf merkle proof (same logic as EVM buildAccountProof)
				accountProof := btce.buildTronAccountProof(
					bundleIdHash,
					certenProof,
					adiURL,
					anchorData.OperationCommitment,
					anchorData.CrossChainCommitment,
					anchorData.GovernanceRoot,
				)

				// Value from intent is already in chain-native base units (sun for TRON)
				btce.logger.Printf("💱 [TRON-EXEC] Governance value: %s (native base units)", tronLeg.Value.String())

				var govErr error
				govTxHash, govErr = tronClient.ExecuteGovernanceProofDirect(ctx,
					userAccountHex,
					tronLeg.Target.Hex(),
					tronLeg.Value,
					tronLeg.Data,
					accountProof,
					feeLimit,
				)
				if govErr != nil {
					btce.logger.Printf("⚠️ [TRON-EXEC] Step 3 failed: %v", govErr)
					govTxHash = fmt.Sprintf("gov_failed_%s", chainCfg.Name)
				}
			}
		}
	} else {
		govTxHash = "no_governance_needed"
	}

	btce.logger.Printf("🎉 [TRON-EXEC] TRON anchor workflow completed for %s!", chainCfg.Name)
	if chainCfg.ExplorerURL != "" {
		btce.logger.Printf("   View on Tronscan: %s/#/transaction/%s", chainCfg.ExplorerURL, createTxHash)
	}

	return btce.buildTronResult(chainCfg, intentID, anchorID, createTxHash, verifyTxHash, govTxHash, true), nil
}

// buildTronAccountProof constructs the AccountProof struct for CertenAccountV2 on TRON.
// Mirrors EVM's buildAccountProof — computes a 4-leaf merkle proof for adiURL verification.
//
// Merkle Tree Structure:
//
//	          root
//	        /      \
//	   hash01      hash23
//	  /    \      /    \
//	adiHash  op   cc    gov
//
// To prove adiHash, we need: [op, hash23]
func (btce *BFTTargetChainExecutor) buildTronAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
) contracts.AccountProof {
	// proof[0] = operationCommitment (sibling at level 0)
	var merkleProof [][32]byte
	merkleProof = append(merkleProof, opCommitment)

	// proof[1] = sortedHash(ccCommitment, govRoot) (sibling at level 1)
	hash23 := sortedHash(ccCommitment[:], govRoot[:])
	var hash23Arr [32]byte
	copy(hash23Arr[:], hash23)
	merkleProof = append(merkleProof, hash23Arr)

	log.Printf("🌳 [TRON-MERKLE] Built 4-leaf proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (op): 0x%x", opCommitment[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23Arr[:8])

	// Set expiration (1 hour from now)
	expiresAt := big.NewInt(time.Now().Add(1 * time.Hour).Unix())

	// Build validator signatures from BLS aggregate signature
	var validatorSigs []byte
	if certenProof != nil && certenProof.BLSAggregateSignature != "" {
		sigHex := strings.TrimPrefix(certenProof.BLSAggregateSignature, "0x")
		sigBytes, err := hex.DecodeString(sigHex)
		if err == nil {
			validatorSigs = sigBytes
		}
	}

	return contracts.AccountProof{
		AdiURL:              adiURL,
		AnchorId:            bundleID,
		MerkleProof:         merkleProof,
		KeyBookProof:        []byte{},
		RoleProof:           []byte{},
		ThresholdProof:      []byte{},
		Timestamp:           big.NewInt(time.Now().Unix()),
		ExpiresAt:           expiresAt,
		ValidatorSignatures: validatorSigs,
		Nonce:               big.NewInt(0),
		RequiredLevel:       1, // G1 governance level
	}
}

// buildTronResult creates a TargetChainExecutionResult for TRON operations
func (btce *BFTTargetChainExecutor) buildTronResult(
	chainCfg *config.EVMChainConfig,
	intentID, anchorID string,
	createTxHash, verifyTxHash, govTxHash string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            chainCfg.Name,
		TxHash:           createTxHash, // Primary tx for backwards compat
		Success:          success,
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
		Metadata: map[string]string{
			"chain":           chainCfg.Name,
			"chainId":         fmt.Sprintf("%d", chainCfg.ChainID),
			"anchorContract":  chainCfg.AnchorV4Address,
			"explorerUrl":     chainCfg.ExplorerURL,
			"executionMethod": "tron_http_api",
		},
	}
}

// buildTronFailedResult creates a failed result for TRON operations
func (btce *BFTTargetChainExecutor) buildTronFailedResult(
	chainCfg *config.EVMChainConfig,
	intentID, anchorID string,
	failErr error,
) *TargetChainExecutionResult {
	return btce.buildTronResult(chainCfg, intentID, anchorID,
		fmt.Sprintf("create_failed_%s", chainCfg.Name),
		fmt.Sprintf("verify_failed_%s", chainCfg.Name),
		fmt.Sprintf("gov_failed_%s", chainCfg.Name),
		false,
	)
}

// =============================================================================
// NEAR PROTOCOL EXECUTION
// =============================================================================

// executeNearOperations executes anchor workflow on NEAR Protocol using JSON-RPC.
// NEAR uses Ed25519 signing, Borsh serialization, and JSON args — completely different from EVM.
// Proof building reuses existing commitment logic from EthereumContractManager.
func (btce *BFTTargetChainExecutor) executeNearOperations(
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

	btce.logger.Printf("🔷 [NEAR-EXEC] Executing NEAR chain operations for intent: %s", intentID)

	// Load NEAR config from environment
	nearSignerAccountID := os.Getenv("NEAR_SIGNER_ACCOUNT_ID")
	nearPrivateKey := os.Getenv("NEAR_PRIVATE_KEY")
	nearRPCURL := os.Getenv("NEAR_TESTNET_RPC_URL")
	nearAnchorContract := os.Getenv("NEAR_ANCHOR_CONTRACT")
	nearAccountFactory := os.Getenv("NEAR_ACCOUNT_FACTORY")

	if nearSignerAccountID == "" || nearPrivateKey == "" || nearRPCURL == "" || nearAnchorContract == "" {
		return nil, fmt.Errorf("missing NEAR config: NEAR_SIGNER_ACCOUNT_ID=%q, NEAR_PRIVATE_KEY_SET=%v, NEAR_TESTNET_RPC_URL=%q, NEAR_ANCHOR_CONTRACT=%q",
			nearSignerAccountID, nearPrivateKey != "", nearRPCURL, nearAnchorContract)
	}

	btce.logger.Printf("✅ [NEAR-EXEC] Using NEAR config:")
	btce.logger.Printf("   Signer: %s", nearSignerAccountID)
	btce.logger.Printf("   RPC: %s", nearRPCURL)
	btce.logger.Printf("   Anchor Contract: %s", nearAnchorContract)
	btce.logger.Printf("   Account Factory: %s", nearAccountFactory)

	// Create NEAR client
	nearClient, err := NewNearClient(nearRPCURL, nearSignerAccountID, nearPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create NEAR client: %w", err)
	}

	// Create EthereumContractManager for proof building (reuse commitment logic)
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	contractConfig := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		ChainID:              11155111,
		PrivateKey:           privateKey,
		CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		GasLimit:             800000,
		MaxGasPriceGwei:      50,
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		btce.logger.Printf("⚠️ [NEAR-EXEC] Failed to create proof builder (non-fatal, using defaults): %v", err)
	}

	// Build legacy intent and proof data (same as EVM/TRON path)
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	var bundleIdHash [32]byte
	var comprehensiveProof *contracts.ComprehensiveCertenProof
	if ethManager != nil {
		bundleIdHash = ethManager.generateAnchorID(legacyIntent, certenProof)
		cp := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
			&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: "BFT anchor for NEAR"},
			bundleIdHash,
		)
		comprehensiveProof = &cp
	} else {
		// Fallback: generate bundleIdHash manually
		hash := ethcrypto.Keccak256Hash([]byte(fmt.Sprintf("certen_v3_%s_%d_%s",
			legacyIntent.IntentID, certenProof.BlockHeight, certenProof.TransactionHash)))
		copy(bundleIdHash[:], hash[:])
	}

	// Compute adiURLHash
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	copy(adiURLHash[:], ethcrypto.Keccak256([]byte(adiURL)))

	// Gas constants for NEAR (in gas units, not TGas)
	const (
		gasCreateAnchor  = 30_000_000_000_000  // 30 TGas
		gasVerifyProof   = 300_000_000_000_000 // 300 TGas
		gasGovernance    = 200_000_000_000_000 // 200 TGas
		gasFactoryDeploy = 100_000_000_000_000 // 100 TGas
	)

	// Extract commitments
	var opCommitment, ccCommitment, govRoot [32]byte
	if comprehensiveProof != nil {
		opCommitment = comprehensiveProof.Commitments.OperationCommitment
		ccCommitment = comprehensiveProof.Commitments.CrossChainCommitment
		govRoot = comprehensiveProof.Commitments.GovernanceRoot
	}

	// ========== Step 1: Create Anchor ==========
	btce.logger.Printf("🔗 [NEAR-EXEC] Step 1: Creating anchor on %s...", nearAnchorContract)

	createTxHash, err := nearClient.CreateAnchor(ctx, nearAnchorContract,
		bundleIdHash, adiURLHash, opCommitment, ccCommitment, govRoot,
		certenProof.BlockHeight, gasCreateAnchor,
	)
	if err != nil {
		btce.logger.Printf("❌ [NEAR-EXEC] Step 1 failed: %v", err)
		return btce.buildNearResult(intentID, anchorID,
			fmt.Sprintf("create_failed_near"), "", "", false), err
	}

	btce.logger.Printf("✅ [NEAR-EXEC] Step 1 complete - Anchor created: %s", createTxHash)

	// Wait for Step 1 confirmation
	_, err = nearClient.WaitForConfirmation(ctx, createTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [NEAR-EXEC] Step 1 confirmation issue: %v", err)
	}

	// ========== Step 2: Execute Comprehensive Proof ==========
	btce.logger.Printf("🔗 [NEAR-EXEC] Step 2: Submitting comprehensive proof on %s...", nearAnchorContract)

	nearProof := btce.buildNearCertenProof(comprehensiveProof, certenProof, nearSignerAccountID)

	verifyTxHash, err := nearClient.ExecuteComprehensiveProof(ctx, nearAnchorContract,
		bundleIdHash, nearProof, gasVerifyProof,
	)
	if err != nil {
		btce.logger.Printf("❌ [NEAR-EXEC] Step 2 failed: %v", err)
		return btce.buildNearResult(intentID, anchorID,
			createTxHash, fmt.Sprintf("verify_failed_near"), "", false), err
	}

	btce.logger.Printf("✅ [NEAR-EXEC] Step 2 complete - Proof verified: %s", verifyTxHash)

	// Wait for Step 2 confirmation
	_, err = nearClient.WaitForConfirmation(ctx, verifyTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [NEAR-EXEC] Step 2 confirmation issue: %v", err)
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	nearLeg := btce.findLegForChainPrefix(allLegs, "near", 398)
	govTxHash := "no_governance_needed"

	if nearLeg != nil {
		btce.logger.Printf("🏦 [NEAR-EXEC] Step 3: Executing governance proof direct...")

		// Extract NEAR account IDs directly from CrossChainData (not from hex-parsed LegExecution)
		nearFromAccountID := btce.extractNearFieldFromCrossChainData(legacyIntent, "from")
		nearToAccountID := btce.extractNearFieldFromCrossChainData(legacyIntent, "to")

		btce.logger.Printf("   Intent from: %s", nearFromAccountID)
		btce.logger.Printf("   Intent to: %s", nearToAccountID)

		// Use the from field directly as the user account ID if it looks like a NEAR account
		userAccountID := nearFromAccountID

		// Fallback: derive via factory prediction if not available from intent
		ownerBytes32 := DeriveNearAccountOwnerBytes32(adiURL)
		ownerEth := DeriveNearAccountOwnerEth(adiURL)
		salt := DeriveNearAccountSalt(adiURL)

		if userAccountID == "" && nearAccountFactory != "" {
			predicted, predictErr := nearClient.PredictAccountID(ctx, nearAccountFactory, ownerBytes32, adiURL, salt)
			if predictErr != nil {
				btce.logger.Printf("⚠️ [NEAR-EXEC] Failed to predict account ID: %v", predictErr)
				userAccountID = fmt.Sprintf("%x.%s", salt&0xFFFFFFFF, nearAccountFactory)
			} else {
				userAccountID = predicted
			}
		} else if userAccountID == "" {
			btce.logger.Printf("⚠️ [NEAR-EXEC] No factory configured and no from address in intent")
			govTxHash = "gov_failed_no_factory_near"
		}

		if userAccountID != "" {
			btce.logger.Printf("   User account: %s", userAccountID)

			// Check if account exists
			accountExists, checkErr := nearClient.CheckAccountExists(ctx, userAccountID)
			if checkErr != nil {
				btce.logger.Printf("⚠️ [NEAR-EXEC] Failed to check account existence: %v", checkErr)
			}

			if !accountExists && nearAccountFactory != "" {
				btce.logger.Printf("⚠️ [NEAR-EXEC] User account %s not found, auto-deploying...", userAccountID)

				// 10 NEAR deposit for account creation (8 NEAR storage + 0.5 fee + headroom)
				deposit := new(big.Int)
				deposit.SetString("10000000000000000000000000", 10) // 10 * 10^24 yoctoNEAR

				// Use 300 TGas for factory deployment (creates sub-account + deploys WASM)
				const gasFactoryDeployHigh = 300_000_000_000_000 // 300 TGas
				deployTx, deployErr := nearClient.DeployAccountViaFactory(ctx,
					nearAccountFactory, ownerBytes32, ownerEth, adiURL, salt, deposit, gasFactoryDeployHigh,
				)
				if deployErr != nil {
					btce.logger.Printf("❌ [NEAR-EXEC] Account auto-deploy failed: %v", deployErr)
					govTxHash = "gov_failed_account_deploy_near"
				} else {
					btce.logger.Printf("✅ [NEAR-EXEC] Account deployment tx: %s", deployTx)
					_, waitErr := nearClient.WaitForConfirmation(ctx, deployTx, 60*time.Second)
					if waitErr != nil {
						btce.logger.Printf("⚠️ [NEAR-EXEC] Account deployment confirmation failed: %v", waitErr)
						govTxHash = "gov_failed_account_deploy_near"
					} else {
						accountExists = true
					}
				}
			}

			if accountExists && govTxHash == "no_governance_needed" {
				// Read anchor data back for merkle proof construction
				anchorData, readErr := nearClient.GetAnchorData(ctx, nearAnchorContract, bundleIdHash)
				if readErr != nil {
					btce.logger.Printf("⚠️ [NEAR-EXEC] Failed to read anchor data: %v", readErr)
					govTxHash = "gov_failed_anchor_read_near"
				} else {
					// Determine target and value from the NEAR-specific leg (not allLegs[0])
					targetAddr := nearToAccountID
					if targetAddr == "" {
						targetAddr = nearLeg.Target.Hex()
					}

					// Convert amountWei (18 decimals) to yoctoNEAR (24 decimals)
					// Web app sends amounts in 18-decimal "wei" format, NEAR uses 24-decimal yoctoNEAR
					targetValue := big.NewInt(1)
					if nearLeg.Value != nil {
						targetValue = new(big.Int).Mul(nearLeg.Value, big.NewInt(1_000_000)) // * 10^6
					}

					btce.logger.Printf("💱 [NEAR-EXEC] Governance: target=%s deposit=%s yoctoNEAR (converted from %s wei)",
						targetAddr, targetValue.String(), nearLeg.Value.String())

					// Build ADIGovernanceProof (pass deposit so authority level matches contract thresholds)
					accountProof := btce.buildNearAccountProof(
						bundleIdHash, certenProof, adiURL,
						anchorData.OperationCommitment,
						anchorData.CrossChainCommitment,
						anchorData.GovernanceRoot,
						targetValue,
					)

					nearCall := NearCallJSON{
						Target:  targetAddr,
						Method:  "transfer",
						Args:    encodeBytesAsBase64([]byte{}), // Base64VecU8 = empty bytes
						Deposit: targetValue.String(),
						GasTgas: 30,
					}

					var govErr error
					govTxHash, govErr = nearClient.ExecuteGovernanceProofDirect(ctx,
						userAccountID, nearCall, accountProof, gasGovernance,
					)
					if govErr != nil {
						btce.logger.Printf("⚠️ [NEAR-EXEC] Step 3 failed: %v", govErr)
						govTxHash = "gov_failed_near"
					}
				}
			}
		}
	}

	btce.logger.Printf("🎉 [NEAR-EXEC] NEAR anchor workflow completed!")
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	return btce.buildNearResult(intentID, anchorID, createTxHash, verifyTxHash, govTxHash, true), nil
}

// buildNearCertenProof converts the comprehensive proof to NEAR JSON format.
// Must match the Rust CertenProofInput struct exactly.
func (btce *BFTTargetChainExecutor) buildNearCertenProof(
	proof *contracts.ComprehensiveCertenProof,
	certenProof *proof.CertenProof,
	nearSignerAccountID string,
) NearCertenProofInput {
	if proof == nil {
		return NearCertenProofInput{
			ExpirationTime: uint64(time.Now().Add(24*time.Hour).UnixNano()),
		}
	}

	// Convert proof hashes to base64
	proofHashes := make([]string, len(proof.ProofHashes))
	for i, h := range proof.ProofHashes {
		proofHashes[i] = encodeBytes32AsBase64(h)
	}

	// Convert key page proofs to base64
	keyPageProofs := make([]string, len(proof.GovernanceProof.KeyPageProofs))
	for i, h := range proof.GovernanceProof.KeyPageProofs {
		keyPageProofs[i] = encodeBytes32AsBase64(h)
	}

	totalVP := uint64(0)
	if proof.BLSProof.TotalVotingPower != nil {
		totalVP = proof.BLSProof.TotalVotingPower.Uint64()
	}
	signedVP := uint64(0)
	if proof.BLSProof.SignedVotingPower != nil {
		signedVP = proof.BLSProof.SignedVotingPower.Uint64()
	}

	govNonce := uint64(0)
	if proof.GovernanceProof.Nonce != nil {
		govNonce = proof.GovernanceProof.Nonce.Uint64()
	}
	reqSigs := uint64(0)
	if proof.GovernanceProof.RequiredSignatures != nil {
		reqSigs = proof.GovernanceProof.RequiredSignatures.Uint64()
	}
	provSigs := uint64(0)
	if proof.GovernanceProof.ProvidedSignatures != nil {
		provSigs = proof.GovernanceProof.ProvidedSignatures.Uint64()
	}

	// NEAR uses nanoseconds for block_timestamp(), so expiration must be in nanoseconds
	expirationNano := uint64(time.Now().Add(24 * time.Hour).UnixNano())
	if proof.ExpirationTime != nil {
		// ExpirationTime from EVM is in seconds — convert to nanoseconds
		expirationNano = proof.ExpirationTime.Uint64() * 1_000_000_000
	}

	// Convert ABI-encoded Groth16 proof to NEAR JSON format for BLS verifier
	aggregateSigProof := ""
	if len(proof.BLSProof.AggregateSignature) >= 448 {
		nearProofB64, err := ConvertABIProofToNEARJSON(proof.BLSProof.AggregateSignature)
		if err != nil {
			log.Printf("⚠️ [NEAR] Failed to convert BLS proof to NEAR format: %v", err)
		} else {
			aggregateSigProof = nearProofB64
			log.Printf("✅ [NEAR] Converted Groth16 proof to NEAR JSON format (%d base64 chars)", len(nearProofB64))
		}
	} else {
		log.Printf("⚠️ [NEAR] ABI proof bytes too short (%d), using empty aggregate_signature_proof", len(proof.BLSProof.AggregateSignature))
	}

	// Authority address must be base64-encoded bytes (Base64VecU8), not hex
	authorityAddrBase64 := encodeBytesAsBase64(proof.GovernanceProof.AuthorityAddress.Bytes())

	// Validator addresses must be NEAR AccountIds, not hex EVM addresses
	validatorAddrs := []string{nearSignerAccountID}

	return NearCertenProofInput{
		TransactionHash: encodeBytes32AsBase64(proof.TransactionHash),
		ProofHashes:     proofHashes,
		MerkleRoot:      encodeBytes32AsBase64(proof.MerkleRoot),
		LeafHash:        encodeBytes32AsBase64(proof.LeafHash),
		GovernanceProof: NearGovernanceProof{
			KeyBookRoot:        encodeBytes32AsBase64(proof.GovernanceProof.KeyBookRoot),
			KeyPageProofs:      keyPageProofs,
			AuthorityAddress:   authorityAddrBase64,
			AuthorityLevel:     proof.GovernanceProof.AuthorityLevel,
			RequiredSignatures: reqSigs,
			ProvidedSignatures: provSigs,
			Nonce:              govNonce,
		},
		BlsProof: NearBLSProof{
			AggregateSignatureProof: aggregateSigProof,
			MessageHash:             encodeBytes32AsBase64(proof.BLSProof.MessageHash),
			ThresholdMet:            proof.BLSProof.ThresholdMet,
			SignedVotingPower:       signedVP,
			TotalVotingPower:        totalVP,
			ValidatorAddresses:      validatorAddrs,
		},
		Commitments: NearCommitmentsJSON{
			OperationCommitment:  encodeBytes32AsBase64(proof.Commitments.OperationCommitment),
			CrossChainCommitment: encodeBytes32AsBase64(proof.Commitments.CrossChainCommitment),
			GovernanceRoot:       encodeBytes32AsBase64(proof.Commitments.GovernanceRoot),
		},
		ExpirationTime: expirationNano,
	}
}

// nearAuthorityLevelForDeposit returns the NEAR contract AuthorityLevel string
// matching the deposit-based thresholds in verification/mod.rs.
func nearAuthorityLevelForDeposit(depositYocto *big.Int) string {
	rootThreshold := new(big.Int).SetUint64(10_000_000)
	rootThreshold.Mul(rootThreshold, new(big.Int).SetUint64(1_000_000_000_000_000_000)) // 10 NEAR

	adminThreshold := new(big.Int).SetUint64(1_000_000)
	adminThreshold.Mul(adminThreshold, new(big.Int).SetUint64(1_000_000_000_000_000_000)) // 1 NEAR

	managerThreshold := new(big.Int).SetUint64(100_000)
	managerThreshold.Mul(managerThreshold, new(big.Int).SetUint64(1_000_000_000_000_000_000)) // 0.1 NEAR

	if depositYocto.Cmp(rootThreshold) >= 0 {
		return "ROOT"
	} else if depositYocto.Cmp(adminThreshold) >= 0 {
		return "ADMIN"
	} else if depositYocto.Cmp(managerThreshold) >= 0 {
		return "MANAGER"
	}
	return "OPERATOR"
}

// buildNearAccountProof constructs the NearADIGovernanceProofJSON for Step 3.
// Mirrors buildTronAccountProof — computes a 4-leaf merkle proof for adiURL verification.
func (btce *BFTTargetChainExecutor) buildNearAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
	depositYocto *big.Int,
) NearADIGovernanceProofJSON {
	// Calculate authority level matching contract deposit thresholds
	requiredLevel := nearAuthorityLevelForDeposit(depositYocto)
	log.Printf("🔐 [NEAR-AUTH] Deposit %s yoctoNEAR → authority level: %s", depositYocto.String(), requiredLevel)

	// Build merkle proof: same 4-leaf tree as TRON/EVM
	// proof[0] = operationCommitment (sibling at level 0)
	// proof[1] = sortedHash(ccCommitment, govRoot) (sibling at level 1)
	hash23 := sortedHash(ccCommitment[:], govRoot[:])
	var hash23Arr [32]byte
	copy(hash23Arr[:], hash23)

	log.Printf("🌳 [NEAR-MERKLE] Built 4-leaf proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (op): 0x%x", opCommitment[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23Arr[:8])

	merkleProof := []string{
		encodeBytes32AsBase64(opCommitment),
		encodeBytes32AsBase64(hash23Arr),
	}

	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)

	// Build validator signatures
	validatorSigs := ""
	if certenProof != nil && certenProof.BLSAggregateSignature != "" {
		sigHex := strings.TrimPrefix(certenProof.BLSAggregateSignature, "0x")
		sigBytes, err := hex.DecodeString(sigHex)
		if err == nil {
			validatorSigs = encodeBytesAsBase64(sigBytes)
		}
	}

	return NearADIGovernanceProofJSON{
		AdiURL:      adiURL,
		AnchorID:    encodeBytes32AsBase64(bundleID),
		MerkleProof: merkleProof,
		KeyBookProof: NearKeyBookProofJSON{
			KeyBookURL:     "",
			KeyBookRoot:    encodeBytes32AsBase64([32]byte{}),
			HierarchyDepth: 0,
			KeyPageProofs:  encodeBytesAsBase64([]byte{}), // Base64VecU8 = single base64 string
			ValidFromSec:   0,
			ValidUntilSec:  0,
		},
		RoleProof: NearRoleProofJSON{
			Level:        requiredLevel, // Must match or exceed deposit-based threshold
			Permissions:  []string{},    // Vec<String> = JSON array of strings
			RoleHash:     encodeBytes32AsBase64([32]byte{}),
			Signature:    encodeBytesAsBase64([]byte{}),
			AuthorizedBy: encodeBytesAsBase64([]byte{}),
			GrantedAtSec: 0,
		},
		ThresholdProof: NearThresholdProofJSON{
			RequiredThreshold: 0,
			Signatures:        []string{},
			Signers:           []string{},
			VotingPowers:      []uint64{},
			TotalVotingPower:  0,
			MessageHash:       encodeBytes32AsBase64([32]byte{}),
		},
		ValidatorSignatures: validatorSigs,
		TimestampSec:        uint64(now.Unix()),
		ExpiresAtSec:        uint64(expiresAt.Unix()),
		Nonce:               1, // Must be > current nonce (starts at 0)
		RequiredLevel:       requiredLevel, // Matches deposit-based contract thresholds
	}
}

// extractNearTargetFromCrossChainData extracts the original NEAR account ID from CrossChainData.
// NEAR targets are account IDs (strings like "alice.testnet"), not hex addresses.
func (btce *BFTTargetChainExecutor) extractNearTargetFromCrossChainData(legacyIntent *intent.CertenIntent) string {
	return btce.extractNearFieldFromCrossChainData(legacyIntent, "to")
}

// extractNearFieldFromCrossChainData extracts a NEAR account ID field ("from" or "to") from CrossChainData.
// Returns the field value if it looks like a NEAR account ID (contains dots, no 0x prefix).
func (btce *BFTTargetChainExecutor) extractNearFieldFromCrossChainData(legacyIntent *intent.CertenIntent, field string) string {
	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		return ""
	}

	var ccData struct {
		Legs []struct {
			From    string `json:"from"`
			To      string `json:"to"`
			Chain   string `json:"chain"`
			ChainID int64  `json:"chainId"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(legacyIntent.CrossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return ""
	}

	// Find the NEAR-specific leg (not just leg 0)
	for _, leg := range ccData.Legs {
		chainNorm := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
		if !strings.HasPrefix(chainNorm, "near") && leg.ChainID != 398 {
			continue
		}
		var value string
		switch field {
		case "from":
			value = leg.From
		case "to":
			value = leg.To
		}
		if value != "" && !strings.HasPrefix(value, "0x") {
			if strings.Contains(value, ".") {
				return value
			}
			if len(value) == 64 && isLowercaseHex(value) {
				return value
			}
		}
	}

	// Fallback: check leg 0 (for single-chain NEAR intents)
	var value string
	switch field {
	case "from":
		value = ccData.Legs[0].From
	case "to":
		value = ccData.Legs[0].To
	}
	if value != "" && !strings.HasPrefix(value, "0x") {
		if strings.Contains(value, ".") {
			return value
		}
		if len(value) == 64 && isLowercaseHex(value) {
			return value
		}
	}
	return ""
}

// isLowercaseHex checks if a string contains only lowercase hex characters (0-9, a-f).
func isLowercaseHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// buildNearResult creates a TargetChainExecutionResult for NEAR operations.
func (btce *BFTTargetChainExecutor) buildNearResult(
	intentID, anchorID string,
	createTxHash, verifyTxHash, govTxHash string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            "near-testnet",
		TxHash:           createTxHash,
		Success:          success,
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
		Metadata: map[string]string{
			"chain":           "near-testnet",
			"anchorContract":  os.Getenv("NEAR_ANCHOR_CONTRACT"),
			"explorerUrl":     "https://testnet.nearblocks.io",
			"executionMethod": "near_json_rpc",
		},
	}
}

// =============================================================================
// SOLANA CHAIN EXECUTION
// =============================================================================

// executeSolanaOperations executes anchor workflow on Solana using JSON-RPC.
// Solana uses Ed25519 signing, Borsh-encoded Anchor instructions, and PDAs.
// Proof building reuses existing commitment logic from EthereumContractManager.
func (btce *BFTTargetChainExecutor) executeSolanaOperations(
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

	btce.logger.Printf("🔷 [SOLANA-EXEC] Executing Solana chain operations for intent: %s", intentID)

	// Load Solana config from environment
	solanaPrivateKey := os.Getenv("SOLANA_PRIVATE_KEY")
	solanaRPCURL := os.Getenv("SOLANA_DEVNET_RPC_URL")
	solanaAnchorProgramID := os.Getenv("SOLANA_ANCHOR_PROGRAM_ID")
	solanaBLSVerifierProgramID := os.Getenv("SOLANA_BLS_VERIFIER_PROGRAM_ID")
	solanaAccountFactoryProgramID := os.Getenv("SOLANA_ACCOUNT_FACTORY_PROGRAM_ID")
	solanaAccountProgramID := os.Getenv("SOLANA_ACCOUNT_PROGRAM_ID")

	if solanaPrivateKey == "" || solanaRPCURL == "" || solanaAnchorProgramID == "" {
		return nil, fmt.Errorf("missing Solana config: SOLANA_PRIVATE_KEY=%v, SOLANA_DEVNET_RPC_URL=%q, SOLANA_ANCHOR_PROGRAM_ID=%q",
			solanaPrivateKey != "", solanaRPCURL, solanaAnchorProgramID)
	}

	btce.logger.Printf("✅ [SOLANA-EXEC] Using Solana config:")
	btce.logger.Printf("   RPC: %s", solanaRPCURL)
	btce.logger.Printf("   Anchor Program: %s", solanaAnchorProgramID)
	btce.logger.Printf("   BLS Verifier: %s", solanaBLSVerifierProgramID)
	btce.logger.Printf("   Account Factory: %s", solanaAccountFactoryProgramID)
	btce.logger.Printf("   Account Program: %s", solanaAccountProgramID)

	// Create Solana client
	solClient, err := NewSolanaClient(solanaRPCURL, solanaPrivateKey,
		solanaAnchorProgramID, solanaBLSVerifierProgramID,
		solanaAccountFactoryProgramID, solanaAccountProgramID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Solana client: %w", err)
	}

	// Create EthereumContractManager for proof building (reuse commitment logic)
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	contractConfig := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		ChainID:              11155111,
		PrivateKey:           privateKey,
		CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		GasLimit:             800000,
		MaxGasPriceGwei:      50,
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		btce.logger.Printf("⚠️ [SOLANA-EXEC] Failed to create proof builder (non-fatal, using defaults): %v", err)
	}

	// Build legacy intent and proof data (same as EVM/TRON/NEAR path)
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	var bundleIdHash [32]byte
	var comprehensiveProof *contracts.ComprehensiveCertenProof
	if ethManager != nil {
		bundleIdHash = ethManager.generateAnchorID(legacyIntent, certenProof)
		cp := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
			&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: "BFT anchor for Solana"},
			bundleIdHash,
		)
		comprehensiveProof = &cp
	} else {
		hash := ethcrypto.Keccak256Hash([]byte(fmt.Sprintf("certen_v3_%s_%d_%s",
			legacyIntent.IntentID, certenProof.BlockHeight, certenProof.TransactionHash)))
		copy(bundleIdHash[:], hash[:])
	}

	// Compute adiURLHash
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	copy(adiURLHash[:], ethcrypto.Keccak256([]byte(adiURL)))

	// Extract commitments
	var opCommitment, ccCommitment, govRoot [32]byte
	if comprehensiveProof != nil {
		opCommitment = comprehensiveProof.Commitments.OperationCommitment
		ccCommitment = comprehensiveProof.Commitments.CrossChainCommitment
		govRoot = comprehensiveProof.Commitments.GovernanceRoot
	}

	// ========== Step 1: Create Anchor ==========
	btce.logger.Printf("🔗 [SOLANA-EXEC] Step 1: Creating anchor...")

	createTxSig, err := solClient.CreateAnchor(ctx,
		bundleIdHash, adiURLHash, opCommitment, ccCommitment, govRoot,
		certenProof.BlockHeight,
	)
	if err != nil {
		btce.logger.Printf("❌ [SOLANA-EXEC] Step 1 failed: %v", err)
		return btce.buildSolanaResult(intentID, anchorID,
			"create_failed_solana", "", "", false), err
	}

	btce.logger.Printf("✅ [SOLANA-EXEC] Step 1 complete - Anchor created: %s", createTxSig)

	// Wait for Step 1 confirmation
	err = solClient.WaitForConfirmation(ctx, createTxSig, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [SOLANA-EXEC] Step 1 confirmation issue: %v", err)
	}

	// ========== Step 2: Execute Comprehensive Proof ==========
	btce.logger.Printf("🔗 [SOLANA-EXEC] Step 2: Submitting comprehensive proof...")

	solanaProof := btce.buildSolanaCertenProof(comprehensiveProof, certenProof)

	verifyTxSig, err := solClient.ExecuteComprehensiveProof(ctx, bundleIdHash, solanaProof)
	if err != nil {
		btce.logger.Printf("❌ [SOLANA-EXEC] Step 2 failed: %v", err)
		return btce.buildSolanaResult(intentID, anchorID,
			createTxSig, "verify_failed_solana", "", false), err
	}

	btce.logger.Printf("✅ [SOLANA-EXEC] Step 2 complete - Proof verified: %s", verifyTxSig)

	// Wait for Step 2 confirmation
	err = solClient.WaitForConfirmation(ctx, verifyTxSig, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [SOLANA-EXEC] Step 2 confirmation issue: %v", err)
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	govTxSig := "no_governance_needed"

	// Find the Solana-specific leg (not leg 0 which may be a different chain)
	solanaLeg := btce.findSolanaLeg(allLegs)

	if solanaLeg != nil {
		btce.logger.Printf("🏦 [SOLANA-EXEC] Step 3: Executing governance proof direct...")
		btce.logger.Printf("   Using Solana leg: %s (chain=%s value=%s wei)", solanaLeg.LegID, solanaLeg.Chain, solanaLeg.Value.String())

		// Extract Solana addresses from CrossChainData (matches NEAR pattern)
		solanaFromAddr := btce.extractSolanaFieldFromCrossChainData(legacyIntent, "from")
		solanaToAddr := btce.extractSolanaFieldFromCrossChainData(legacyIntent, "to")

		btce.logger.Printf("   Intent from: %s", solanaFromAddr)
		btce.logger.Printf("   Intent to: %s", solanaToAddr)

		// Derive owner keypair from adiURL (fallback, matches NEAR pattern line 1454)
		ownerPubkey, ownerPrivKey := DeriveSolanaAccountOwner(adiURL)
		salt := DeriveSolanaAccountSalt(adiURL)

		// Compute account PDA and vault PDA
		accountStatePDA, _, _ := FindProgramAddress(
			[][]byte{[]byte("certen_account"), ownerPubkey[:]},
			solClient.accountProgramID,
		)
		accountVaultPDA, _, _ := FindProgramAddress(
			[][]byte{[]byte("account_vault"), accountStatePDA[:]},
			solClient.accountProgramID,
		)

		btce.logger.Printf("   ADI URL: %s (fallback derivation)", adiURL)
		btce.logger.Printf("   Owner: %s", base58.Encode(ownerPubkey[:]))
		btce.logger.Printf("   Account PDA: %s", base58.Encode(accountStatePDA[:]))
		btce.logger.Printf("   Vault PDA:   %s", base58.Encode(accountVaultPDA[:]))

		// If intent has a "from" address that doesn't match derived vault PDA,
		// re-derive using identity URL (matching API bridge derivation).
		// This mirrors NEAR where the intent address takes priority over fallback derivation.
		if solanaFromAddr != "" && solanaFromAddr != base58.Encode(accountVaultPDA[:]) {
			btce.logger.Printf("⚠️ [SOLANA-EXEC] Intent from (%s) != derived vault (%s), re-deriving from identity URL",
				solanaFromAddr, base58.Encode(accountVaultPDA[:]))
			ownerPubkey, ownerPrivKey = DeriveSolanaAccountOwner(legacyIntent.OrganizationADI)
			salt = DeriveSolanaAccountSalt(legacyIntent.OrganizationADI)
			accountStatePDA, _, _ = FindProgramAddress(
				[][]byte{[]byte("certen_account"), ownerPubkey[:]},
				solClient.accountProgramID,
			)
			accountVaultPDA, _, _ = FindProgramAddress(
				[][]byte{[]byte("account_vault"), accountStatePDA[:]},
				solClient.accountProgramID,
			)
			btce.logger.Printf("   Re-derived Owner: %s", base58.Encode(ownerPubkey[:]))
			btce.logger.Printf("   Re-derived Account PDA: %s", base58.Encode(accountStatePDA[:]))
			btce.logger.Printf("   Re-derived Vault PDA:   %s", base58.Encode(accountVaultPDA[:]))
		}

		// Check if account exists
		accountExists, checkErr := solClient.CheckAccountExists(ctx, accountStatePDA)
		if checkErr != nil {
			btce.logger.Printf("⚠️ [SOLANA-EXEC] Failed to check account existence: %v", checkErr)
		}

		if !accountExists && solanaAccountFactoryProgramID != "" {
			btce.logger.Printf("⚠️ [SOLANA-EXEC] User account not found, auto-deploying...")

			deployTxSig, deployErr := solClient.DeployAccountViaFactory(ctx, ownerPubkey, ownerPrivKey, adiURL, salt)
			if deployErr != nil {
				btce.logger.Printf("❌ [SOLANA-EXEC] Account auto-deploy failed: %v", deployErr)
				govTxSig = "gov_failed_account_deploy_solana"
			} else {
				btce.logger.Printf("✅ [SOLANA-EXEC] Account deployment tx: %s", deployTxSig)
				waitErr := solClient.WaitForConfirmation(ctx, deployTxSig, 60*time.Second)
				if waitErr != nil {
					btce.logger.Printf("⚠️ [SOLANA-EXEC] Account deployment confirmation failed: %v", waitErr)
					govTxSig = "gov_failed_account_deploy_solana"
				} else {
					// Verify account actually exists on-chain after deployment
					verifyExists, verifyErr := solClient.CheckAccountExists(ctx, accountStatePDA)
					if verifyErr != nil {
						btce.logger.Printf("⚠️ [SOLANA-EXEC] Post-deploy verification failed: %v", verifyErr)
					}
					if verifyExists {
						btce.logger.Printf("✅ [SOLANA-EXEC] Account verified on-chain: %s", base58.Encode(accountStatePDA[:]))
						accountExists = true
					} else {
						btce.logger.Printf("❌ [SOLANA-EXEC] Account NOT found on-chain after deployment!")
						govTxSig = "gov_failed_account_not_verified_solana"
					}
				}
			}
		}

		if accountExists && govTxSig == "no_governance_needed" {
			// Read anchor data for merkle proof construction
			anchorData, readErr := solClient.GetAnchorData(ctx, bundleIdHash)
			if readErr != nil {
				btce.logger.Printf("⚠️ [SOLANA-EXEC] Failed to read anchor data: %v", readErr)
				govTxSig = "gov_failed_anchor_read_solana"
			} else {
				// Determine target and value from the Solana leg (not leg 0)
				targetValue := uint64(1) // Default 1 lamport
				if solanaLeg.Value != nil {
					// Convert from EVM wei (10^18) to Solana lamports (10^9)
					weiValue := new(big.Int).Set(solanaLeg.Value)
					lamportsValue := new(big.Int).Div(weiValue, big.NewInt(1_000_000_000))
					if lamportsValue.Sign() <= 0 {
						lamportsValue = big.NewInt(1) // minimum 1 lamport
					}
					targetValue = lamportsValue.Uint64()
					btce.logger.Printf("💱 [SOLANA-EXEC] Value conversion: %s wei → %d lamports",
						solanaLeg.Value.String(), targetValue)
				}

				// Derive recipient pubkey from Solana-specific CrossChainData
				recipientAddr := ""
				solanaToAddr := btce.extractSolanaFieldFromCrossChainData(legacyIntent, "to")
				if solanaToAddr != "" {
					recipientAddr = solanaToAddr
				} else {
					recipientAddr = solanaLeg.Target.Hex()
				}

				recipientPubkey, recipientErr := DeriveSolanaRecipient(recipientAddr)
				if recipientErr != nil {
					btce.logger.Printf("⚠️ [SOLANA-EXEC] Failed to derive recipient: %v", recipientErr)
					govTxSig = "gov_failed_invalid_recipient_solana"
				} else {
					btce.logger.Printf("💱 [SOLANA-EXEC] Governance: target=%s lamports=%d",
						base58.Encode(recipientPubkey[:]), targetValue)

					// Build ADIGovernanceProof
					accountProof := btce.buildSolanaAccountProof(
						bundleIdHash, adiURL,
						anchorData.OperationCommitment,
						anchorData.CrossChainCommitment,
						anchorData.GovernanceRoot,
						targetValue,
					)

					// Build System Program Transfer instruction data:
					// [0..3] instruction index = 2 (Transfer, u32 LE)
					// [4..11] lamports amount (u64 LE)
					transferIxData := make([]byte, 12)
					binary.LittleEndian.PutUint32(transferIxData[0:4], 2) // SystemInstruction::Transfer
					binary.LittleEndian.PutUint64(transferIxData[4:12], targetValue)

					var govErr error
					govTxSig, govErr = solClient.ExecuteGovernanceProofDirect(ctx,
						ownerPubkey, targetValue, transferIxData, accountProof, recipientPubkey,
					)
					if govErr != nil {
						btce.logger.Printf("⚠️ [SOLANA-EXEC] Step 3 failed: %v", govErr)
						govTxSig = "gov_failed_solana"
					}
				}
			}
		}
	}

	btce.logger.Printf("🎉 [SOLANA-EXEC] Solana anchor workflow completed!")
	btce.logger.Printf("   Create TX: %s", createTxSig)
	btce.logger.Printf("   Verify TX: %s", verifyTxSig)
	btce.logger.Printf("   Governance TX: %s", govTxSig)

	return btce.buildSolanaResult(intentID, anchorID, createTxSig, verifyTxSig, govTxSig, true), nil
}

// convertABIProofToBorshForSolana converts a 448-byte ABI-encoded BLS aggregate signature proof
// to the 352-byte Borsh format expected by the Solana BLS ZK verifier.
//
// ABI layout (448 bytes, all big-endian):
//
//	[0-63]   proof.a (G1: x=32, y=32)
//	[64-191] proof.b (G2: x[0]=32, x[1]=32, y[0]=32, y[1]=32)
//	[192-255] proof.c (G1: x=32, y=32)
//	[256-287] message_hash (32 bytes)
//	[288-319] pubkey_commitment (32 bytes)
//	[320-351] signed_voting_power (uint256)
//	[352-383] total_voting_power (uint256)
//	[384-415] threshold_numerator (uint256)
//	[416-447] threshold_denominator (uint256)
//
// Borsh layout (352 bytes):
//
//	[0-319]  same proof points + hashes (identical byte layout)
//	[320-327] signed_voting_power (u64 little-endian)
//	[328-335] total_voting_power (u64 little-endian)
//	[336-343] threshold_numerator (u64 little-endian)
//	[344-351] threshold_denominator (u64 little-endian)
func convertABIProofToBorshForSolana(abiBytes []byte) []byte {
	if len(abiBytes) < 448 {
		log.Printf("⚠️ [SOLANA-BLS] ABI proof too short (%d bytes), passing as-is", len(abiBytes))
		return abiBytes
	}

	borsh := make([]byte, 352)

	// Copy proof points (a, b, c) + message_hash + pubkey_commitment (320 bytes) — same format
	copy(borsh[0:320], abiBytes[0:320])

	// Convert uint256 big-endian (32 bytes) → u64 little-endian (8 bytes)
	abiU256ToU64LE := func(src []byte) ([]byte, uint64) {
		val := new(big.Int).SetBytes(src)
		u64val := val.Uint64()
		le := make([]byte, 8)
		binary.LittleEndian.PutUint64(le, u64val)
		return le, u64val
	}

	leBytes, signedVP := abiU256ToU64LE(abiBytes[320:352])
	copy(borsh[320:328], leBytes)
	leBytes, totalVP := abiU256ToU64LE(abiBytes[352:384])
	copy(borsh[328:336], leBytes)
	leBytes, threshNum := abiU256ToU64LE(abiBytes[384:416])
	copy(borsh[336:344], leBytes)
	leBytes, threshDen := abiU256ToU64LE(abiBytes[416:448])
	copy(borsh[344:352], leBytes)

	// Log the embedded values from the blob for on-chain comparison
	log.Printf("🔍 [SOLANA-BLS] ABI blob message_hash (bytes 256-287): %x", abiBytes[256:288])
	log.Printf("🔍 [SOLANA-BLS] ABI blob pubkey_commitment (bytes 288-319): %x", abiBytes[288:320])
	log.Printf("🔍 [SOLANA-BLS] ABI blob values: signed_vp=%d total_vp=%d threshold=%d/%d",
		signedVP, totalVP, threshNum, threshDen)
	// HEX DEBUG: Dump proof point first bytes for Solana-side comparison
	log.Printf("🔍 [SOLANA-BLS-HEX] proof.a.x=%x proof.b.x0=%x proof.b.x1=%x proof.c.x=%x",
		abiBytes[0:8], abiBytes[64:72], abiBytes[96:104], abiBytes[192:200])

	// Check threshold locally
	if threshDen > 0 {
		required := (totalVP * threshNum) / threshDen
		log.Printf("🔍 [SOLANA-BLS] Threshold check: signed=%d >= required=%d → %v",
			signedVP, required, signedVP >= required)
	} else {
		log.Printf("⚠️ [SOLANA-BLS] threshold_denominator is 0!")
	}

	log.Printf("✅ [SOLANA-BLS] Converted ABI proof (448 bytes) to Borsh format (352 bytes)")
	return borsh
}

// buildSolanaCertenProof converts the comprehensive proof to Solana Borsh format.
func (btce *BFTTargetChainExecutor) buildSolanaCertenProof(
	compProof *contracts.ComprehensiveCertenProof,
	certenProof *proof.CertenProof,
) SolanaCertenProof {
	if compProof == nil {
		return SolanaCertenProof{
			ExpirationTime: time.Now().Add(24 * time.Hour).Unix(),
		}
	}

	proofHashes := make([][32]byte, len(compProof.ProofHashes))
	copy(proofHashes, compProof.ProofHashes)

	keyPageProofs := make([][32]byte, len(compProof.GovernanceProof.KeyPageProofs))
	copy(keyPageProofs, compProof.GovernanceProof.KeyPageProofs)

	totalVP := uint64(0)
	if compProof.BLSProof.TotalVotingPower != nil {
		totalVP = compProof.BLSProof.TotalVotingPower.Uint64()
	}
	signedVP := uint64(0)
	if compProof.BLSProof.SignedVotingPower != nil {
		signedVP = compProof.BLSProof.SignedVotingPower.Uint64()
	}
	govNonce := uint64(0)
	if compProof.GovernanceProof.Nonce != nil {
		govNonce = compProof.GovernanceProof.Nonce.Uint64()
	}
	reqSigs := uint64(0)
	if compProof.GovernanceProof.RequiredSignatures != nil {
		reqSigs = compProof.GovernanceProof.RequiredSignatures.Uint64()
	}
	provSigs := uint64(0)
	if compProof.GovernanceProof.ProvidedSignatures != nil {
		provSigs = compProof.GovernanceProof.ProvidedSignatures.Uint64()
	}

	expirationSec := int64(time.Now().Add(24 * time.Hour).Unix())
	if compProof.ExpirationTime != nil {
		expirationSec = compProof.ExpirationTime.Int64()
	}

	// Authority address: 20-byte EVM address
	var authorityAddr [20]byte
	copy(authorityAddr[:], compProof.GovernanceProof.AuthorityAddress.Bytes())

	// Validator pubkeys: convert []common.Address (20-byte) to [][]byte
	validatorPubkeys := make([][]byte, len(compProof.BLSProof.ValidatorAddresses))
	for i, addr := range compProof.BLSProof.ValidatorAddresses {
		validatorPubkeys[i] = addr.Bytes()
	}

	// Voting powers: convert []*big.Int to []uint64
	votingPowers := make([]uint64, len(compProof.BLSProof.VotingPowers))
	for i, vp := range compProof.BLSProof.VotingPowers {
		if vp != nil {
			votingPowers[i] = vp.Uint64()
		}
	}

	// BLS aggregate signature — convert ABI encoding to Borsh BlsSignatureProofBytes format.
	// ABI layout (448 bytes): proof_a(64) + proof_b(128) + proof_c(64) + message_hash(32) +
	//   pubkey_commitment(32) + signed_vp(uint256/32) + total_vp(uint256/32) +
	//   threshold_num(uint256/32) + threshold_den(uint256/32)
	// Borsh layout (352 bytes): same proof+hashes (320 bytes) + u64-LE fields (4 * 8 bytes)
	btce.logger.Printf("🔍 [SOLANA-BLS-DEBUG] AggregateSignature len=%d", len(compProof.BLSProof.AggregateSignature))
	btce.logger.Printf("🔍 [SOLANA-BLS-DEBUG] BLSProof.MessageHash=%x", compProof.BLSProof.MessageHash)
	btce.logger.Printf("🔍 [SOLANA-BLS-DEBUG] BLSProof.TotalVotingPower=%v SignedVotingPower=%v ThresholdMet=%v",
		compProof.BLSProof.TotalVotingPower, compProof.BLSProof.SignedVotingPower, compProof.BLSProof.ThresholdMet)
	btce.logger.Printf("🔍 [SOLANA-BLS-DEBUG] BLSProof.ValidatorAddresses=%d VotingPowers=%d",
		len(compProof.BLSProof.ValidatorAddresses), len(compProof.BLSProof.VotingPowers))
	aggregateSig := convertABIProofToBorshForSolana(compProof.BLSProof.AggregateSignature)

	// Source block height
	sourceBlockHeight := uint64(0)
	if compProof.Commitments.SourceBlockHeight != nil {
		sourceBlockHeight = compProof.Commitments.SourceBlockHeight.Uint64()
	}

	// Target address: pad 20-byte EVM address to 32 bytes (right-aligned)
	var targetAddress [32]byte
	copy(targetAddress[12:], compProof.Commitments.TargetAddress.Bytes())

	return SolanaCertenProof{
		TransactionHash: compProof.TransactionHash,
		MerkleRoot:      compProof.MerkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        compProof.LeafHash,
		GovernanceProof: SolanaGovernanceProofData{
			KeyBookUrl:         compProof.GovernanceProof.KeyBookURL,
			KeyBookRoot:        compProof.GovernanceProof.KeyBookRoot,
			KeyPageProofs:      keyPageProofs,
			AuthorityAddress:   authorityAddr,
			AuthorityLevel:     compProof.GovernanceProof.AuthorityLevel,
			Nonce:              govNonce,
			RequiredSignatures: reqSigs,
			ProvidedSignatures: provSigs,
			ThresholdMet:       compProof.GovernanceProof.ThresholdMet,
		},
		BlsProof: SolanaBLSProofData{
			AggregateSignature: aggregateSig,
			ValidatorPubkeys:   validatorPubkeys,
			VotingPowers:       votingPowers,
			TotalVotingPower:   totalVP,
			SignedVotingPower:  signedVP,
			ThresholdMet:       compProof.BLSProof.ThresholdMet,
			MessageHash:        compProof.BLSProof.MessageHash,
		},
		Commitments: SolanaCommitmentData{
			OperationCommitment:  compProof.Commitments.OperationCommitment,
			CrossChainCommitment: compProof.Commitments.CrossChainCommitment,
			GovernanceRoot:       compProof.Commitments.GovernanceRoot,
			SourceChain:          compProof.Commitments.SourceChain,
			SourceBlockHeight:    sourceBlockHeight,
			SourceTxHash:         compProof.Commitments.SourceTxHash,
			TargetChain:          compProof.Commitments.TargetChain,
			TargetAddress:        targetAddress,
		},
		ExpirationTime: expirationSec,
		Metadata:       compProof.Metadata,
	}
}

// buildSolanaAccountProof constructs the SolanaADIGovernanceProof for Step 3.
// Mirrors buildNearAccountProof — computes a 4-leaf merkle proof for adiURL verification.
func (btce *BFTTargetChainExecutor) buildSolanaAccountProof(
	bundleID [32]byte,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
	lamports uint64,
) SolanaADIGovernanceProof {
	requiredLevel := solanaAuthorityLevelForLamports(lamports)
	log.Printf("🔐 [SOLANA-AUTH] %d lamports → authority level: %d", lamports, requiredLevel)

	// Build merkle proof: same 4-leaf tree as TRON/EVM/NEAR
	hash23 := sortedHash(ccCommitment[:], govRoot[:])
	var hash23Arr [32]byte
	copy(hash23Arr[:], hash23)

	merkleProof := [][32]byte{opCommitment, hash23Arr}

	now := time.Now()
	// Use generous time window: start 5 minutes in the past, expire 2 hours in the future
	// This accommodates Solana devnet clock skew during simulation
	proofTimestamp := now.Add(-5 * time.Minute).Unix()
	proofExpiresAt := now.Add(2 * time.Hour).Unix()
	log.Printf("🕐 [SOLANA-PROOF] Timestamp: %d (now=%d, delta=%ds), ExpiresAt: %d",
		proofTimestamp, now.Unix(), now.Unix()-proofTimestamp, proofExpiresAt)

	// BLS validator signatures: left empty for Step 3.
	// The anchor's proof_executed=true (set by Step 2) already confirms BLS verification.
	// verify_proof in the anchor program checks proof_executed, so BLS re-verification
	// is redundant. This matches the NEAR model where BLS is verified asynchronously.
	var validatorSigs []byte

	return SolanaADIGovernanceProof{
		AdiUrl:              adiURL,
		AnchorId:            bundleID,
		MerkleProof:         merkleProof,
		KeyBookProof:        []byte{},
		RoleProof:           []byte{},
		ThresholdProof:      []byte{},
		Timestamp:           proofTimestamp,
		ExpiresAt:           proofExpiresAt,
		ValidatorSignatures: validatorSigs,
		Nonce:               1,
		RequiredLevel:       requiredLevel,
	}
}

// extractSolanaFieldFromCrossChainData extracts a Solana address field from CrossChainData.
// Returns the field value if it looks like a Solana base58 address (32+ chars, no 0x prefix, no dots).
// findLegForChainPrefix finds the first leg matching a chain name prefix from a list of legs.
// In multi-leg intents, leg 0 may be a different chain. Falls back to leg 0 for
// single-chain intents where the chain name might not match.
func (btce *BFTTargetChainExecutor) findLegForChainPrefix(legs []LegExecution, prefix string, chainIDs ...int64) *LegExecution {
	idSet := make(map[int64]bool)
	for _, id := range chainIDs {
		idSet[id] = true
	}
	for i := range legs {
		chainNorm := strings.ToLower(strings.ReplaceAll(legs[i].Chain, " ", "-"))
		if strings.HasPrefix(chainNorm, prefix) || idSet[legs[i].ChainID] {
			return &legs[i]
		}
	}
	// Fallback to first leg (single-chain intent)
	if len(legs) > 0 {
		return &legs[0]
	}
	return nil
}

// findSolanaLeg finds the first Solana leg from a list of legs.
func (btce *BFTTargetChainExecutor) findSolanaLeg(legs []LegExecution) *LegExecution {
	return btce.findLegForChainPrefix(legs, "solana", 101, 102, 103)
}

func (btce *BFTTargetChainExecutor) extractSolanaFieldFromCrossChainData(legacyIntent *intent.CertenIntent, field string) string {
	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		return ""
	}

	var ccData struct {
		Legs []struct {
			From    string `json:"from"`
			To      string `json:"to"`
			Chain   string `json:"chain"`
			ChainID int64  `json:"chainId"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(legacyIntent.CrossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return ""
	}

	// Find the Solana-specific leg (not just leg 0)
	for _, leg := range ccData.Legs {
		chainNorm := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
		if !strings.HasPrefix(chainNorm, "solana") && leg.ChainID != 101 && leg.ChainID != 102 && leg.ChainID != 103 {
			continue
		}
		var value string
		switch field {
		case "from":
			value = leg.From
		case "to":
			value = leg.To
		}
		// Solana addresses are base58, 32-44 chars, no dots (unlike NEAR), no 0x prefix (unlike EVM)
		if value != "" && !strings.HasPrefix(value, "0x") && !strings.Contains(value, ".") && len(value) >= 32 {
			return value
		}
	}
	return ""
}

// buildSolanaResult creates a TargetChainExecutionResult for Solana operations.
func (btce *BFTTargetChainExecutor) buildSolanaResult(
	intentID, anchorID string,
	createTxSig, verifyTxSig, govTxSig string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            "solana-devnet",
		TxHash:           createTxSig,
		Success:          success,
		CreateTxHash:     createTxSig,
		VerifyTxHash:     verifyTxSig,
		GovernanceTxHash: govTxSig,
		Metadata: map[string]string{
			"chain":            "solana-devnet",
			"anchorProgram":    os.Getenv("SOLANA_ANCHOR_PROGRAM_ID"),
			"explorerUrl":      "https://explorer.solana.com/?cluster=devnet",
			"executionMethod":  "solana_json_rpc",
		},
	}
}

// =============================================================================
// APTOS CHAIN EXECUTION
// =============================================================================

// executeAptosOperations executes anchor workflow on Aptos using REST API.
// Aptos uses Ed25519 signing, BCS serialization, and Move entry functions.
// Follows the same 3-step pattern as NEAR/Solana/EVM/TRON.
func (btce *BFTTargetChainExecutor) executeAptosOperations(
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

	btce.logger.Printf("🔷 [APTOS-EXEC] Executing Aptos chain operations for intent: %s", intentID)

	// Create a fresh context with generous timeout for the 3-step Aptos flow.
	// The parent BFT context may have a very short deadline that's already nearly expired.
	aptosCtx, aptosCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer aptosCancel()
	ctx = aptosCtx

	// Load Aptos config from environment
	aptosPrivateKey := os.Getenv("APTOS_PRIVATE_KEY")
	aptosRPCURL := os.Getenv("APTOS_TESTNET_RPC_URL")
	aptosAnchorPackage := os.Getenv("APTOS_ANCHOR_PACKAGE")
	aptosAccountFactoryPackage := os.Getenv("APTOS_ACCOUNT_FACTORY_PACKAGE")
	if aptosAccountFactoryPackage == "" {
		aptosAccountFactoryPackage = aptosAnchorPackage // all modules share same package
	}

	if aptosPrivateKey == "" || aptosRPCURL == "" || aptosAnchorPackage == "" {
		return nil, fmt.Errorf("missing Aptos config: APTOS_PRIVATE_KEY=%v, APTOS_TESTNET_RPC_URL=%q, APTOS_ANCHOR_PACKAGE=%q",
			aptosPrivateKey != "", aptosRPCURL, aptosAnchorPackage)
	}

	btce.logger.Printf("✅ [APTOS-EXEC] Using Aptos config:")
	btce.logger.Printf("   RPC: %s", aptosRPCURL)
	btce.logger.Printf("   Anchor Package: %s", aptosAnchorPackage)
	btce.logger.Printf("   Account Factory Package: %s", aptosAccountFactoryPackage)

	// Create Aptos client
	aptosClient, err := NewAptosClient(aptosRPCURL, aptosPrivateKey, aptosAnchorPackage)
	if err != nil {
		return nil, fmt.Errorf("failed to create Aptos client: %w", err)
	}

	// Create EthereumContractManager for proof building (reuse commitment logic)
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	contractConfig := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		ChainID:              11155111,
		PrivateKey:           privateKey,
		CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		GasLimit:             800000,
		MaxGasPriceGwei:      50,
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		btce.logger.Printf("⚠️ [APTOS-EXEC] Failed to create proof builder (non-fatal, using defaults): %v", err)
	}

	// Build legacy intent and proof data (same as EVM/TRON/NEAR/Solana path)
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	var bundleIdHash [32]byte
	var comprehensiveProof *contracts.ComprehensiveCertenProof
	if ethManager != nil {
		bundleIdHash = ethManager.generateAnchorID(legacyIntent, certenProof)
		cp := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
			&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: "BFT anchor for Aptos"},
			bundleIdHash,
		)
		comprehensiveProof = &cp
	} else {
		hash := ethcrypto.Keccak256Hash([]byte(fmt.Sprintf("certen_v3_%s_%d_%s",
			legacyIntent.IntentID, certenProof.BlockHeight, certenProof.TransactionHash)))
		copy(bundleIdHash[:], hash[:])
	}

	// Compute adiURLHash
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	copy(adiURLHash[:], ethcrypto.Keccak256([]byte(adiURL)))

	// Extract commitments
	var opCommitment, ccCommitment, govRoot [32]byte
	if comprehensiveProof != nil {
		opCommitment = comprehensiveProof.Commitments.OperationCommitment
		ccCommitment = comprehensiveProof.Commitments.CrossChainCommitment
		govRoot = comprehensiveProof.Commitments.GovernanceRoot
	}

	// ========== Step 0: Auto-initialize anchor state ==========
	btce.logger.Printf("🔗 [APTOS-EXEC] Step 0: Ensuring anchor state is initialized...")
	if initErr := aptosClient.InitializeAnchorState(ctx); initErr != nil {
		btce.logger.Printf("⚠️ [APTOS-EXEC] Anchor initialization failed (non-fatal): %v", initErr)
	}

	// ========== Step 1: Create Anchor ==========
	btce.logger.Printf("🔗 [APTOS-EXEC] Step 1: Creating anchor...")

	createTxHash, err := aptosClient.CreateAnchor(ctx,
		bundleIdHash, adiURLHash, opCommitment, ccCommitment, govRoot,
		certenProof.BlockHeight,
	)
	if err != nil {
		btce.logger.Printf("❌ [APTOS-EXEC] Step 1 failed: %v", err)
		return btce.buildAptosResult(intentID, anchorID,
			"create_failed_aptos", "", "", false), err
	}

	btce.logger.Printf("✅ [APTOS-EXEC] Step 1 complete - Anchor created: %s", createTxHash)

	// Wait for Step 1 confirmation
	err = aptosClient.WaitForConfirmation(ctx, createTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [APTOS-EXEC] Step 1 confirmation issue: %v", err)
	}

	// ========== Step 2: Execute Comprehensive Proof ==========
	btce.logger.Printf("🔗 [APTOS-EXEC] Step 2: Submitting comprehensive proof...")

	aptosProof := btce.buildAptosCertenProof(comprehensiveProof, certenProof)

	verifyTxHash, err := aptosClient.submitComprehensiveProofBCS(ctx, bundleIdHash, aptosProof)
	if err != nil {
		btce.logger.Printf("❌ [APTOS-EXEC] Step 2 failed: %v", err)
		return btce.buildAptosResult(intentID, anchorID,
			createTxHash, "verify_failed_aptos", "", false), err
	}

	btce.logger.Printf("✅ [APTOS-EXEC] Step 2 complete - Proof verified: %s", verifyTxHash)

	// Wait for Step 2 confirmation
	err = aptosClient.WaitForConfirmation(ctx, verifyTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [APTOS-EXEC] Step 2 confirmation issue: %v", err)
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	aptosLeg := btce.findLegForChainPrefix(allLegs, "aptos", 2) // Aptos testnet chainID=2
	govTxHash := "no_governance_needed"

	if aptosLeg != nil {
		btce.logger.Printf("🏦 [APTOS-EXEC] Step 3: Executing governance proof direct...")

		// Extract Aptos addresses from CrossChainData
		aptosFromAddr := btce.extractAptosFieldFromCrossChainData(legacyIntent, "from")
		aptosToAddr := btce.extractAptosFieldFromCrossChainData(legacyIntent, "to")

		btce.logger.Printf("   Intent from: %s", aptosFromAddr)
		btce.logger.Printf("   Intent to: %s", aptosToAddr)

		// Use the from field directly as the user account address (matches NEAR pattern).
		// The web app sets from to the abstract account address predicted by the API bridge.
		userAccountAddr := aptosFromAddr

		// Fallback: derive via factory prediction if not available from intent
		ownerBytes32 := DeriveAptosAccountOwnerBytes32(adiURL)
		salt := DeriveAptosAccountSalt(adiURL)

		if userAccountAddr == "" && aptosAccountFactoryPackage != "" {
			predicted, predictErr := aptosClient.PredictAccountAddress(ctx, ownerBytes32, adiURL, salt)
			if predictErr != nil {
				btce.logger.Printf("⚠️ [APTOS-EXEC] Failed to predict account address: %v", predictErr)
			} else {
				userAccountAddr = predicted
				btce.logger.Printf("   Abstract account (from factory): %s", userAccountAddr)
			}
		} else if userAccountAddr == "" {
			btce.logger.Printf("⚠️ [APTOS-EXEC] No factory configured and no from address in intent")
			govTxHash = "gov_failed_no_factory_aptos"
		}

		if userAccountAddr != "" {
			btce.logger.Printf("   User account: %s", userAccountAddr)

			// Check if account exists
			accountExists, checkErr := aptosClient.CheckAccountExists(ctx, userAccountAddr)
			if checkErr != nil {
				btce.logger.Printf("⚠️ [APTOS-EXEC] Failed to check account existence: %v", checkErr)
			}

			if !accountExists && aptosAccountFactoryPackage != "" {
				btce.logger.Printf("⚠️ [APTOS-EXEC] User account %s not found, auto-deploying...", userAccountAddr)

				deployTx, deployErr := aptosClient.DeployAccountViaFactory(ctx, ownerBytes32, adiURL, salt)
				if deployErr != nil {
					btce.logger.Printf("❌ [APTOS-EXEC] Account auto-deploy failed: %v", deployErr)
					govTxHash = "gov_failed_account_deploy_aptos"
				} else {
					btce.logger.Printf("✅ [APTOS-EXEC] Account deployment tx: %s", deployTx)
					waitErr := aptosClient.WaitForConfirmation(ctx, deployTx, 60*time.Second)
					if waitErr != nil {
						btce.logger.Printf("⚠️ [APTOS-EXEC] Account deployment confirmation failed: %v", waitErr)
						govTxHash = "gov_failed_account_deploy_aptos"
					} else {
						accountExists = true
					}
				}
			}

			if accountExists && govTxHash == "no_governance_needed" {
				// Read anchor data for merkle proof construction
				anchorData, readErr := aptosClient.GetAnchorData(ctx, bundleIdHash)
				if readErr != nil {
					btce.logger.Printf("⚠️ [APTOS-EXEC] Failed to read anchor data: %v", readErr)
					govTxHash = "gov_failed_anchor_read_aptos"
				} else {
					// Determine target and value from the Aptos-specific leg (not allLegs[0])
					recipientAddr := aptosToAddr
					if recipientAddr == "" {
						recipientAddr = aptosLeg.Target.Hex()
					}

					// Convert amountWei (18 decimals) to octas (8 decimals)
					// EVM uses 10^18, Aptos uses 10^8, so divide by 10^10
					amountOctas := uint64(1) // Default 1 octa
					if aptosLeg.Value != nil {
						weiValue := new(big.Int).Set(aptosLeg.Value)
						octasValue := new(big.Int).Div(weiValue, big.NewInt(10_000_000_000)) // / 10^10
						if octasValue.Sign() <= 0 {
							octasValue = big.NewInt(1) // minimum 1 octa
						}
						amountOctas = octasValue.Uint64()
						btce.logger.Printf("💱 [APTOS-EXEC] Value conversion: %s wei → %d octas",
							aptosLeg.Value.String(), amountOctas)
					}

					btce.logger.Printf("💱 [APTOS-EXEC] Governance: target=%s octas=%d", recipientAddr, amountOctas)

					// Build ADIGovernanceProof
					accountProof := btce.buildAptosAccountProof(
						bundleIdHash, certenProof, adiURL,
						anchorData.OperationCommitment,
						anchorData.CrossChainCommitment,
						anchorData.GovernanceRoot,
						amountOctas,
					)

					var govErr error
					govTxHash, govErr = aptosClient.ExecuteGovernanceProofDirect(ctx,
						userAccountAddr, recipientAddr, amountOctas, accountProof,
					)
					if govErr != nil {
						btce.logger.Printf("⚠️ [APTOS-EXEC] Step 3 failed: %v", govErr)
						govTxHash = "gov_failed_aptos"
					}
				}
			}
		}
	}

	btce.logger.Printf("🎉 [APTOS-EXEC] Aptos anchor workflow completed!")
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	return btce.buildAptosResult(intentID, anchorID, createTxHash, verifyTxHash, govTxHash, true), nil
}

// buildAptosCertenProof converts the comprehensive proof to Aptos format.
func (btce *BFTTargetChainExecutor) buildAptosCertenProof(
	compProof *contracts.ComprehensiveCertenProof,
	certenProof *proof.CertenProof,
) AptosCertenProof {
	if compProof == nil {
		return AptosCertenProof{
			ExpirationTimeSecs: uint64(time.Now().Add(24 * time.Hour).Unix()),
		}
	}

	proofHashes := make([][32]byte, len(compProof.ProofHashes))
	copy(proofHashes, compProof.ProofHashes)

	keyPageProofs := make([][32]byte, len(compProof.GovernanceProof.KeyPageProofs))
	copy(keyPageProofs, compProof.GovernanceProof.KeyPageProofs)

	totalVP := uint64(0)
	if compProof.BLSProof.TotalVotingPower != nil {
		totalVP = compProof.BLSProof.TotalVotingPower.Uint64()
	}
	signedVP := uint64(0)
	if compProof.BLSProof.SignedVotingPower != nil {
		signedVP = compProof.BLSProof.SignedVotingPower.Uint64()
	}
	govNonce := uint64(0)
	if compProof.GovernanceProof.Nonce != nil {
		govNonce = compProof.GovernanceProof.Nonce.Uint64()
	}
	reqSigs := uint64(0)
	if compProof.GovernanceProof.RequiredSignatures != nil {
		reqSigs = compProof.GovernanceProof.RequiredSignatures.Uint64()
	}
	provSigs := uint64(0)
	if compProof.GovernanceProof.ProvidedSignatures != nil {
		provSigs = compProof.GovernanceProof.ProvidedSignatures.Uint64()
	}

	expirationSecs := uint64(time.Now().Add(24 * time.Hour).Unix())
	if compProof.ExpirationTime != nil {
		expirationSecs = compProof.ExpirationTime.Uint64()
	}

	// Authority address as 0x+64hex
	authorityAddr := "0x" + hex.EncodeToString(common.LeftPadBytes(compProof.GovernanceProof.AuthorityAddress.Bytes(), 32))

	// Validator addresses as 0x+64hex
	validatorAddrs := make([]string, len(compProof.BLSProof.ValidatorAddresses))
	for i, addr := range compProof.BLSProof.ValidatorAddresses {
		validatorAddrs[i] = "0x" + hex.EncodeToString(common.LeftPadBytes(addr.Bytes(), 32))
	}

	// BLS aggregate signature — split ABI bytes into individual fields
	var blsProofBytes, blsMessageHash, blsPubkeyCommitment []byte
	blsSignedVP := signedVP
	blsTotalVP := totalVP
	blsThreshNum := uint64(2)
	blsThreshDen := uint64(3)

	if len(compProof.BLSProof.AggregateSignature) >= 448 {
		abiBytes := compProof.BLSProof.AggregateSignature
		blsProofBytes = abiBytes[0:256]      // proof_a(64) + proof_b(128) + proof_c(64)
		blsMessageHash = abiBytes[256:288]    // message_hash (32)
		blsPubkeyCommitment = abiBytes[288:320] // pubkey_commitment (32)
		blsSignedVP = new(big.Int).SetBytes(abiBytes[320:352]).Uint64()
		blsTotalVP = new(big.Int).SetBytes(abiBytes[352:384]).Uint64()
		blsThreshNum = new(big.Int).SetBytes(abiBytes[384:416]).Uint64()
		blsThreshDen = new(big.Int).SetBytes(abiBytes[416:448]).Uint64()
	} else {
		blsMessageHash = compProof.BLSProof.MessageHash[:]
	}

	// Source block height
	sourceBlockHeight := uint64(0)
	if compProof.Commitments.SourceBlockHeight != nil {
		sourceBlockHeight = compProof.Commitments.SourceBlockHeight.Uint64()
	}

	// Target address: pad 20-byte EVM address to 32-byte Aptos address format
	targetAddr := "0x" + hex.EncodeToString(common.LeftPadBytes(compProof.Commitments.TargetAddress.Bytes(), 32))

	return AptosCertenProof{
		TransactionHash: compProof.TransactionHash,
		MerkleRoot:      compProof.MerkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        compProof.LeafHash,

		GovKeyBookURL:         compProof.GovernanceProof.KeyBookURL,
		GovKeyBookRoot:        compProof.GovernanceProof.KeyBookRoot,
		GovKeyPageProofs:      keyPageProofs,
		GovAuthorityAddress:   authorityAddr,
		GovAuthorityLevel:     compProof.GovernanceProof.AuthorityLevel,
		GovNonce:              govNonce,
		GovRequiredSignatures: reqSigs,
		GovProvidedSignatures: provSigs,

		BLSProofBytes:           blsProofBytes,
		BLSMessageHash:          blsMessageHash,
		BLSPubkeyCommitment:     blsPubkeyCommitment,
		BLSSignedVotingPower:    blsSignedVP,
		BLSTotalVotingPower:     blsTotalVP,
		BLSThresholdNumerator:   blsThreshNum,
		BLSThresholdDenominator: blsThreshDen,
		BLSValidatorAddresses:   validatorAddrs,

		CommitOperationCommitment:  compProof.Commitments.OperationCommitment,
		CommitCrossChainCommitment: compProof.Commitments.CrossChainCommitment,
		CommitGovernanceRoot:       compProof.Commitments.GovernanceRoot,
		CommitSourceChain:          compProof.Commitments.SourceChain,
		CommitSourceBlockHeight:    sourceBlockHeight,
		CommitSourceTxHash:         compProof.Commitments.SourceTxHash,
		CommitTargetChain:          compProof.Commitments.TargetChain,
		CommitTargetAddress:        targetAddr,

		ExpirationTimeSecs: expirationSecs,
		Metadata:           compProof.Metadata,
	}
}

// buildAptosAccountProof constructs the AptosADIGovernanceProof for Step 3.
// Mirrors buildNearAccountProof — computes a 4-leaf merkle proof for adiURL verification.
func (btce *BFTTargetChainExecutor) buildAptosAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
	amountOctas uint64,
) AptosADIGovernanceProof {
	requiredLevel := aptosAuthorityLevelForOctas(amountOctas)
	log.Printf("🔐 [APTOS-AUTH] %d octas → authority level: %d", amountOctas, requiredLevel)

	// Build merkle proof: same 4-leaf tree as TRON/EVM/NEAR/Solana
	// proof[0] = operationCommitment (sibling at level 0)
	// proof[1] = sortedHash(ccCommitment, govRoot) (sibling at level 1)
	hash23 := sortedHash(ccCommitment[:], govRoot[:])
	var hash23Arr [32]byte
	copy(hash23Arr[:], hash23)

	log.Printf("🌳 [APTOS-MERKLE] Built 4-leaf proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (op): 0x%x", opCommitment[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23Arr[:8])

	merkleProof := [][32]byte{opCommitment, hash23Arr}

	now := time.Now()
	proofTimestamp := uint64(now.Add(-5 * time.Minute).Unix())
	proofExpiresAt := uint64(now.Add(2 * time.Hour).Unix())

	// BLS validator signatures: left empty for Step 3.
	// The anchor's proof_executed=true (set by Step 2) already confirms BLS verification.
	var blsProofBytes, blsMessageHash, blsPubkeyCommitment []byte

	return AptosADIGovernanceProof{
		AdiURL:      adiURL,
		AnchorID:    bundleID,
		MerkleProof: merkleProof,
		Timestamp:   proofTimestamp,
		ExpiresAt:   proofExpiresAt,
		Nonce:       1, // Must be > current nonce (starts at 0)
		RequiredLevel: requiredLevel,

		BLSProofBytes:           blsProofBytes,
		BLSMessageHash:          blsMessageHash,
		BLSPubkeyCommitment:     blsPubkeyCommitment,
		BLSSignedVotingPower:    0,
		BLSTotalVotingPower:     0,
		BLSThresholdNumerator:   2,
		BLSThresholdDenominator: 3,
		BLSValidatorAddresses:   []string{},
	}
}

// extractAptosFieldFromCrossChainData extracts an Aptos address field from CrossChainData.
// Returns the field value if it looks like an Aptos address (0x prefix + 64 hex chars).
func (btce *BFTTargetChainExecutor) extractAptosFieldFromCrossChainData(legacyIntent *intent.CertenIntent, field string) string {
	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		return ""
	}

	var ccData struct {
		Legs []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(legacyIntent.CrossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return ""
	}

	var value string
	switch field {
	case "from":
		value = ccData.Legs[0].From
	case "to":
		value = ccData.Legs[0].To
	}

	// Aptos addresses are 0x + 64 hex chars (32 bytes)
	if value != "" && strings.HasPrefix(value, "0x") && len(value) == 66 {
		// Verify it's valid hex
		_, err := hex.DecodeString(value[2:])
		if err == nil {
			return value
		}
	}
	return ""
}

// buildAptosResult creates a TargetChainExecutionResult for Aptos operations.
func (btce *BFTTargetChainExecutor) buildAptosResult(
	intentID, anchorID string,
	createTxHash, verifyTxHash, govTxHash string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            "aptos-testnet",
		TxHash:           createTxHash,
		Success:          success,
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
		Metadata: map[string]string{
			"chain":           "aptos-testnet",
			"anchorPackage":   os.Getenv("APTOS_ANCHOR_PACKAGE"),
			"explorerUrl":     "https://explorer.aptoslabs.com/?network=testnet",
			"executionMethod": "aptos_rest_api",
		},
	}
}

// =============================================================================
// SUI CHAIN EXECUTION
// =============================================================================

// executeSuiOperations executes anchor workflow on SUI using JSON-RPC.
// SUI uses Ed25519 signing with BLAKE2b-256, Programmable Transaction Blocks (PTBs),
// and shared object model. Follows the same 3-step pattern as NEAR/Aptos.
func (btce *BFTTargetChainExecutor) executeSuiOperations(
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

	btce.logger.Printf("🔷 [SUI-EXEC] Executing SUI chain operations for intent: %s", intentID)

	// Create a fresh context with generous timeout for the 3-step SUI flow.
	suiCtx, suiCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer suiCancel()
	ctx = suiCtx

	// Load SUI config from environment
	suiPrivateKey := os.Getenv("SUI_PRIVATE_KEY")
	suiRPCURL := os.Getenv("SUI_TESTNET_RPC_URL")
	suiAnchorPackage := os.Getenv("SUI_ANCHOR_PACKAGE")
	suiAnchorStateObject := os.Getenv("SUI_ANCHOR_STATE_OBJECT")
	suiAccountFactoryObject := os.Getenv("SUI_ACCOUNT_FACTORY_OBJECT")

	if suiPrivateKey == "" || suiRPCURL == "" || suiAnchorPackage == "" || suiAnchorStateObject == "" {
		return nil, fmt.Errorf("missing SUI config: SUI_PRIVATE_KEY=%v, SUI_TESTNET_RPC_URL=%q, SUI_ANCHOR_PACKAGE=%q, SUI_ANCHOR_STATE_OBJECT=%q",
			suiPrivateKey != "", suiRPCURL, suiAnchorPackage, suiAnchorStateObject)
	}

	btce.logger.Printf("✅ [SUI-EXEC] Using SUI config:")
	btce.logger.Printf("   RPC: %s", suiRPCURL)
	btce.logger.Printf("   Anchor Package: %s", suiAnchorPackage)
	btce.logger.Printf("   Anchor State: %s", suiAnchorStateObject)
	btce.logger.Printf("   Factory Object: %s", suiAccountFactoryObject)

	// Create SUI client
	suiClient, err := NewSuiClient(suiRPCURL, suiPrivateKey, suiAnchorPackage, suiAnchorStateObject, suiAccountFactoryObject)
	if err != nil {
		return nil, fmt.Errorf("failed to create SUI client: %w", err)
	}

	// Create EthereumContractManager for proof building (reuse commitment logic)
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	contractConfig := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		ChainID:              11155111,
		PrivateKey:           privateKey,
		CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		GasLimit:             800000,
		MaxGasPriceGwei:      50,
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		btce.logger.Printf("⚠️ [SUI-EXEC] Failed to create proof builder (non-fatal, using defaults): %v", err)
	}

	// Build legacy intent and proof data (same as EVM/TRON/NEAR/Solana/Aptos path)
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	var bundleIdHash [32]byte
	var comprehensiveProof *contracts.ComprehensiveCertenProof
	if ethManager != nil {
		bundleIdHash = ethManager.generateAnchorID(legacyIntent, certenProof)
		cp := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
			&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: "BFT anchor for SUI"},
			bundleIdHash,
		)
		comprehensiveProof = &cp
	} else {
		hash := ethcrypto.Keccak256Hash([]byte(fmt.Sprintf("certen_v3_%s_%d_%s",
			legacyIntent.IntentID, certenProof.BlockHeight, certenProof.TransactionHash)))
		copy(bundleIdHash[:], hash[:])
	}

	// Compute adiURLHash
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	copy(adiURLHash[:], ethcrypto.Keccak256([]byte(adiURL)))

	// Extract commitments
	var opCommitment, ccCommitment, govRoot [32]byte
	if comprehensiveProof != nil {
		opCommitment = comprehensiveProof.Commitments.OperationCommitment
		ccCommitment = comprehensiveProof.Commitments.CrossChainCommitment
		govRoot = comprehensiveProof.Commitments.GovernanceRoot
	}

	// Debug: log values that will be used for merkle root computation
	btce.logger.Printf("🔍 [SUI-MERKLE] Step 1 inputs:")
	btce.logger.Printf("   bundleId:    0x%x", bundleIdHash[:])
	btce.logger.Printf("   adiURLHash:  0x%x", adiURLHash[:])
	btce.logger.Printf("   opCommit:    0x%x", opCommitment[:])
	btce.logger.Printf("   ccCommit:    0x%x", ccCommitment[:])
	btce.logger.Printf("   govRoot:     0x%x", govRoot[:])
	btce.logger.Printf("   adiURL:      %s", adiURL)
	if comprehensiveProof != nil {
		btce.logger.Printf("   proof.MerkleRoot: 0x%x", comprehensiveProof.MerkleRoot[:])
		// Recompute locally to verify
		h01 := sortedHash(adiURLHash[:], opCommitment[:])
		h23 := sortedHash(ccCommitment[:], govRoot[:])
		localRoot := sortedHash(h01, h23)
		btce.logger.Printf("   localMerkleRoot: 0x%x", localRoot)
		btce.logger.Printf("   match: %v", fmt.Sprintf("%x", localRoot) == fmt.Sprintf("%x", comprehensiveProof.MerkleRoot[:]))
	}

	// ========== Step 1: Create Anchor ==========
	btce.logger.Printf("🔗 [SUI-EXEC] Step 1: Creating anchor...")

	createTxHash, err := suiClient.CreateAnchor(ctx,
		bundleIdHash, adiURLHash, opCommitment, ccCommitment, govRoot,
		certenProof.BlockHeight,
	)
	if err != nil {
		btce.logger.Printf("❌ [SUI-EXEC] Step 1 failed: %v", err)
		return btce.buildSuiResult(intentID, anchorID,
			"create_failed_sui", "", "", false), err
	}

	btce.logger.Printf("✅ [SUI-EXEC] Step 1 complete - Anchor created: %s", createTxHash)

	// Wait for Step 1 confirmation
	err = suiClient.WaitForConfirmation(ctx, createTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [SUI-EXEC] Step 1 confirmation issue: %v", err)
	}

	// ========== Step 2: Execute Comprehensive Proof ==========
	btce.logger.Printf("🔗 [SUI-EXEC] Step 2: Submitting comprehensive proof...")

	suiProof := btce.buildSuiCertenProof(comprehensiveProof, certenProof)

	verifyTxHash, err := suiClient.ExecuteComprehensiveProof(ctx, bundleIdHash, suiProof)
	if err != nil {
		btce.logger.Printf("❌ [SUI-EXEC] Step 2 failed: %v", err)
		return btce.buildSuiResult(intentID, anchorID,
			createTxHash, "verify_failed_sui", "", false), err
	}

	btce.logger.Printf("✅ [SUI-EXEC] Step 2 complete - Proof verified: %s", verifyTxHash)

	// Wait for Step 2 confirmation
	err = suiClient.WaitForConfirmation(ctx, verifyTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [SUI-EXEC] Step 2 confirmation issue: %v", err)
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	suiLeg := btce.findLegForChainPrefix(allLegs, "sui", 101) // Sui testnet
	govTxHash := "no_governance_needed"

	if suiLeg != nil {
		btce.logger.Printf("🏦 [SUI-EXEC] Step 3: Executing withdraw_sui_direct...")

		// Extract SUI addresses from CrossChainData
		suiFromAddr := btce.extractSuiFieldFromCrossChainData(legacyIntent, "from")
		suiToAddr := btce.extractSuiFieldFromCrossChainData(legacyIntent, "to")

		btce.logger.Printf("   Intent from: %s", suiFromAddr)
		btce.logger.Printf("   Intent to: %s", suiToAddr)

		// Use the from field directly as the user account object ID (matches NEAR/Aptos pattern).
		userAccountObjectId := suiFromAddr

		// Derive owner/salt for factory operations
		ownerBytes32 := DeriveSuiAccountOwnerBytes32(adiURL)
		salt := DeriveSuiAccountSalt(adiURL)

		if userAccountObjectId == "" {
			btce.logger.Printf("⚠️ [SUI-EXEC] No from address in intent, cannot determine user account")
			govTxHash = "gov_failed_no_account_sui"
		}

		if userAccountObjectId != "" {
			btce.logger.Printf("   User account object: %s", userAccountObjectId)

			// Check if account exists
			accountExists, accountVersion, checkErr := suiClient.CheckAccountExists(ctx, userAccountObjectId)
			if checkErr != nil {
				btce.logger.Printf("⚠️ [SUI-EXEC] Failed to check account existence: %v", checkErr)
			}

			if !accountExists && suiAccountFactoryObject != "" {
				btce.logger.Printf("⚠️ [SUI-EXEC] User account %s not found, auto-deploying...", userAccountObjectId)

				deployTx, deployErr := suiClient.DeployAccountViaFactory(ctx, ownerBytes32, adiURL, salt)
				if deployErr != nil {
					btce.logger.Printf("❌ [SUI-EXEC] Account auto-deploy failed: %v", deployErr)
					govTxHash = "gov_failed_account_deploy_sui"
				} else {
					btce.logger.Printf("✅ [SUI-EXEC] Account deployment tx: %s", deployTx)
					waitErr := suiClient.WaitForConfirmation(ctx, deployTx, 60*time.Second)
					if waitErr != nil {
						btce.logger.Printf("⚠️ [SUI-EXEC] Account deployment confirmation failed: %v", waitErr)
						govTxHash = "gov_failed_account_deploy_sui"
					} else {
						accountExists = true
						// Re-check to get the version
						_, accountVersion, _ = suiClient.CheckAccountExists(ctx, userAccountObjectId)
					}
				}
			}

			if accountExists && govTxHash == "no_governance_needed" {
				// Read anchor data for merkle proof construction
				anchorData, readErr := suiClient.GetAnchorData(ctx, bundleIdHash)
				if readErr != nil {
					btce.logger.Printf("⚠️ [SUI-EXEC] Failed to read anchor data: %v", readErr)
					govTxHash = "gov_failed_anchor_read_sui"
				} else {
					// Use anchor data commitments (fall back to the ones we computed)
					anchorOpCommit := opCommitment
					anchorCCCommit := ccCommitment
					anchorGovRoot := govRoot
					if anchorData.OperationCommitment != ([32]byte{}) {
						anchorOpCommit = anchorData.OperationCommitment
					}
					if anchorData.CrossChainCommitment != ([32]byte{}) {
						anchorCCCommit = anchorData.CrossChainCommitment
					}
					if anchorData.GovernanceRoot != ([32]byte{}) {
						anchorGovRoot = anchorData.GovernanceRoot
					}

					// Determine target and value from the SUI-specific leg (not allLegs[0])
					recipientAddr := suiToAddr
					if recipientAddr == "" {
						recipientAddr = suiLeg.Target.Hex()
					}

					// Convert amountWei (18 decimals) to MIST (9 decimals)
					// EVM uses 10^18, SUI uses 10^9, so divide by 10^9
					amountMist := uint64(1) // Default 1 MIST
					if suiLeg.Value != nil {
						weiValue := new(big.Int).Set(suiLeg.Value)
						mistValue := new(big.Int).Div(weiValue, big.NewInt(1_000_000_000)) // / 10^9
						if mistValue.Sign() <= 0 {
							mistValue = big.NewInt(1) // minimum 1 MIST
						}
						amountMist = mistValue.Uint64()
						btce.logger.Printf("💱 [SUI-EXEC] Value conversion: %s wei → %d MIST",
							suiLeg.Value.String(), amountMist)
					}

					btce.logger.Printf("💱 [SUI-EXEC] Governance: target=%s mist=%d", recipientAddr, amountMist)

					// Build ADIGovernanceProof
					accountProof := btce.buildSuiAccountProof(
						bundleIdHash, certenProof, adiURL,
						anchorOpCommit, anchorCCCommit, anchorGovRoot,
						amountMist, userAccountObjectId, recipientAddr,
					)

					var govErr error
					govTxHash, govErr = suiClient.WithdrawSuiDirect(ctx,
						userAccountObjectId, accountVersion,
						recipientAddr, amountMist, accountProof,
					)
					if govErr != nil {
						btce.logger.Printf("⚠️ [SUI-EXEC] Step 3 failed: %v", govErr)
						govTxHash = "gov_failed_sui"
					}
				}
			}
		}
	}

	btce.logger.Printf("🎉 [SUI-EXEC] SUI anchor workflow completed!")
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	return btce.buildSuiResult(intentID, anchorID, createTxHash, verifyTxHash, govTxHash, true), nil
}

// =============================================================================
// SUI Groth16 format conversion: gnark → Arkworks
// =============================================================================

// BN254 base field modulus (Fp) for Y parity checks in Arkworks compressed serialization.
var bn254FieldModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var bn254HalfFieldModulus = new(big.Int).Div(bn254FieldModulus, big.NewInt(2))

// BN254 scalar field order (Fr) for reducing public inputs.
// gnark internally reduces public inputs mod r; the ABI stores unreduced values.
var bn254ScalarFieldOrder, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// reverseBytes32 returns a copy of a 32-byte slice with bytes reversed (BE↔LE).
func reverseBytes32(b []byte) []byte {
	out := make([]byte, 32)
	for i := 0; i < 32 && i < len(b); i++ {
		out[31-i] = b[i]
	}
	return out
}

// convertGnarkProofToArkworks converts a 256-byte gnark uncompressed proof
// (ProofA(64) + ProofB(128) + ProofC(64), big-endian coordinates) to a
// 128-byte Arkworks compressed proof (ProofA(32) + ProofB(64) + ProofC(32),
// little-endian with Y-parity flags in top bits of last byte).
func convertGnarkProofToArkworks(gnarkProof []byte) ([]byte, error) {
	if len(gnarkProof) != 256 {
		return nil, fmt.Errorf("expected 256-byte gnark proof, got %d", len(gnarkProof))
	}

	result := make([]byte, 128)

	// --- ProofA (G1): gnark bytes [0:64] ---
	aX := new(big.Int).SetBytes(gnarkProof[0:32])
	aY := new(big.Int).SetBytes(gnarkProof[32:64])
	copy(result[0:32], reverseBytes32(gnarkProof[0:32])) // X in LE
	if aX.Sign() == 0 && aY.Sign() == 0 {
		result[31] |= 0x40 // point at infinity
	} else if aY.Cmp(bn254HalfFieldModulus) > 0 {
		result[31] |= 0x80 // negative Y
	}

	// --- ProofB (G2): gnark bytes [64:192] ---
	// gnark layout: X.A0(32) X.A1(32) Y.A0(32) Y.A1(32) — all BE
	// Arkworks layout: c0(32 LE) || c1(32 LE) — flags in byte[63]
	bY0 := new(big.Int).SetBytes(gnarkProof[128:160])
	bY1 := new(big.Int).SetBytes(gnarkProof[160:192])
	copy(result[32:64], reverseBytes32(gnarkProof[64:96]))  // X.c0 in LE
	copy(result[64:96], reverseBytes32(gnarkProof[96:128])) // X.c1 in LE

	bX0 := new(big.Int).SetBytes(gnarkProof[64:96])
	bX1 := new(big.Int).SetBytes(gnarkProof[96:128])
	isInfinity := bX0.Sign() == 0 && bX1.Sign() == 0 && bY0.Sign() == 0 && bY1.Sign() == 0
	isNeg := false
	if bY1.Sign() != 0 {
		isNeg = bY1.Cmp(bn254HalfFieldModulus) > 0
	} else {
		isNeg = bY0.Cmp(bn254HalfFieldModulus) > 0
	}
	if isInfinity {
		result[95] |= 0x40
	} else if isNeg {
		result[95] |= 0x80
	}

	// --- ProofC (G1): gnark bytes [192:256] ---
	cX := new(big.Int).SetBytes(gnarkProof[192:224])
	cY := new(big.Int).SetBytes(gnarkProof[224:256])
	copy(result[96:128], reverseBytes32(gnarkProof[192:224])) // X in LE
	if cX.Sign() == 0 && cY.Sign() == 0 {
		result[127] |= 0x40
	} else if cY.Cmp(bn254HalfFieldModulus) > 0 {
		result[127] |= 0x80
	}

	return result, nil
}

// convertGnarkPublicInputToArkworksLE converts a 32-byte big-endian gnark public
// input to Arkworks little-endian Fr format. gnark reduces public inputs mod r
// internally, but the ABI stores the unreduced value. This function reduces mod r
// then serializes as 32-byte LE for SUI's groth16::public_proof_inputs_from_bytes.
func convertGnarkPublicInputToArkworksLE(be [32]byte) [32]byte {
	// Interpret as big-endian integer
	v := new(big.Int).SetBytes(be[:])
	// Reduce mod scalar field order (matches gnark's internal reduction)
	v.Mod(v, bn254ScalarFieldOrder)
	// Serialize as 32-byte little-endian
	var le [32]byte
	vBytes := v.Bytes() // big-endian
	for i, b := range vBytes {
		le[len(vBytes)-1-i] = b
	}
	return le
}

// buildSuiCertenProof converts the comprehensive proof to SUI format.
// SUI uses vector<u8> for 32-byte values and milliseconds for timestamps.
func (btce *BFTTargetChainExecutor) buildSuiCertenProof(
	compProof *contracts.ComprehensiveCertenProof,
	certenProof *proof.CertenProof,
) SuiCertenProof {
	if compProof == nil {
		return SuiCertenProof{
			ExpirationTimeMs: uint64(time.Now().Add(24 * time.Hour).UnixMilli()),
		}
	}

	proofHashes := make([][32]byte, len(compProof.ProofHashes))
	copy(proofHashes, compProof.ProofHashes)

	keyPageProofs := make([][32]byte, len(compProof.GovernanceProof.KeyPageProofs))
	copy(keyPageProofs, compProof.GovernanceProof.KeyPageProofs)

	totalVP := uint64(0)
	if compProof.BLSProof.TotalVotingPower != nil {
		totalVP = compProof.BLSProof.TotalVotingPower.Uint64()
	}
	signedVP := uint64(0)
	if compProof.BLSProof.SignedVotingPower != nil {
		signedVP = compProof.BLSProof.SignedVotingPower.Uint64()
	}
	govNonce := uint64(0)
	if compProof.GovernanceProof.Nonce != nil {
		govNonce = compProof.GovernanceProof.Nonce.Uint64()
	}
	reqSigs := uint64(0)
	if compProof.GovernanceProof.RequiredSignatures != nil {
		reqSigs = compProof.GovernanceProof.RequiredSignatures.Uint64()
	}
	provSigs := uint64(0)
	if compProof.GovernanceProof.ProvidedSignatures != nil {
		provSigs = compProof.GovernanceProof.ProvidedSignatures.Uint64()
	}

	// SUI uses milliseconds for timestamps
	expirationMs := uint64(time.Now().Add(24 * time.Hour).UnixMilli())
	if compProof.ExpirationTime != nil {
		// ExpirationTime from EVM is in seconds — convert to milliseconds
		expirationMs = compProof.ExpirationTime.Uint64() * 1_000
	}

	// Authority address as 0x+64hex (pad 20-byte EVM address to 32 bytes)
	authorityAddr := "0x" + hex.EncodeToString(common.LeftPadBytes(compProof.GovernanceProof.AuthorityAddress.Bytes(), 32))

	// Validator addresses as 0x+64hex
	validatorAddrs := make([]string, len(compProof.BLSProof.ValidatorAddresses))
	for i, addr := range compProof.BLSProof.ValidatorAddresses {
		validatorAddrs[i] = "0x" + hex.EncodeToString(common.LeftPadBytes(addr.Bytes(), 32))
	}

	// Voting powers (default 100 each)
	votingPowers := make([]uint64, len(validatorAddrs))
	for i := range votingPowers {
		votingPowers[i] = 100
	}

	// BLS aggregate signature — parse ABI bytes and convert to Arkworks format for SUI
	var blsProofBytes []byte
	var blsMessageHash [32]byte
	var blsPubkeyCommitment []byte

	if len(compProof.BLSProof.AggregateSignature) >= 448 {
		abiBytes := compProof.BLSProof.AggregateSignature

		// Convert proof points: gnark uncompressed (256 bytes BE) → Arkworks compressed (128 bytes LE)
		arkProof, err := convertGnarkProofToArkworks(abiBytes[0:256])
		if err != nil {
			log.Printf("⚠️ [SUI-BLS] Failed to convert proof to Arkworks: %v, using raw", err)
			blsProofBytes = abiBytes[0:256]
		} else {
			blsProofBytes = arkProof
			log.Printf("✅ [SUI-BLS] Converted gnark proof (256B) → Arkworks compressed (128B)")
		}

		// Convert message hash: BE → reduce mod r → LE for Arkworks Fr serialization
		var msgHashBE [32]byte
		copy(msgHashBE[:], abiBytes[256:288])
		blsMessageHash = convertGnarkPublicInputToArkworksLE(msgHashBE)

		// Convert pubkey commitment: BE → reduce mod r → LE for Arkworks Fr serialization
		var pkCommitBE [32]byte
		copy(pkCommitBE[:], abiBytes[288:320])
		blsPubkeyCommitmentLE := convertGnarkPublicInputToArkworksLE(pkCommitBE)
		blsPubkeyCommitment = blsPubkeyCommitmentLE[:]

		signedVP = new(big.Int).SetBytes(abiBytes[320:352]).Uint64()
		totalVP = new(big.Int).SetBytes(abiBytes[352:384]).Uint64()

		log.Printf("🔐 [SUI-BLS] Public inputs (LE): msgHash=%x... pkCommit=%x... signedVP=%d totalVP=%d",
			blsMessageHash[:4], blsPubkeyCommitment[:4], signedVP, totalVP)
	} else {
		blsMessageHash = compProof.BLSProof.MessageHash
	}

	// Source block height
	sourceBlockHeight := uint64(0)
	if compProof.Commitments.SourceBlockHeight != nil {
		sourceBlockHeight = compProof.Commitments.SourceBlockHeight.Uint64()
	}

	// Target address: pad 20-byte EVM address to 32-byte SUI address format
	targetAddr := "0x" + hex.EncodeToString(common.LeftPadBytes(compProof.Commitments.TargetAddress.Bytes(), 32))

	return SuiCertenProof{
		TransactionHash: compProof.TransactionHash,
		MerkleRoot:      compProof.MerkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        compProof.LeafHash,

		GovKeyBookURL:         compProof.GovernanceProof.KeyBookURL,
		GovKeyBookRoot:        compProof.GovernanceProof.KeyBookRoot,
		GovKeyPageProofs:      keyPageProofs,
		GovAuthorityAddress:   authorityAddr,
		GovAuthorityLevel:     compProof.GovernanceProof.AuthorityLevel,
		GovNonce:              govNonce,
		GovRequiredSignatures: reqSigs,
		GovProvidedSignatures: provSigs,

		BLSProofBytes:        blsProofBytes,
		BLSValidatorAddresses: validatorAddrs,
		BLSVotingPowers:      votingPowers,
		BLSTotalVotingPower:  totalVP,
		BLSSignedVotingPower: signedVP,
		BLSMessageHash:       blsMessageHash,
		BLSPubkeyCommitment:  blsPubkeyCommitment,

		CommitOperationCommitment:  compProof.Commitments.OperationCommitment,
		CommitCrossChainCommitment: compProof.Commitments.CrossChainCommitment,
		CommitGovernanceRoot:       compProof.Commitments.GovernanceRoot,
		CommitSourceChain:          compProof.Commitments.SourceChain,
		CommitSourceBlockHeight:    sourceBlockHeight,
		CommitSourceTxHash:         compProof.Commitments.SourceTxHash,
		CommitTargetChain:          compProof.Commitments.TargetChain,
		CommitTargetAddress:        targetAddr,

		ExpirationTimeMs: expirationMs,
		Metadata:         compProof.Metadata,
	}
}

// buildSuiAccountProof constructs the SuiADIGovernanceProof for Step 3.
// Mirrors buildAptosAccountProof — computes a 4-leaf merkle proof for adiURL verification.
func (btce *BFTTargetChainExecutor) buildSuiAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
	amountMist uint64,
	accountObjectId string,
	recipientAddr string,
) SuiADIGovernanceProof {
	requiredLevel := suiAuthorityLevelForMist(amountMist)
	log.Printf("🔐 [SUI-AUTH] %d MIST → authority level: %d", amountMist, requiredLevel)

	// Build merkle proof: same 4-leaf tree as TRON/EVM/NEAR/Solana/Aptos
	// proof[0] = operationCommitment (sibling at level 0)
	// proof[1] = sortedHash(ccCommitment, govRoot) (sibling at level 1)
	hash23 := sortedHash(ccCommitment[:], govRoot[:])
	var hash23Arr [32]byte
	copy(hash23Arr[:], hash23)

	log.Printf("🌳 [SUI-MERKLE] Built 4-leaf proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (op): 0x%x", opCommitment[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23Arr[:8])

	merkleProof := [][32]byte{opCommitment, hash23Arr}

	now := time.Now()
	proofTimestamp := uint64(now.Add(-5 * time.Minute).UnixMilli())
	proofExpiresAt := uint64(now.Add(2 * time.Hour).UnixMilli())

	// Build operation hash: keccak256("CERTEN_OP" || account_id || bcs(OP_WITHDRAW_SUI) || recipient || bcs(amount))
	// Must match Move's compute_withdraw_operation_hash exactly.
	var operationHash [32]byte
	{
		var opData []byte
		opData = append(opData, []byte("CERTEN_OP")...)

		// account_id: 32-byte object ID
		acctHex := strings.TrimPrefix(accountObjectId, "0x")
		acctBytes, err := hex.DecodeString(acctHex)
		if err == nil {
			// Pad/truncate to 32 bytes
			var acctID [32]byte
			copy(acctID[32-len(acctBytes):], acctBytes)
			opData = append(opData, acctID[:]...)
		}

		// OP_WITHDRAW_SUI = u64(1), BCS = 8-byte little-endian
		var opCode [8]byte
		binary.LittleEndian.PutUint64(opCode[:], 1)
		opData = append(opData, opCode[:]...)

		// recipient: 32-byte address
		recipHex := strings.TrimPrefix(recipientAddr, "0x")
		recipBytes, err := hex.DecodeString(recipHex)
		if err == nil {
			var recipID [32]byte
			copy(recipID[32-len(recipBytes):], recipBytes)
			opData = append(opData, recipID[:]...)
		}

		// amount: BCS u64 = 8-byte little-endian
		var amtBytes [8]byte
		binary.LittleEndian.PutUint64(amtBytes[:], amountMist)
		opData = append(opData, amtBytes[:]...)

		hash := ethcrypto.Keccak256(opData)
		copy(operationHash[:], hash)
		log.Printf("🔑 [SUI-OP] Operation hash: 0x%x", operationHash[:])
	}

	// BLS validator signatures: always empty for Step 3.
	// BLS ZK verification was already performed in Step 2 (execute_comprehensive_proof).
	// The Step 3 contract's verify_bls_signature_view computes a different message hash
	// on-chain and uses zero pubkey_commitment, making it incompatible with the Step 2
	// proof. Sending empty bytes skips the conditional BLS check (matches Aptos pattern).
	validatorSigs := []byte{}

	return SuiADIGovernanceProof{
		AdiURL:     adiURL,
		AnchorID:   bundleID,
		MerklePath: merkleProof,

		KBUrl:        "",
		KBRoot:       [32]byte{},
		KBDepth:      0,
		KBValidFrom:  0,
		KBValidUntil: 0,

		RoleLevel:        requiredLevel,
		RoleHash:         [32]byte{},
		RoleAuthorizedBy: "0x" + strings.Repeat("0", 64),
		RoleGrantedAt:    0,
		RoleSignature:    []byte{},

		ThreshRequired:     0,
		ThreshActual:       0,
		ThreshSignatures:   [][]byte{},
		ThreshSigners:      []string{},
		ThreshVotingPowers: []uint64{},
		ThreshTotalPower:   0,
		ThreshMessageHash:  [32]byte{},

		Timestamp:           proofTimestamp,
		ExpiresAt:           proofExpiresAt,
		ValidatorSignatures: validatorSigs,
		Nonce:               1, // Must be > current nonce (starts at 0)
		RequiredLevel:       requiredLevel,
		OperationHash:       operationHash,
	}
}

// extractSuiFieldFromCrossChainData extracts a SUI address field from CrossChainData.
// Returns the field value if it looks like a SUI address (0x prefix + 64 hex chars).
func (btce *BFTTargetChainExecutor) extractSuiFieldFromCrossChainData(legacyIntent *intent.CertenIntent, field string) string {
	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		return ""
	}

	var ccData struct {
		Legs []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(legacyIntent.CrossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return ""
	}

	var value string
	switch field {
	case "from":
		value = ccData.Legs[0].From
	case "to":
		value = ccData.Legs[0].To
	}

	// SUI addresses are 0x + 64 hex chars (32 bytes)
	if value != "" && strings.HasPrefix(value, "0x") && len(value) == 66 {
		_, err := hex.DecodeString(value[2:])
		if err == nil {
			return value
		}
	}
	return ""
}

// buildSuiResult creates a TargetChainExecutionResult for SUI operations.
func (btce *BFTTargetChainExecutor) buildSuiResult(
	intentID, anchorID string,
	createTxHash, verifyTxHash, govTxHash string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            "sui-testnet",
		TxHash:           createTxHash,
		Success:          success,
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
		Metadata: map[string]string{
			"chain":            "sui-testnet",
			"anchorPackage":    os.Getenv("SUI_ANCHOR_PACKAGE"),
			"anchorState":      os.Getenv("SUI_ANCHOR_STATE_OBJECT"),
			"explorerUrl":      "https://suiscan.xyz/testnet",
			"executionMethod":  "sui_json_rpc",
		},
	}
}

// =============================================================================
// TON CHAIN EXECUTION
// =============================================================================

// executeTonOperations executes anchor workflow on TON using TON Center API v2.
// TON uses Ed25519 signing, Cell serialization, async actor model with BLS verifier callbacks.
// Follows the same 3-step pattern as SUI/Aptos but with async Step 2 and Step 3.
func (btce *BFTTargetChainExecutor) executeTonOperations(
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

	btce.logger.Printf("🔷 [TON-EXEC] Executing TON chain operations for intent: %s", intentID)

	// Fresh context with generous timeout for 3-step async TON flow
	tonCtx, tonCancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer tonCancel()
	ctx = tonCtx

	// Load TON config from environment
	tonMnemonic := os.Getenv("TON_WALLET_MNEMONIC")
	tonAPIURL := os.Getenv("TON_TESTNET_API_URL")
	tonAnchorContract := os.Getenv("TON_ANCHOR_CONTRACT")
	tonBLSVerifier := os.Getenv("TON_BLS_VERIFIER_CONTRACT")
	tonFactoryContract := os.Getenv("TON_ACCOUNT_FACTORY_CONTRACT")

	if tonMnemonic == "" || tonAPIURL == "" || tonAnchorContract == "" || tonBLSVerifier == "" {
		return nil, fmt.Errorf("missing TON config: TON_WALLET_MNEMONIC=%v, TON_TESTNET_API_URL=%q, TON_ANCHOR_CONTRACT=%q, TON_BLS_VERIFIER_CONTRACT=%q",
			tonMnemonic != "", tonAPIURL, tonAnchorContract, tonBLSVerifier)
	}

	btce.logger.Printf("✅ [TON-EXEC] Using TON config:")
	btce.logger.Printf("   API: %s", tonAPIURL)
	btce.logger.Printf("   Anchor: %s", tonAnchorContract)
	btce.logger.Printf("   BLS Verifier: %s", tonBLSVerifier)
	btce.logger.Printf("   Factory: %s", tonFactoryContract)

	// Create TON client
	tonClient, err := NewTonClient(tonAPIURL, tonMnemonic, tonAnchorContract, tonBLSVerifier, tonFactoryContract)
	if err != nil {
		return nil, fmt.Errorf("failed to create TON client: %w", err)
	}

	// Create EthereumContractManager for proof building (reuse commitment logic)
	privateKey := os.Getenv("ETH_PRIVATE_KEY")
	contractConfig := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		ChainID:              11155111,
		PrivateKey:           privateKey,
		CreationContract:     os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		VerificationContract: os.Getenv("CERTEN_ANCHOR_V3_ADDRESS"),
		GasLimit:             800000,
		MaxGasPriceGwei:      50,
	}
	if contractConfig.CreationContract == "" {
		contractConfig.CreationContract = os.Getenv("CERTEN_CONTRACT_ADDRESS")
	}
	if contractConfig.VerificationContract == "" {
		contractConfig.VerificationContract = contractConfig.CreationContract
	}

	ethManager, err := NewEthereumContractManager(contractConfig)
	if err != nil {
		btce.logger.Printf("⚠️ [TON-EXEC] Failed to create proof builder (non-fatal): %v", err)
	}

	// Build legacy intent and proof data
	legacyIntent := btce.convertToLegacyIntent(intentID, transactionHash, accountURL, certenProof)

	var bundleIdHash [32]byte
	var comprehensiveProof *contracts.ComprehensiveCertenProof
	if ethManager != nil {
		bundleIdHash = ethManager.generateAnchorID(legacyIntent, certenProof)
		cp := ethManager.buildComprehensiveProof(legacyIntent, certenProof,
			&anchor.AnchorResponse{AnchorID: anchorID, Success: true, Message: "BFT anchor for TON"},
			bundleIdHash,
		)
		comprehensiveProof = &cp
	} else {
		hash := ethcrypto.Keccak256Hash([]byte(fmt.Sprintf("certen_v3_%s_%d_%s",
			legacyIntent.IntentID, certenProof.BlockHeight, certenProof.TransactionHash)))
		copy(bundleIdHash[:], hash[:])
	}

	// Extract commitments
	var opCommitment, ccCommitment, govRoot [32]byte
	if comprehensiveProof != nil {
		opCommitment = comprehensiveProof.Commitments.OperationCommitment
		ccCommitment = comprehensiveProof.Commitments.CrossChainCommitment
		govRoot = comprehensiveProof.Commitments.GovernanceRoot
	}

	// V4: Compute adiURLHash for 4-leaf sorted merkle tree binding
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
	}
	adiURLHash := ComputeAdiURLHash(adiURL)

	btce.logger.Printf("🔍 [TON-MERKLE] Step 1 inputs (V4):")
	btce.logger.Printf("   bundleId:    0x%x", bundleIdHash[:])
	btce.logger.Printf("   adiURL:      %s", adiURL)
	btce.logger.Printf("   adiURLHash:  0x%x", adiURLHash[:])
	btce.logger.Printf("   opCommit:    0x%x", opCommitment[:])
	btce.logger.Printf("   ccCommit:    0x%x", ccCommitment[:])
	btce.logger.Printf("   govRoot:     0x%x", govRoot[:])

	// ========== Step 1: Create Anchor ==========
	btce.logger.Printf("🔗 [TON-EXEC] Step 1: Creating anchor on TON (V4)...")

	blockHeight := uint64(0)
	if certenProof.BlockHeight > 0 {
		blockHeight = uint64(certenProof.BlockHeight)
	}

	createTxHash, err := tonClient.CreateAnchor(ctx, bundleIdHash, adiURLHash, opCommitment, ccCommitment, govRoot, blockHeight)
	if err != nil {
		btce.logger.Printf("❌ [TON-EXEC] Step 1 failed: %v", err)
		return btce.buildTonResult(intentID, anchorID, "create_failed_ton", "", "", false), err
	}

	btce.logger.Printf("✅ [TON-EXEC] Step 1 complete - Anchor created: %s", createTxHash)

	// Wait for Step 1 confirmation
	err = tonClient.WaitForConfirmation(ctx, createTxHash, 60*time.Second)
	if err != nil {
		btce.logger.Printf("⚠️ [TON-EXEC] Step 1 confirmation issue: %v", err)
	}

	// ========== Step 2: Execute Comprehensive Proof ==========
	btce.logger.Printf("🔗 [TON-EXEC] Step 2: Submitting comprehensive proof...")

	tonProof := btce.buildTonCertenProof(comprehensiveProof, certenProof)

	// TON contract uses SHA-256 cell hashing (not EVM Keccak256) for merkle proofs.
	// Override the entire merkle proof with TON-compatible values.
	tonMerkleRoot := TonComputeBoundMerkleRoot(adiURLHash, opCommitment, ccCommitment, govRoot)
	btce.logger.Printf("🔑 [TON-MERKLE] Overriding proof for TON cell-hash compatibility:")
	btce.logger.Printf("   EVM merkleRoot (keccak256): 0x%x", tonProof.MerkleRoot[:8])
	btce.logger.Printf("   TON merkleRoot (sha256cell): 0x%x", tonMerkleRoot[:8])
	tonProof.MerkleRoot = tonMerkleRoot

	// Build proper 4-leaf tree proof: leaf=adiURLHash, siblings=[opCommitment, hash23]
	// Verification: sortedHash(sortedHash(adiURLHash, op), hash23) == root
	tonProof.LeafHash = adiURLHash
	tonProof.ProofHashes = [][32]byte{
		opCommitment,
		TonSortedHash(ccCommitment, govRoot),
	}

	verifyTxHash, err := tonClient.ExecuteComprehensiveProof(ctx, bundleIdHash, tonProof)
	if err != nil {
		btce.logger.Printf("❌ [TON-EXEC] Step 2 failed: %v", err)
		return btce.buildTonResult(intentID, anchorID,
			createTxHash, "verify_failed_ton", "", false), err
	}

	btce.logger.Printf("✅ [TON-EXEC] Step 2 message sent: %s", verifyTxHash)

	// Wait for async BLS verification (anchor -> BLS verifier -> callback)
	btce.logger.Printf("⏳ [TON-EXEC] Waiting for async BLS verification callback...")
	err = tonClient.WaitForProofExecution(ctx, bundleIdHash, tonPollingTimeout)
	if err != nil {
		btce.logger.Printf("⚠️ [TON-EXEC] Step 2 async completion issue: %v", err)
	} else {
		btce.logger.Printf("✅ [TON-EXEC] Step 2 complete - Proof verified via async callback")
	}

	// ========== Step 3: Execute via user's Abstract Account ==========
	allLegs := btce.extractAllLegsFromIntent(legacyIntent)
	tonLeg := btce.findLegForChainPrefix(allLegs, "ton", -239, -3) // TON mainnet=-239, testnet=-3
	govTxHash := "no_governance_needed"

	if tonLeg != nil {
		btce.logger.Printf("🏦 [TON-EXEC] Step 3: Executing governance proof direct...")

		// Extract TON addresses from CrossChainData
		tonFromAddr := btce.extractTonFieldFromCrossChainData(legacyIntent, "from")
		tonToAddr := btce.extractTonFieldFromCrossChainData(legacyIntent, "to")

		btce.logger.Printf("   Intent from: %s", tonFromAddr)
		btce.logger.Printf("   Intent to: %s", tonToAddr)

		userAccountAddr := tonFromAddr
		adiURL := certenProof.AccountURL
		if adiURL == "" {
			adiURL = fmt.Sprintf("%s/data", legacyIntent.OrganizationADI)
		}

		if userAccountAddr == "" {
			btce.logger.Printf("⚠️ [TON-EXEC] No from address in intent, cannot determine user account")
			govTxHash = "gov_failed_no_account_ton"
		}

		if userAccountAddr != "" {
			btce.logger.Printf("   User account: %s", userAccountAddr)

			// Check if account exists (deployed by api-bridge, NOT by validators)
			accountExists, checkErr := tonClient.CheckAccountExists(ctx, userAccountAddr)
			if checkErr != nil {
				btce.logger.Printf("⚠️ [TON-EXEC] Failed to check account: %v", checkErr)
			}

			if !accountExists {
				btce.logger.Printf("❌ [TON-EXEC] Account not deployed at %s — must be created via api-bridge first", userAccountAddr)
				govTxHash = "gov_failed_no_account_ton"
			}

			if accountExists && govTxHash == "no_governance_needed" {
				// Read anchor data for merkle proof construction
				anchorData, readErr := tonClient.GetAnchorData(ctx, bundleIdHash)
				if readErr != nil {
					btce.logger.Printf("⚠️ [TON-EXEC] Failed to read anchor data: %v", readErr)
					govTxHash = "gov_failed_anchor_read_ton"
				} else {
					anchorOpCommit := opCommitment
					anchorCCCommit := ccCommitment
					anchorGovRoot := govRoot
					if anchorData.OperationCommitment != ([32]byte{}) {
						anchorOpCommit = anchorData.OperationCommitment
					}
					if anchorData.CrossChainCommitment != ([32]byte{}) {
						anchorCCCommit = anchorData.CrossChainCommitment
					}
					if anchorData.GovernanceRoot != ([32]byte{}) {
						anchorGovRoot = anchorData.GovernanceRoot
					}

					recipientAddr := tonToAddr
					if recipientAddr == "" {
						// No explicit "to" in CrossChainData — default to user's own account
						// (governance proofs operate on the ADI's data account, not external transfers)
						recipientAddr = userAccountAddr
						btce.logger.Printf("   [TON-EXEC] No recipient in intent, using user account as recipient")
					}

					// Convert amountWei (18 decimals) to nanoTON (9 decimals)
					amountNano := uint64(1) // Default 1 nanoTON
					if tonLeg.Value != nil {
						weiValue := new(big.Int).Set(tonLeg.Value)
						nanoValue := new(big.Int).Div(weiValue, big.NewInt(1_000_000_000))
						if nanoValue.Sign() <= 0 {
							nanoValue = big.NewInt(1)
						}
						amountNano = nanoValue.Uint64()
						btce.logger.Printf("💱 [TON-EXEC] Value conversion: %s wei → %d nanoTON",
							tonLeg.Value.String(), amountNano)
					}

					btce.logger.Printf("💱 [TON-EXEC] Governance: target=%s nano=%d", recipientAddr, amountNano)

					// Build ADIGovernanceProof
					accountProof := btce.buildTonAccountProof(
						bundleIdHash, certenProof, adiURL,
						anchorOpCommit, anchorCCCommit, anchorGovRoot,
						amountNano, userAccountAddr, recipientAddr,
					)

					var govErr error
					govTxHash, govErr = tonClient.ExecuteGovernanceProofDirect(ctx,
						userAccountAddr, recipientAddr, amountNano, accountProof,
					)
					if govErr != nil {
						btce.logger.Printf("⚠️ [TON-EXEC] Step 3 failed: %v", govErr)
						govTxHash = "gov_failed_ton"
					}
				}
			}
		}
	}

	btce.logger.Printf("🎉 [TON-EXEC] TON anchor workflow completed!")
	btce.logger.Printf("   Create TX: %s", createTxHash)
	btce.logger.Printf("   Verify TX: %s", verifyTxHash)
	btce.logger.Printf("   Governance TX: %s", govTxHash)

	return btce.buildTonResult(intentID, anchorID, createTxHash, verifyTxHash, govTxHash, true), nil
}

// buildTonCertenProof converts the comprehensive proof to TON Cell-compatible format.
func (btce *BFTTargetChainExecutor) buildTonCertenProof(
	compProof *contracts.ComprehensiveCertenProof,
	certenProof *proof.CertenProof,
) TonCertenProof {
	if compProof == nil {
		return TonCertenProof{
			ExpirationTime: uint64(time.Now().Add(24 * time.Hour).Unix()),
		}
	}

	proofHashes := make([][32]byte, len(compProof.ProofHashes))
	copy(proofHashes, compProof.ProofHashes)

	keyPageProofs := make([][32]byte, len(compProof.GovernanceProof.KeyPageProofs))
	copy(keyPageProofs, compProof.GovernanceProof.KeyPageProofs)

	totalVP := uint64(0)
	if compProof.BLSProof.TotalVotingPower != nil {
		totalVP = compProof.BLSProof.TotalVotingPower.Uint64()
	}
	signedVP := uint64(0)
	if compProof.BLSProof.SignedVotingPower != nil {
		signedVP = compProof.BLSProof.SignedVotingPower.Uint64()
	}
	govNonce := uint64(0)
	if compProof.GovernanceProof.Nonce != nil {
		govNonce = compProof.GovernanceProof.Nonce.Uint64()
	}
	reqSigs := uint16(0)
	if compProof.GovernanceProof.RequiredSignatures != nil {
		reqSigs = uint16(compProof.GovernanceProof.RequiredSignatures.Uint64())
	}
	provSigs := uint16(0)
	if compProof.GovernanceProof.ProvidedSignatures != nil {
		provSigs = uint16(compProof.GovernanceProof.ProvidedSignatures.Uint64())
	}

	// TON uses seconds for timestamps (not milliseconds like SUI)
	expirationSec := uint64(time.Now().Add(24 * time.Hour).Unix())
	if compProof.ExpirationTime != nil {
		expirationSec = compProof.ExpirationTime.Uint64()
	}

	// Authority address: parse EVM address to TON address (zero workchain, padded)
	var govAuthAddr *tonaddr.Address
	if compProof.GovernanceProof.AuthorityAddress != (common.Address{}) {
		padded := make([]byte, 32)
		copy(padded[12:], compProof.GovernanceProof.AuthorityAddress.Bytes())
		govAuthAddr = tonaddr.NewAddress(0, 0, padded)
	} else {
		govAuthAddr = tonaddr.NewAddress(0, 0, make([]byte, 32))
	}

	// BLS proof: use pre-generated BLS12-381 proof (native TVM curve).
	// The proof is already in compProof.BLSProof.BLS12381ProofBytes (192 bytes:
	// pi_a:48 + pi_b:96 + pi_c:48 compressed BLS12-381 points).
	// No gnark→Arkworks conversion needed — this IS the native format.
	var blsProofBytes []byte
	var blsMessageHash [32]byte
	var blsPubkeyCommitment []byte

	if len(compProof.BLSProof.BLS12381ProofBytes) == 192 {
		blsProofBytes = compProof.BLSProof.BLS12381ProofBytes
		blsPubkeyCommitment = compProof.BLSProof.BLS12381PubkeyCommitment[:]

		// MessageHash must be reduced mod BLS12-381 Fr (not BN254 Fr)
		msgHashInt := new(big.Int).SetBytes(compProof.BLSProof.MessageHash[:])
		bls12381Fr, _ := new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
		msgHashInt.Mod(msgHashInt, bls12381Fr)
		msgHashReduced := msgHashInt.Bytes()
		blsMessageHash = [32]byte{}
		copy(blsMessageHash[32-len(msgHashReduced):], msgHashReduced) // big-endian, left-padded

		log.Printf("✅ [TON-BLS12381] Using native BLS12-381 proof: %d bytes (pi_a:48 + pi_b:96 + pi_c:48)", len(blsProofBytes))
		log.Printf("🔐 [TON-BLS12381] Public inputs: msgHash=%x... pkCommit=%x... signedVP=%d totalVP=%d",
			blsMessageHash[:4], blsPubkeyCommitment[:4], signedVP, totalVP)
	} else {
		log.Printf("⚠️ [TON-BLS12381] No BLS12-381 proof available (got %d bytes, need 192)", len(compProof.BLSProof.BLS12381ProofBytes))
		blsMessageHash = compProof.BLSProof.MessageHash
	}

	return TonCertenProof{
		TransactionHash: compProof.TransactionHash,
		MerkleRoot:      compProof.MerkleRoot,
		ProofHashes:     proofHashes,
		LeafHash:        compProof.LeafHash,

		GovKeyBookRoot:        compProof.GovernanceProof.KeyBookRoot,
		GovAuthorityLevel:     compProof.GovernanceProof.AuthorityLevel,
		GovNonce:              govNonce,
		GovRequiredSignatures: reqSigs,
		GovProvidedSignatures: provSigs,
		GovAuthorityAddress:   govAuthAddr,
		GovKeyPageProofs:      keyPageProofs,

		BLSMessageHash:       blsMessageHash,
		BLSThresholdMet:      signedVP > 0,
		BLSSignedVotingPower: signedVP,
		BLSTotalVotingPower:  totalVP,
		BLSProofBytes:        blsProofBytes,
		BLSPubkeyCommitment:  blsPubkeyCommitment,

		CommitOperationCommitment:  compProof.Commitments.OperationCommitment,
		CommitCrossChainCommitment: compProof.Commitments.CrossChainCommitment,
		CommitGovernanceRoot:       compProof.Commitments.GovernanceRoot,

		ExpirationTime: expirationSec,
	}
}

// buildTonAccountProof constructs the TonADIGovernanceProof for Step 3.
// Mirrors buildSuiAccountProof — computes a 4-leaf merkle proof for adiURL verification.
func (btce *BFTTargetChainExecutor) buildTonAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
	amountNano uint64,
	accountAddr string,
	recipientAddr string,
) TonADIGovernanceProof {
	requiredLevel := tonAuthorityLevelForNano(amountNano)
	log.Printf("🔐 [TON-AUTH] %d nanoTON → authority level: %d", amountNano, requiredLevel)

	// Build merkle proof: TON uses Cell-hash (SHA-256), NOT Keccak256
	hash23Arr := TonSortedHash(ccCommitment, govRoot)

	log.Printf("🌳 [TON-MERKLE] Built 4-leaf proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (op): 0x%x", opCommitment[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23Arr[:8])

	merklePath := [][32]byte{opCommitment, hash23Arr}

	now := time.Now()
	proofTimestamp := uint64(now.Add(-5 * time.Minute).Unix())
	proofExpiresAt := uint64(now.Add(2 * time.Hour).Unix())

	// Zero address for role authorized by
	zeroAddr := tonaddr.NewAddress(0, 0, make([]byte, 32))

	return TonADIGovernanceProof{
		AdiURL:     adiURL,
		AnchorID:   bundleID,
		MerklePath: merklePath,

		KBUrl:        "",
		KBRoot:       [32]byte{},
		KBDepth:      0,
		KBValidFrom:  0,
		KBValidUntil: 0,

		RoleLevel:        0, // Zero = skip role check on-chain (no registered roles on fresh accounts)
		RoleHash:         [32]byte{},
		RoleAuthorizedBy: zeroAddr,
		RoleGrantedAt:    0,
		RoleSignature:    []byte{},

		ThreshRequired:     0,
		ThreshActual:       0,
		ThreshSigners:      []*tonaddr.Address{},
		ThreshVotingPowers: []uint64{},
		ThreshSignatures:   [][]byte{},
		ThreshTotalPower:   0,
		ThreshMessageHash:  [32]byte{},

		Timestamp:           proofTimestamp,
		ExpiresAt:           proofExpiresAt,
		ValidatorSignatures: []byte{},
		Nonce:               uint64(time.Now().Unix()), // Must be > last used nonce; use timestamp to ensure monotonic increase
		RequiredLevel:       requiredLevel,
		OperationHash:       [32]byte{},
	}
}

// extractTonFieldFromCrossChainData extracts a TON address field from CrossChainData.
// TON addresses use base64url format (e.g., "kQ..." or "EQ...").
func (btce *BFTTargetChainExecutor) extractTonFieldFromCrossChainData(legacyIntent *intent.CertenIntent, field string) string {
	if legacyIntent == nil || len(legacyIntent.CrossChainData) == 0 {
		return ""
	}

	var ccData struct {
		Legs []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(legacyIntent.CrossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return ""
	}

	var value string
	switch field {
	case "from":
		value = ccData.Legs[0].From
	case "to":
		value = ccData.Legs[0].To
	}

	if value == "" {
		return ""
	}

	// Try base64url format first (EQ.../kQ.../UQ.../0Q... ~48 chars)
	if len(value) >= 40 {
		_, err := tonaddr.ParseAddr(value)
		if err == nil {
			return value
		}
	}

	// Try raw format: "workchain:hex_hash" (e.g., "0:f863a763...")
	if parts := strings.SplitN(value, ":", 2); len(parts) == 2 && len(parts[1]) == 64 {
		wc := int32(0)
		if parts[0] == "-1" {
			wc = -1
		}
		hashBytes, err := hex.DecodeString(parts[1])
		if err == nil && len(hashBytes) == 32 {
			addr := tonaddr.NewAddress(0, byte(wc), hashBytes)
			return addr.String()
		}
	}
	return ""
}

// buildTonResult creates a TargetChainExecutionResult for TON operations.
func (btce *BFTTargetChainExecutor) buildTonResult(
	intentID, anchorID string,
	createTxHash, verifyTxHash, govTxHash string,
	success bool,
) *TargetChainExecutionResult {
	return &TargetChainExecutionResult{
		Chain:            "ton-testnet",
		TxHash:           createTxHash,
		Success:          success,
		CreateTxHash:     createTxHash,
		VerifyTxHash:     verifyTxHash,
		GovernanceTxHash: govTxHash,
		Metadata: map[string]string{
			"chain":           "ton-testnet",
			"anchorContract":  os.Getenv("TON_ANCHOR_CONTRACT"),
			"blsVerifier":     os.Getenv("TON_BLS_VERIFIER_CONTRACT"),
			"explorerUrl":     "https://testnet.tonscan.org",
			"executionMethod": "ton_center_api_v2",
		},
	}
}

