// Copyright 2025 Certen Protocol
//
// EVM Chain Execution Strategy
// Implements ChainExecutionStrategy for Ethereum and EVM-compatible chains
//
// Per Unified Multi-Chain Architecture:
// - Primary strategy for EVM chains (Ethereum, Arbitrum, Optimism, Base, Polygon, etc.)
// - Implements 3-step anchor workflow (Create → Verify → Governance)
// - Uses existing ethereum_contracts.go functionality

package strategy

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
)

// =============================================================================
// EVM STRATEGY CONFIGURATION
// =============================================================================

// EVMStrategyConfig holds configuration for the EVM chain strategy
type EVMStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// PrivateKey is the hex-encoded private key for signing transactions
	PrivateKeyHex string

	// ContractAddresses for the anchor workflow
	AnchorContractAddress string // CertenAnchorV3 unified contract

	// Gas configuration
	GasLimit        uint64
	MaxGasPriceGwei int64

	// Timeouts
	TxTimeout      time.Duration // Timeout for transaction submission
	ReceiptTimeout time.Duration // Timeout for receipt confirmation
	PollingInterval time.Duration // Interval for polling receipts

	// ValidatorID for logging
	ValidatorID string
}

// DefaultEVMStrategyConfig returns default configuration
func DefaultEVMStrategyConfig() *EVMStrategyConfig {
	return &EVMStrategyConfig{
		GasLimit:        3000000,
		MaxGasPriceGwei: 100,
		TxTimeout:       2 * time.Minute,
		ReceiptTimeout:  30 * time.Minute,
		PollingInterval: 12 * time.Second,
	}
}

// =============================================================================
// EVM CHAIN EXECUTION STRATEGY
// =============================================================================

// EVMStrategy implements ChainExecutionStrategy for EVM chains
type EVMStrategy struct {
	mu sync.RWMutex

	// Configuration
	config *EVMStrategyConfig

	// Ethereum client
	client *ethclient.Client

	// Transaction auth
	auth    *bind.TransactOpts
	chainID *big.Int

	// Contract addresses
	anchorContract common.Address

	// Observer for transaction watching
	observer *EVMObserver

	// State
	initialized bool

	// Callbacks
	onTxSubmitted func(txHash string)
	onTxConfirmed func(txHash string, blockNumber uint64)
}

// NewEVMStrategy creates a new EVM chain execution strategy
func NewEVMStrategy(config *EVMStrategyConfig) (*EVMStrategy, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.ChainConfig == nil {
		return nil, fmt.Errorf("chain config is required")
	}

	if config.ChainConfig.RPC == "" {
		return nil, fmt.Errorf("RPC endpoint is required")
	}

	strategy := &EVMStrategy{
		config: config,
	}

	// Connect to Ethereum client
	client, err := ethclient.Dial(config.ChainConfig.RPC)
	if err != nil {
		return nil, fmt.Errorf("connect to ethereum: %w", err)
	}
	strategy.client = client

	// Get chain ID
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("get chain ID: %w", err)
	}
	strategy.chainID = chainID

	// Parse private key and create auth
	if config.PrivateKeyHex != "" {
		privateKey, err := crypto.HexToECDSA(config.PrivateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
		if err != nil {
			return nil, fmt.Errorf("create transactor: %w", err)
		}

		auth.GasLimit = config.GasLimit
		if config.MaxGasPriceGwei > 0 {
			auth.GasPrice = big.NewInt(config.MaxGasPriceGwei * 1e9) // Convert Gwei to Wei
		}

		strategy.auth = auth
	}

	// Parse contract address
	if config.AnchorContractAddress != "" {
		if !common.IsHexAddress(config.AnchorContractAddress) {
			return nil, fmt.Errorf("invalid anchor contract address: %s", config.AnchorContractAddress)
		}
		strategy.anchorContract = common.HexToAddress(config.AnchorContractAddress)
	}

	// Create observer
	observerConfig := &EVMObserverConfig{
		Client:                strategy.client,
		ChainID:               chainID.Int64(),
		ValidatorID:           config.ValidatorID,
		RequiredConfirmations: config.ChainConfig.RequiredConfirmations,
		PollingInterval:       config.PollingInterval,
		Timeout:               config.ReceiptTimeout,
	}
	observer, err := NewEVMObserver(observerConfig)
	if err != nil {
		return nil, fmt.Errorf("create observer: %w", err)
	}
	strategy.observer = observer

	strategy.initialized = true

	return strategy, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE IMPLEMENTATION
// =============================================================================

// Platform returns the chain platform identifier
func (s *EVMStrategy) Platform() ChainPlatform {
	return ChainPlatformEVM
}

// ChainID returns the specific chain ID
func (s *EVMStrategy) ChainID() string {
	return s.chainID.String()
}

// NetworkName returns the human-readable network name
func (s *EVMStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return fmt.Sprintf("evm-%s", s.chainID.String())
}

// CreateAnchor creates an anchor transaction on the EVM chain (Step 1)
func (s *EVMStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, fmt.Errorf("strategy not initialized")
	}

	if s.auth == nil {
		return nil, fmt.Errorf("no transaction auth configured")
	}

	// Build the anchor data
	// This would call the CertenAnchorV3 contract's createAnchor function
	// The actual contract interaction is delegated to the existing ethereum_contracts.go

	// For now, we create a placeholder that demonstrates the interface
	// In production, this would use the contract bindings

	result := &AnchorResult{
		Status:    0, // Pending
		Timestamp: time.Now().UTC(),
	}

	// The actual implementation would:
	// 1. Encode the createAnchor call with req data
	// 2. Send the transaction
	// 3. Return the tx hash

	return result, fmt.Errorf("CreateAnchor: use EthereumContractManager.CreateBatchAnchorV3 for actual implementation")
}

// SubmitProof submits proof for on-chain verification (Step 2)
func (s *EVMStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, fmt.Errorf("strategy not initialized")
	}

	if s.auth == nil {
		return nil, fmt.Errorf("no transaction auth configured")
	}

	result := &AnchorResult{
		Status:    0,
		Timestamp: time.Now().UTC(),
	}

	// The actual implementation would:
	// 1. Encode the executeComprehensiveProof call
	// 2. Include BLS signature verification data
	// 3. Send the transaction

	return result, fmt.Errorf("SubmitProof: use EthereumContractManager.ExecuteComprehensiveProof for actual implementation")
}

// ExecuteWithGovernance executes with governance verification (Step 3)
func (s *EVMStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil, fmt.Errorf("strategy not initialized")
	}

	result := &AnchorResult{
		Status:    0,
		Timestamp: time.Now().UTC(),
	}

	// The actual implementation would:
	// 1. Verify governance proof
	// 2. Execute the final anchor step
	// 3. Return the result

	return result, fmt.Errorf("ExecuteWithGovernance: use EthereumContractManager.ExecuteWithGovernanceProof for actual implementation")
}

// ObserveTransaction watches a transaction until finalization
func (s *EVMStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	if !common.IsHexAddress(txHash) && len(txHash) != 66 {
		// Try to parse as hex hash
		if len(txHash) == 64 {
			txHash = "0x" + txHash
		}
	}

	hash := common.HexToHash(txHash)
	return s.observer.ObserveTransaction(ctx, hash)
}

// ObserveTransactionAsync starts async observation with callbacks
func (s *EVMStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
	onFinalized func(*ObservationResult),
	onFailed func(error)) error {

	go func() {
		result, err := s.ObserveTransaction(ctx, txHash)
		if err != nil {
			if onFailed != nil {
				onFailed(err)
			}
			return
		}
		if onFinalized != nil {
			onFinalized(result)
		}
	}()

	return nil
}

// GetRequiredConfirmations returns confirmations needed for finality
func (s *EVMStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 12 // Default for Ethereum mainnet
}

// GetCurrentBlock returns the current block number
func (s *EVMStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	return s.client.BlockNumber(ctx)
}

// GetTransactionReceipt retrieves a transaction receipt
func (s *EVMStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	hash := common.HexToHash(txHash)
	receipt, err := s.client.TransactionReceipt(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get receipt: %w", err)
	}

	result := &ObservationResult{
		TxHash:      txHash,
		BlockNumber: receipt.BlockNumber.Uint64(),
		BlockHash:   receipt.BlockHash.Hex(),
		Status:      uint8(receipt.Status),
		GasUsed:     receipt.GasUsed,
		ObservedAt:  time.Now().UTC(),
	}

	// Get block for timestamp
	block, err := s.client.BlockByHash(ctx, receipt.BlockHash)
	if err == nil {
		result.BlockTimestamp = time.Unix(int64(block.Time()), 0)
	}

	// Calculate confirmations
	currentBlock, err := s.client.BlockNumber(ctx)
	if err == nil {
		result.Confirmations = int(currentBlock - receipt.BlockNumber.Uint64())
		result.RequiredConfirmations = s.GetRequiredConfirmations()
		result.IsFinalized = result.Confirmations >= result.RequiredConfirmations
	}

	// Extract logs
	for _, log := range receipt.Logs {
		topics := make([]string, len(log.Topics))
		for i, t := range log.Topics {
			topics[i] = t.Hex()
		}
		result.Logs = append(result.Logs, EventLog{
			Address:  log.Address.Hex(),
			Topics:   topics,
			Data:     log.Data,
			LogIndex: log.Index,
		})
	}

	return result, nil
}

// EstimateGas estimates gas for an anchor operation
func (s *EVMStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	// Build call message
	// This would construct the actual contract call data
	msg := ethereum.CallMsg{
		From: s.auth.From,
		To:   &s.anchorContract,
		Gas:  0, // Let estimation figure it out
		Data: nil, // Would be encoded call data
	}

	gas, err := s.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, fmt.Errorf("estimate gas: %w", err)
	}

	// Add 20% buffer
	return gas * 120 / 100, nil
}

// HealthCheck verifies connectivity to the chain
func (s *EVMStrategy) HealthCheck(ctx context.Context) error {
	// Check client connection
	_, err := s.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("get block number: %w", err)
	}

	// Check chain ID matches
	chainID, err := s.client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("get chain ID: %w", err)
	}

	if chainID.Cmp(s.chainID) != 0 {
		return fmt.Errorf("chain ID mismatch: expected %s, got %s", s.chainID, chainID)
	}

	return nil
}

// Config returns the chain configuration
func (s *EVMStrategy) Config() *ChainConfig {
	return s.config.ChainConfig
}

// =============================================================================
// ADDITIONAL EVM-SPECIFIC METHODS
// =============================================================================

// GetClient returns the underlying Ethereum client
func (s *EVMStrategy) GetClient() *ethclient.Client {
	return s.client
}

// GetAuth returns the transaction auth
func (s *EVMStrategy) GetAuth() *bind.TransactOpts {
	return s.auth
}

// GetAnchorContractAddress returns the anchor contract address
func (s *EVMStrategy) GetAnchorContractAddress() common.Address {
	return s.anchorContract
}

// SendTransaction sends a raw transaction
func (s *EVMStrategy) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return s.client.SendTransaction(ctx, tx)
}

// GetNonce gets the current nonce for the account
func (s *EVMStrategy) GetNonce(ctx context.Context) (uint64, error) {
	if s.auth == nil {
		return 0, fmt.Errorf("no auth configured")
	}
	return s.client.PendingNonceAt(ctx, s.auth.From)
}

// GetBalance gets the balance of the account
func (s *EVMStrategy) GetBalance(ctx context.Context) (*big.Int, error) {
	if s.auth == nil {
		return nil, fmt.Errorf("no auth configured")
	}
	return s.client.BalanceAt(ctx, s.auth.From, nil)
}

// SetCallbacks sets transaction callbacks
func (s *EVMStrategy) SetCallbacks(onSubmitted func(string), onConfirmed func(string, uint64)) {
	s.onTxSubmitted = onSubmitted
	s.onTxConfirmed = onConfirmed
}

// =============================================================================
// EVM STRATEGY FACTORY
// =============================================================================

// NewEVMStrategyFromConfig creates an EVM strategy from chain config
func NewEVMStrategyFromConfig(chainConfig *ChainConfig, privateKeyHex string, validatorID string) (*EVMStrategy, error) {
	config := &EVMStrategyConfig{
		ChainConfig:           chainConfig,
		PrivateKeyHex:         privateKeyHex,
		AnchorContractAddress: chainConfig.ContractAddress,
		GasLimit:              3000000,
		MaxGasPriceGwei:       100,
		TxTimeout:             2 * time.Minute,
		ReceiptTimeout:        30 * time.Minute,
		PollingInterval:       12 * time.Second,
		ValidatorID:           validatorID,
	}

	return NewEVMStrategy(config)
}

// NewSepoliaStrategy creates an EVM strategy configured for Sepolia testnet
func NewSepoliaStrategy(rpcURL, privateKeyHex, contractAddress, validatorID string) (*EVMStrategy, error) {
	chainConfig := &ChainConfig{
		Platform:              ChainPlatformEVM,
		ChainID:               "11155111", // Sepolia
		NetworkName:           "sepolia",
		RPC:                   rpcURL,
		ContractAddress:       contractAddress,
		RequiredConfirmations: 2, // Lower for testnet
		Enabled:               true,
	}

	return NewEVMStrategyFromConfig(chainConfig, privateKeyHex, validatorID)
}

// NewMainnetStrategy creates an EVM strategy configured for Ethereum mainnet
func NewMainnetStrategy(rpcURL, privateKeyHex, contractAddress, validatorID string) (*EVMStrategy, error) {
	chainConfig := &ChainConfig{
		Platform:              ChainPlatformEVM,
		ChainID:               "1", // Mainnet
		NetworkName:           "ethereum-mainnet",
		RPC:                   rpcURL,
		ContractAddress:       contractAddress,
		RequiredConfirmations: 12, // Standard for mainnet
		Enabled:               true,
	}

	return NewEVMStrategyFromConfig(chainConfig, privateKeyHex, validatorID)
}

// =============================================================================
// ANCHOR WORKFLOW HELPER
// =============================================================================

// ExecuteAnchorWorkflow executes the complete 3-step anchor workflow
func (s *EVMStrategy) ExecuteAnchorWorkflow(ctx context.Context, req *AnchorRequest, proof *ProofSubmission, govParams *ExecutionParams) (*AnchorWorkflowState, error) {
	state := &AnchorWorkflowState{
		RequestID: uuid.New(),
		Started:   time.Now().UTC(),
	}

	// Step 1: Create Anchor
	step1Result, err := s.CreateAnchor(ctx, req)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 1 failed: %v", err)
		return state, err
	}
	state.Step1TxHash = step1Result.TxHash
	state.Step1Result = step1Result
	state.Step1Done = true
	state.AnchorID = step1Result.AnchorID

	// Observe Step 1
	obs1, err := s.ObserveTransaction(ctx, step1Result.TxHash)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 1 observation failed: %v", err)
		return state, err
	}
	if !obs1.IsFinalized {
		state.Failed = true
		state.FailReason = "step 1 not finalized"
		return state, fmt.Errorf("step 1 not finalized")
	}

	// Step 2: Submit Proof
	proof.AnchorID = state.AnchorID
	step2Result, err := s.SubmitProof(ctx, state.AnchorID, proof)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 2 failed: %v", err)
		return state, err
	}
	state.Step2TxHash = step2Result.TxHash
	state.Step2Result = step2Result
	state.Step2Done = true

	// Observe Step 2
	obs2, err := s.ObserveTransaction(ctx, step2Result.TxHash)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 2 observation failed: %v", err)
		return state, err
	}
	if !obs2.IsFinalized {
		state.Failed = true
		state.FailReason = "step 2 not finalized"
		return state, fmt.Errorf("step 2 not finalized")
	}

	// Step 3: Execute with Governance
	govParams.AnchorID = state.AnchorID
	step3Result, err := s.ExecuteWithGovernance(ctx, state.AnchorID, govParams)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 3 failed: %v", err)
		return state, err
	}
	state.Step3TxHash = step3Result.TxHash
	state.Step3Result = step3Result
	state.Step3Done = true

	// Observe Step 3
	obs3, err := s.ObserveTransaction(ctx, step3Result.TxHash)
	if err != nil {
		state.Failed = true
		state.FailReason = fmt.Sprintf("step 3 observation failed: %v", err)
		return state, err
	}
	if !obs3.IsFinalized {
		state.Failed = true
		state.FailReason = "step 3 not finalized"
		return state, fmt.Errorf("step 3 not finalized")
	}

	completed := time.Now().UTC()
	state.Completed = &completed

	return state, nil
}
