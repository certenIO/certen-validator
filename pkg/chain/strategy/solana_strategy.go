// Copyright 2025 Certen Protocol
//
// Solana Chain Execution Strategy
// Implements ChainExecutionStrategy for Solana blockchain
//
// Per Unified Multi-Chain Architecture:
// - Native Ed25519 signature support
// - ~400ms slot times, ~32 slot finality
// - Program-based smart contracts
//
// Observation uses Solana JSON-RPC API (getTransaction, getSlot, getHealth).
// Steps 1-3 are handled by BFT target chain integration.

package strategy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// =============================================================================
// SOLANA STRATEGY CONFIGURATION
// =============================================================================

// SolanaStrategyConfig holds configuration for the Solana chain strategy
type SolanaStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// RPC endpoint
	RPCURL string

	// Program IDs
	AnchorProgramID string

	// Validator identity
	ValidatorID string

	// Commitment level (processed, confirmed, finalized)
	Commitment string

	// Observation config
	PollingInterval time.Duration
	Timeout         time.Duration
}

// DefaultSolanaStrategyConfig returns default configuration
func DefaultSolanaStrategyConfig() *SolanaStrategyConfig {
	return &SolanaStrategyConfig{
		Commitment:      "finalized",
		PollingInterval: 2 * time.Second,
		Timeout:         5 * time.Minute,
	}
}

// =============================================================================
// SOLANA JSON-RPC TYPES
// =============================================================================

type solanaRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type solanaRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type solanaTransactionResult struct {
	Slot      uint64 `json:"slot"`
	BlockTime *int64 `json:"blockTime"`
	Meta      *struct {
		Err                  interface{} `json:"err"`
		Fee                  uint64      `json:"fee"`
		LogMessages          []string    `json:"logMessages"`
		ComputeUnitsConsumed *uint64     `json:"computeUnitsConsumed"`
	} `json:"meta"`
	Transaction struct {
		Message struct {
			AccountKeys []string `json:"accountKeys"`
		} `json:"message"`
	} `json:"transaction"`
}

// =============================================================================
// SOLANA CHAIN EXECUTION STRATEGY
// =============================================================================

// SolanaStrategy implements ChainExecutionStrategy for Solana
type SolanaStrategy struct {
	config     *SolanaStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewSolanaStrategy creates a new Solana chain execution strategy
func NewSolanaStrategy(config *SolanaStrategyConfig) (*SolanaStrategy, error) {
	if config == nil {
		config = DefaultSolanaStrategyConfig()
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 2 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}

	return &SolanaStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), "[SolanaStrategy] ", log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE IMPLEMENTATION
// =============================================================================

// Platform returns the chain platform identifier
func (s *SolanaStrategy) Platform() ChainPlatform {
	return ChainPlatformSolana
}

// ChainID returns the specific chain ID
func (s *SolanaStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "solana-mainnet"
}

// NetworkName returns the human-readable network name
func (s *SolanaStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return "solana"
}

// CreateAnchor creates an anchor transaction on Solana (Step 1)
// NOTE: Primary execution path is via BFT target chain integration.
func (s *SolanaStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("SolanaStrategy.CreateAnchor: use BFT target chain integration")
}

// SubmitProof submits proof for on-chain verification (Step 2)
func (s *SolanaStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("SolanaStrategy.SubmitProof: use BFT target chain integration")
}

// ExecuteWithGovernance executes with governance verification (Step 3)
func (s *SolanaStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("SolanaStrategy.ExecuteWithGovernance: use BFT target chain integration")
}

// ObserveTransaction watches a Solana transaction until finalization.
// Uses getTransaction with configurable commitment level.
// Solana finality: ~32 slots (~12.8s) for "finalized" commitment.
func (s *SolanaStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	s.logger.Printf("Observing Solana transaction %s...", txHash[:min(16, len(txHash))])

	if s.config.RPCURL == "" {
		return nil, fmt.Errorf("Solana RPC URL not configured")
	}

	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("observation timed out for tx %s", txHash[:min(16, len(txHash))])

		case <-ticker.C:
			result, err := s.getTransaction(timeoutCtx, txHash)
			if err != nil {
				s.logger.Printf("getTransaction failed (retrying): %v", err)
				continue
			}
			if result == nil {
				continue // Not found yet
			}

			// Check for transaction error
			status := uint8(1) // Success
			if result.Meta != nil && result.Meta.Err != nil {
				status = 2 // Failed
			}

			// Get current slot for confirmation count
			currentSlot, err := s.GetCurrentBlock(timeoutCtx)
			if err != nil {
				continue
			}

			confirmations := int(currentSlot - result.Slot)
			required := s.GetRequiredConfirmations()

			if confirmations >= required || s.config.Commitment == "finalized" {
				blockTime := time.Now()
				if result.BlockTime != nil {
					blockTime = time.Unix(*result.BlockTime, 0)
				}

				gasUsed := uint64(0)
				if result.Meta != nil {
					gasUsed = result.Meta.Fee
					if result.Meta.ComputeUnitsConsumed != nil {
						gasUsed = *result.Meta.ComputeUnitsConsumed
					}
				}

				// Fetch block hash for the slot
				blockHash, err := s.getBlockHash(timeoutCtx, result.Slot)
				if err != nil {
					s.logger.Printf("getBlockHash failed (non-fatal): %v", err)
				}

				// Extract fee payer (first account key)
				txFrom := ""
				if len(result.Transaction.Message.AccountKeys) > 0 {
					txFrom = result.Transaction.Message.AccountKeys[0]
				}

				s.logger.Printf("Transaction finalized at slot %d (%d confirmations)", result.Slot, confirmations)

				return &ObservationResult{
					TxHash:                txHash,
					BlockNumber:           result.Slot,
					BlockHash:             blockHash,
					BlockTimestamp:        blockTime,
					Status:                status,
					Confirmations:         confirmations,
					RequiredConfirmations: required,
					IsFinalized:           true,
					ResultHash:            s.computeResultHash(txHash, result.Slot),
					GasUsed:               gasUsed,
					ObservedAt:            time.Now().UTC(),
					ObserverValidatorID:   s.config.ValidatorID,
					TxFrom:                txFrom,
					ChainName:             s.NetworkName(),
				}, nil
			}

			s.logger.Printf("Waiting for confirmations: %d/%d (slot %d)", confirmations, required, result.Slot)
		}
	}
}

// ObserveTransactionAsync starts async observation with callbacks
func (s *SolanaStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
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
func (s *SolanaStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 32
}

// GetCurrentBlock returns the current slot number
func (s *SolanaStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	if s.config.RPCURL == "" {
		return 0, fmt.Errorf("Solana RPC URL not configured")
	}

	resp, err := s.rpcCall(ctx, "getSlot", []interface{}{
		map[string]string{"commitment": s.config.Commitment},
	})
	if err != nil {
		return 0, fmt.Errorf("getSlot: %w", err)
	}

	var slot uint64
	if err := json.Unmarshal(resp.Result, &slot); err != nil {
		return 0, fmt.Errorf("getSlot: unmarshal: %w", err)
	}

	return slot, nil
}

// GetTransactionReceipt retrieves a transaction without waiting for confirmations
func (s *SolanaStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	result, err := s.getTransaction(ctx, txHash)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("transaction %s not found", txHash[:min(16, len(txHash))])
	}

	status := uint8(1)
	if result.Meta != nil && result.Meta.Err != nil {
		status = 2
	}

	currentSlot, _ := s.GetCurrentBlock(ctx)
	confirmations := int(currentSlot - result.Slot)

	blockTime := time.Now()
	if result.BlockTime != nil {
		blockTime = time.Unix(*result.BlockTime, 0)
	}

	// Fetch block hash for the slot
	blockHash, err := s.getBlockHash(ctx, result.Slot)
	if err != nil {
		s.logger.Printf("getBlockHash failed (non-fatal): %v", err)
	}

	// Extract fee payer (first account key)
	txFrom := ""
	if len(result.Transaction.Message.AccountKeys) > 0 {
		txFrom = result.Transaction.Message.AccountKeys[0]
	}

	return &ObservationResult{
		TxHash:                txHash,
		BlockNumber:           result.Slot,
		BlockHash:             blockHash,
		BlockTimestamp:        blockTime,
		Status:                status,
		Confirmations:         confirmations,
		RequiredConfirmations: s.GetRequiredConfirmations(),
		IsFinalized:           confirmations >= s.GetRequiredConfirmations(),
		ResultHash:            s.computeResultHash(txHash, result.Slot),
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
		TxFrom:                txFrom,
		ChainName:             s.NetworkName(),
	}, nil
}

// EstimateGas estimates compute units for a transaction
func (s *SolanaStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	return 400000, nil
}

// HealthCheck verifies connectivity to Solana
func (s *SolanaStrategy) HealthCheck(ctx context.Context) error {
	if s.config.RPCURL == "" {
		return fmt.Errorf("Solana RPC URL not configured")
	}

	resp, err := s.rpcCall(ctx, "getHealth", nil)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	var health string
	if err := json.Unmarshal(resp.Result, &health); err != nil {
		// getHealth returns "ok" as a string
		return nil // If we got a response, the node is up
	}

	if health != "ok" {
		return fmt.Errorf("Solana node unhealthy: %s", health)
	}

	return nil
}

// Config returns the chain configuration
func (s *SolanaStrategy) Config() *ChainConfig {
	return s.config.ChainConfig
}

// =============================================================================
// SOLANA JSON-RPC HELPERS
// =============================================================================

func (s *SolanaStrategy) getTransaction(ctx context.Context, signature string) (*solanaTransactionResult, error) {
	resp, err := s.rpcCall(ctx, "getTransaction", []interface{}{
		signature,
		map[string]interface{}{
			"commitment":                     s.config.Commitment,
			"maxSupportedTransactionVersion": 0,
		},
	})
	if err != nil {
		return nil, err
	}

	// null result means tx not found
	if string(resp.Result) == "null" {
		return nil, nil
	}

	var result solanaTransactionResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal transaction: %w", err)
	}

	return &result, nil
}

func (s *SolanaStrategy) rpcCall(ctx context.Context, method string, params interface{}) (*solanaRPCResponse, error) {
	if params == nil {
		params = []interface{}{}
	}

	reqBody := solanaRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.RPCURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp solanaRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return &rpcResp, nil
}

// getBlockHash fetches the block hash for a given slot via getBlock RPC.
func (s *SolanaStrategy) getBlockHash(ctx context.Context, slot uint64) (string, error) {
	resp, err := s.rpcCall(ctx, "getBlock", []interface{}{
		slot,
		map[string]interface{}{
			"commitment":         s.config.Commitment,
			"transactionDetails": "none",
			"rewards":            false,
		},
	})
	if err != nil {
		return "", fmt.Errorf("getBlock(%d): %w", slot, err)
	}

	var block struct {
		Blockhash string `json:"blockhash"`
	}
	if err := json.Unmarshal(resp.Result, &block); err != nil {
		return "", fmt.Errorf("getBlock(%d): unmarshal: %w", slot, err)
	}

	return block.Blockhash, nil
}

func (s *SolanaStrategy) computeResultHash(txHash string, slot uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", slot)))
	h.Write([]byte("solana"))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

// NewSolanaMainnetStrategy creates a strategy for Solana mainnet
func NewSolanaMainnetStrategy(rpcURL, programID, validatorID string) (*SolanaStrategy, error) {
	config := &SolanaStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformSolana,
			ChainID:               "101",
			NetworkName:           "solana-mainnet",
			RPC:                   rpcURL,
			ContractAddress:       programID,
			RequiredConfirmations: 32,
			Enabled:               true,
		},
		RPCURL:          rpcURL,
		AnchorProgramID: programID,
		ValidatorID:     validatorID,
		Commitment:      "finalized",
		PollingInterval: 2 * time.Second,
		Timeout:         5 * time.Minute,
	}

	return NewSolanaStrategy(config)
}

// NewSolanaDevnetStrategy creates a strategy for Solana devnet
func NewSolanaDevnetStrategy(rpcURL, programID, validatorID string) (*SolanaStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	config := &SolanaStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformSolana,
			ChainID:               "103",
			NetworkName:           "solana-devnet",
			RPC:                   rpcURL,
			ContractAddress:       programID,
			RequiredConfirmations: 16,
			Enabled:               true,
		},
		RPCURL:          rpcURL,
		AnchorProgramID: programID,
		ValidatorID:     validatorID,
		Commitment:      "confirmed",
		PollingInterval: 2 * time.Second,
		Timeout:         5 * time.Minute,
	}

	return NewSolanaStrategy(config)
}
