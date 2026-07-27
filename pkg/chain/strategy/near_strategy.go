// Copyright 2025 Certen Protocol
//
// NEAR Chain Execution Strategy
// Implements ChainExecutionStrategy for NEAR Protocol
//
// Per Unified Multi-Chain Architecture:
// - Native Ed25519 signature support
// - ~1 second blocks with Nightshade sharding
// - Rust/AssemblyScript smart contracts
//
// Observation uses NEAR JSON-RPC API (tx, status, block).
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
// NEAR STRATEGY CONFIGURATION
// =============================================================================

// NEARStrategyConfig holds configuration for the NEAR chain strategy
type NEARStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// RPC endpoint
	RPCURL string

	// Contract account
	AnchorContractAccount string

	// Signer account
	SignerAccount string

	// Validator identity
	ValidatorID string

	// Observation config
	PollingInterval time.Duration
	Timeout         time.Duration
}

// DefaultNEARStrategyConfig returns default configuration
func DefaultNEARStrategyConfig() *NEARStrategyConfig {
	return &NEARStrategyConfig{
		PollingInterval: 2 * time.Second,
		Timeout:         3 * time.Minute,
	}
}

// =============================================================================
// NEAR JSON-RPC TYPES
// =============================================================================

type nearRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type nearRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Name  string `json:"name"`
		Cause struct {
			Name string      `json:"name"`
			Info interface{} `json:"info"`
		} `json:"cause"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type nearTxResult struct {
	Status      interface{} `json:"status"`
	Transaction struct {
		SignerID string `json:"signer_id"`
	} `json:"transaction"`
	TransactionOutcome struct {
		BlockHash string `json:"block_hash"`
		ID        string `json:"id"`
		Outcome   struct {
			GasBurnt uint64      `json:"gas_burnt"`
			Status   interface{} `json:"status"`
			Logs     []string    `json:"logs"`
		} `json:"outcome"`
	} `json:"transaction_outcome"`
	ReceiptsOutcome []struct {
		BlockHash string `json:"block_hash"`
		Outcome   struct {
			GasBurnt uint64 `json:"gas_burnt"`
		} `json:"outcome"`
	} `json:"receipts_outcome"`
}

type nearBlockResult struct {
	Header struct {
		Height    uint64 `json:"height"`
		Hash      string `json:"hash"`
		Timestamp uint64 `json:"timestamp"` // nanoseconds
	} `json:"header"`
}

type nearStatusResult struct {
	SyncInfo struct {
		LatestBlockHeight uint64 `json:"latest_block_height"`
		LatestBlockHash   string `json:"latest_block_hash"`
		LatestBlockTime   string `json:"latest_block_time"`
		Syncing           bool   `json:"syncing"`
	} `json:"sync_info"`
}

// =============================================================================
// NEAR CHAIN EXECUTION STRATEGY
// =============================================================================

// NEARStrategy implements ChainExecutionStrategy for NEAR
type NEARStrategy struct {
	config     *NEARStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewNEARStrategy creates a new NEAR chain execution strategy
func NewNEARStrategy(config *NEARStrategyConfig) (*NEARStrategy, error) {
	if config == nil {
		config = DefaultNEARStrategyConfig()
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 2 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Minute
	}

	return &NEARStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), "[NEARStrategy] ", log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE
// =============================================================================

func (s *NEARStrategy) Platform() ChainPlatform { return ChainPlatformNEAR }

func (s *NEARStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "near-mainnet"
}

func (s *NEARStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return "near"
}

func (s *NEARStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("NEARStrategy.CreateAnchor: use BFT target chain integration")
}

func (s *NEARStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("NEARStrategy.SubmitProof: use BFT target chain integration")
}

func (s *NEARStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("NEARStrategy.ExecuteWithGovernance: use BFT target chain integration")
}

// ObserveTransaction watches a NEAR transaction until finalization.
// NEAR has near-instant finality (~1-2 blocks). The tx method returns
// the final execution outcome once the transaction is included.
func (s *NEARStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	s.logger.Printf("Observing NEAR transaction %s...", txHash[:min(16, len(txHash))])

	if s.config.RPCURL == "" {
		return nil, fmt.Errorf("NEAR RPC URL not configured")
	}

	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// NEAR tx method needs sender_id. Try the anchor contract as sender.
	senderID := s.config.AnchorContractAccount
	if senderID == "" {
		senderID = s.config.SignerAccount
	}

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("observation timed out for tx %s", txHash[:min(16, len(txHash))])

		case <-ticker.C:
			txResult, err := s.getTx(timeoutCtx, txHash, senderID)
			if err != nil {
				s.logger.Printf("tx query failed (retrying): %v", err)
				continue
			}

			// Get current block height
			currentHeight, err := s.GetCurrentBlock(timeoutCtx)
			if err != nil {
				continue
			}

			// Extract block hash from transaction outcome to get the block height
			blockHash := txResult.TransactionOutcome.BlockHash
			txBlockHeight, _ := s.getBlockHeight(timeoutCtx, blockHash)

			confirmations := int(currentHeight - txBlockHeight)
			if confirmations < 0 {
				confirmations = 0
			}
			required := s.GetRequiredConfirmations()

			// Determine success/failure from status
			status := uint8(1) // Success
			if statusMap, ok := txResult.Status.(map[string]interface{}); ok {
				if _, hasFailure := statusMap["Failure"]; hasFailure {
					status = 2
				}
			}

			// Calculate total gas used
			gasUsed := txResult.TransactionOutcome.Outcome.GasBurnt
			for _, receipt := range txResult.ReceiptsOutcome {
				gasUsed += receipt.Outcome.GasBurnt
			}

			if confirmations >= required {
				s.logger.Printf("Transaction finalized at height %d (%d confirmations)", txBlockHeight, confirmations)

				return &ObservationResult{
					TxHash:                txHash,
					BlockNumber:           txBlockHeight,
					BlockHash:             blockHash,
					BlockTimestamp:        time.Now(), // NEAR block timestamp requires additional query
					Status:                status,
					Confirmations:         confirmations,
					RequiredConfirmations: required,
					IsFinalized:           true,
					ResultHash:            s.computeResultHash(txHash, txBlockHeight, blockHash),
					GasUsed:               gasUsed,
					ObservedAt:            time.Now().UTC(),
					ObserverValidatorID:   s.config.ValidatorID,
					TxFrom:                txResult.Transaction.SignerID,
					ChainName:             s.NetworkName(),
				}, nil
			}

			s.logger.Printf("Waiting for confirmations: %d/%d (height %d)", confirmations, required, txBlockHeight)
		}
	}
}

func (s *NEARStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
	onFinalized func(*ObservationResult), onFailed func(error)) error {
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

func (s *NEARStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 3
}

// GetCurrentBlock returns the current block height via status RPC
func (s *NEARStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	if s.config.RPCURL == "" {
		return 0, fmt.Errorf("NEAR RPC URL not configured")
	}

	resp, err := s.rpcCall(ctx, "status", []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("status: %w", err)
	}

	var status nearStatusResult
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return 0, fmt.Errorf("unmarshal status: %w", err)
	}

	return status.SyncInfo.LatestBlockHeight, nil
}

// GetTransactionReceipt retrieves transaction info without waiting
func (s *NEARStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	senderID := s.config.AnchorContractAccount
	if senderID == "" {
		senderID = s.config.SignerAccount
	}

	txResult, err := s.getTx(ctx, txHash, senderID)
	if err != nil {
		return nil, err
	}

	currentHeight, _ := s.GetCurrentBlock(ctx)
	blockHash := txResult.TransactionOutcome.BlockHash
	txBlockHeight, _ := s.getBlockHeight(ctx, blockHash)
	confirmations := int(currentHeight - txBlockHeight)

	status := uint8(1)
	if statusMap, ok := txResult.Status.(map[string]interface{}); ok {
		if _, hasFailure := statusMap["Failure"]; hasFailure {
			status = 2
		}
	}

	return &ObservationResult{
		TxHash:                txHash,
		BlockNumber:           txBlockHeight,
		BlockHash:             blockHash,
		Status:                status,
		Confirmations:         confirmations,
		RequiredConfirmations: s.GetRequiredConfirmations(),
		IsFinalized:           confirmations >= s.GetRequiredConfirmations(),
		ResultHash:            s.computeResultHash(txHash, txBlockHeight, blockHash),
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
		TxFrom:                txResult.Transaction.SignerID,
		ChainName:             s.NetworkName(),
	}, nil
}

func (s *NEARStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	return 100000000000000, nil // 100 TGas
}

// HealthCheck verifies connectivity to NEAR
func (s *NEARStrategy) HealthCheck(ctx context.Context) error {
	if s.config.RPCURL == "" {
		return fmt.Errorf("NEAR RPC URL not configured")
	}

	resp, err := s.rpcCall(ctx, "status", []interface{}{})
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	var status nearStatusResult
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return fmt.Errorf("health check: unmarshal: %w", err)
	}

	if status.SyncInfo.Syncing {
		return fmt.Errorf("NEAR node is syncing")
	}

	s.logger.Printf("Health check OK: height=%d", status.SyncInfo.LatestBlockHeight)
	return nil
}

func (s *NEARStrategy) Config() *ChainConfig { return s.config.ChainConfig }

// =============================================================================
// NEAR JSON-RPC HELPERS
// =============================================================================

func (s *NEARStrategy) getTx(ctx context.Context, txHash, senderID string) (*nearTxResult, error) {
	// NEAR tx method: params = [tx_hash, sender_account_id]
	params := []interface{}{txHash, senderID}

	// Use EXPERIMENTAL_tx_status for detailed outcome
	resp, err := s.rpcCall(ctx, "EXPERIMENTAL_tx_status", params)
	if err != nil {
		// Fall back to basic tx method
		resp, err = s.rpcCall(ctx, "tx", params)
		if err != nil {
			return nil, err
		}
	}

	var result nearTxResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal tx: %w", err)
	}

	return &result, nil
}

func (s *NEARStrategy) getBlockHeight(ctx context.Context, blockHash string) (uint64, error) {
	resp, err := s.rpcCall(ctx, "block", map[string]interface{}{
		"block_id": blockHash,
	})
	if err != nil {
		return 0, err
	}

	var block nearBlockResult
	if err := json.Unmarshal(resp.Result, &block); err != nil {
		return 0, err
	}

	return block.Header.Height, nil
}

func (s *NEARStrategy) rpcCall(ctx context.Context, method string, params interface{}) (*nearRPCResponse, error) {
	reqBody := nearRPCRequest{
		JSONRPC: "2.0",
		ID:      "certen",
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

	var rpcResp nearRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s (code %d)", rpcResp.Error.Message, rpcResp.Error.Code)
	}

	return &rpcResp, nil
}

func (s *NEARStrategy) computeResultHash(txHash string, height uint64, blockHash string) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", height)))
	h.Write([]byte(blockHash))
	h.Write([]byte("near"))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

func NewNEARMainnetStrategy(rpcURL, contractAccount, signerAccount, validatorID string) (*NEARStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://rpc.mainnet.near.org"
	}
	config := &NEARStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformNEAR,
			ChainID:               "397",
			NetworkName:           "near-mainnet",
			RPC:                   rpcURL,
			ContractAddress:       contractAccount,
			RequiredConfirmations: 3,
			Enabled:               true,
		},
		RPCURL:                rpcURL,
		AnchorContractAccount: contractAccount,
		SignerAccount:         signerAccount,
		ValidatorID:           validatorID,
		PollingInterval:       2 * time.Second,
		Timeout:               3 * time.Minute,
	}
	return NewNEARStrategy(config)
}

func NewNEARTestnetStrategy(rpcURL, contractAccount, signerAccount, validatorID string) (*NEARStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://test.rpc.fastnear.com"
	}
	config := &NEARStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformNEAR,
			ChainID:               "398",
			NetworkName:           "near-testnet",
			RPC:                   rpcURL,
			ContractAddress:       contractAccount,
			RequiredConfirmations: 2,
			Enabled:               true,
		},
		RPCURL:                rpcURL,
		AnchorContractAccount: contractAccount,
		SignerAccount:         signerAccount,
		ValidatorID:           validatorID,
		PollingInterval:       2 * time.Second,
		Timeout:               3 * time.Minute,
	}
	return NewNEARStrategy(config)
}
