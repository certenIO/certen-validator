// Copyright 2025 Certen Protocol
//
// CosmWasm Chain Execution Strategy
// Implements ChainExecutionStrategy for Cosmos SDK chains with CosmWasm
//
// Per Unified Multi-Chain Architecture:
// - Native Ed25519/Secp256k1 signature support
// - Tendermint/CometBFT consensus (~6s blocks)
// - CosmWasm smart contracts
// - Supports: Osmosis, Neutron, Injective, Juno
//
// Observation uses Cosmos REST API:
//   - /cosmos/tx/v1beta1/txs/{hash} for tx lookup
//   - /cosmos/base/tendermint/v1beta1/blocks/latest for block height
// Steps 1-3 are handled by BFT target chain integration.

package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// COSMWASM STRATEGY CONFIGURATION
// =============================================================================

// CosmWasmStrategyConfig holds configuration for the CosmWasm chain strategy
type CosmWasmStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// RPC endpoints
	RPCURL  string // REST API (LCD) endpoint
	GRPCURL string

	// Contract addresses
	AnchorContractAddress string

	// Chain-specific
	ChainPrefix string // e.g., "osmo", "neutron", "inj"
	Denom       string // e.g., "uosmo", "untrn"

	// Validator identity
	ValidatorID string

	// Observation config
	PollingInterval time.Duration
	Timeout         time.Duration
}

// DefaultCosmWasmStrategyConfig returns default configuration
func DefaultCosmWasmStrategyConfig() *CosmWasmStrategyConfig {
	return &CosmWasmStrategyConfig{
		PollingInterval: 3 * time.Second,
		Timeout:         3 * time.Minute,
	}
}

// =============================================================================
// COSMOS REST API TYPES
// =============================================================================

type cosmosTxResponse struct {
	Tx         interface{} `json:"tx"`
	TxResponse struct {
		Height    string `json:"height"`
		TxHash    string `json:"txhash"`
		Code      int    `json:"code"`
		RawLog    string `json:"raw_log"`
		GasWanted string `json:"gas_wanted"`
		GasUsed   string `json:"gas_used"`
		Timestamp string `json:"timestamp"`
	} `json:"tx_response"`
}

type cosmosBlockResponse struct {
	Block struct {
		Header struct {
			Height  string `json:"height"`
			Time    string `json:"time"`
			ChainID string `json:"chain_id"`
		} `json:"header"`
	} `json:"block"`
}

type cosmosNodeInfoResponse struct {
	DefaultNodeInfo struct {
		Network string `json:"network"`
		Version string `json:"version"`
	} `json:"default_node_info"`
	ApplicationVersion struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"application_version"`
}

// =============================================================================
// COSMWASM CHAIN EXECUTION STRATEGY
// =============================================================================

// CosmWasmStrategy implements ChainExecutionStrategy for CosmWasm chains
type CosmWasmStrategy struct {
	config     *CosmWasmStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewCosmWasmStrategy creates a new CosmWasm chain execution strategy
func NewCosmWasmStrategy(config *CosmWasmStrategyConfig) (*CosmWasmStrategy, error) {
	if config == nil {
		config = DefaultCosmWasmStrategyConfig()
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 3 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Minute
	}

	return &CosmWasmStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), fmt.Sprintf("[CosmWasm-%s] ", config.ChainPrefix), log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE
// =============================================================================

func (s *CosmWasmStrategy) Platform() ChainPlatform { return ChainPlatformCosmWasm }

func (s *CosmWasmStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "cosmwasm"
}

func (s *CosmWasmStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return "cosmwasm"
}

func (s *CosmWasmStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("CosmWasmStrategy.CreateAnchor: use BFT target chain integration")
}

func (s *CosmWasmStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("CosmWasmStrategy.SubmitProof: use BFT target chain integration")
}

func (s *CosmWasmStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("CosmWasmStrategy.ExecuteWithGovernance: use BFT target chain integration")
}

// ObserveTransaction watches a Cosmos transaction until finalization.
// Tendermint/CometBFT has instant finality once a block is committed,
// but we wait for RequiredConfirmations blocks for safety.
func (s *CosmWasmStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	s.logger.Printf("Observing transaction %s...", txHash[:min(16, len(txHash))])

	if s.config.RPCURL == "" {
		return nil, fmt.Errorf("Cosmos RPC URL not configured")
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
			txResp, err := s.getTx(timeoutCtx, txHash)
			if err != nil {
				s.logger.Printf("getTx failed (retrying): %v", err)
				continue
			}

			txHeight, _ := strconv.ParseUint(txResp.TxResponse.Height, 10, 64)
			gasUsed, _ := strconv.ParseUint(txResp.TxResponse.GasUsed, 10, 64)

			status := uint8(1) // Success
			if txResp.TxResponse.Code != 0 {
				status = 2 // Failed
			}

			// Get current block height for confirmation count
			currentHeight, err := s.GetCurrentBlock(timeoutCtx)
			if err != nil {
				continue
			}

			confirmations := int(currentHeight - txHeight)
			if confirmations < 0 {
				confirmations = 0
			}
			required := s.GetRequiredConfirmations()

			txTime, _ := time.Parse(time.RFC3339Nano, txResp.TxResponse.Timestamp)

			if confirmations >= required {
				s.logger.Printf("Transaction finalized at height %d (%d confirmations)", txHeight, confirmations)

				return &ObservationResult{
					TxHash:                txHash,
					BlockNumber:           txHeight,
					BlockHash:             "", // Would need separate block query
					BlockTimestamp:        txTime,
					Status:                status,
					Confirmations:        confirmations,
					RequiredConfirmations: required,
					IsFinalized:           true,
					ResultHash:            s.computeResultHash(txHash, txHeight),
					GasUsed:               gasUsed,
					ObservedAt:            time.Now().UTC(),
					ObserverValidatorID:   s.config.ValidatorID,
				}, nil
			}

			s.logger.Printf("Waiting for confirmations: %d/%d (height %d)", confirmations, required, txHeight)
		}
	}
}

func (s *CosmWasmStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
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

func (s *CosmWasmStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 2
}

// GetCurrentBlock returns the latest block height via Cosmos REST API
func (s *CosmWasmStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	if s.config.RPCURL == "" {
		return 0, fmt.Errorf("Cosmos RPC URL not configured")
	}

	url := strings.TrimSuffix(s.config.RPCURL, "/") + "/cosmos/base/tendermint/v1beta1/blocks/latest"

	body, err := s.restGet(ctx, url)
	if err != nil {
		return 0, fmt.Errorf("GetCurrentBlock: %w", err)
	}

	var block cosmosBlockResponse
	if err := json.Unmarshal(body, &block); err != nil {
		return 0, fmt.Errorf("unmarshal block: %w", err)
	}

	height, err := strconv.ParseUint(block.Block.Header.Height, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse height: %w", err)
	}

	return height, nil
}

// GetTransactionReceipt retrieves transaction info without waiting
func (s *CosmWasmStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	txResp, err := s.getTx(ctx, txHash)
	if err != nil {
		return nil, err
	}

	txHeight, _ := strconv.ParseUint(txResp.TxResponse.Height, 10, 64)
	gasUsed, _ := strconv.ParseUint(txResp.TxResponse.GasUsed, 10, 64)
	txTime, _ := time.Parse(time.RFC3339Nano, txResp.TxResponse.Timestamp)

	status := uint8(1)
	if txResp.TxResponse.Code != 0 {
		status = 2
	}

	currentHeight, _ := s.GetCurrentBlock(ctx)
	confirmations := int(currentHeight - txHeight)

	return &ObservationResult{
		TxHash:                txHash,
		BlockNumber:           txHeight,
		BlockTimestamp:        txTime,
		Status:                status,
		Confirmations:        confirmations,
		RequiredConfirmations: s.GetRequiredConfirmations(),
		IsFinalized:           confirmations >= s.GetRequiredConfirmations(),
		ResultHash:            s.computeResultHash(txHash, txHeight),
		GasUsed:               gasUsed,
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
	}, nil
}

func (s *CosmWasmStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	return 500000, nil
}

// HealthCheck verifies connectivity to the Cosmos chain
func (s *CosmWasmStrategy) HealthCheck(ctx context.Context) error {
	if s.config.RPCURL == "" {
		return fmt.Errorf("Cosmos RPC URL not configured")
	}

	url := strings.TrimSuffix(s.config.RPCURL, "/") + "/cosmos/base/tendermint/v1beta1/node_info"

	body, err := s.restGet(ctx, url)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	var info cosmosNodeInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("health check: unmarshal: %w", err)
	}

	s.logger.Printf("Health check OK: network=%s, version=%s",
		info.DefaultNodeInfo.Network, info.ApplicationVersion.Version)
	return nil
}

func (s *CosmWasmStrategy) Config() *ChainConfig { return s.config.ChainConfig }

// =============================================================================
// COSMOS REST API HELPERS
// =============================================================================

func (s *CosmWasmStrategy) getTx(ctx context.Context, txHash string) (*cosmosTxResponse, error) {
	// Cosmos REST API expects uppercase hex hash
	hash := strings.ToUpper(txHash)
	url := strings.TrimSuffix(s.config.RPCURL, "/") + "/cosmos/tx/v1beta1/txs/" + hash

	body, err := s.restGet(ctx, url)
	if err != nil {
		return nil, err
	}

	var txResp cosmosTxResponse
	if err := json.Unmarshal(body, &txResp); err != nil {
		return nil, fmt.Errorf("unmarshal tx: %w", err)
	}

	if txResp.TxResponse.TxHash == "" {
		return nil, fmt.Errorf("transaction not found")
	}

	return &txResp, nil
}

func (s *CosmWasmStrategy) restGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	return body, nil
}

func (s *CosmWasmStrategy) computeResultHash(txHash string, height uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", height)))
	h.Write([]byte(s.config.ChainPrefix))
	h.Write([]byte("cosmos"))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

func NewOsmosisStrategy(rpcURL, contractAddress, validatorID string) (*CosmWasmStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://lcd.osmosis.zone"
	}
	config := &CosmWasmStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformCosmWasm,
			ChainID:               "osmosis-1",
			NetworkName:           "osmosis",
			RPC:                   rpcURL,
			ContractAddress:       contractAddress,
			RequiredConfirmations: 2,
			Enabled:               true,
		},
		RPCURL:                rpcURL,
		AnchorContractAddress: contractAddress,
		ChainPrefix:           "osmo",
		Denom:                 "uosmo",
		ValidatorID:           validatorID,
		PollingInterval:       3 * time.Second,
		Timeout:               3 * time.Minute,
	}
	return NewCosmWasmStrategy(config)
}

func NewNeutronStrategy(rpcURL, contractAddress, validatorID string) (*CosmWasmStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://rest-falcron.pion-1.ntrn.tech"
	}
	config := &CosmWasmStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformCosmWasm,
			ChainID:               "neutron-1",
			NetworkName:           "neutron",
			RPC:                   rpcURL,
			ContractAddress:       contractAddress,
			RequiredConfirmations: 2,
			Enabled:               true,
		},
		RPCURL:                rpcURL,
		AnchorContractAddress: contractAddress,
		ChainPrefix:           "neutron",
		Denom:                 "untrn",
		ValidatorID:           validatorID,
		PollingInterval:       3 * time.Second,
		Timeout:               3 * time.Minute,
	}
	return NewCosmWasmStrategy(config)
}

func NewInjectiveStrategy(rpcURL, contractAddress, validatorID string) (*CosmWasmStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://lcd.injective.network"
	}
	config := &CosmWasmStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformCosmWasm,
			ChainID:               "injective-1",
			NetworkName:           "injective",
			RPC:                   rpcURL,
			ContractAddress:       contractAddress,
			RequiredConfirmations: 2,
			Enabled:               true,
		},
		RPCURL:                rpcURL,
		AnchorContractAddress: contractAddress,
		ChainPrefix:           "inj",
		Denom:                 "inj",
		ValidatorID:           validatorID,
		PollingInterval:       3 * time.Second,
		Timeout:               3 * time.Minute,
	}
	return NewCosmWasmStrategy(config)
}
