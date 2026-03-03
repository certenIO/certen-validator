// Copyright 2025 Certen Protocol
//
// Move Chain Execution Strategy
// Implements ChainExecutionStrategy for Move-based chains (Aptos, Sui)
//
// Per Unified Multi-Chain Architecture:
// - Native Ed25519 signature support
// - Supports: Aptos (REST API), Sui (JSON-RPC)
// - Move smart contracts
//
// Observation uses:
//   - Aptos: REST API /transactions/by_hash/{hash}
//   - Sui: JSON-RPC sui_getTransactionBlock
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
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// MOVE STRATEGY CONFIGURATION
// =============================================================================

// MoveStrategyConfig holds configuration for the Move chain strategy
type MoveStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// RPC endpoint
	RPCURL string

	// Module/Package addresses
	AnchorModuleAddress string

	// Chain type (aptos or sui)
	MoveChainType string

	// Validator identity
	ValidatorID string

	// Observation config
	PollingInterval time.Duration
	Timeout         time.Duration
}

// DefaultMoveStrategyConfig returns default configuration
func DefaultMoveStrategyConfig() *MoveStrategyConfig {
	return &MoveStrategyConfig{
		PollingInterval: 2 * time.Second,
		Timeout:         3 * time.Minute,
	}
}

// =============================================================================
// APTOS REST API TYPES
// =============================================================================

type aptosTransaction struct {
	Type                string `json:"type"`
	Version             string `json:"version"`
	Hash                string `json:"hash"`
	Sender              string `json:"sender"`
	StateChangeHash     string `json:"state_change_hash"`
	EventRootHash       string `json:"event_root_hash"`
	StateCheckpointHash string `json:"state_checkpoint_hash"`
	GasUsed             string `json:"gas_used"`
	Success             bool   `json:"success"`
	VMStatus            string `json:"vm_status"`
	AccumulatorRootHash string `json:"accumulator_root_hash"`
	Timestamp           string `json:"timestamp"` // microseconds
}

type aptosLedgerInfo struct {
	ChainID             int    `json:"chain_id"`
	Epoch               string `json:"epoch"`
	LedgerVersion       string `json:"ledger_version"`
	OldestLedgerVersion string `json:"oldest_ledger_version"`
	LedgerTimestamp     string `json:"ledger_timestamp"`
	NodeRole            string `json:"node_role"`
	OldestBlockHeight   string `json:"oldest_block_height"`
	BlockHeight         string `json:"block_height"`
	GitHash             string `json:"git_hash"`
}

// =============================================================================
// SUI JSON-RPC TYPES
// =============================================================================

type suiRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type suiRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type suiTransactionBlock struct {
	Digest      string `json:"digest"`
	Transaction struct {
		Data struct {
			Sender  string `json:"sender"`
			GasData struct {
				Budget string `json:"budget"`
			} `json:"gasData"`
		} `json:"data"`
	} `json:"transaction"`
	Effects struct {
		Status struct {
			Status string `json:"status"`
		} `json:"status"`
		GasUsed struct {
			ComputationCost         string `json:"computationCost"`
			StorageCost             string `json:"storageCost"`
			StorageRebate           string `json:"storageRebate"`
			NonRefundableStorageFee string `json:"nonRefundableStorageFee"`
		} `json:"gasUsed"`
		TransactionDigest string `json:"transactionDigest"`
	} `json:"effects"`
	TimestampMs string `json:"timestampMs"`
	Checkpoint  string `json:"checkpoint"`
}

// =============================================================================
// MOVE CHAIN EXECUTION STRATEGY
// =============================================================================

// MoveStrategy implements ChainExecutionStrategy for Move chains
type MoveStrategy struct {
	config     *MoveStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewMoveStrategy creates a new Move chain execution strategy
func NewMoveStrategy(config *MoveStrategyConfig) (*MoveStrategy, error) {
	if config == nil {
		config = DefaultMoveStrategyConfig()
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 2 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Minute
	}

	return &MoveStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), fmt.Sprintf("[MoveStrategy-%s] ", config.MoveChainType), log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE
// =============================================================================

func (s *MoveStrategy) Platform() ChainPlatform { return ChainPlatformMove }

func (s *MoveStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "move"
}

func (s *MoveStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return s.config.MoveChainType
}

func (s *MoveStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("MoveStrategy.CreateAnchor: use BFT target chain integration")
}

func (s *MoveStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("MoveStrategy.SubmitProof: use BFT target chain integration")
}

func (s *MoveStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("MoveStrategy.ExecuteWithGovernance: use BFT target chain integration")
}

// ObserveTransaction watches a Move chain transaction until finalization.
// Routes to Aptos REST API or Sui JSON-RPC based on MoveChainType.
// Both Aptos and Sui have near-instant finality via BFT consensus.
func (s *MoveStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	s.logger.Printf("Observing transaction %s...", txHash[:min(16, len(txHash))])

	if s.config.RPCURL == "" {
		return nil, fmt.Errorf("Move RPC URL not configured")
	}

	switch strings.ToLower(s.config.MoveChainType) {
	case "aptos":
		return s.observeAptos(ctx, txHash)
	case "sui":
		return s.observeSui(ctx, txHash)
	default:
		return nil, fmt.Errorf("unknown Move chain type: %s", s.config.MoveChainType)
	}
}

func (s *MoveStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
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

func (s *MoveStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 1
}

// GetCurrentBlock returns current version (Aptos) or checkpoint (Sui)
func (s *MoveStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	if s.config.RPCURL == "" {
		return 0, fmt.Errorf("Move RPC URL not configured")
	}

	switch strings.ToLower(s.config.MoveChainType) {
	case "aptos":
		return s.aptosGetCurrentVersion(ctx)
	case "sui":
		return s.suiGetLatestCheckpoint(ctx)
	default:
		return 0, fmt.Errorf("unknown Move chain type: %s", s.config.MoveChainType)
	}
}

// GetTransactionReceipt retrieves transaction info
func (s *MoveStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	// For Move chains, observation and receipt are essentially the same
	// since both have instant finality
	return s.ObserveTransaction(ctx, txHash)
}

func (s *MoveStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	return 100000, nil
}

// HealthCheck verifies connectivity
func (s *MoveStrategy) HealthCheck(ctx context.Context) error {
	if s.config.RPCURL == "" {
		return fmt.Errorf("Move RPC URL not configured")
	}

	_, err := s.GetCurrentBlock(ctx)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

func (s *MoveStrategy) Config() *ChainConfig { return s.config.ChainConfig }

// =============================================================================
// APTOS OBSERVATION
// =============================================================================

func (s *MoveStrategy) observeAptos(ctx context.Context, txHash string) (*ObservationResult, error) {
	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("Aptos observation timed out for tx %s", txHash[:min(16, len(txHash))])

		case <-ticker.C:
			tx, err := s.aptosGetTransaction(timeoutCtx, txHash)
			if err != nil {
				s.logger.Printf("Aptos getTransaction failed (retrying): %v", err)
				continue
			}

			version, _ := strconv.ParseUint(tx.Version, 10, 64)
			gasUsed, _ := strconv.ParseUint(tx.GasUsed, 10, 64)
			timestamp, _ := strconv.ParseInt(tx.Timestamp, 10, 64)

			status := uint8(1)
			if !tx.Success {
				status = 2
			}

			// Aptos has instant finality via BFT — if we got the tx, it's final
			s.logger.Printf("Aptos transaction finalized at version %d, success=%v", version, tx.Success)

			return &ObservationResult{
				TxHash:                txHash,
				BlockNumber:           version,
				BlockHash:             tx.AccumulatorRootHash,
				BlockTimestamp:        time.Unix(timestamp/1_000_000, (timestamp%1_000_000)*1000),
				Status:                status,
				Confirmations:        1,
				RequiredConfirmations: 1,
				IsFinalized:           true,
				ResultHash:            s.computeResultHash(txHash, version, tx.StateChangeHash),
				GasUsed:               gasUsed,
				TxFrom:               tx.Sender,
				ObservedAt:            time.Now().UTC(),
				ObserverValidatorID:   s.config.ValidatorID,
			}, nil
		}
	}
}

func (s *MoveStrategy) aptosGetTransaction(ctx context.Context, txHash string) (*aptosTransaction, error) {
	url := strings.TrimSuffix(s.config.RPCURL, "/") + "/v1/transactions/by_hash/" + txHash

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("transaction not found")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var tx aptosTransaction
	if err := json.Unmarshal(body, &tx); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return &tx, nil
}

func (s *MoveStrategy) aptosGetCurrentVersion(ctx context.Context) (uint64, error) {
	url := strings.TrimSuffix(s.config.RPCURL, "/") + "/v1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var info aptosLedgerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return 0, err
	}

	version, err := strconv.ParseUint(info.LedgerVersion, 10, 64)
	if err != nil {
		return 0, err
	}

	return version, nil
}

// =============================================================================
// SUI OBSERVATION
// =============================================================================

func (s *MoveStrategy) observeSui(ctx context.Context, txHash string) (*ObservationResult, error) {
	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("Sui observation timed out for tx %s", txHash[:min(16, len(txHash))])

		case <-ticker.C:
			block, err := s.suiGetTransactionBlock(timeoutCtx, txHash)
			if err != nil {
				s.logger.Printf("Sui getTransactionBlock failed (retrying): %v", err)
				continue
			}

			checkpoint, _ := strconv.ParseUint(block.Checkpoint, 10, 64)
			timestampMs, _ := strconv.ParseInt(block.TimestampMs, 10, 64)

			status := uint8(1)
			if block.Effects.Status.Status != "success" {
				status = 2
			}

			// Calculate gas used from effects
			compute, _ := strconv.ParseUint(block.Effects.GasUsed.ComputationCost, 10, 64)
			storage, _ := strconv.ParseUint(block.Effects.GasUsed.StorageCost, 10, 64)
			gasUsed := compute + storage

			// Sui has instant finality via Narwhal/Bullshark consensus
			s.logger.Printf("Sui transaction finalized at checkpoint %d, status=%s", checkpoint, block.Effects.Status.Status)

			return &ObservationResult{
				TxHash:                txHash,
				BlockNumber:           checkpoint,
				BlockHash:             block.Digest,
				BlockTimestamp:        time.Unix(timestampMs/1000, (timestampMs%1000)*int64(time.Millisecond)),
				Status:                status,
				Confirmations:        1,
				RequiredConfirmations: 1,
				IsFinalized:           true,
				ResultHash:            s.computeResultHash(txHash, checkpoint, block.Digest),
				GasUsed:               gasUsed,
				TxFrom:               block.Transaction.Data.Sender,
				ObservedAt:            time.Now().UTC(),
				ObserverValidatorID:   s.config.ValidatorID,
			}, nil
		}
	}
}

func (s *MoveStrategy) suiGetTransactionBlock(ctx context.Context, digest string) (*suiTransactionBlock, error) {
	reqBody := suiRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sui_getTransactionBlock",
		Params: []interface{}{
			digest,
			map[string]bool{
				"showEffects":   true,
				"showInput":     true,
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.RPCURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp suiRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	var block suiTransactionBlock
	if err := json.Unmarshal(rpcResp.Result, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

func (s *MoveStrategy) suiGetLatestCheckpoint(ctx context.Context) (uint64, error) {
	reqBody := suiRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "sui_getLatestCheckpointSequenceNumber",
		Params:  []interface{}{},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.RPCURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var rpcResp suiRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return 0, err
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	var checkpoint string
	if err := json.Unmarshal(rpcResp.Result, &checkpoint); err != nil {
		return 0, err
	}

	return strconv.ParseUint(checkpoint, 10, 64)
}

func (s *MoveStrategy) computeResultHash(txHash string, blockNum uint64, extra string) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", blockNum)))
	h.Write([]byte(extra))
	h.Write([]byte(s.config.MoveChainType))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

func NewAptosMainnetStrategy(rpcURL, moduleAddress, validatorID string) (*MoveStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://fullnode.mainnet.aptoslabs.com"
	}
	// Strip /v1 suffix — observation methods append /v1/... paths themselves
	rpcURL = strings.TrimSuffix(rpcURL, "/v1")
	config := &MoveStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformMove,
			ChainID:               "1",
			NetworkName:           "aptos",
			RPC:                   rpcURL,
			ContractAddress:       moduleAddress,
			RequiredConfirmations: 1,
			Enabled:               true,
		},
		RPCURL:              rpcURL,
		AnchorModuleAddress: moduleAddress,
		MoveChainType:       "aptos",
		ValidatorID:         validatorID,
		PollingInterval:     2 * time.Second,
		Timeout:             3 * time.Minute,
	}
	return NewMoveStrategy(config)
}

func NewAptosTestnetStrategy(rpcURL, moduleAddress, validatorID string) (*MoveStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://fullnode.testnet.aptoslabs.com"
	}
	// Strip /v1 suffix — observation methods append /v1/... paths themselves
	rpcURL = strings.TrimSuffix(rpcURL, "/v1")
	config := &MoveStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformMove,
			ChainID:               "2",
			NetworkName:           "aptos-testnet",
			RPC:                   rpcURL,
			ContractAddress:       moduleAddress,
			RequiredConfirmations: 1,
			Enabled:               true,
		},
		RPCURL:              rpcURL,
		AnchorModuleAddress: moduleAddress,
		MoveChainType:       "aptos",
		ValidatorID:         validatorID,
		PollingInterval:     2 * time.Second,
		Timeout:             3 * time.Minute,
	}
	return NewMoveStrategy(config)
}

func NewSuiMainnetStrategy(rpcURL, packageID, validatorID string) (*MoveStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://fullnode.mainnet.sui.io:443"
	}
	config := &MoveStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformMove,
			ChainID:               "sui-mainnet",
			NetworkName:           "sui",
			RPC:                   rpcURL,
			ContractAddress:       packageID,
			RequiredConfirmations: 1,
			Enabled:               true,
		},
		RPCURL:              rpcURL,
		AnchorModuleAddress: packageID,
		MoveChainType:       "sui",
		ValidatorID:         validatorID,
		PollingInterval:     2 * time.Second,
		Timeout:             3 * time.Minute,
	}
	return NewMoveStrategy(config)
}

func NewSuiTestnetStrategy(rpcURL, packageID, validatorID string) (*MoveStrategy, error) {
	if rpcURL == "" {
		rpcURL = "https://fullnode.testnet.sui.io:443"
	}
	config := &MoveStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformMove,
			ChainID:               "sui-testnet",
			NetworkName:           "sui-testnet",
			RPC:                   rpcURL,
			ContractAddress:       packageID,
			RequiredConfirmations: 1,
			Enabled:               true,
		},
		RPCURL:              rpcURL,
		AnchorModuleAddress: packageID,
		MoveChainType:       "sui",
		ValidatorID:         validatorID,
		PollingInterval:     2 * time.Second,
		Timeout:             3 * time.Minute,
	}
	return NewMoveStrategy(config)
}
