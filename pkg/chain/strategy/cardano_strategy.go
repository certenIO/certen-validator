// Copyright 2025 Certen Protocol
//
// Cardano Chain Execution Strategy
// Implements ChainExecutionStrategy for Cardano (Plutus V3 / Aiken).
//
// Per Unified Multi-Chain Architecture:
// - BLS12-381 ZK attestation verified on-chain (Groth16 + BSB22), at parity
//   with EVM/NEAR — the A+++ messageHash-bound proof.
// - UTXO model: anchors/accounts are script-locked UTXOs with inline datums.
//
// Observation uses the Blockfrost HTTP API (/txs/{hash}, /blocks/latest).
// Steps 1-3 (create anchor / submit proof / governance) are handled by the
// BFT target chain integration via the Lucid+Blockfrost tx-server bridge.

package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// =============================================================================
// CARDANO STRATEGY CONFIGURATION
// =============================================================================

// CardanoStrategyConfig holds configuration for the Cardano chain strategy.
type CardanoStrategyConfig struct {
	ChainConfig *ChainConfig

	// Blockfrost project ID + API base URL (network-specific).
	BlockfrostProjectID string
	BlockfrostBaseURL   string

	// Anchor script address (informational; observation is by tx hash).
	AnchorAddress string

	ValidatorID string

	PollingInterval time.Duration
	Timeout         time.Duration
}

// =============================================================================
// BLOCKFROST RESPONSE TYPES
// =============================================================================

type blockfrostTx struct {
	Hash        string `json:"hash"`
	Block       string `json:"block"`
	BlockHeight uint64 `json:"block_height"`
	BlockTime   int64  `json:"block_time"` // POSIX seconds
	Slot        uint64 `json:"slot"`
	Index       int    `json:"index"`
	Fees        string `json:"fees"`
	ValidContract bool `json:"valid_contract"`
}

type blockfrostBlockLatest struct {
	Height uint64 `json:"height"`
	Hash   string `json:"hash"`
	Time   int64  `json:"time"`
	Slot   uint64 `json:"slot"`
}

// =============================================================================
// CARDANO CHAIN EXECUTION STRATEGY
// =============================================================================

// CardanoStrategy implements ChainExecutionStrategy for Cardano.
type CardanoStrategy struct {
	config     *CardanoStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewCardanoStrategy creates a new Cardano chain execution strategy.
func NewCardanoStrategy(config *CardanoStrategyConfig) (*CardanoStrategy, error) {
	if config == nil {
		return nil, fmt.Errorf("cardano strategy config required")
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 5 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}
	return &CardanoStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), "[CardanoStrategy] ", log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE
// =============================================================================

func (s *CardanoStrategy) Platform() ChainPlatform { return ChainPlatformCardano }

func (s *CardanoStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "cardano-preview"
}

func (s *CardanoStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return "cardano-preview"
}

func (s *CardanoStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("CardanoStrategy.CreateAnchor: use BFT target chain integration")
}

func (s *CardanoStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("CardanoStrategy.SubmitProof: use BFT target chain integration")
}

func (s *CardanoStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("CardanoStrategy.ExecuteWithGovernance: use BFT target chain integration")
}

// ObserveTransaction watches a Cardano transaction until it has enough
// confirmations. Cardano tx hashes are 32-byte (64 hex). Workflow steps that
// were intentionally skipped (e.g. governance when no account UTXO is wired)
// arrive as non-hash placeholder strings ("no_governance_needed",
// "gov_skipped_…", "*_failed_*"); these are returned as a synthetic finalized
// result so the writeback can still record the real create/verify txs.
func (s *CardanoStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	if !isObservableCardanoTxHash(txHash) {
		s.logger.Printf("Skipping non-hash workflow step %q (treated as finalized)", txHash)
		return s.syntheticFinalized(txHash), nil
	}

	s.logger.Printf("Observing Cardano transaction %s...", txHash[:min(16, len(txHash))])

	if s.config.BlockfrostProjectID == "" {
		return nil, fmt.Errorf("Blockfrost project ID not configured")
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
			tx, err := s.getTx(timeoutCtx, txHash)
			if err != nil {
				s.logger.Printf("tx query failed (retrying): %v", err)
				continue
			}

			currentHeight, err := s.GetCurrentBlock(timeoutCtx)
			if err != nil {
				continue
			}

			confirmations := int(currentHeight - tx.BlockHeight)
			if confirmations < 0 {
				confirmations = 0
			}
			required := s.GetRequiredConfirmations()

			// On Cardano, a tx that includes a Plutus script spend only lands
			// in a block if the script validated. valid_contract == false would
			// mean a phase-2 failure (collateral consumed). Map to status.
			status := uint8(1)
			if !tx.ValidContract {
				status = 2
			}

			if confirmations >= required {
				s.logger.Printf("Transaction finalized at height %d (%d confirmations)", tx.BlockHeight, confirmations)
				return &ObservationResult{
					TxHash:                txHash,
					BlockNumber:           tx.BlockHeight,
					BlockHash:             tx.Block,
					BlockTimestamp:        time.Unix(tx.BlockTime, 0).UTC(),
					Status:                status,
					Confirmations:         confirmations,
					RequiredConfirmations: required,
					IsFinalized:           true,
					ResultHash:            s.computeResultHash(txHash, tx.BlockHeight, tx.Block),
					ObservedAt:            time.Now().UTC(),
					ObserverValidatorID:   s.config.ValidatorID,
					ChainName:             s.NetworkName(),
				}, nil
			}

			s.logger.Printf("Waiting for confirmations: %d/%d (height %d)", confirmations, required, tx.BlockHeight)
		}
	}
}

func (s *CardanoStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
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

func (s *CardanoStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	return 1
}

// GetCurrentBlock returns the current chain tip height via /blocks/latest.
func (s *CardanoStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	if s.config.BlockfrostProjectID == "" {
		return 0, fmt.Errorf("Blockfrost project ID not configured")
	}

	body, err := s.get(ctx, "/blocks/latest")
	if err != nil {
		return 0, fmt.Errorf("blocks/latest: %w", err)
	}

	var blk blockfrostBlockLatest
	if err := json.Unmarshal(body, &blk); err != nil {
		return 0, fmt.Errorf("unmarshal block: %w", err)
	}
	return blk.Height, nil
}

func (s *CardanoStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	if !isObservableCardanoTxHash(txHash) {
		return s.syntheticFinalized(txHash), nil
	}

	tx, err := s.getTx(ctx, txHash)
	if err != nil {
		return nil, err
	}
	currentHeight, _ := s.GetCurrentBlock(ctx)
	confirmations := int(currentHeight - tx.BlockHeight)
	if confirmations < 0 {
		confirmations = 0
	}
	status := uint8(1)
	if !tx.ValidContract {
		status = 2
	}
	return &ObservationResult{
		TxHash:                txHash,
		BlockNumber:           tx.BlockHeight,
		BlockHash:             tx.Block,
		BlockTimestamp:        time.Unix(tx.BlockTime, 0).UTC(),
		Status:                status,
		Confirmations:         confirmations,
		RequiredConfirmations: s.GetRequiredConfirmations(),
		IsFinalized:           confirmations >= s.GetRequiredConfirmations(),
		ResultHash:            s.computeResultHash(txHash, tx.BlockHeight, tx.Block),
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
		ChainName:             s.NetworkName(),
	}, nil
}

func (s *CardanoStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	// Cardano fees are computed by the tx-server at build time; return a
	// representative ex-unit/fee figure.
	return 1_000_000, nil // ~1 ADA in lovelace, indicative
}

// HealthCheck verifies connectivity to Blockfrost.
func (s *CardanoStrategy) HealthCheck(ctx context.Context) error {
	if s.config.BlockfrostProjectID == "" {
		return fmt.Errorf("Blockfrost project ID not configured")
	}
	height, err := s.GetCurrentBlock(ctx)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	s.logger.Printf("Health check OK: tip height=%d", height)
	return nil
}

func (s *CardanoStrategy) Config() *ChainConfig { return s.config.ChainConfig }

// =============================================================================
// BLOCKFROST HELPERS
// =============================================================================

func (s *CardanoStrategy) getTx(ctx context.Context, txHash string) (*blockfrostTx, error) {
	body, err := s.get(ctx, "/txs/"+txHash)
	if err != nil {
		return nil, err
	}
	var tx blockfrostTx
	if err := json.Unmarshal(body, &tx); err != nil {
		return nil, fmt.Errorf("unmarshal tx: %w", err)
	}
	if tx.Hash == "" {
		return nil, fmt.Errorf("tx not found / not yet indexed")
	}
	return &tx, nil
}

func (s *CardanoStrategy) get(ctx context.Context, path string) ([]byte, error) {
	url := strings.TrimRight(s.config.BlockfrostBaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("project_id", s.config.BlockfrostProjectID)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (404): %s", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("blockfrost status %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (s *CardanoStrategy) computeResultHash(txHash string, height uint64, blockHash string) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", height)))
	h.Write([]byte(blockHash))
	h.Write([]byte("cardano"))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// syntheticFinalized returns a finalized observation for a skipped workflow
// step (governance not executed). Carries the placeholder string as TxHash so
// the writeback records what happened without failing the cycle.
func (s *CardanoStrategy) syntheticFinalized(label string) *ObservationResult {
	return &ObservationResult{
		TxHash:                label,
		Status:                1,
		Confirmations:         s.GetRequiredConfirmations(),
		RequiredConfirmations: s.GetRequiredConfirmations(),
		IsFinalized:           true,
		ResultHash:            s.computeResultHash(label, 0, ""),
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
		ChainName:             s.NetworkName(),
	}
}

// isObservableCardanoTxHash reports whether s is a real Cardano tx hash
// (32 bytes / 64 lowercase-or-upper hex chars) rather than a placeholder.
func isObservableCardanoTxHash(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

// blockfrostBaseURLForNetwork returns the Blockfrost API base URL for a
// Cardano network name ("Preview"/"Preprod"/"Mainnet", case-insensitive).
func blockfrostBaseURLForNetwork(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "preprod":
		return "https://cardano-preprod.blockfrost.io/api/v0"
	case "mainnet":
		return "https://cardano-mainnet.blockfrost.io/api/v0"
	default: // preview
		return "https://cardano-preview.blockfrost.io/api/v0"
	}
}

// NewCardanoPreviewStrategy builds a Cardano Preview strategy from a Blockfrost
// project ID and the deployed anchor script address.
func NewCardanoPreviewStrategy(blockfrostProjectID, anchorAddress, validatorID string) (*CardanoStrategy, error) {
	return newCardanoStrategyForNetwork("Preview", "cardano-preview", blockfrostProjectID, anchorAddress, validatorID)
}

func newCardanoStrategyForNetwork(network, chainID, blockfrostProjectID, anchorAddress, validatorID string) (*CardanoStrategy, error) {
	baseURL := blockfrostBaseURLForNetwork(network)
	config := &CardanoStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformCardano,
			ChainID:               chainID,
			NetworkName:           chainID,
			RPC:                   baseURL,
			ContractAddress:       anchorAddress,
			RequiredConfirmations: 1,
			Enabled:               true,
		},
		BlockfrostProjectID: blockfrostProjectID,
		BlockfrostBaseURL:   baseURL,
		AnchorAddress:       anchorAddress,
		ValidatorID:         validatorID,
		PollingInterval:     5 * time.Second,
		Timeout:             5 * time.Minute,
	}
	return NewCardanoStrategy(config)
}
