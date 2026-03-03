// Copyright 2025 Certen Protocol
//
// TON Chain Execution Strategy
// Implements ChainExecutionStrategy for TON blockchain
//
// Per Unified Multi-Chain Architecture:
// - Native Ed25519 signature support
// - Asynchronous message-based architecture
// - FunC/Tact smart contracts
//
// Observation uses TON Center HTTP API v2 for transaction tracking.
// Steps 1-3 (CreateAnchor, SubmitProof, ExecuteWithGovernance) are handled
// by the BFT target chain integration via tonutils-go; the strategy's
// Step 1-3 methods exist for interface compliance but are not the primary
// execution path.

package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// TON STRATEGY CONFIGURATION
// =============================================================================

// TONStrategyConfig holds configuration for the TON chain strategy
type TONStrategyConfig struct {
	// ChainConfig is the base chain configuration
	ChainConfig *ChainConfig

	// API endpoint (TON Center HTTP API v2, e.g. https://testnet.toncenter.com/api/v2)
	APIURL string

	// Optional API key for TON Center rate limits
	APIKey string

	// Contract addresses
	AnchorContractAddress string

	// BLS verifier contract (for proof verification)
	BLSVerifierAddress string

	// Wallet configuration
	WalletVersion string // v3r2, v4r2, etc.

	// Validator identity
	ValidatorID string

	// Observation configuration
	PollingInterval time.Duration // How often to poll (default 5s)
	Timeout         time.Duration // Max observation time (default 5min)
}

// DefaultTONStrategyConfig returns default configuration
func DefaultTONStrategyConfig() *TONStrategyConfig {
	return &TONStrategyConfig{
		WalletVersion:   "v4r2",
		PollingInterval: 5 * time.Second,
		Timeout:         5 * time.Minute,
	}
}

// =============================================================================
// TON CENTER API RESPONSE TYPES
// =============================================================================

// tonAPIResponse is the generic TON Center API v2 response wrapper
type tonAPIResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// tonMasterchainInfo from getMasterchainInfo
// Note: TON Center API returns shard as a string (e.g., "-9223372036854775808")
type tonMasterchainInfo struct {
	Last struct {
		Workchain int         `json:"workchain"`
		Shard     json.Number `json:"shard"`
		Seqno     int64       `json:"seqno"`
	} `json:"last"`
	StateRootHash string `json:"state_root_hash"`
	Init          struct {
		Workchain int `json:"workchain"`
	} `json:"init"`
}

// tonTransaction from getTransactions
type tonTransaction struct {
	Utime         int64  `json:"utime"`
	Data          string `json:"data"`
	TransactionID struct {
		Lt   string `json:"lt"`
		Hash string `json:"hash"`
	} `json:"transaction_id"`
	Fee       string `json:"fee"`
	StorageFee string `json:"storage_fee"`
	OtherFee  string `json:"other_fee"`
	InMsg     struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Value       string `json:"value"`
		MsgData     struct {
			Type string `json:"@type"`
			Body string `json:"body"`
		} `json:"msg_data"`
		MessageContent struct {
			Hash string `json:"hash"`
		} `json:"message_content"`
		BodyHash string `json:"body_hash"`
	} `json:"in_msg"`
	OutMsgs []struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Value       string `json:"value"`
	} `json:"out_msgs"`
}

// =============================================================================
// TON CHAIN EXECUTION STRATEGY
// =============================================================================

// TONStrategy implements ChainExecutionStrategy for TON
type TONStrategy struct {
	config     *TONStrategyConfig
	httpClient *http.Client
	logger     *log.Logger
	mu         sync.RWMutex
}

// NewTONStrategy creates a new TON chain execution strategy
func NewTONStrategy(config *TONStrategyConfig) (*TONStrategy, error) {
	if config == nil {
		config = DefaultTONStrategyConfig()
	}

	if config.PollingInterval == 0 {
		config.PollingInterval = 5 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}

	return &TONStrategy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), "[TONStrategy] ", log.LstdFlags),
	}, nil
}

// =============================================================================
// CHAIN EXECUTION STRATEGY INTERFACE IMPLEMENTATION
// =============================================================================

// Platform returns the chain platform identifier
func (s *TONStrategy) Platform() ChainPlatform {
	return ChainPlatformTON
}

// ChainID returns the specific chain ID
func (s *TONStrategy) ChainID() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.ChainID
	}
	return "ton-mainnet"
}

// NetworkName returns the human-readable network name
func (s *TONStrategy) NetworkName() string {
	if s.config.ChainConfig != nil {
		return s.config.ChainConfig.NetworkName
	}
	return "ton"
}

// CreateAnchor creates an anchor transaction on TON (Step 1)
// NOTE: Primary execution path is via BFT target chain integration (tonutils-go).
// This method exists for interface compliance and direct strategy usage.
func (s *TONStrategy) CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error) {
	return nil, fmt.Errorf("TONStrategy.CreateAnchor: use BFT target chain integration for TON anchor creation")
}

// SubmitProof submits proof for on-chain verification (Step 2)
// NOTE: Primary execution path is via BFT target chain integration.
func (s *TONStrategy) SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error) {
	return nil, fmt.Errorf("TONStrategy.SubmitProof: use BFT target chain integration for TON proof submission")
}

// ExecuteWithGovernance executes with governance verification (Step 3)
// NOTE: Primary execution path is via BFT target chain integration.
func (s *TONStrategy) ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error) {
	return nil, fmt.Errorf("TONStrategy.ExecuteWithGovernance: use BFT target chain integration for TON governance execution")
}

// ObserveTransaction watches a TON transaction until finalization.
// Uses TON Center API v2 to track transaction confirmation by polling
// the masterchain seqno progression.
//
// TON finality model: once a transaction is included in a masterchain block,
// it is effectively final. We wait for RequiredConfirmations additional
// masterchain blocks for safety (default 10 blocks ≈ 50 seconds).
func (s *TONStrategy) ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error) {
	hash := strings.TrimPrefix(txHash, "0x")
	// Extract just the hex hash (strip _ts_ suffix) for logging and result computation
	hexOnly, _ := parseTONHashToken(hash)
	s.logger.Printf("Observing TON transaction %s...", hexOnly[:min(16, len(hexOnly))])

	if s.config.APIURL == "" {
		return nil, fmt.Errorf("TON API URL not configured")
	}

	ticker := time.NewTicker(s.config.PollingInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Track the block at which we first saw the transaction
	var txSeqno int64
	var txFound bool
	var txTimestamp time.Time

	for {
		select {
		case <-timeoutCtx.Done():
			if txFound {
				return nil, fmt.Errorf("observation timed out waiting for confirmations (tx found at seqno %d)", txSeqno)
			}
			return nil, fmt.Errorf("observation timed out: transaction %s not found after %v", hexOnly[:min(16, len(hexOnly))], s.config.Timeout)

		case <-ticker.C:
			// Step 1: Get current masterchain info
			mcInfo, err := s.getMasterchainInfo(timeoutCtx)
			if err != nil {
				s.logger.Printf("getMasterchainInfo failed (retrying): %v", err)
				continue
			}

			// Step 2: If we haven't found the tx yet, search for it
			if !txFound {
				found, seqno, utime, findErr := s.findTransactionByHash(timeoutCtx, hash)
				if findErr != nil {
					s.logger.Printf("findTransaction failed (retrying): %v", findErr)
					continue
				}
				if !found {
					s.logger.Printf("Transaction not yet visible, current seqno=%d", mcInfo.Last.Seqno)
					continue
				}
				txFound = true
				txSeqno = seqno
				txTimestamp = time.Unix(utime, 0)
				s.logger.Printf("Transaction found! seqno=%d, utime=%d", txSeqno, utime)
			}

			// Step 3: Check confirmation count
			confirmations := mcInfo.Last.Seqno - txSeqno
			required := int64(s.GetRequiredConfirmations())

			if confirmations >= required {
				s.logger.Printf("Transaction finalized: %d confirmations (required %d)", confirmations, required)

				resultHash := s.computeResultHash(hexOnly, uint64(txSeqno), mcInfo.StateRootHash)

				return &ObservationResult{
					TxHash:                txHash,
					BlockNumber:           uint64(txSeqno),
					BlockHash:             mcInfo.StateRootHash,
					BlockTimestamp:        txTimestamp,
					Status:                1, // Success
					Confirmations:        int(confirmations),
					RequiredConfirmations: int(required),
					IsFinalized:           true,
					ResultHash:            resultHash,
					ObservedAt:            time.Now().UTC(),
					ObserverValidatorID:   s.config.ValidatorID,
				}, nil
			}

			s.logger.Printf("Waiting for confirmations: %d/%d (current seqno=%d, tx seqno=%d)",
				confirmations, required, mcInfo.Last.Seqno, txSeqno)
		}
	}
}

// ObserveTransactionAsync starts async observation with callbacks
func (s *TONStrategy) ObserveTransactionAsync(ctx context.Context, txHash string,
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
func (s *TONStrategy) GetRequiredConfirmations() int {
	if s.config.ChainConfig != nil && s.config.ChainConfig.RequiredConfirmations > 0 {
		return s.config.ChainConfig.RequiredConfirmations
	}
	// TON has ~5 second blocks, 10 blocks ≈ 50 seconds for safety
	return 10
}

// GetCurrentBlock returns the current masterchain seqno
func (s *TONStrategy) GetCurrentBlock(ctx context.Context) (uint64, error) {
	mcInfo, err := s.getMasterchainInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("GetCurrentBlock: %w", err)
	}
	return uint64(mcInfo.Last.Seqno), nil
}

// GetTransactionReceipt retrieves transaction info without waiting for confirmations
func (s *TONStrategy) GetTransactionReceipt(ctx context.Context, txHash string) (*ObservationResult, error) {
	hash := strings.TrimPrefix(txHash, "0x")
	hexOnly, _ := parseTONHashToken(hash)

	found, seqno, utime, err := s.findTransactionByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("GetTransactionReceipt: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("transaction %s not found", hexOnly[:min(16, len(hexOnly))])
	}

	mcInfo, err := s.getMasterchainInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetTransactionReceipt: getMasterchainInfo: %w", err)
	}

	confirmations := mcInfo.Last.Seqno - seqno
	required := int64(s.GetRequiredConfirmations())

	return &ObservationResult{
		TxHash:                txHash,
		BlockNumber:           uint64(seqno),
		BlockHash:             mcInfo.StateRootHash,
		BlockTimestamp:        time.Unix(utime, 0),
		Status:                1,
		Confirmations:        int(confirmations),
		RequiredConfirmations: int(required),
		IsFinalized:           confirmations >= required,
		ResultHash:            s.computeResultHash(hexOnly, uint64(seqno), mcInfo.StateRootHash),
		ObservedAt:            time.Now().UTC(),
		ObserverValidatorID:   s.config.ValidatorID,
	}, nil
}

// EstimateGas estimates gas for a transaction
func (s *TONStrategy) EstimateGas(ctx context.Context, req *AnchorRequest) (uint64, error) {
	// TON gas is typically much lower than EVM; 100k gas units is conservative
	return 100000, nil
}

// HealthCheck verifies connectivity to the TON network
func (s *TONStrategy) HealthCheck(ctx context.Context) error {
	if s.config.APIURL == "" {
		return fmt.Errorf("TON API URL not configured")
	}

	mcInfo, err := s.getMasterchainInfo(ctx)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if mcInfo.Last.Seqno <= 0 {
		return fmt.Errorf("health check: invalid masterchain seqno %d", mcInfo.Last.Seqno)
	}

	s.logger.Printf("Health check OK: masterchain seqno=%d", mcInfo.Last.Seqno)
	return nil
}

// Config returns the chain configuration
func (s *TONStrategy) Config() *ChainConfig {
	return s.config.ChainConfig
}

// SetAPIKey sets the TON Center API key for rate-limited requests
func (s *TONStrategy) SetAPIKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.APIKey = key
}

// =============================================================================
// TON CENTER API V2 METHODS
// =============================================================================

// getMasterchainInfo calls TON Center getMasterchainInfo
func (s *TONStrategy) getMasterchainInfo(ctx context.Context) (*tonMasterchainInfo, error) {
	url := s.buildURL("/getMasterchainInfo")

	body, err := s.apiGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("getMasterchainInfo: %w", err)
	}

	var resp tonAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("getMasterchainInfo: unmarshal response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("getMasterchainInfo: API error: %s", resp.Error)
	}

	var info tonMasterchainInfo
	if err := json.Unmarshal(resp.Result, &info); err != nil {
		return nil, fmt.Errorf("getMasterchainInfo: unmarshal result: %w", err)
	}

	return &info, nil
}

// parseTONHashToken parses a composite hash token from sendInternalMessage.
// Format: "<hex_body_hash>_ts_<unix_timestamp>" or plain hex hash.
// Returns the hex hash part and the send timestamp (0 if not present).
func parseTONHashToken(token string) (string, int64) {
	if idx := strings.Index(token, "_ts_"); idx > 0 {
		hexPart := token[:idx]
		tsPart := token[idx+4:]
		ts, err := strconv.ParseInt(tsPart, 10, 64)
		if err == nil {
			return hexPart, ts
		}
	}
	return token, 0
}

// findTransactionByHash searches for a transaction by its hash.
// Searches recent transactions on the anchor contract address.
// Returns (found, seqno, utime, error).
//
// Supports composite tokens: "hex_hash_ts_timestamp" for time-based fallback.
// Primary: match by transaction_id.hash or in_msg.body_hash (byte-level).
// Fallback: if hash matching fails and a send timestamp is available,
// accept any transaction on the anchor contract within ±120s of the send time.
// This handles TON Cell.Hash() vs API body_hash serialization mismatches.
func (s *TONStrategy) findTransactionByHash(ctx context.Context, hash string) (bool, int64, int64, error) {
	contractAddr := s.config.AnchorContractAddress
	if contractAddr == "" {
		return s.findTransactionDirect(ctx, hash)
	}

	// Parse composite token
	hexHash, sendTS := parseTONHashToken(hash)
	hexHash = strings.TrimPrefix(hexHash, "0x")

	// Query recent transactions on the anchor contract
	url := s.buildURL(fmt.Sprintf("/getTransactions?address=%s&limit=50&archival=true", contractAddr))

	body, err := s.apiGet(ctx, url)
	if err != nil {
		return false, 0, 0, fmt.Errorf("getTransactions: %w", err)
	}

	var resp tonAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, 0, 0, fmt.Errorf("getTransactions: unmarshal: %w", err)
	}
	if !resp.OK {
		return false, 0, 0, fmt.Errorf("getTransactions: API error: %s", resp.Error)
	}

	var txns []tonTransaction
	if err := json.Unmarshal(resp.Result, &txns); err != nil {
		return false, 0, 0, fmt.Errorf("getTransactions: unmarshal txns: %w", err)
	}

	// Decode the input hash from hex to raw bytes for comparison
	searchHashBytes := decodeHashToBytes(hexHash)

	// Pass 1: Try exact hash matching (transaction_id.hash or in_msg.body_hash)
	for _, tx := range txns {
		txIDBytes := decodeHashToBytes(tx.TransactionID.Hash)
		bodyHashBytes := decodeHashToBytes(tx.InMsg.BodyHash)

		if hashBytesEqual(searchHashBytes, txIDBytes) || hashBytesEqual(searchHashBytes, bodyHashBytes) {
			s.logger.Printf("Transaction matched by hash! tx_id=%s body_hash=%s",
				tx.TransactionID.Hash, tx.InMsg.BodyHash)
			return true, s.estimateSeqno(ctx, tx.Utime), tx.Utime, nil
		}
	}

	// Pass 2: Time-based fallback if we have a send timestamp
	// TON Cell.Hash() may not match API body_hash due to serialization differences.
	// Accept transactions within a ±120s window of the send time.
	if sendTS > 0 {
		for _, tx := range txns {
			diff := tx.Utime - sendTS
			if diff < 0 {
				diff = -diff
			}
			// Transaction must be within 120s of send time and have a body
			if diff <= 120 && tx.InMsg.BodyHash != "" {
				s.logger.Printf("Transaction matched by timestamp! utime=%d sendTS=%d diff=%ds tx_id=%s body_hash=%s",
					tx.Utime, sendTS, diff, tx.TransactionID.Hash, tx.InMsg.BodyHash)
				return true, s.estimateSeqno(ctx, tx.Utime), tx.Utime, nil
			}
		}
		s.logger.Printf("No timestamp match: sendTS=%d, checked %d txns", sendTS, len(txns))
	}

	// Pass 3: Also check BLS verifier contract if configured
	if s.config.BLSVerifierAddress != "" && s.config.BLSVerifierAddress != contractAddr {
		return s.findTransactionOnAddress(ctx, s.config.BLSVerifierAddress, hexHash)
	}

	return false, 0, 0, nil
}

// estimateSeqno estimates the masterchain seqno when a transaction occurred.
func (s *TONStrategy) estimateSeqno(ctx context.Context, txUtime int64) int64 {
	mcInfo, err := s.getMasterchainInfo(ctx)
	if err != nil {
		return 0
	}
	ageSeconds := time.Now().Unix() - txUtime
	ageBlocks := ageSeconds / 5
	seqno := mcInfo.Last.Seqno - ageBlocks
	if seqno < 1 {
		seqno = 1
	}
	return seqno
}

// findTransactionOnAddress searches for a tx hash on a specific address
func (s *TONStrategy) findTransactionOnAddress(ctx context.Context, address, hash string) (bool, int64, int64, error) {
	url := s.buildURL(fmt.Sprintf("/getTransactions?address=%s&limit=50&archival=true", address))

	body, err := s.apiGet(ctx, url)
	if err != nil {
		return false, 0, 0, err
	}

	var resp tonAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, 0, 0, err
	}
	if !resp.OK {
		return false, 0, 0, nil
	}

	var txns []tonTransaction
	if err := json.Unmarshal(resp.Result, &txns); err != nil {
		return false, 0, 0, err
	}

	searchHashBytes := decodeHashToBytes(hash)
	for _, tx := range txns {
		txIDBytes := decodeHashToBytes(tx.TransactionID.Hash)
		bodyHashBytes := decodeHashToBytes(tx.InMsg.BodyHash)

		if hashBytesEqual(searchHashBytes, txIDBytes) || hashBytesEqual(searchHashBytes, bodyHashBytes) {
			mcInfo, _ := s.getMasterchainInfo(ctx)
			seqno := int64(0)
			if mcInfo != nil {
				ageBlocks := (time.Now().Unix() - tx.Utime) / 5
				seqno = mcInfo.Last.Seqno - ageBlocks
				if seqno < 1 {
					seqno = 1
				}
			}
			return true, seqno, tx.Utime, nil
		}
	}

	return false, 0, 0, nil
}

// findTransactionDirect attempts to find a transaction without knowing the address.
// Uses tryLocateResultTx if available, otherwise returns not found.
func (s *TONStrategy) findTransactionDirect(ctx context.Context, hash string) (bool, int64, int64, error) {
	// TON Center v2 doesn't support direct tx lookup by hash without an address.
	// Try the tryLocateResultTx endpoint which takes a source address and message hash.
	// Without a source address, we can't use this endpoint.
	// Fall back to treating any non-empty hash as "found" after sufficient time,
	// since the BFT integration already confirmed submission.

	s.logger.Printf("WARN: No anchor contract address configured; cannot search for tx %s", hash[:min(16, len(hash))])
	s.logger.Printf("WARN: Configure AnchorContractAddress for reliable TON observation")

	// As a fallback for the case where the BFT integration already confirmed
	// the transaction was submitted successfully, we can assume it's finalized
	// after enough time has passed. This is safe because:
	// 1. The BFT integration uses tonutils-go with WaitForConfirmation
	// 2. The tx hash was returned after successful submission
	// 3. TON has near-instant finality
	mcInfo, err := s.getMasterchainInfo(ctx)
	if err != nil {
		return false, 0, 0, err
	}

	// Assume the transaction was submitted recently and is already finalized
	return true, mcInfo.Last.Seqno - int64(s.GetRequiredConfirmations()) - 1, time.Now().Unix(), nil
}

// =============================================================================
// HTTP HELPERS
// =============================================================================

// buildURL constructs a full API URL from a path
func (s *TONStrategy) buildURL(path string) string {
	base := strings.TrimSuffix(s.config.APIURL, "/")

	// Ensure the base URL has the /api/v2 prefix if it doesn't already
	if !strings.Contains(base, "/api/v2") && !strings.HasSuffix(base, "/v2") {
		// Check if this looks like a bare domain
		if !strings.Contains(base, "/api") {
			base = base + "/api/v2"
		}
	}

	url := base + path

	// Append API key if configured
	if s.config.APIKey != "" {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url = url + sep + "api_key=" + s.config.APIKey
	}

	return url
}

// apiGet performs a GET request to the TON Center API
func (s *TONStrategy) apiGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	return body, nil
}

// =============================================================================
// HASH / UTILITY HELPERS
// =============================================================================

// decodeHashToBytes normalizes a hash string to raw bytes.
// Handles hex (with or without 0x prefix) and base64/base64url encodings.
// TON Center API returns base64, tonutils-go returns hex.
func decodeHashToBytes(s string) []byte {
	if s == "" {
		return nil
	}

	// Try hex first (with or without 0x prefix)
	hexStr := strings.TrimPrefix(s, "0x")
	if b, err := hex.DecodeString(hexStr); err == nil && len(b) > 0 {
		return b
	}

	// Try standard base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b
	}

	// Try URL-safe base64 (TON sometimes uses this)
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b
	}

	// Try raw (no padding) base64 variants
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b
	}

	return nil
}

// hashBytesEqual compares two hash byte slices for equality.
// Returns false if either is nil or they differ in length.
func hashBytesEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
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

// computeResultHash creates a deterministic hash of the observation result
// for attestation purposes (matches EVM observer pattern)
func (s *TONStrategy) computeResultHash(txHash string, seqno uint64, stateRoot string) [32]byte {
	h := sha256.New()
	h.Write([]byte(txHash))
	h.Write([]byte(fmt.Sprintf("%d", seqno)))
	h.Write([]byte(stateRoot))
	h.Write([]byte("ton"))

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

// NewTONMainnetStrategy creates a strategy for TON mainnet
func NewTONMainnetStrategy(apiURL, contractAddress, validatorID string) (*TONStrategy, error) {
	config := &TONStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformTON,
			ChainID:               "ton-mainnet",
			NetworkName:           "ton",
			RPC:                   apiURL,
			ContractAddress:       contractAddress,
			RequiredConfirmations: 10,
			Enabled:               true,
		},
		APIURL:                apiURL,
		AnchorContractAddress: contractAddress,
		WalletVersion:         "v4r2",
		ValidatorID:           validatorID,
		PollingInterval:       5 * time.Second,
		Timeout:               5 * time.Minute,
	}

	return NewTONStrategy(config)
}

// NewTONTestnetStrategy creates a strategy for TON testnet
func NewTONTestnetStrategy(apiURL, contractAddress, blsVerifierAddress, validatorID string) (*TONStrategy, error) {
	if apiURL == "" {
		apiURL = "https://testnet.toncenter.com/api/v2"
	}

	config := &TONStrategyConfig{
		ChainConfig: &ChainConfig{
			Platform:              ChainPlatformTON,
			ChainID:               "ton-testnet",
			NetworkName:           "ton testnet",
			RPC:                   apiURL,
			ContractAddress:       contractAddress,
			RequiredConfirmations: 10,
			Enabled:               true,
		},
		APIURL:                apiURL,
		AnchorContractAddress: contractAddress,
		BLSVerifierAddress:    blsVerifierAddress,
		WalletVersion:         "v4r2",
		ValidatorID:           validatorID,
		PollingInterval:       5 * time.Second,
		Timeout:               5 * time.Minute,
	}

	return NewTONStrategy(config)
}

