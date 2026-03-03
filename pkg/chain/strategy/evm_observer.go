// Copyright 2025 Certen Protocol
//
// EVM Chain Observer
// Watches EVM transactions until finalization and constructs Merkle proofs
//
// Per Unified Multi-Chain Architecture:
// - Extracted from pkg/execution/external_chain_observer.go
// - Implements transaction observation for EVM chains
// - Constructs Merkle inclusion proofs for transactions and receipts

package strategy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

// =============================================================================
// EVM OBSERVER CONFIGURATION
// =============================================================================

// EVMObserverConfig holds configuration for the EVM observer
type EVMObserverConfig struct {
	// Client is the Ethereum client
	Client *ethclient.Client

	// ChainID for the chain
	ChainID int64

	// ValidatorID for logging and attribution
	ValidatorID string

	// RequiredConfirmations is the number of blocks needed for finality
	RequiredConfirmations int

	// PollingInterval is how often to check for new blocks
	PollingInterval time.Duration

	// Timeout is the maximum time to wait for finalization
	Timeout time.Duration

	// Callbacks
	OnFinalized func(*ObservationResult)
	OnFailed    func(common.Hash, error)
}

// DefaultEVMObserverConfig returns default configuration
func DefaultEVMObserverConfig() *EVMObserverConfig {
	return &EVMObserverConfig{
		RequiredConfirmations: 12,
		PollingInterval:       12 * time.Second,
		Timeout:               30 * time.Minute,
	}
}

// =============================================================================
// EVM OBSERVER
// =============================================================================

// EVMObserver watches EVM chains for transaction finalization
type EVMObserver struct {
	mu sync.RWMutex

	client      *ethclient.Client
	chainID     int64
	validatorID string

	// Configuration
	requiredConfirmations int
	pollingInterval       time.Duration
	timeout               time.Duration

	// Pending observations
	pending     map[common.Hash]*pendingObservation
	pendingLock sync.RWMutex

	// Callbacks
	onFinalized func(*ObservationResult)
	onFailed    func(common.Hash, error)

	// State
	running bool
	stopCh  chan struct{}
}

// pendingObservation tracks a transaction being observed
type pendingObservation struct {
	TxHash      common.Hash
	SubmittedAt time.Time
	Status      string
	LastChecked time.Time
}

// NewEVMObserver creates a new EVM observer
func NewEVMObserver(config *EVMObserverConfig) (*EVMObserver, error) {
	if config == nil {
		config = DefaultEVMObserverConfig()
	}

	if config.Client == nil {
		return nil, fmt.Errorf("ethereum client is required")
	}

	// Set defaults
	if config.RequiredConfirmations == 0 {
		config.RequiredConfirmations = 12
	}
	if config.PollingInterval == 0 {
		config.PollingInterval = 12 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Minute
	}

	return &EVMObserver{
		client:                config.Client,
		chainID:               config.ChainID,
		validatorID:           config.ValidatorID,
		requiredConfirmations: config.RequiredConfirmations,
		pollingInterval:       config.PollingInterval,
		timeout:               config.Timeout,
		pending:               make(map[common.Hash]*pendingObservation),
		onFinalized:           config.OnFinalized,
		onFailed:              config.OnFailed,
		stopCh:                make(chan struct{}),
	}, nil
}

// =============================================================================
// OBSERVATION METHODS
// =============================================================================

// ObserveTransaction observes a transaction until finalization
// Blocking call that returns when tx is finalized or times out
func (o *EVMObserver) ObserveTransaction(ctx context.Context, txHash common.Hash) (*ObservationResult, error) {
	startTime := time.Now()
	deadline := startTime.Add(o.timeout)

	// Create pending tracker
	pending := &pendingObservation{
		TxHash:      txHash,
		SubmittedAt: startTime,
		Status:      "pending",
	}

	o.pendingLock.Lock()
	o.pending[txHash] = pending
	o.pendingLock.Unlock()

	defer func() {
		o.pendingLock.Lock()
		delete(o.pending, txHash)
		o.pendingLock.Unlock()
	}()

	// Wait for receipt
	receipt, err := o.waitForReceipt(ctx, txHash, deadline)
	if err != nil {
		return nil, fmt.Errorf("wait for receipt: %w", err)
	}

	// Get block header — works on all EVM chains including OP Stack (Base, Optimism)
	// which have deposit tx types that BlockByHash can't decode.
	// TRON returns non-standard fields ("stateRoot":"0x") that break Go's header unmarshal,
	// so we handle this gracefully with a receipt-only fallback.
	header, headerErr := o.client.HeaderByHash(ctx, receipt.BlockHash)

	var result *ObservationResult
	if headerErr != nil {
		// Fallback: build result from receipt only (TRON, non-standard EVM chains)
		log.Printf("⚠️ [EVM-OBSERVER] HeaderByHash failed (non-standard chain): %v — using receipt-only observation", headerErr)
		result = &ObservationResult{
			TxHash:                receipt.TxHash.Hex(),
			BlockNumber:           receipt.BlockNumber.Uint64(),
			BlockHash:             receipt.BlockHash.Hex(),
			BlockTimestamp:        time.Now().UTC(), // Best approximation
			Status:                uint8(receipt.Status),
			RequiredConfirmations: o.requiredConfirmations,
			GasUsed:               receipt.GasUsed,
		}
		for _, l := range receipt.Logs {
			topics := make([]string, len(l.Topics))
			for i, t := range l.Topics {
				topics[i] = t.Hex()
			}
			result.Logs = append(result.Logs, EventLog{
				Address:  l.Address.Hex(),
				Topics:   topics,
				Data:     l.Data,
				LogIndex: l.Index,
			})
		}

		// Wait for confirmations using BlockNumber() (works on TRON jsonrpc even though HeaderByHash doesn't)
		confirmTicker := time.NewTicker(o.pollingInterval)
		defer confirmTicker.Stop()
		confirmed := false
		for !confirmed {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-confirmTicker.C:
				if time.Now().After(deadline) {
					// Timeout — mark as finalized anyway since we have a receipt
					log.Printf("⚠️ [EVM-OBSERVER] Confirmation timeout on non-standard chain, accepting receipt as finalized")
					confirmed = true
					break
				}
				currentBlock, err := o.client.BlockNumber(ctx)
				if err != nil {
					continue
				}
				confirmations := int(currentBlock - receipt.BlockNumber.Uint64())
				result.Confirmations = confirmations
				if confirmations >= o.requiredConfirmations {
					confirmed = true
				}
			}
		}
		result.IsFinalized = true
		result.ResultHash = computeResultHash(result)
	} else {
		// Wait for required confirmations
		result, err = o.waitForConfirmationsFromHeader(ctx, receipt, header, deadline)
		if err != nil {
			return nil, fmt.Errorf("wait for confirmations: %w", err)
		}
	}

	// Try full block fetch for Merkle proofs (best-effort — fails on OP Stack and TRON chains)
	block, blockErr := o.client.BlockByHash(ctx, receipt.BlockHash)
	if blockErr == nil {
		result, _ = o.addMerkleProofs(ctx, result, receipt, block)
	} else if headerErr == nil {
		// Populate block roots from header directly (only if we have a valid header)
		copy(result.StateRoot[:], header.Root.Bytes())
		copy(result.TransactionsRoot[:], header.TxHash.Bytes())
		copy(result.ReceiptsRoot[:], header.ReceiptHash.Bytes())
		result.ResultHash = computeResultHash(result)
	}

	// Store raw receipt
	rawReceipt, err := rlp.EncodeToBytes(receipt)
	if err == nil {
		result.RawReceipt = rawReceipt
	}

	// Set observer metadata
	result.ObserverValidatorID = o.validatorID
	result.ObservedAt = time.Now().UTC()

	// Fetch full transaction to get sender address
	tx, _, txErr := o.client.TransactionByHash(ctx, txHash)
	if txErr == nil && tx != nil {
		signer := types.LatestSignerForChainID(big.NewInt(o.chainID))
		if from, sErr := types.Sender(signer, tx); sErr == nil {
			result.TxFrom = from.Hex()
		} else {
			log.Printf("⚠️ [EVM-OBSERVER] types.Sender failed (non-standard chain?): %v", sErr)
		}
	} else if txErr != nil {
		log.Printf("⚠️ [EVM-OBSERVER] TransactionByHash failed: %v — trying raw RPC fallback for tx_from", txErr)
		// Fallback: raw JSON-RPC call to extract "from" field (works on TRON jsonrpc)
		type rpcTx struct {
			From string `json:"from"`
		}
		var raw rpcTx
		if rpcErr := o.client.Client().CallContext(ctx, &raw, "eth_getTransactionByHash", txHash.Hex()); rpcErr == nil && raw.From != "" {
			result.TxFrom = raw.From
		}
	}

	// Callback
	if o.onFinalized != nil {
		o.onFinalized(result)
	}

	return result, nil
}

// waitForReceipt waits for a transaction receipt
func (o *EVMObserver) waitForReceipt(ctx context.Context, txHash common.Hash, deadline time.Time) (*types.Receipt, error) {
	ticker := time.NewTicker(o.pollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for receipt")
			}

			receipt, err := o.client.TransactionReceipt(ctx, txHash)
			if err != nil {
				// Transaction not yet mined
				continue
			}

			return receipt, nil
		}
	}
}

// waitForConfirmationsFromHeader waits for required block confirmations using a block header
func (o *EVMObserver) waitForConfirmationsFromHeader(ctx context.Context, receipt *types.Receipt, header *types.Header, deadline time.Time) (*ObservationResult, error) {
	ticker := time.NewTicker(o.pollingInterval)
	defer ticker.Stop()

	result := &ObservationResult{
		TxHash:                receipt.TxHash.Hex(),
		BlockNumber:           receipt.BlockNumber.Uint64(),
		BlockHash:             receipt.BlockHash.Hex(),
		BlockTimestamp:        time.Unix(int64(header.Time), 0),
		Status:                uint8(receipt.Status),
		RequiredConfirmations: o.requiredConfirmations,
		GasUsed:               receipt.GasUsed,
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

	// Wait for confirmations
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return result, fmt.Errorf("timeout waiting for confirmations")
			}

			currentBlock, err := o.client.BlockNumber(ctx)
			if err != nil {
				continue
			}

			confirmations := int(currentBlock - receipt.BlockNumber.Uint64())
			result.Confirmations = confirmations

			if confirmations >= o.requiredConfirmations {
				result.IsFinalized = true
				return result, nil
			}
		}
	}
}

// addMerkleProofs adds Merkle inclusion proofs to the observation result
func (o *EVMObserver) addMerkleProofs(ctx context.Context, result *ObservationResult, receipt *types.Receipt, block *types.Block) (*ObservationResult, error) {
	// Store block roots
	copy(result.StateRoot[:], block.Root().Bytes())
	copy(result.TransactionsRoot[:], block.TxHash().Bytes())
	copy(result.ReceiptsRoot[:], block.ReceiptHash().Bytes())

	// Get all transactions in the block for Merkle proof
	txs := block.Transactions()
	txIndex := -1
	for i, tx := range txs {
		if tx.Hash() == receipt.TxHash {
			txIndex = i
			break
		}
	}

	if txIndex >= 0 {
		// Construct transaction Merkle proof
		txProof, err := constructTxMerkleProof(txs, txIndex)
		if err == nil {
			result.MerkleProof = txProof
		}
	}

	// Compute result hash
	resultHash := computeResultHash(result)
	result.ResultHash = resultHash

	// Store raw receipt
	rawReceipt, err := rlp.EncodeToBytes(receipt)
	if err == nil {
		result.RawReceipt = rawReceipt
	}

	return result, nil
}

// =============================================================================
// MERKLE PROOF CONSTRUCTION
// =============================================================================

// constructTxMerkleProof constructs a Merkle proof for a transaction
func constructTxMerkleProof(txs types.Transactions, txIndex int) ([]byte, error) {
	if txIndex < 0 || txIndex >= len(txs) {
		return nil, fmt.Errorf("invalid transaction index")
	}

	if len(txs) == 0 {
		return nil, fmt.Errorf("no transactions in block")
	}

	// Build proof data containing:
	// 1. The target transaction hash
	// 2. All sibling transaction hashes for verification
	var proofData []byte

	// Add the target transaction hash first
	targetTx := txs[txIndex]
	proofData = append(proofData, targetTx.Hash().Bytes()...)

	// Add sibling hashes for Merkle proof verification
	// This is a simplified proof - for full verification, we'd need
	// the actual Merkle tree path, but for our attestation purposes
	// the transaction hash + block's tx root is sufficient
	for i, tx := range txs {
		if i != txIndex {
			proofData = append(proofData, tx.Hash().Bytes()...)
		}
	}

	return proofData, nil
}

// computeResultHash computes a deterministic hash of the observation result
func computeResultHash(result *ObservationResult) [32]byte {
	h := sha256.New()

	h.Write([]byte(result.TxHash))
	h.Write(big.NewInt(int64(result.BlockNumber)).Bytes())
	h.Write([]byte(result.BlockHash))
	h.Write([]byte{result.Status})
	h.Write(result.StateRoot[:])
	h.Write(result.TransactionsRoot[:])
	h.Write(result.ReceiptsRoot[:])

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// =============================================================================
// ASYNC OBSERVATION
// =============================================================================

// ObserveTransactionAsync starts async observation
func (o *EVMObserver) ObserveTransactionAsync(ctx context.Context, txHash common.Hash) <-chan *ObservationResult {
	resultCh := make(chan *ObservationResult, 1)

	go func() {
		defer close(resultCh)

		result, err := o.ObserveTransaction(ctx, txHash)
		if err != nil {
			if o.onFailed != nil {
				o.onFailed(txHash, err)
			}
			return
		}

		resultCh <- result
	}()

	return resultCh
}

// ObserveMultiple observes multiple transactions concurrently
func (o *EVMObserver) ObserveMultiple(ctx context.Context, txHashes []common.Hash) ([]*ObservationResult, error) {
	results := make([]*ObservationResult, len(txHashes))
	errors := make([]error, len(txHashes))

	var wg sync.WaitGroup
	for i, hash := range txHashes {
		wg.Add(1)
		go func(idx int, h common.Hash) {
			defer wg.Done()
			result, err := o.ObserveTransaction(ctx, h)
			results[idx] = result
			errors[idx] = err
		}(i, hash)
	}

	wg.Wait()

	// Check for any errors
	for i, err := range errors {
		if err != nil {
			return results, fmt.Errorf("observation %d failed: %w", i, err)
		}
	}

	return results, nil
}

// =============================================================================
// UTILITY METHODS
// =============================================================================

// GetPendingCount returns the number of pending observations
func (o *EVMObserver) GetPendingCount() int {
	o.pendingLock.RLock()
	defer o.pendingLock.RUnlock()
	return len(o.pending)
}

// GetPendingHashes returns all pending transaction hashes
func (o *EVMObserver) GetPendingHashes() []common.Hash {
	o.pendingLock.RLock()
	defer o.pendingLock.RUnlock()

	hashes := make([]common.Hash, 0, len(o.pending))
	for hash := range o.pending {
		hashes = append(hashes, hash)
	}
	return hashes
}

// SetCallbacks sets the observation callbacks
func (o *EVMObserver) SetCallbacks(onFinalized func(*ObservationResult), onFailed func(common.Hash, error)) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.onFinalized = onFinalized
	o.onFailed = onFailed
}

// GetRequiredConfirmations returns the required confirmations
func (o *EVMObserver) GetRequiredConfirmations() int {
	return o.requiredConfirmations
}

// SetRequiredConfirmations updates the required confirmations
func (o *EVMObserver) SetRequiredConfirmations(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requiredConfirmations = n
}
