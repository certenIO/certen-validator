// Copyright 2025 Certen Protocol
//
// EVM Chain Observer
// Watches EVM transactions until finalization and proves them in their block
//
// Per Unified Multi-Chain Architecture:
// - Extracted from pkg/execution/external_chain_observer.go
// - Implements transaction observation for EVM chains
// - Builds Merkle-Patricia inclusion proofs of the transaction and its receipt against the block's transactionsRoot and
//   receiptsRoot (pkg/ethproof, shared with the settlement gate), verifies them, and binds them into the signed result
//   hash (RB5-F16)

package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
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

	// Finality is where a settlement's finality facts come from: independent providers that must agree (RB5-F53).
	// FinalityErr says why there is none; every non-TRON observation is then refused by it.
	Finality    ethrpc.FinalityReader
	FinalityErr error

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

// FinalityError says why this observer has no agreeing providers (RB5-F53), or nil when it has them.
func (o *EVMObserver) FinalityError() error { return o.finalityErr }

// EVMObserver watches EVM chains for transaction finalization
type EVMObserver struct {
	mu sync.RWMutex

	client      *ethclient.Client
	chainID     int64
	validatorID string

	finality    ethrpc.FinalityReader // RB5-F53: agreeing independent providers
	finalityErr error

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
		finality:              config.Finality,
		finalityErr:           config.FinalityErr,
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

	if tronChainIDs[o.chainID] {
		return o.observeTron(ctx, txHash, deadline)
	}
	result, err := o.observeSettled(ctx, txHash, deadline)
	if err != nil {
		return nil, err
	}
	if o.onFinalized != nil {
		o.onFinalized(result)
	}
	return result, nil
}

// observeSettled is the observation on every chain but TRON.
//
//   - The receipt is the one the FINALIZED chain holds: its block at or below the chain's finalized tag, canonical at its
//     height, the receipt that block's own (ethrpc.SettledInFinalizedChain, RB5-F49), all read from agreeing providers
//     (RB5-F53).
//   - The transaction and its receipt are proven in that block by Merkle-Patricia inclusion proofs against the header's
//     transactionsRoot and receiptsRoot (pkg/ethproof, RB5-F16), built from the block's agreed bodies and verified before
//     use. The proofs and the header are carried on the result, verify offline (VerifyObservationProofs), and are bound
//     into its ResultHash - the hash Phase 8 signs.
//   - What the transaction called and who sent it are read from the proven transaction itself, not from a provider's
//     paraphrase of it.
//
// A settlement that cannot be proven is refused by name; it is never observed without its proofs.
func (o *EVMObserver) observeSettled(ctx context.Context, txHash common.Hash, deadline time.Time) (*ObservationResult, error) {
	if o.finality == nil {
		return nil, fmt.Errorf("chain %d: no agreeing providers to observe %s with: %v", o.chainID, txHash.Hex(), o.finalityErr)
	}
	receipt, err := ethrpc.SettledInFinalizedChain(ctx, o.finality, txHash, deadline, o.pollingInterval, log.Printf)
	if err != nil {
		return nil, fmt.Errorf("observe %s in the finalized chain %d: %w", txHash.Hex(), o.chainID, err)
	}
	// By HASH, from the agreeing providers: a read by height could be answered by a backend on another fork.
	header, err := o.finality.HeaderByHash(ctx, receipt.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("read the finalized header %s on chain %d: %w", receipt.BlockHash.Hex(), o.chainID, err)
	}
	if header.Hash() != receipt.BlockHash {
		return nil, fmt.Errorf("the finalized header at %d on chain %d is %s, the receipt names %s", receipt.BlockNumber.Uint64(),
			o.chainID, header.Hash().Hex(), receipt.BlockHash.Hex())
	}
	src, ok := o.finality.(ethproof.Source)
	if !ok {
		return nil, fmt.Errorf("chain %d: the finality reader (%T) cannot serve a block's agreed bodies, so %s cannot be proven in its block",
			o.chainID, o.finality, txHash.Hex())
	}
	settlement, err := ethproof.BuildWithin(ctx, src, receipt.BlockHash, txHash, uint64(receipt.TransactionIndex), deadline, o.pollingInterval)
	if err != nil {
		return nil, &UnprovenSettlementError{ChainID: o.chainID, TxHash: txHash.Hex(), BlockHash: receipt.BlockHash.Hex(),
			BlockNumber: receipt.BlockNumber.Uint64(), Status: receipt.Status, Err: err}
	}

	result := o.finalizedResult(ctx, receipt, header)
	// What the transaction called and who signed it, from the proven transaction.
	var tx types.Transaction
	if err := tx.UnmarshalBinary(settlement.Tx.LeafValue); err != nil {
		return nil, fmt.Errorf("the proven transaction %s on chain %d does not decode: %w", txHash.Hex(), o.chainID, err)
	}
	if to := tx.To(); to != nil {
		result.TxTo = to.Hex()
	}
	if data := tx.Data(); len(data) >= 4 {
		result.TxSelector = hex.EncodeToString(data[:4])
	}
	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(o.chainID)), &tx)
	if err != nil {
		return nil, fmt.Errorf("recover the sender of %s on chain %d: %w", txHash.Hex(), o.chainID, err)
	}
	result.TxFrom = from.Hex()
	result.ObserverValidatorID = o.validatorID
	result.ObservedAt = time.Now().UTC()
	if err := bindInclusion(result, settlement); err != nil {
		return nil, fmt.Errorf("chain %d: %w", o.chainID, err)
	}
	return result, nil
}

// bindInclusion carries a settlement's proofs on the observation exactly as they are emitted - the transaction proof as
// MerkleProof, the receipt proof as ReceiptProof (each the JSON of an ethproof.InclusionProof), the header as
// BlockHeaderRLP, and the proven receipt as RawReceipt - verifies them as a reader would, from those bytes alone, takes
// the block's roots from the verified header, and binds all of it into the ResultHash.
func bindInclusion(result *ObservationResult, s *ethproof.Settlement) error {
	txJSON, err := json.Marshal(s.Tx)
	if err != nil {
		return fmt.Errorf("encode the transaction proof of %s: %w", s.TxHash.Hex(), err)
	}
	rcJSON, err := json.Marshal(s.Receipt)
	if err != nil {
		return fmt.Errorf("encode the receipt proof of %s: %w", s.TxHash.Hex(), err)
	}
	result.MerkleProof, result.ReceiptProof, result.BlockHeaderRLP = txJSON, rcJSON, common.CopyBytes(s.Header)
	result.RawReceipt = common.CopyBytes(s.Receipt.LeafValue)
	header, receipt, err := VerifyObservationProofs(result)
	if err != nil {
		return err
	}
	copy(result.StateRoot[:], header.Root.Bytes())
	copy(result.TransactionsRoot[:], header.TxHash.Bytes())
	copy(result.ReceiptsRoot[:], header.ReceiptHash.Bytes())
	if receipt.Succeeded() != (result.Status == 1) {
		return fmt.Errorf("the proven receipt of %s says succeeded=%v, the observation states status %d", s.TxHash.Hex(), receipt.Succeeded(), result.Status)
	}
	result.ResultHash = computeResultHash(result)
	return nil
}

// VerifyObservationProofs verifies, from the observation's own bytes, that its transaction and its receipt are included
// in its block: BlockHeaderRLP hashes to BlockHash, MerkleProof proves TxHash and ReceiptProof its receipt at the same
// index, against that header's transactionsRoot and receiptsRoot (ethproof.VerifySettlement). It returns the header and
// the proven receipt.
func VerifyObservationProofs(result *ObservationResult) (*types.Header, *ethproof.ReceiptLeaf, error) {
	var txProof, rcProof ethproof.InclusionProof
	if err := json.Unmarshal(result.MerkleProof, &txProof); err != nil {
		return nil, nil, fmt.Errorf("the transaction proof of %s does not decode: %w", result.TxHash, err)
	}
	if err := json.Unmarshal(result.ReceiptProof, &rcProof); err != nil {
		return nil, nil, fmt.Errorf("the receipt proof of %s does not decode: %w", result.TxHash, err)
	}
	header, receipt, err := ethproof.VerifySettlement(common.HexToHash(result.BlockHash), result.BlockHeaderRLP,
		common.HexToHash(result.TxHash), &txProof, &rcProof)
	if err != nil {
		return nil, nil, fmt.Errorf("the inclusion proofs of %s: %w", result.TxHash, err)
	}
	return header, receipt, nil
}

// observeTron is the observation on TRON's EVM-compatible networks (outside the supported scope; restored by runbook
// RB8). TRON's nodes serve headers go-ethereum cannot decode, so it keeps its receipt-only path. It carries no inclusion
// proofs - none is built from what TRON serves, and none is claimed.
func (o *EVMObserver) observeTron(ctx context.Context, txHash common.Hash, deadline time.Time) (*ObservationResult, error) {
	var (
		receipt   *types.Receipt
		header    *types.Header
		headerErr error
		result    *ObservationResult
		err       error
	)
	// TRON (outside the settled chains' scope): unchanged.
	if receipt, err = o.waitForReceipt(ctx, txHash, deadline); err != nil {
		return nil, fmt.Errorf("wait for receipt: %w", err)
	}
	// TRON returns non-standard fields ("stateRoot":"0x") that break Go's header unmarshal, so a receipt-only observation
	// stands in when its header cannot be read.
	header, headerErr = o.client.HeaderByHash(ctx, receipt.BlockHash)
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
			ChainIDNumeric:        o.chainID,
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

	// The block's roots, from whichever read TRON's node answers. They are the header's: a full-block read
	// (BlockByHash) carried the same roots and also decoded the body, which go-ethereum refuses on a chain that stores
	// something else in sha3Uncles (Telcoin Adiri, RB7 Phase A F-RPC-10). The header read above is used.
	if headerErr == nil {
		// Populate block roots from header directly (only if we have a valid header)
		copy(result.StateRoot[:], header.Root.Bytes())
		copy(result.TransactionsRoot[:], header.TxHash.Bytes())
		copy(result.ReceiptsRoot[:], header.ReceiptHash.Bytes())
		result.ResultHash = computeResultHash(result)
	} else {
		// HeaderByHash failed (TRON's non-standard fields) — the raw JSON-RPC block for its roots
		type rpcBlockRoots struct {
			StateRoot        string `json:"stateRoot"`
			TransactionsRoot string `json:"transactionsRoot"`
			ReceiptsRoot     string `json:"receiptsRoot"`
		}
		var rawBlock rpcBlockRoots
		if rpcErr := o.client.Client().CallContext(ctx, &rawBlock, "eth_getBlockByHash", receipt.BlockHash.Hex(), false); rpcErr == nil {
			if decoded := common.FromHex(rawBlock.StateRoot); len(decoded) == 32 {
				copy(result.StateRoot[:], decoded)
			}
			if decoded := common.FromHex(rawBlock.TransactionsRoot); len(decoded) == 32 {
				copy(result.TransactionsRoot[:], decoded)
			}
			if decoded := common.FromHex(rawBlock.ReceiptsRoot); len(decoded) == 32 {
				copy(result.ReceiptsRoot[:], decoded)
			}
			result.ResultHash = computeResultHash(result)
		}
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
		// What the transaction called: the write-back states it from here, never from a template.
		if to := tx.To(); to != nil {
			result.TxTo = to.Hex()
		}
		if data := tx.Data(); len(data) >= 4 {
			result.TxSelector = hex.EncodeToString(data[:4])
		}
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

// tronChainIDs are TRON's EVM-compatible JSON-RPC networks (mainnet, Shasta, Nile). Their nodes return
// headers go-ethereum cannot decode, and the receipt-only observation and raw-RPC reads in
// ObserveTransaction exist for them alone. TRON is outside the supported scope and keeps that path for
// its restoration (runbook RB8); every other chain gets an error where it would have got a stand-in.
var tronChainIDs = map[int64]bool{728126428: true, 2494104990: true, 3448148188: true}

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

// finalizedResult is the observation of a receipt in a finalized block (RB5-F49): final by the chain's own finalized tag,
// so IsFinalized; Confirmations is how far the head has moved past it, for the record.
func (o *EVMObserver) finalizedResult(ctx context.Context, receipt *types.Receipt, header *types.Header) *ObservationResult {
	result := &ObservationResult{
		TxHash:                receipt.TxHash.Hex(),
		BlockNumber:           receipt.BlockNumber.Uint64(),
		BlockHash:             receipt.BlockHash.Hex(),
		BlockTimestamp:        time.Unix(int64(header.Time), 0),
		Status:                uint8(receipt.Status),
		RequiredConfirmations: o.requiredConfirmations,
		GasUsed:               receipt.GasUsed,
		ChainIDNumeric:        o.chainID,
		IsFinalized:           true,
	}
	for _, l := range receipt.Logs {
		topics := make([]string, len(l.Topics))
		for i, t := range l.Topics {
			topics[i] = t.Hex()
		}
		result.Logs = append(result.Logs, EventLog{Address: l.Address.Hex(), Topics: topics, Data: l.Data, LogIndex: l.Index})
	}
	if head, err := o.client.BlockNumber(ctx); err == nil && head >= receipt.BlockNumber.Uint64() {
		result.Confirmations = int(head - receipt.BlockNumber.Uint64())
	}
	return result
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
		ChainIDNumeric:        o.chainID,
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

// resultHashInclusionTag opens the part of the result hash that binds the inclusion proofs (RB5-F16).
const resultHashInclusionTag = "certen:evm-observation:inclusion:v1"

// computeResultHash computes a deterministic hash of the observation result: the transaction, its block and status, the
// block's roots, and - domain-tagged and length-prefixed - the exact inclusion proofs and header the observation carries
// (MerkleProof, ReceiptProof, BlockHeaderRLP). A signature over it therefore signs the proofs, byte for byte, that
// VerifyObservationProofs checks; every validator that proves the same settlement from the same block computes the same
// bytes. TRON's observation carries none, and binds that it carries none.
func computeResultHash(result *ObservationResult) [32]byte {
	h := sha256.New()

	h.Write([]byte(result.TxHash))
	h.Write(big.NewInt(int64(result.BlockNumber)).Bytes())
	h.Write([]byte(result.BlockHash))
	h.Write([]byte{result.Status})
	h.Write(result.StateRoot[:])
	h.Write(result.TransactionsRoot[:])
	h.Write(result.ReceiptsRoot[:])

	h.Write([]byte(resultHashInclusionTag))
	var n [8]byte
	for _, part := range [][]byte{result.MerkleProof, result.ReceiptProof, result.BlockHeaderRLP} {
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}

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
