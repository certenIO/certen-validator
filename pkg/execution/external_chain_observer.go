// Copyright 2025 Certen Protocol
//
// External Chain Observer - Watches external chains for transaction finalization
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 7
//
// This service:
// 1. Watches for transaction confirmation on Ethereum
// 2. Waits for finalization (12+ block confirmations)
// 3. Constructs Merkle inclusion proofs for transactions and receipts
// 4. Returns cryptographically verifiable ExternalChainResult

package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// EXTERNAL CHAIN OBSERVER
// =============================================================================

// ExternalChainObserver watches external chains for transaction finalization
// and constructs cryptographic proofs of execution
type ExternalChainObserver struct {
	ethClient   *ethclient.Client
	rpcClient   *rpc.Client // RB-5: raw client for eth_getProof (storage-slot state proofs)
	chainID     int64
	validatorID string

	// Configuration
	requiredConfirmations int           // Number of blocks required for finalization
	pollingInterval       time.Duration // How often to check for new blocks
	timeout               time.Duration // Maximum time to wait for finalization

	// Tracking pending executions
	pending     map[common.Hash]*PendingExecution
	pendingLock sync.RWMutex

	// Callbacks
	onFinalized func(*ExternalChainResult)
	onFailed    func(*PendingExecution, error)

	// State
	running bool
	stopCh  chan struct{}
	logger  Logger
}

// ExternalChainObserverConfig contains configuration for the observer
type ExternalChainObserverConfig struct {
	EthereumRPC           string
	ChainID               int64
	ValidatorID           string
	RequiredConfirmations int           // Default: 12 for Ethereum mainnet, 2 for testnets
	PollingInterval       time.Duration // Default: 12 seconds (1 block time)
	Timeout               time.Duration // Default: 30 minutes
	OnFinalized           func(*ExternalChainResult)
	OnFailed              func(*PendingExecution, error)
	Logger                Logger
}

// NewExternalChainObserver creates a new external chain observer
func NewExternalChainObserver(config *ExternalChainObserverConfig) (*ExternalChainObserver, error) {
	if config.EthereumRPC == "" {
		return nil, fmt.Errorf("ethereum RPC URL required")
	}

	// Dial the raw RPC client so we can derive both the high-level ethclient and the
	// gethclient (RB-5: gethclient exposes eth_getProof for storage-slot state proofs).
	rpcClient, err := rpc.DialContext(context.Background(), config.EthereumRPC)
	if err != nil {
		return nil, fmt.Errorf("connect to ethereum: %w", err)
	}
	client := ethclient.NewClient(rpcClient)

	// Set defaults
	requiredConf := config.RequiredConfirmations
	if requiredConf == 0 {
		requiredConf = 12 // Default for mainnet
	}

	pollingInterval := config.PollingInterval
	if pollingInterval == 0 {
		pollingInterval = 12 * time.Second
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}

	return &ExternalChainObserver{
		ethClient:             client,
		rpcClient:             rpcClient,
		chainID:               config.ChainID,
		validatorID:           config.ValidatorID,
		requiredConfirmations: requiredConf,
		pollingInterval:       pollingInterval,
		timeout:               timeout,
		pending:               make(map[common.Hash]*PendingExecution),
		onFinalized:           config.OnFinalized,
		onFailed:              config.OnFailed,
		stopCh:                make(chan struct{}),
		logger:                config.Logger,
	}, nil
}

// =============================================================================
// CORE OBSERVATION METHODS
// =============================================================================

// ObserveTransaction observes a single transaction until it's finalized
// This is a blocking call that returns when the tx is finalized or times out
func (o *ExternalChainObserver) ObserveTransaction(
	ctx context.Context,
	txHash common.Hash,
) (*ExternalChainResult, error) {

	o.log("📡 [OBSERVER] Starting observation for tx: %s", txHash.Hex())

	startTime := time.Now()
	deadline := startTime.Add(o.timeout)

	// Wait for receipt
	receipt, err := o.waitForReceipt(ctx, txHash, deadline)
	if err != nil {
		return nil, fmt.Errorf("wait for receipt: %w", err)
	}

	o.log("📦 [OBSERVER] Receipt received for tx: %s in block %d", txHash.Hex(), receipt.BlockNumber.Uint64())

	// Wait for finalization (required confirmations)
	err = o.waitForFinalization(ctx, receipt.BlockNumber, deadline)
	if err != nil {
		return nil, fmt.Errorf("wait for finalization: %w", err)
	}

	o.log("✅ [OBSERVER] Transaction finalized with %d confirmations", o.requiredConfirmations)

	// The header bound to the receipt (required), and the full block when this chain's
	// transactions can be decoded (an enrichment, for the inclusion proofs). See fetchBlockForResult.
	block, fullBlock, err := o.fetchBlockForResult(ctx, receipt)
	if err != nil {
		return nil, err
	}

	// Get the transaction
	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}

	// Compute current confirmations
	currentBlock, err := o.ethClient.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("get current block: %w", err)
	}
	confirmations := int(currentBlock - receipt.BlockNumber.Uint64())

	// Create the external chain result
	result := FromEthereumReceipt(receipt, tx, block, o.chainID, confirmations, o.validatorID)

	// Construct Merkle inclusion proofs. From the decoded block when go-ethereum could decode every
	// transaction; otherwise from the raw JSON block, encoding the chain's own transaction types by
	// hand and refusing unless both roots match the header (see raw_block_proofs.go). Never from a
	// partial list: a trie over a subset has the wrong root and proves nothing.
	if fullBlock != nil {
		txProof, err := o.constructTxInclusionProof(ctx, fullBlock, receipt.TransactionIndex)
		if err != nil {
			o.log("⚠️ [OBSERVER] Failed to construct tx inclusion proof: %v", err)
			// Continue without proof - result is still valid from receipt
		} else {
			result.TxInclusionProof = txProof
		}

		receiptProof, err := o.constructReceiptInclusionProof(ctx, fullBlock, receipt)
		if err != nil {
			o.log("⚠️ [OBSERVER] Failed to construct receipt inclusion proof: %v", err)
		} else {
			result.ReceiptInclusionProof = receiptProof
		}
	} else {
		txProof, receiptProof, err := o.inclusionProofsFromRaw(ctx, block.Header(), receipt.TransactionIndex)
		if err != nil {
			o.log("⚠️ [OBSERVER] Inclusion proofs from raw block failed on chain %d: %v", o.chainID, err)
		} else {
			result.TxInclusionProof = txProof
			result.ReceiptInclusionProof = receiptProof
			o.log("✅ [OBSERVER] Inclusion proofs built from the raw block (chain %d); both roots matched the header", o.chainID)
		}
	}

	o.log("🎉 [OBSERVER] External chain result complete: hash=%s status=%d", result.ToHex()[:16], result.Status)

	return result, nil
}

// fetchBlockForResult returns the block the receipt landed in, in two forms: a header-only block
// bound to the receipt (always, or an error), and the fully decoded block when this chain allows it
// (otherwise nil).
//
// WHY TWO. ethclient.BlockByNumber decodes every transaction in the block with go-ethereum's own
// types, and rejects the whole block on the first type it does not know. Every OP-stack block (Base,
// Optimism) carries a type-0x7e deposit transaction, and Arbitrum blocks carry Nitro's own types, so
// on those chains the call fails with "transaction type not supported" — for every block, always.
// Until 2026-09-04 that failure aborted the observation, the RB gate failed, and no contract call on
// Base or Arbitrum could be proved: 54 Base artifacts existed and all were value transfers, which
// never reach this path.
//
// What the result actually needs from the block is the header: its hash (RB-2 binding to the
// receipt's block hash, so a lying RPC cannot substitute roots), its time, and its transactions,
// receipts and state roots. HeaderByNumber decodes only the header, which is the upstream geth
// layout on OP-stack and Nitro chains alike, so the binding and the roots hold there. The full block
// is wanted only to build the Merkle inclusion tries, and those were already best-effort: skipping
// them on a chain whose transactions cannot be decoded loses an enrichment, not the proof of effect,
// which comes from the receipt bound to the header.
func (o *ExternalChainObserver) fetchBlockForResult(
	ctx context.Context,
	receipt *types.Receipt,
) (headerBlock *types.Block, fullBlock *types.Block, err error) {
	header, err := o.ethClient.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("get block header: %w", err)
	}
	// RB-2: bind the fetched header to the receipt's block hash. header.Hash() recomputes the hash
	// from the header fields; if a lying RPC served a header whose TransactionsRoot/ReceiptsRoot do
	// not belong to the canonical block, this catches it before those roots are treated as
	// authoritative.
	if header.Hash() != receipt.BlockHash {
		return nil, nil, fmt.Errorf("header binding failed: header.Hash()=%s != receipt.BlockHash=%s (untrusted RPC header)",
			header.Hash().Hex(), receipt.BlockHash.Hex())
	}
	headerBlock = types.NewBlockWithHeader(header)

	full, err := o.ethClient.BlockByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		o.log("ℹ️ [OBSERVER] Full block %d not decodable by go-ethereum on chain %d (%v) — inclusion proofs will be built from the raw block",
			receipt.BlockNumber.Uint64(), o.chainID, err)
		return headerBlock, nil, nil
	}
	if full.Hash() != receipt.BlockHash {
		return nil, nil, fmt.Errorf("header binding failed: block.Hash()=%s != receipt.BlockHash=%s (untrusted RPC block)",
			full.Hash().Hex(), receipt.BlockHash.Hex())
	}
	return headerBlock, full, nil
}

// =============================================================================
// INTERNAL WAITING METHODS
// =============================================================================

// waitForReceipt polls for the transaction receipt
func (o *ExternalChainObserver) waitForReceipt(
	ctx context.Context,
	txHash common.Hash,
	deadline time.Time,
) (*types.Receipt, error) {

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

			receipt, err := o.ethClient.TransactionReceipt(ctx, txHash)
			if err == ethereum.NotFound {
				continue // Transaction not yet mined
			}
			if err != nil {
				o.log("⚠️ [OBSERVER] Error getting receipt: %v", err)
				continue
			}

			return receipt, nil
		}
	}
}

// waitForFinalization waits for the required number of block confirmations
func (o *ExternalChainObserver) waitForFinalization(
	ctx context.Context,
	txBlockNumber *big.Int,
	deadline time.Time,
) error {

	ticker := time.NewTicker(o.pollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for finalization")
			}

			currentBlock, err := o.ethClient.BlockNumber(ctx)
			if err != nil {
				o.log("⚠️ [OBSERVER] Error getting block number: %v", err)
				continue
			}

			confirmations := int(currentBlock - txBlockNumber.Uint64())
			if confirmations >= o.requiredConfirmations {
				return nil
			}

			o.log("⏳ [OBSERVER] Waiting for finalization: %d/%d confirmations",
				confirmations, o.requiredConfirmations)
		}
	}
}

// =============================================================================
// MERKLE PROOF CONSTRUCTION
// =============================================================================

// constructTxInclusionProof constructs a Merkle proof that the transaction
// is included in the block's transaction trie
func (o *ExternalChainObserver) constructTxInclusionProof(
	ctx context.Context,
	block *types.Block,
	txIndex uint,
) (*MerkleInclusionProof, error) {

	txs := block.Transactions()
	if int(txIndex) >= len(txs) {
		return nil, fmt.Errorf("tx index %d out of range", txIndex)
	}

	// Build the transaction trie. RB-2: use the canonical consensus encoding
	// (tx.MarshalBinary — typed-aware EIP-2718 envelope for typed txs, RLP for legacy)
	// so the trie root equals the block header's TransactionsRoot; otherwise the
	// independent VerifyProof against block.TxHash() would reject valid typed-tx proofs.
	txTrie := trie.NewEmpty(nil)
	for i, tx := range txs {
		key, _ := rlp.EncodeToBytes(uint(i))
		val, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode tx %d: %w", i, err)
		}
		txTrie.Update(key, val)
	}

	// Get the proof path
	key, _ := rlp.EncodeToBytes(uint(txIndex))
	proof := NewMerkleProofCollector()
	if err := txTrie.Prove(key, proof); err != nil {
		return nil, fmt.Errorf("generate tx proof: %w", err)
	}

	// Convert to our proof format
	tx := txs[txIndex]
	txRLP, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode leaf tx: %w", err)
	}
	leafHash := crypto.Keccak256Hash(txRLP)

	return &MerkleInclusionProof{
		LeafHash:        [32]byte(leafHash),
		LeafIndex:       uint64(txIndex),
		ProofHashes:     proof.GetHashes(),
		ProofDirections: proof.GetDirections(),
		ExpectedRoot:    [32]byte(block.TxHash()), // RB-2: bound to the block header's TxHash
		ProofNodes:      proof.GetNodes(),         // RB-2: raw proof set for independent VerifyProof
		LeafValue:       txRLP,                    // RB-2: exact RLP(tx) the proof must resolve to
		Verified:        true,                     // legacy flag; Verify() no longer trusts it
	}, nil
}

// constructReceiptInclusionProof constructs a Merkle proof that the receipt
// is included in the block's receipt trie
func (o *ExternalChainObserver) constructReceiptInclusionProof(
	ctx context.Context,
	block *types.Block,
	receipt *types.Receipt,
) (*MerkleInclusionProof, error) {

	// RB-2 / RB-SEC-1: fetch ALL receipts in ONE call (eth_getBlockReceipts) instead of one
	// RPC per tx. Under concurrent peer verification, N-per-tx fetches across the fleet
	// rate-limit the shared RPC and cause spurious proof-construction failures (nil proof →
	// honest peers wrongly refuse valid calls).
	txs := block.Transactions()
	receipts, err := o.ethClient.BlockReceipts(ctx, rpc.BlockNumberOrHashWithHash(block.Hash(), false))
	if err != nil {
		return nil, fmt.Errorf("get block receipts: %w", err)
	}
	if len(receipts) != len(txs) {
		return nil, fmt.Errorf("block receipts count %d != tx count %d", len(receipts), len(txs))
	}

	if int(receipt.TransactionIndex) >= len(receipts) {
		return nil, fmt.Errorf("receipt index %d out of range", receipt.TransactionIndex)
	}

	// Build the receipt trie. RB-2: use the canonical consensus encoding
	// (receipt.MarshalBinary — typed-aware) so the trie root equals the block header's
	// ReceiptsRoot, enabling independent VerifyProof against block.ReceiptHash().
	receiptTrie := trie.NewEmpty(nil)
	for i, r := range receipts {
		key, _ := rlp.EncodeToBytes(uint(i))
		val, err := r.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode receipt %d: %w", i, err)
		}
		receiptTrie.Update(key, val)
	}

	// Get the proof path
	key, _ := rlp.EncodeToBytes(uint(receipt.TransactionIndex))
	proof := NewMerkleProofCollector()
	if err := receiptTrie.Prove(key, proof); err != nil {
		return nil, fmt.Errorf("generate receipt proof: %w", err)
	}

	// Convert to our proof format
	receiptRLP, err := receipt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode leaf receipt: %w", err)
	}
	leafHash := crypto.Keccak256Hash(receiptRLP)

	return &MerkleInclusionProof{
		LeafHash:        [32]byte(leafHash),
		LeafIndex:       uint64(receipt.TransactionIndex),
		ProofHashes:     proof.GetHashes(),
		ProofDirections: proof.GetDirections(),
		ExpectedRoot:    [32]byte(block.ReceiptHash()), // RB-2: bound to the block header's ReceiptHash
		ProofNodes:      proof.GetNodes(),              // RB-2: raw proof set for independent VerifyProof
		LeafValue:       receiptRLP,                    // RB-2: exact RLP(receipt) the proof must resolve to
		Verified:        true,                          // legacy flag; Verify() no longer trusts it
	}, nil
}

// =============================================================================
// RB-5: STORAGE-SLOT STATE PROOF FETCH (eth_getProof)
// =============================================================================

// fetchStateProofs fetches eth_getProof for each committed (account, slot) at the given
// block and converts the results into independently verifiable StateProofs. Slots are
// grouped per account to minimize RPC calls. Returns nil if no gethclient is available.
func (o *ExternalChainObserver) fetchStateProofs(ctx context.Context, blockNumber *big.Int, slots []ExpectedStateSlot) []*StateProof {
	if o.rpcClient == nil || len(slots) == 0 {
		return nil
	}
	byAccount := make(map[common.Address][]common.Hash)
	order := make([]common.Address, 0)
	for _, s := range slots {
		if _, ok := byAccount[s.Account]; !ok {
			order = append(order, s.Account)
		}
		byAccount[s.Account] = append(byAccount[s.Account], s.Slot)
	}

	blockArg := "latest"
	if blockNumber != nil {
		blockArg = "0x" + blockNumber.Text(16)
	}

	var proofs []*StateProof
	for _, account := range order {
		keys := make([]string, 0, len(byAccount[account]))
		for _, slot := range byAccount[account] {
			keys = append(keys, slot.Hex())
		}
		var res EthGetProofResult
		if err := o.rpcClient.CallContext(ctx, &res, "eth_getProof", account, keys, blockArg); err != nil {
			o.log("⚠️ [OBSERVER] eth_getProof failed for %s: %v", account.Hex(), err)
			continue
		}
		for _, slot := range byAccount[account] {
			sp, err := StateProofFromRPC(&res, account, slot)
			if err != nil {
				o.log("⚠️ [OBSERVER] state proof build failed for %s[%s]: %v", account.Hex(), slot.Hex(), err)
				continue
			}
			proofs = append(proofs, sp)
		}
	}
	return proofs
}

// =============================================================================
// MERKLE PROOF COLLECTOR (implements ethdb.KeyValueWriter for trie.Prove)
// =============================================================================

// MerkleProofCollector collects proof nodes during trie proving
type MerkleProofCollector struct {
	nodes      map[string][]byte
	order      []string
	hashes     [][32]byte
	directions []uint8
}

// NewMerkleProofCollector creates a new proof collector
func NewMerkleProofCollector() *MerkleProofCollector {
	return &MerkleProofCollector{
		nodes:      make(map[string][]byte),
		order:      make([]string, 0),
		hashes:     make([][32]byte, 0),
		directions: make([]uint8, 0),
	}
}

// Put implements ethdb.KeyValueWriter
// Per CERTEN spec: Ethereum Patricia Trie uses Keccak256, NOT SHA256
func (c *MerkleProofCollector) Put(key []byte, value []byte) error {
	keyStr := string(key)
	c.nodes[keyStr] = value
	c.order = append(c.order, keyStr)

	// The key IS the Keccak256 hash of the node value (from go-ethereum trie)
	// Use the key directly as the hash instead of recomputing
	// This ensures compatibility with Ethereum's native hash function
	var hash [32]byte
	if len(key) == 32 {
		// Key is already the Keccak256 hash from the trie
		copy(hash[:], key)
	} else {
		// Fallback: compute Keccak256 if key is not a hash (shouldn't happen)
		hash = crypto.Keccak256Hash(value)
	}
	c.hashes = append(c.hashes, hash)

	// Direction based on key nibble (for Patricia trie traversal)
	if len(key) > 0 {
		c.directions = append(c.directions, key[0]&0x01)
	} else {
		c.directions = append(c.directions, 0)
	}

	return nil
}

// Delete implements ethdb.KeyValueWriter
func (c *MerkleProofCollector) Delete(key []byte) error {
	delete(c.nodes, string(key))
	return nil
}

// GetHashes returns the collected proof hashes
func (c *MerkleProofCollector) GetHashes() [][32]byte {
	return c.hashes
}

// GetDirections returns the proof directions
func (c *MerkleProofCollector) GetDirections() []uint8 {
	return c.directions
}

// GetNodes returns the raw RLP-encoded proof nodes in the order they were emitted
// by trie.Prove (root → leaf). RB-2: this is the proof set independently re-verified
// by MerkleInclusionProof.Verify via trie.VerifyProof.
func (c *MerkleProofCollector) GetNodes() [][]byte {
	nodes := make([][]byte, 0, len(c.order))
	for _, k := range c.order {
		nodes = append(nodes, c.nodes[k])
	}
	return nodes
}

// =============================================================================
// BACKGROUND OBSERVATION SERVICE
// =============================================================================

// =============================================================================
// LOGGING
// =============================================================================

func (o *ExternalChainObserver) log(format string, args ...interface{}) {
	if o.logger != nil {
		o.logger.Printf(format, args...)
	}
}

// =============================================================================
// UTILITY METHODS
// =============================================================================

// settlementAccountABI decodes a settlement: the execution entry points of CertenAccountV7_2, the account factory V10
// creates and the only one a V8.2 tree settles (RB5-F29). It is the artifact-extracted ABI the settlement is sent with
// (contracts.CertenAccountV7_2ABI), so the decoder and the sender cannot drift. Its proof tuple ends in uint64
// authorityPage - the certified key page the leaf binds - where CertenAccountV7's ended in a declared uint8 level.
var settlementAccountABI, settlementAccountABIErr = abi.JSON(strings.NewReader(contracts.CertenAccountV7_2ABI))
