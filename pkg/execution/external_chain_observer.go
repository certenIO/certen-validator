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

// certenAccountABI is parsed once for decoding the V6.1 abstract-account execution wrapper
// (executeGovernanceProofDirect). Nil only if the generated metadata fails to parse, in which
// case EffectHasCalldata falls back to the raw-tx check.
var certenAccountABI, _ = contracts.CertenAccountV2MetaData.GetAbi()

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
	commitment *ExecutionCommitment,
) (*ExternalChainResult, error) {

	o.log("📡 [OBSERVER] Starting observation for tx: %s", txHash.Hex())

	startTime := time.Now()
	deadline := startTime.Add(o.timeout)

	// Create pending execution tracker
	pending := &PendingExecution{
		TxHash:                txHash,
		SubmittedAt:           startTime,
		RequiredConfirmations: o.requiredConfirmations,
		Status:                "pending",
	}

	if commitment != nil {
		pending.OperationID = commitment.OperationID
		pending.ExpectedTarget = commitment.TargetContract
		pending.ExpectedValue = commitment.ExpectedValue
	}

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

	// Construct Merkle inclusion proofs — only from a block whose every transaction decoded, since
	// a trie built from a partial transaction list has the wrong root and proves nothing.
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
	}

	// RB-5: if the intent committed storage-slot effects, fetch and attach state proofs
	// so the commitment gate can independently verify them against the block stateRoot.
	if commitment != nil && len(commitment.ExpectedState) > 0 {
		result.StateProofs = o.fetchStateProofs(ctx, receipt.BlockNumber, commitment.ExpectedState)
	}

	// Verify commitment if provided
	if commitment != nil {
		o.log("🔍 [OBSERVER] Commitment provided, verifying against result...")
		if !commitment.VerifyAgainstResult(result) {
			o.log("❌ [OBSERVER] Commitment verification FAILED")
			return nil, fmt.Errorf("result does not match execution commitment")
		}
		o.log("✅ [OBSERVER] Result verified against execution commitment")
	} else {
		o.log("⏭️ [OBSERVER] No commitment provided, skipping verification")
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
		o.log("⚠️ [OBSERVER] Full block %d not decodable on chain %d (%v) — inclusion proofs skipped; header binding and receipt verification still apply",
			receipt.BlockNumber.Uint64(), o.chainID, err)
		return headerBlock, nil, nil
	}
	if full.Hash() != receipt.BlockHash {
		return nil, nil, fmt.Errorf("header binding failed: block.Hash()=%s != receipt.BlockHash=%s (untrusted RPC block)",
			full.Hash().Hex(), receipt.BlockHash.Hex())
	}
	return headerBlock, full, nil
}

// TrackExecution adds an execution to be tracked asynchronously
func (o *ExternalChainObserver) TrackExecution(pending *PendingExecution) {
	o.pendingLock.Lock()
	defer o.pendingLock.Unlock()
	o.pending[pending.TxHash] = pending
	o.log("📝 [OBSERVER] Tracking execution: %s", pending.TxHash.Hex())
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

// VerifyExecutedCall is the RB-2/RB-4/RB-5 attestation gate for a proof-gated contract
// call. It independently re-observes the executed governance transaction and:
//   - RB-2: rebuilds the tx & receipt inclusion proofs (canonical encoding, header-bound)
//     and verifies them via go-ethereum trie.VerifyProof against the block roots;
//   - RB-4: requires every committed event to appear in the inclusion-proven receipt logs
//     (the call's effect — an internal-call event by the target — not just non-revert);
//   - RB-5: if committed state slots are present, fetches eth_getProof and verifies each
//     slot holds the committed value against the finalized stateRoot.
//
// Returns an error (⇒ caller must refuse to attest / write back) on any failure. The
// outer tx targets the abstract account, not the call target, so this deliberately does
// NOT use VerifyAgainstResult (which checks the outer target/selector); it checks the
// receipt logs directly, which capture the target's event via the internal call.
func (o *ExternalChainObserver) VerifyExecutedCall(
	ctx context.Context,
	txHash common.Hash,
	expectedEvents []ExpectedEvent,
	expectedState []ExpectedStateSlot,
) (*ExternalChainResult, error) {
	// Observe (nil commitment ⇒ build result + inclusion proofs, skip outer-target checks).
	result, err := o.ObserveTransaction(ctx, txHash, nil)
	if err != nil {
		return nil, fmt.Errorf("observe executed call tx %s: %w", txHash.Hex(), err)
	}
	if result.Status != 1 {
		return nil, fmt.Errorf("executed call tx %s failed (status=%d)", txHash.Hex(), result.Status)
	}

	// RB-2: independently verify tx + receipt inclusion against the header roots.
	if result.TxInclusionProof == nil || !result.TxInclusionProof.Verify() {
		return nil, fmt.Errorf("RB-2: tx inclusion proof failed to verify for %s", txHash.Hex())
	}
	if result.ReceiptInclusionProof == nil || !result.ReceiptInclusionProof.Verify() {
		return nil, fmt.Errorf("RB-2: receipt inclusion proof failed to verify for %s", txHash.Hex())
	}

	gate := &ExecutionCommitment{ExpectedCallEvents: expectedEvents, ExpectedState: expectedState}

	// RB-4: the committed event(s) must be present in the inclusion-proven receipt logs.
	if len(expectedEvents) > 0 {
		if !gate.verifyExpectedEventsStrict(result, expectedEvents) {
			return nil, fmt.Errorf("RB-4: committed event(s) not found in inclusion-proven logs for %s", txHash.Hex())
		}
	}

	// RB-5: optional storage-slot state proofs against the finalized stateRoot.
	if len(expectedState) > 0 {
		result.StateProofs = o.fetchStateProofs(ctx, result.BlockNumber, expectedState)
		if !gate.verifyExpectedState(result) {
			return nil, fmt.Errorf("RB-5: committed state slot(s) not proven for %s", txHash.Hex())
		}
	}

	return result, nil
}

// TxHasCalldata reports whether the on-chain execution tx carries non-empty input data,
// i.e. it is a contract call rather than a native value transfer. This is executor-
// INDEPENDENT ground truth (read straight from the chain), used by peer verification to
// cross-check the "is contract call" classification against what actually executed —
// closing the forged-intent-pointer bypass where an executor claims a call was "native".
// Fails closed: any RPC/lookup error is returned to the caller to refuse on.
func (o *ExternalChainObserver) TxHasCalldata(ctx context.Context, txHash common.Hash) (bool, error) {
	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil {
		return false, fmt.Errorf("fetch execution tx %s: %w", txHash.Hex(), err)
	}
	if tx == nil {
		return false, fmt.Errorf("execution tx %s not found", txHash.Hex())
	}
	return len(tx.Data()) > 0, nil
}

// EffectHasCalldata reports whether the EXECUTED EFFECT carried calldata — i.e. whether the
// value-moving call was a contract call rather than a native transfer. This is the correct
// signal for RB-SEC-1's "native classification" cross-check.
//
// In the V6.1 model the execution tx is a call to the user's abstract account via
//
//	executeGovernanceProofDirect(address target, uint256 value, bytes data, <proof>)
//
// so the OUTER tx input is ALWAYS non-empty (it is the account-method call itself). Using
// len(tx.Data())>0 there would flag every native transfer as a contract call and make peers
// refuse to attest (the Phase-8 quorum failure). The real effect is the INNER `data` the
// account forwards to `target`; this decodes that argument via the account ABI. For any
// non-wrapper (legacy direct-call) execution shape it falls back to the raw tx calldata.
func (o *ExternalChainObserver) EffectHasCalldata(ctx context.Context, txHash common.Hash) (bool, error) {
	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil {
		return false, fmt.Errorf("fetch execution tx %s: %w", txHash.Hex(), err)
	}
	if tx == nil {
		return false, fmt.Errorf("execution tx %s not found", txHash.Hex())
	}
	input := tx.Data()

	inner, matched, derr := decodeAbstractAccountEffectCalldata(input)
	if derr != nil {
		// Selector matched the wrapper but the body won't decode — anomalous; fail closed so
		// the caller refuses rather than silently treating it as native.
		return false, fmt.Errorf("cross-check %s: %w", txHash.Hex(), derr)
	}
	if matched {
		return inner, nil
	}

	// Legacy / direct execution: the tx input IS the effect calldata.
	return len(input) > 0, nil
}

// decodeAbstractAccountEffectCalldata inspects a raw execution-tx input. If it is the V6.1
// abstract-account executeGovernanceProofDirect(target,value,data,proof) wrapper, it returns
// (innerHasCalldata, true, nil) — where innerHasCalldata reflects the INNER `data` the account
// forwards to `target`. If the input is not that wrapper, it returns (false, false, nil) and the
// caller should use the raw-input length. If it IS the wrapper but the body won't decode, it
// returns (false, true, err) so the caller fails closed. Pure/uses only the parsed ABI so it is
// unit-testable without an RPC.
func decodeAbstractAccountEffectCalldata(input []byte) (innerHasCalldata bool, matched bool, err error) {
	if len(input) < 4 {
		return false, false, nil
	}

	// Try every known account ABI, not just one.
	//
	// This matched ONLY the CertenAccountV2 binding. Accounts minted by factory V9 are
	// CertenAccountV7, whose ADIGovernanceProof tuple gained operationID — a different type list,
	// therefore a different 4-byte selector. MethodById missed, the function reported
	// matched=false, and EffectHasCalldata fell back to `len(input) > 0` on the OUTER wrapper
	// input, which is never empty. So every native-transfer intent looked like a contract call
	// and every peer refused to attest with
	//
	//	execution tx … carries calldata but committed intent has no contract-call leg
	//
	// leaving Phase 8 at achieved=1 of required=5 and blocking every write-back to
	// acc://certen-protocol.acme/execution-results from 2026-07-29. A version-specific decoder is
	// a latent version trap: each new account release silently re-breaks attestation. Matching
	// across all known ABIs by NAME removes that.
	for _, abiDef := range certenAccountABIs() {
		if abiDef == nil {
			continue
		}
		m, mErr := abiDef.MethodById(input[:4])
		if mErr != nil {
			continue
		}
		switch m.Name {
		case "executeGovernanceProofDirect":
			args, uErr := m.Inputs.Unpack(input[4:])
			if uErr != nil {
				return false, true, fmt.Errorf("decode %s wrapper: %w", m.Name, uErr)
			}
			// (target address, value uint256, data bytes, proof tuple) — data is index 2.
			if len(args) < 3 {
				return false, true, fmt.Errorf("unexpected %s arg count (%d)", m.Name, len(args))
			}
			data, ok := args[2].([]byte)
			if !ok {
				return false, true, fmt.Errorf("unexpected inner data type in %s", m.Name)
			}
			return len(data) > 0, true, nil

		case "batchExecuteGovernanceProofDirect":
			args, uErr := m.Inputs.Unpack(input[4:])
			if uErr != nil {
				return false, true, fmt.Errorf("decode %s wrapper: %w", m.Name, uErr)
			}
			// (targets address[], values uint256[], datas bytes[], proof tuple) — datas is index 2.
			if len(args) < 3 {
				return false, true, fmt.Errorf("unexpected %s arg count (%d)", m.Name, len(args))
			}
			datas, ok := args[2].([][]byte)
			if !ok {
				return false, true, fmt.Errorf("unexpected inner datas type in %s", m.Name)
			}
			// A multi-leg batch is a contract call if ANY leg carries calldata. Requiring all of
			// them would let a contract-call leg ride along beside native legs unverified.
			for _, d := range datas {
				if len(d) > 0 {
					return true, true, nil
				}
			}
			return false, true, nil
		}
	}

	// Not an account wrapper: legacy / direct execution, where the tx input IS the effect.
	return false, false, nil
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

// Start begins the background observation service
func (o *ExternalChainObserver) Start() {
	if o.running {
		return
	}
	o.running = true
	go o.observeLoop()
	o.log("🚀 [OBSERVER] Background observation service started")
}

// Stop stops the background observation service
func (o *ExternalChainObserver) Stop() {
	if !o.running {
		return
	}
	o.running = false
	close(o.stopCh)
	o.log("🛑 [OBSERVER] Background observation service stopped")
}

// observeLoop is the main background loop that checks pending executions
func (o *ExternalChainObserver) observeLoop() {
	ticker := time.NewTicker(o.pollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-o.stopCh:
			return
		case <-ticker.C:
			o.checkPendingExecutions()
		}
	}
}

// checkPendingExecutions checks all pending executions for finalization
func (o *ExternalChainObserver) checkPendingExecutions() {
	o.pendingLock.Lock()
	pending := make([]*PendingExecution, 0, len(o.pending))
	for _, p := range o.pending {
		pending = append(pending, p)
	}
	o.pendingLock.Unlock()

	ctx := context.Background()

	for _, p := range pending {
		// Check if timed out
		if time.Since(p.SubmittedAt) > o.timeout {
			o.handleTimeout(p)
			continue
		}

		// Try to get result
		result, err := o.checkExecution(ctx, p)
		if err != nil {
			// F.4 remediation: Handle expected "not yet" errors gracefully
			if err == ErrNotYetMined || err == ErrNotYetFinalized {
				// Expected state - transaction still pending
				continue
			}
			o.log("⚠️ [OBSERVER] Error checking execution %s: %v", p.TxHash.Hex(), err)
			continue
		}

		if result != nil {
			o.handleFinalized(p, result)
		}
	}
}

// checkExecution checks a single pending execution
func (o *ExternalChainObserver) checkExecution(ctx context.Context, p *PendingExecution) (*ExternalChainResult, error) {
	receipt, err := o.ethClient.TransactionReceipt(ctx, p.TxHash)
	if err == ethereum.NotFound {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrNotYetMined
	}
	if err != nil {
		return nil, err
	}

	// Check confirmations
	currentBlock, err := o.ethClient.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	confirmations := int(currentBlock - receipt.BlockNumber.Uint64())
	p.CurrentConfirmations = confirmations
	p.LastCheckedAt = time.Now()

	if confirmations < o.requiredConfirmations {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrNotYetFinalized
	}

	// Header bound to the receipt (required) and the full block when decodable (see fetchBlockForResult).
	block, fullBlock, err := o.fetchBlockForResult(ctx, receipt)
	if err != nil {
		return nil, err
	}

	tx, _, err := o.ethClient.TransactionByHash(ctx, p.TxHash)
	if err != nil {
		return nil, err
	}

	result := FromEthereumReceipt(receipt, tx, block, o.chainID, confirmations, o.validatorID)

	// Construct proofs — only from a fully decoded block (a partial list has the wrong root).
	if fullBlock != nil {
		txProof, _ := o.constructTxInclusionProof(ctx, fullBlock, receipt.TransactionIndex)
		result.TxInclusionProof = txProof
		receiptProof, _ := o.constructReceiptInclusionProof(ctx, fullBlock, receipt)
		result.ReceiptInclusionProof = receiptProof
	}

	return result, nil
}

// handleFinalized handles a finalized execution
func (o *ExternalChainObserver) handleFinalized(p *PendingExecution, result *ExternalChainResult) {
	o.pendingLock.Lock()
	delete(o.pending, p.TxHash)
	o.pendingLock.Unlock()

	p.Status = "finalized"

	o.log("🎉 [OBSERVER] Execution finalized: %s", p.TxHash.Hex())

	if o.onFinalized != nil {
		o.onFinalized(result)
	}
}

// handleTimeout handles a timed-out execution
func (o *ExternalChainObserver) handleTimeout(p *PendingExecution) {
	o.pendingLock.Lock()
	delete(o.pending, p.TxHash)
	o.pendingLock.Unlock()

	p.Status = "timeout"

	o.log("⏰ [OBSERVER] Execution timed out: %s", p.TxHash.Hex())

	if o.onFailed != nil {
		o.onFailed(p, fmt.Errorf("execution timed out after %v", o.timeout))
	}
}

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

// GetPendingCount returns the number of pending executions
func (o *ExternalChainObserver) GetPendingCount() int {
	o.pendingLock.RLock()
	defer o.pendingLock.RUnlock()
	return len(o.pending)
}

// GetPendingExecution returns a pending execution by tx hash
func (o *ExternalChainObserver) GetPendingExecution(txHash common.Hash) *PendingExecution {
	o.pendingLock.RLock()
	defer o.pendingLock.RUnlock()
	return o.pending[txHash]
}

// IsRunning returns true if the observer is running
func (o *ExternalChainObserver) IsRunning() bool {
	return o.running
}

// certenAccountV7ABIJSON declares the V7 execution wrappers.
//
// Hand-declared because the validator has no generated V7 binding, and the decoder must not depend
// on one existing. Only the two entry points that carry an effect are needed — the proof tuple is
// spelled out solely so the selector matches; nothing reads its fields here.
//
// ADIGovernanceProof: (string adiURL, bytes32 anchorId, bytes32[] merkleProof, bytes32 operationID,
// bytes keyBookProof, bytes roleProof, bytes thresholdProof, uint256 timestamp, uint256 expiresAt,
// bytes validatorSignatures, uint256 nonce, AuthorityLevel requiredLevel) — the enum is uint8.
const certenAccountV7ABIJSON = `[
 {"type":"function","name":"executeGovernanceProofDirect","stateMutability":"nonpayable","outputs":[],
  "inputs":[
   {"name":"target","type":"address"},
   {"name":"value","type":"uint256"},
   {"name":"data","type":"bytes"},
   {"name":"proof","type":"tuple","components":[
     {"name":"adiURL","type":"string"},
     {"name":"anchorId","type":"bytes32"},
     {"name":"merkleProof","type":"bytes32[]"},
     {"name":"operationID","type":"bytes32"},
     {"name":"keyBookProof","type":"bytes"},
     {"name":"roleProof","type":"bytes"},
     {"name":"thresholdProof","type":"bytes"},
     {"name":"timestamp","type":"uint256"},
     {"name":"expiresAt","type":"uint256"},
     {"name":"validatorSignatures","type":"bytes"},
     {"name":"nonce","type":"uint256"},
     {"name":"requiredLevel","type":"uint8"}]}]},
 {"type":"function","name":"batchExecuteGovernanceProofDirect","stateMutability":"nonpayable","outputs":[],
  "inputs":[
   {"name":"targets","type":"address[]"},
   {"name":"values","type":"uint256[]"},
   {"name":"datas","type":"bytes[]"},
   {"name":"proof","type":"tuple","components":[
     {"name":"adiURL","type":"string"},
     {"name":"anchorId","type":"bytes32"},
     {"name":"merkleProof","type":"bytes32[]"},
     {"name":"operationID","type":"bytes32"},
     {"name":"keyBookProof","type":"bytes"},
     {"name":"roleProof","type":"bytes"},
     {"name":"thresholdProof","type":"bytes"},
     {"name":"timestamp","type":"uint256"},
     {"name":"expiresAt","type":"uint256"},
     {"name":"validatorSignatures","type":"bytes"},
     {"name":"nonce","type":"uint256"},
     {"name":"requiredLevel","type":"uint8"}]}]}]`

var certenAccountV7ABI, certenAccountV7ABIErr = abi.JSON(strings.NewReader(certenAccountV7ABIJSON))

// certenAccountABIs returns every account ABI the decoder should try, newest first.
//
// Add each new account version here. A version absent from this list is not a decode failure — it
// silently degrades to treating the wrapper input as the effect, which is exactly the false
// positive that stopped attestation for six days.
func certenAccountABIs() []*abi.ABI {
	out := make([]*abi.ABI, 0, 2)
	if certenAccountV7ABIErr == nil {
		out = append(out, &certenAccountV7ABI)
	}
	if certenAccountABI != nil {
		out = append(out, certenAccountABI)
	}
	return out
}
