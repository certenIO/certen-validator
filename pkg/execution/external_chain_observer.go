// Copyright 2025 Certen Protocol
//
// External Chain Observer - Watches external chains for transaction finalization
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 7
//
// This service:
// 1. Watches for transaction confirmation on Ethereum
// 2. Waits for finalization (12+ block confirmations)
// 3. Builds the transaction and receipt Merkle-Patricia inclusion proofs (pkg/ethproof)
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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// EXTERNAL CHAIN OBSERVER
// =============================================================================

// ExternalChainObserver watches external chains for transaction finalization
// and constructs cryptographic proofs of execution
type ExternalChainObserver struct {
	ethClient *ethclient.Client
	rpcClient *rpc.Client // RB-5: raw client for eth_getProof (storage-slot state proofs)

	// finality is where a settlement's finality facts come from: independent providers that must agree (RB5-F53).
	// finalityErr says why there is none; every observation is then refused by it, never read from one provider.
	finality    ethrpc.FinalityReader
	finalityErr error
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
	rpcClient, err := ethrpc.DialRPCRetrying(context.Background(), config.EthereumRPC)
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
		timeout = ethrpc.FinalityBound
	}

	// The agreeing reader over this chain's independent providers (RB5-F53). Without it there is no observation: the
	// reason is kept and every ObserveTransaction refuses by it.
	var finality ethrpc.FinalityReader
	agreeing, finalityErr := ethrpc.FinalityReaderForChain(context.Background(), config.ChainID, config.EthereumRPC)
	if finalityErr == nil {
		finality = agreeing
	}

	return &ExternalChainObserver{
		ethClient:             client,
		rpcClient:             rpcClient,
		finality:              finality,
		finalityErr:           finalityErr,
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

	// The transaction's receipt as the FINALIZED chain holds it (RB5-F49): its block is final and canonical, and the
	// receipt is that block's own - not an index entry that may name a block a reorg replaced.
	receipt, err := o.settledInFinalizedChain(ctx, txHash, deadline)
	if err != nil {
		return nil, err
	}

	o.log("✅ [OBSERVER] Transaction %s is in finalized block %d (%s)", txHash.Hex(), receipt.BlockNumber.Uint64(), receipt.BlockHash.Hex())

	// The header bound to the receipt, read by hash from the agreeing providers.
	header, err := o.agreedHeader(ctx, receipt)
	if err != nil {
		return nil, err
	}

	// The transaction itself: read from one provider, and accepted only as the transaction with this hash.
	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}
	if tx == nil || tx.Hash() != txHash {
		return nil, fmt.Errorf("the provider's transaction for %s is not that transaction", txHash.Hex())
	}

	// Compute current confirmations
	currentBlock, err := o.ethClient.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("get current block: %w", err)
	}
	confirmations := int(currentBlock - receipt.BlockNumber.Uint64())

	// Create the external chain result
	result := FromEthereumReceipt(receipt, tx, types.NewBlockWithHeader(header), o.chainID, confirmations, o.validatorID)

	// The transaction and receipt inclusion proofs (RB-2, RB5-F16): built by pkg/ethproof from the block's agreed bodies,
	// checked against the header's roots and verified before they are kept. A block whose proofs cannot be built keeps
	// none, and says why: every caller that needs them refuses by that reason.
	if settlement, err := o.inclusionProofs(ctx, receipt, deadline); err != nil {
		o.log("⚠️ [OBSERVER] No inclusion proofs for %s on chain %d: %v", txHash.Hex(), o.chainID, err)
		result.inclusionErr = err
	} else {
		result.TxInclusionProof = settlement.Tx
		result.ReceiptInclusionProof = settlement.Receipt
	}

	o.log("🎉 [OBSERVER] External chain result complete: hash=%s status=%d", result.ToHex()[:16], result.Status)

	return result, nil
}

// agreedHeader is the header of the receipt's block, read by HASH from the agreeing providers (RB5-F53) and bound to the
// receipt's block hash (RB-2): header.Hash() recomputes the hash from the header's fields, so roots that do not belong to
// that block cannot be served in its name.
func (o *ExternalChainObserver) agreedHeader(ctx context.Context, receipt *types.Receipt) (*types.Header, error) {
	if o.finality == nil {
		return nil, fmt.Errorf("chain %d: no agreeing providers to read block %s with: %v", o.chainID, receipt.BlockHash.Hex(), o.finalityErr)
	}
	header, err := o.finality.HeaderByHash(ctx, receipt.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("get block header: %w", err)
	}
	if header.Hash() != receipt.BlockHash {
		return nil, fmt.Errorf("header binding failed: header.Hash()=%s != receipt.BlockHash=%s (untrusted RPC header)",
			header.Hash().Hex(), receipt.BlockHash.Hex())
	}
	return header, nil
}

// inclusionProofs proves the receipt's transaction and the receipt in their block through pkg/ethproof, from the agreeing
// providers' reads of the block's bodies.
func (o *ExternalChainObserver) inclusionProofs(ctx context.Context, receipt *types.Receipt, deadline time.Time) (*ethproof.Settlement, error) {
	src, ok := o.finality.(ethproof.Source)
	if !ok {
		return nil, fmt.Errorf("chain %d: the finality reader (%T) cannot serve a block's agreed bodies, so no proof is built from it", o.chainID, o.finality)
	}
	return ethproof.BuildWithin(ctx, src, receipt.BlockHash, receipt.TxHash, uint64(receipt.TransactionIndex), deadline, o.pollingInterval)
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

// settledInFinalizedChain is the transaction's receipt as the finalized chain holds it - ethrpc.SettledInFinalizedChain,
// the one rule this observer and the chain strategy's observer share (RB5-F49).
func (o *ExternalChainObserver) settledInFinalizedChain(ctx context.Context, txHash common.Hash, deadline time.Time) (*types.Receipt, error) {
	if o.finality == nil {
		return nil, fmt.Errorf("chain %d: no agreeing providers to observe %s with: %v", o.chainID, txHash.Hex(), o.finalityErr)
	}
	return ethrpc.SettledInFinalizedChain(ctx, o.finality, txHash, deadline, o.pollingInterval, o.log)
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

// settlementAccountABI decodes a settlement on a v3 chain: the execution entry points of CertenAccountV7_2, the account
// factory V10 creates (RB5-F29). It is the artifact-extracted ABI the settlement is sent with
// (contracts.CertenAccountV7_2ABI), so the decoder and the sender cannot drift. Its proof tuple ends in uint64
// authorityPage - the certified key page the leaf binds - where CertenAccountV7's ended in a declared uint8 level.
var settlementAccountABI, settlementAccountABIErr = abi.JSON(strings.NewReader(contracts.CertenAccountV7_2ABI))

// settlementAccountV7_3ABI decodes a settlement to a CertenAccountV7_3 (factory V11, RB5-F57), whose proof tuple ends in
// the window its v4 leaf binds - so its entry points have other selectors than CertenAccountV7_2's.
var settlementAccountV7_3ABI, settlementAccountV7_3ABIErr = abi.JSON(strings.NewReader(contracts.CertenAccountV7_3ABI))

// settlementMethod is the account execution entry point calldata calls and the account generation it belongs to. The
// selector names exactly one generation: the two proof tuples differ, so their selectors do.
func settlementMethod(input []byte) (*abi.Method, AccountLeafVersion, error) {
	if len(input) < 4 {
		return nil, "", fmt.Errorf("no calldata")
	}
	if settlementAccountABIErr != nil {
		return nil, "", fmt.Errorf("account ABI unavailable: %w", settlementAccountABIErr)
	}
	if settlementAccountV7_3ABIErr != nil {
		return nil, "", fmt.Errorf("CertenAccountV7_3 ABI unavailable: %w", settlementAccountV7_3ABIErr)
	}
	if m, err := settlementAccountABI.MethodById(input[:4]); err == nil {
		return m, AccountLeafV3, nil
	}
	if m, err := settlementAccountV7_3ABI.MethodById(input[:4]); err == nil {
		return m, AccountLeafV4, nil
	}
	return nil, "", fmt.Errorf("not a CertenAccountV7_2 call, nor a CertenAccountV7_3 call")
}
