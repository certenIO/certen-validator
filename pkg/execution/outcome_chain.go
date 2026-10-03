package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// The outcome path's reads of a chain, through independent providers that agree (RB5 D4, RB5-F53)
// =============================================================================
//
// Contract state is read at a RECENT block every provider holds (ethrpc.RecentAgreedHeader), never at the finalized
// block: a provider that keeps no historical state cannot serve the finalized block's state at all (Arbitrum Sepolia's
// publicnode, measured 2026-10-03: "historical state ... is not available"). Every fact read there is monotonic and
// write-once - a consumed leaf stays consumed, an anchor's proofExecuted stays set, an outcome root is written once - so
// "not consumed at a recent block" holds at every earlier block, and a fact that must be FINAL is tied to the finalized
// chain through the block its own transaction mined in: at or below the agreed finalized block, canonical at its height.

// outcomeObserveTimeout bounds an observation the outcome path makes. It observes only transactions it has already
// read as final, so the observation does not wait on finality.
const outcomeObserveTimeout = 2 * time.Minute

// OutcomeAnchorView is a batch anchor and its outcome registry as independent providers agree on them at one recent
// block.
type OutcomeAnchorView struct {
	At             *types.Header
	Anchor         *contracts.AnchorState
	LeafCount      uint64
	CurrentSetRoot [32]byte // the anchor's currentValidatorSetRoot
	RecordedRoot   [32]byte // the registry's outcomeRoots(bundleId); zero until recorded
	RecordedIn     uint64   // the registry's recordedInBlock(bundleId)
}

// OutcomeAnchorReader reads an anchor and its outcome registry.
type OutcomeAnchorReader interface {
	AnchorView(ctx context.Context, bundleID [32]byte) (*OutcomeAnchorView, error)
	// OutcomeMessage is the registry's own outcomeMessage(bundleId, root) at the view's block.
	OutcomeMessage(ctx context.Context, bundleID, root [32]byte, at *types.Header) ([32]byte, error)
}

// OutcomeChainReader is everything the outcome peer and recorder read of one chain.
type OutcomeChainReader interface {
	OutcomeChain
	OutcomeAnchorReader
}

var (
	outcomeAnchorABI   = mustParseABI(contracts.CertenAnchorV8_2BatchABI)
	outcomeRegistryABI = mustParseABI(contracts.CertenOutcomeRegistryV1ABI)
	outcomeAccountABI  = mustParseABI(contracts.CertenAccountV7_2ABI)
)

func mustParseABI(j string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(j))
	if err != nil {
		panic(err)
	}
	return a
}

// AgreedOutcomeChain is OutcomeChainReader over a chain's independent providers.
type AgreedOutcomeChain struct {
	chainID  int64
	reader   *ethrpc.AgreeingReader
	observer *ExternalChainObserver
	anchor   common.Address
	registry common.Address

	mu       sync.Mutex
	consumed map[string]*LeafConsumption // final consumptions, by account and leaf: they never change
}

// NewAgreedOutcomeChain dials the chain's independent providers (its primary rpcURL and its configured fallbacks; at
// least ethrpc.MinAgreeingProviders distinct hosts, or it refuses) for the anchor and its outcome registry.
func NewAgreedOutcomeChain(ctx context.Context, chainID int64, rpcURL string, anchor, registry common.Address) (*AgreedOutcomeChain, error) {
	reader, err := ethrpc.FinalityReaderForChain(ctx, chainID, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("outcome reads of chain %d: %w", chainID, err)
	}
	obs, err := NewExternalChainObserver(&ExternalChainObserverConfig{EthereumRPC: rpcURL, ChainID: chainID, ValidatorID: "outcome",
		RequiredConfirmations: 1, PollingInterval: 2 * time.Second, Timeout: outcomeObserveTimeout})
	if err != nil {
		return nil, fmt.Errorf("outcome reads of chain %d: %w", chainID, err)
	}
	if obs.finality == nil {
		return nil, fmt.Errorf("outcome reads of chain %d: %v", chainID, obs.finalityErr)
	}
	return &AgreedOutcomeChain{chainID: chainID, reader: reader, observer: obs, anchor: anchor, registry: registry,
		consumed: map[string]*LeafConsumption{}}, nil
}

func (c *AgreedOutcomeChain) ChainID() int64 { return c.chainID }

func (c *AgreedOutcomeChain) FinalizedHeader(ctx context.Context) (*types.Header, error) {
	return c.reader.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
}

func (c *AgreedOutcomeChain) HeaderAt(ctx context.Context, number uint64) (*types.Header, error) {
	return c.reader.HeaderByNumber(ctx, new(big.Int).SetUint64(number))
}

func (c *AgreedOutcomeChain) call(ctx context.Context, parsed abi.ABI, to common.Address, at common.Hash, method string, args ...interface{}) ([]interface{}, error) {
	data, err := parsed.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	ret, err := c.reader.CallContractAtHash(ctx, ethereum.CallMsg{To: &to, Data: data}, at)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		code, err := c.reader.CodeAtHash(ctx, to, at)
		if err != nil {
			return nil, err
		}
		if len(code) == 0 {
			return nil, fmt.Errorf("%s has no code at block %s: %w", to.Hex(), at.Hex(), errNoContractCode)
		}
		return nil, fmt.Errorf("%s.%s returned nothing at block %s", to.Hex(), method, at.Hex())
	}
	return parsed.Unpack(method, ret)
}

// errNoContractCode marks a call to an address without code.
var errNoContractCode = errors.New("no contract code")

// LeafConsumption: see OutcomeChain. isLeafConsumed is read at a recent agreed block; a consumed leaf's LeafConsumed log
// is located through each provider in turn (a locator, never a fact) and established by its transaction's agreed
// receipt.
func (c *AgreedOutcomeChain) LeafConsumption(ctx context.Context, account common.Address, leaf [32]byte, searchFrom time.Time) (*LeafConsumption, uint64, error) {
	key := account.Hex() + common.Hash(leaf).Hex()
	c.mu.Lock()
	if cached := c.consumed[key]; cached != nil {
		c.mu.Unlock()
		return cached, cached.Block, nil
	}
	c.mu.Unlock()

	at, err := c.reader.RecentAgreedHeader(ctx)
	if err != nil {
		return nil, 0, err
	}
	out, err := c.call(ctx, outcomeAccountABI, account, at.Hash(), "isLeafConsumed", leaf)
	if errors.Is(err, errNoContractCode) {
		return nil, at.Number.Uint64(), nil // an account with no code has consumed nothing (RB3-F63)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("isLeafConsumed(0x%x) on %s: %w", leaf[:8], account.Hex(), err)
	}
	if consumed, ok := out[0].(bool); !ok {
		return nil, 0, fmt.Errorf("isLeafConsumed returned %T", out[0])
	} else if !consumed {
		return nil, at.Number.Uint64(), nil
	}

	logs, err := c.locateLeafConsumed(ctx, account, leaf, searchFrom, at.Number.Uint64())
	if err != nil {
		return nil, 0, err
	}
	for _, l := range logs {
		cons, err := c.consumptionIn(ctx, account, leaf, l.TxHash)
		if err != nil {
			return nil, 0, err
		}
		if cons == nil {
			continue
		}
		// Kept once it is final - at or below the finalized block and canonical at its height.
		if fin, ferr := c.FinalizedHeader(ctx); ferr == nil && cons.Block <= fin.Number.Uint64() {
			if h, herr := c.HeaderAt(ctx, cons.Block); herr == nil && h.Hash() == cons.BlockHash {
				c.mu.Lock()
				c.consumed[key] = cons
				c.mu.Unlock()
			}
		}
		return cons, at.Number.Uint64(), nil
	}
	return nil, 0, outcomeNotYet("leaf 0x%x is consumed on %s as of block %d, and no provider returns its LeafConsumed log "+
		"from %s", leaf[:8], account.Hex(), at.Number.Uint64(), searchFrom.UTC().Format(time.RFC3339))
}

// consumptionIn is the consumption of leaf in tx, as tx's agreed receipt states it; nil when the receipt holds none.
func (c *AgreedOutcomeChain) consumptionIn(ctx context.Context, account common.Address, leaf [32]byte, tx common.Hash) (*LeafConsumption, error) {
	r, err := c.reader.TransactionReceipt(ctx, tx)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return nil, outcomeNotYet("the receipt of %s is not held by every provider yet", tx.Hex())
		}
		return nil, err
	}
	for _, lg := range r.Logs {
		if lg.Address == account && len(lg.Topics) >= 3 && lg.Topics[0] == leafConsumedTopic && lg.Topics[2] == common.Hash(leaf) {
			return &LeafConsumption{Anchor: lg.Topics[1], Tx: tx, Block: r.BlockNumber.Uint64(), BlockHash: r.BlockHash}, nil
		}
	}
	return nil, nil
}

// locateLeafConsumed asks every provider, from the block at searchFrom to block to, for the account's LeafConsumed logs
// of leaf. Locators only: the caller establishes each through its agreed receipt.
func (c *AgreedOutcomeChain) locateLeafConsumed(ctx context.Context, account common.Address, leaf [32]byte, searchFrom time.Time, to uint64) ([]types.Log, error) {
	q := ethereum.FilterQuery{Addresses: []common.Address{account}, Topics: [][]common.Hash{{leafConsumedTopic}, nil, {common.Hash(leaf)}}}
	var found []types.Log
	var failures []string
	for _, loc := range c.reader.Locators() {
		head, err := loc.HeaderByNumber(ctx, new(big.Int).SetUint64(to))
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", loc.Host, err))
			continue
		}
		from, err := searchBlockAtOrBefore(to, head.Time, uint64(searchFrom.Unix()), func(n uint64) (uint64, error) {
			h, err := loc.HeaderByNumber(ctx, new(big.Int).SetUint64(n))
			if err != nil {
				return 0, err
			}
			return h.Time, nil
		})
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", loc.Host, err))
			continue
		}
		for lo := from; lo <= to; lo += proofExecutedChunk {
			hi := lo + proofExecutedChunk - 1
			if hi > to {
				hi = to
			}
			logs, err := filterLogsSplitting(ctx, loc, q, lo, hi)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", loc.Host, err))
				break
			}
			if len(logs) > 0 {
				found = append(found, logs...)
				break
			}
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	if len(failures) > 0 {
		return nil, readErr(fmt.Errorf("locating LeafConsumed(0x%x) on %s: %s", leaf[:8], account.Hex(), strings.Join(failures, "; ")))
	}
	return nil, nil
}

// MemberExecution: see OutcomeChain. The transaction is read as final first, so the observation does not wait.
func (c *AgreedOutcomeChain) MemberExecution(ctx context.Context, tx common.Hash, legs []CommittedLeg, opID [32]byte, account common.Address) (*ExternalChainResult, []CommittedEffect, []CommittedEffect, error) {
	if err := c.requireFinal(ctx, tx); err != nil {
		return nil, nil, nil, err
	}
	if _, err := c.observer.ObserveTransaction(ctx, tx); err != nil {
		return nil, nil, nil, readErr(fmt.Errorf("observing %s: %w", tx.Hex(), err))
	}
	return c.observer.ClassifyMemberExecution(ctx, tx, legs, opID, account)
}

// RevertedAttempt: see OutcomeChain.
func (c *AgreedOutcomeChain) RevertedAttempt(ctx context.Context, tx common.Hash, legs []CommittedLeg, opID [32]byte, account common.Address) (*ExternalChainResult, error) {
	r, err := c.reader.TransactionReceipt(ctx, tx)
	if errors.Is(err, ethereum.NotFound) {
		return nil, fmt.Errorf("%w: %s is not mined", ErrNotAnAttempt, tx.Hex())
	}
	if err != nil {
		return nil, err
	}
	if r.Status != types.ReceiptStatusFailed {
		return nil, fmt.Errorf("%w: %s did not revert", ErrNotAnAttempt, tx.Hex())
	}
	if err := c.requireFinal(ctx, tx); err != nil {
		return nil, err
	}
	if _, err := c.observer.ObserveTransaction(ctx, tx); err != nil {
		return nil, readErr(fmt.Errorf("observing %s: %w", tx.Hex(), err))
	}
	res, err := c.observer.VerifyRevertedCall(ctx, tx, committedCalls(legs), opID, account)
	if err != nil {
		if IsChainReadError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrNotAnAttempt, err)
	}
	return res, nil
}

// requireFinal is ErrOutcomeNotYet unless tx's agreed receipt is in the finalized chain.
func (c *AgreedOutcomeChain) requireFinal(ctx context.Context, tx common.Hash) error {
	r, err := c.reader.TransactionReceipt(ctx, tx)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return outcomeNotYet("%s is not mined in every provider's view", tx.Hex())
		}
		return err
	}
	fin, err := c.FinalizedHeader(ctx)
	if err != nil {
		return err
	}
	if r.BlockNumber.Uint64() > fin.Number.Uint64() {
		return outcomeNotYet("%s is in block %d, not final (finalized %d)", tx.Hex(), r.BlockNumber.Uint64(), fin.Number.Uint64())
	}
	h, err := c.HeaderAt(ctx, r.BlockNumber.Uint64())
	if err != nil {
		return err
	}
	if h.Hash() != r.BlockHash {
		return outcomeNotYet("%s's receipt names block %s, the finalized block at %d is %s", tx.Hex(), r.BlockHash.Hex(),
			r.BlockNumber.Uint64(), h.Hash().Hex())
	}
	return nil
}

// AnchorView: see OutcomeAnchorReader.
func (c *AgreedOutcomeChain) AnchorView(ctx context.Context, bundleID [32]byte) (*OutcomeAnchorView, error) {
	at, err := c.reader.RecentAgreedHeader(ctx)
	if err != nil {
		return nil, err
	}
	v := &OutcomeAnchorView{At: at}
	ret, err := c.reader.CallContractAtHash(ctx, ethereum.CallMsg{To: &c.anchor, Data: contracts.AnchorsCallData(bundleID)}, at.Hash())
	if err != nil {
		return nil, fmt.Errorf("anchors(0x%x) on %s: %w", bundleID[:8], c.anchor.Hex(), err)
	}
	if v.Anchor, err = contracts.DecodeAnchorsReturn(ret); err != nil {
		return nil, err
	}
	words := []struct {
		parsed abi.ABI
		to     common.Address
		method string
		args   []interface{}
		set    func(interface{}) error
	}{
		{outcomeAnchorABI, c.anchor, "batchLeafCount", []interface{}{bundleID}, func(x interface{}) error {
			n, ok := x.(*big.Int)
			if !ok || !n.IsUint64() {
				return fmt.Errorf("batchLeafCount is %v", x)
			}
			v.LeafCount = n.Uint64()
			return nil
		}},
		{outcomeAnchorABI, c.anchor, "currentValidatorSetRoot", nil, func(x interface{}) error {
			r, ok := x.([32]byte)
			v.CurrentSetRoot = r
			return okOr(ok, "currentValidatorSetRoot", x)
		}},
		{outcomeRegistryABI, c.registry, "outcomeRoots", []interface{}{bundleID}, func(x interface{}) error {
			r, ok := x.([32]byte)
			v.RecordedRoot = r
			return okOr(ok, "outcomeRoots", x)
		}},
		{outcomeRegistryABI, c.registry, "recordedInBlock", []interface{}{bundleID}, func(x interface{}) error {
			n, ok := x.(*big.Int)
			if !ok || !n.IsUint64() {
				return fmt.Errorf("recordedInBlock is %v", x)
			}
			v.RecordedIn = n.Uint64()
			return nil
		}},
	}
	for _, w := range words {
		out, err := c.call(ctx, w.parsed, w.to, at.Hash(), w.method, w.args...)
		if err != nil {
			return nil, fmt.Errorf("%s on %s: %w", w.method, w.to.Hex(), err)
		}
		if err := w.set(out[0]); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func okOr(ok bool, what string, x interface{}) error {
	if !ok {
		return fmt.Errorf("%s returned %T", what, x)
	}
	return nil
}

// OutcomeMessage: see OutcomeAnchorReader.
func (c *AgreedOutcomeChain) OutcomeMessage(ctx context.Context, bundleID, root [32]byte, at *types.Header) ([32]byte, error) {
	out, err := c.call(ctx, outcomeRegistryABI, c.registry, at.Hash(), "outcomeMessage", bundleID, root)
	if err != nil {
		return [32]byte{}, fmt.Errorf("outcomeMessage on %s: %w", c.registry.Hex(), err)
	}
	m, ok := out[0].([32]byte)
	return m, okOr(ok, "outcomeMessage", out[0])
}

// RecordedOutcomeTx is a recordBatchOutcome transaction as the chain holds it: its agreed receipt's
// BatchOutcomeRecorded event and the proof its calldata carried.
type RecordedOutcomeTx struct {
	BundleID    [32]byte
	Tx          common.Hash
	Block       uint64
	Recorder    common.Address
	Root        [32]byte
	MessageHash [32]byte
	Proof       contracts.CertenAnchorV4BLSProofData
}

// batchOutcomeRecordedTopic is the registry's BatchOutcomeRecorded(bytes32,bytes32,address,bytes32) event.
var batchOutcomeRecordedTopic = outcomeRegistryABI.Events["BatchOutcomeRecorded"].ID

// RecordedOutcome is the transaction that recorded bundleID's outcome in block (the registry's recordedInBlock): its
// event located through each provider, established by its agreed receipt, and its calldata read from a provider and
// bound to its hash.
func (c *AgreedOutcomeChain) RecordedOutcome(ctx context.Context, bundleID [32]byte, block uint64) (*RecordedOutcomeTx, error) {
	q := ethereum.FilterQuery{Addresses: []common.Address{c.registry}, FromBlock: new(big.Int).SetUint64(block),
		ToBlock: new(big.Int).SetUint64(block), Topics: [][]common.Hash{{batchOutcomeRecordedTopic}, {common.Hash(bundleID)}}}
	var failures []string
	for _, loc := range c.reader.Locators() {
		logs, err := loc.FilterLogs(ctx, q)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", loc.Host, err))
			continue
		}
		for _, l := range logs {
			r, err := c.reader.TransactionReceipt(ctx, l.TxHash)
			if err != nil {
				return nil, err
			}
			for _, lg := range r.Logs {
				if lg.Address != c.registry || len(lg.Topics) != 4 || lg.Topics[0] != batchOutcomeRecordedTopic ||
					lg.Topics[1] != common.Hash(bundleID) || len(lg.Data) != 32 {
					continue
				}
				out := &RecordedOutcomeTx{BundleID: bundleID, Tx: l.TxHash, Block: r.BlockNumber.Uint64(), Recorder: common.BytesToAddress(lg.Topics[3][12:]),
					Root: lg.Topics[2]}
				copy(out.MessageHash[:], lg.Data)
				if err := c.recordedProof(ctx, out); err != nil {
					return nil, err
				}
				return out, nil
			}
		}
	}
	if len(failures) > 0 {
		return nil, readErr(fmt.Errorf("locating BatchOutcomeRecorded(0x%x) in block %d: %s", bundleID[:8], block, strings.Join(failures, "; ")))
	}
	return nil, outcomeNotYet("no provider returns the BatchOutcomeRecorded event of 0x%x in block %d", bundleID[:8], block)
}

// recordedProof reads the record transaction's calldata - from any provider, bound to the transaction's hash - and
// decodes the quorum proof it submitted.
func (c *AgreedOutcomeChain) recordedProof(ctx context.Context, rec *RecordedOutcomeTx) error {
	for _, loc := range c.reader.Locators() {
		tx, _, err := loc.TransactionByHash(ctx, rec.Tx)
		if err != nil || tx == nil || tx.Hash() != rec.Tx {
			continue
		}
		bundle, root, proof, err := decodeRecordBatchOutcome(tx.Data())
		if err != nil {
			return fmt.Errorf("transaction %s: %w", rec.Tx.Hex(), err)
		}
		if bundle != rec.BundleID || root != rec.Root {
			return fmt.Errorf("recordBatchOutcome %s submitted root 0x%x, its event names 0x%x", rec.Tx.Hex(), root[:8], rec.Root[:8])
		}
		if proof.MessageHash != rec.MessageHash {
			return fmt.Errorf("recordBatchOutcome %s carried message 0x%x, its event names 0x%x", rec.Tx.Hex(), proof.MessageHash[:8], rec.MessageHash[:8])
		}
		rec.Proof = *proof
		return nil
	}
	return readErr(fmt.Errorf("no provider returns the calldata of %s", rec.Tx.Hex()))
}

// decodeRecordBatchOutcome decodes recordBatchOutcome calldata: the anchor, the root and the quorum proof submitted.
func decodeRecordBatchOutcome(data []byte) (bundle, root [32]byte, proof *contracts.CertenAnchorV4BLSProofData, err error) {
	method := outcomeRegistryABI.Methods["recordBatchOutcome"]
	if len(data) < 4 || !bytes.Equal(data[:4], method.ID) {
		return bundle, root, nil, fmt.Errorf("not a recordBatchOutcome call")
	}
	args, err := method.Inputs.Unpack(data[4:])
	if err != nil || len(args) != 3 {
		return bundle, root, nil, fmt.Errorf("recordBatchOutcome calldata does not decode: %v", err)
	}
	b, ok1 := args[0].([32]byte)
	r, ok2 := args[1].([32]byte)
	if !ok1 || !ok2 {
		return bundle, root, nil, fmt.Errorf("recordBatchOutcome calldata carries %T, %T", args[0], args[1])
	}
	defer func() {
		// abi.ConvertType panics on a struct that does not match; that is a decode failure here, never a crash.
		if p := recover(); p != nil {
			proof, err = nil, fmt.Errorf("recordBatchOutcome calldata carries no BLSProofData: %v", p)
		}
	}()
	pr, ok := abi.ConvertType(args[2], new(contracts.CertenAnchorV4BLSProofData)).(*contracts.CertenAnchorV4BLSProofData)
	if !ok || pr == nil {
		return b, r, nil, fmt.Errorf("recordBatchOutcome calldata carries no BLSProofData")
	}
	return b, r, pr, nil
}
