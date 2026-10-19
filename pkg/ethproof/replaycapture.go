// Copyright 2026 Certen Protocol

package ethproof

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// =============================================================================
// Capturing the S6 replay-guard proof at inclusion (RB10 Phase B)
// =============================================================================
//
// No public provider serves old state (R10 Q3): a replay-guard proof can only be read while the settlement block is at, or
// within a block or two of, the head. So the capture starts when the settlement is first observed - at inclusion, not at
// finality - runs beside the observation, and never delays it: the settlement, its attestation and its write-back do not
// wait for it, and nothing it finds enters a hashed input.
//
// It asks the chain's agreeing providers one after the other for the slot at the newest block each can prove (After,
// at or after the settlement block), and for the same slot at the settlement block's parent (Before). A provider that
// cannot serve is named with its error. Every proof is verified against the AGREED header's state root before it is
// kept, so which provider served the bytes does not matter.

// ReplayCaptureBudget is how long a capture keeps asking before it states what it could not prove.
const ReplayCaptureBudget = 2 * time.Minute

// ReasonCaptureNotAttempted: the settlement was first observed at finality and no capture ran at inclusion.
const ReasonCaptureNotAttempted = "capture_not_attempted_in_window"

// replayAfterCandidates is how many of the newest blocks, down to the settlement block, are tried for After.
const replayAfterCandidates = 4

// ReplayStateProvider is one provider asked for an account's state proof.
type ReplayStateProvider interface {
	Name() string
	TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error)
	// GetProof is the provider's eth_getProof answer as JSON.
	GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error)
}

// ReplayCaptureSource is what a capture reads: the chain through its agreeing providers (receipt, headers), and the
// individual providers it asks for state.
type ReplayCaptureSource interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	StateProviders() []ReplayStateProvider
}

// replayLocators is the part of an ethrpc.AgreeingReader a capture needs.
type replayLocators interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	Locators() []ethrpc.LocatorClient
}

type locatorProvider struct{ ethrpc.LocatorClient }

func (l locatorProvider) Name() string { return l.Host }

type locatorSource struct{ replayLocators }

func (l locatorSource) StateProviders() []ReplayStateProvider {
	locs := l.Locators()
	out := make([]ReplayStateProvider, len(locs))
	for i, c := range locs {
		out[i] = locatorProvider{c}
	}
	return out
}

// ReplaySourceOf is the capture source of a chain's finality reader: the reader itself when it is one, or an agreeing
// reader's providers. False when the reader cannot serve state proofs at all.
func ReplaySourceOf(reader interface{}) (ReplayCaptureSource, bool) {
	switch r := reader.(type) {
	case ReplayCaptureSource:
		return r, true
	case replayLocators:
		return locatorSource{r}, true
	}
	return nil, false
}

// ReplayCaptureConfig configures a capture.
type ReplayCaptureConfig struct {
	ChainID int64
	Source  ReplayCaptureSource
	Budget  time.Duration // default ReplayCaptureBudget
	Poll    time.Duration // default 2s
	Clock   ReplayClock   // default WallClock; a replay clock over a recorded world (RB10-F9)
	Logf    func(string, ...interface{})
	// Concurrent is the most captures of this chain that are in the After phase at once (default
	// DefaultReplayCaptureConcurrency): the rest wait for a slot and spend their budget doing so. The slot is held for the
	// After phase only (RB10-B10); the Before phase of a capture that has its After runs beside the others without one. The
	// size is fixed by the first capture of the chain in a store.
	Concurrent int
	// afterDone is called once when the capture's After phase is over - its After proof is in hand, or the capture ended for
	// whatever reason - and frees the capture slot a capturer holds for it (RB10-B10 D1).
	afterDone func()
}

func (c *ReplayCaptureConfig) concurrent() int {
	if c.Concurrent <= 0 {
		return DefaultReplayCaptureConcurrency
	}
	return c.Concurrent
}

func (c *ReplayCaptureConfig) budget() time.Duration {
	if c.Budget <= 0 {
		return ReplayCaptureBudget
	}
	return c.Budget
}

func (c *ReplayCaptureConfig) clock() ReplayClock {
	if c.Clock == nil {
		return WallClock
	}
	return c.Clock
}

func (c *ReplayCaptureConfig) poll() time.Duration {
	if c.Poll <= 0 {
		return 2 * time.Second
	}
	return c.Poll
}

func (c *ReplayCaptureConfig) logf(format string, args ...interface{}) {
	if c.Logf == nil {
		return
	}
	// Whatever a provider said may carry its URL, and so its API key (RB10-B11): the text arguments are sanitised, the format is the caller's.
	clean := make([]interface{}, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			clean[i] = RedactEndpoints(v)
		case error:
			clean[i] = RedactEndpoints(v.Error())
		default:
			clean[i] = a
		}
	}
	c.Logf(format, clean...)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

type getProofAnswer struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []struct {
		Key   string          `json:"key"`
		Value string          `json:"value"`
		Proof []hexutil.Bytes `json:"proof"`
	} `json:"storageProof"`
}

// proveAt reads the slot's proof from one provider at one block and verifies it against the block's state root: the
// returned SlotProof states only what the verification found.
func proveAt(ctx context.Context, p ReplayStateProvider, contract common.Address, slot common.Hash, hdr *types.Header) (*SlotProof, *StorageResult, error) {
	raw, err := p.GetProof(ctx, contract, []string{slot.Hex()}, "0x"+hdr.Number.Text(16))
	if err != nil {
		return nil, nil, err
	}
	var ans getProofAnswer
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, nil, fmt.Errorf("the answer cannot be read: %w", err)
	}
	if len(ans.StorageProof) != 1 {
		return nil, nil, fmt.Errorf("%d storage proofs for the one slot asked", len(ans.StorageProof))
	}
	st := ans.StorageProof[0]
	nodes := func(in []hexutil.Bytes) [][]byte { return hexNodeList(in) }
	res, err := VerifyStorage(hdr.Root, contract, nodes(ans.AccountProof), slot, nodes(st.Proof))
	if err != nil {
		return nil, nil, fmt.Errorf("does not verify against the agreed state root of block %d: %w", hdr.Number.Uint64(), err)
	}
	// What the provider's text says of the value is checked against what the proof proves.
	if v := strings.TrimPrefix(strings.TrimPrefix(st.Value, "0x"), "0X"); v != "" {
		got, ok := new(big.Int).SetString(v, 16)
		if !ok || common.BigToHash(got) != res.Value {
			return nil, nil, fmt.Errorf("states value %s, the proof proves %s", st.Value, res.Value.Hex())
		}
	} else if res.Value != (common.Hash{}) {
		return nil, nil, fmt.Errorf("states an empty value, the proof proves %s", res.Value.Hex())
	}
	sp := &SlotProof{AccountAbsent: !res.Account.Exists, StorageHash: res.Account.StorageRoot, CodeHash: res.Account.CodeHash, Value: res.Value,
		AccountProof: []hexutil.Bytes{}, StorageProof: []hexutil.Bytes{}}
	for _, n := range ans.AccountProof {
		sp.AccountProof = append(sp.AccountProof, n)
	}
	for _, n := range st.Proof {
		sp.StorageProof = append(sp.StorageProof, n)
	}
	if !res.Account.Exists {
		sp.StorageHash, sp.CodeHash = common.Hash{}, common.Hash{}
	}
	return sp, res, nil
}

// CaptureReplayGuard captures the replay-guard evidence of the settlement txHash, trying for up to the budget. It returns
// evidence: a proof, or the named state saying what it could not prove, at which block, from which providers. It returns
// nil only for a transaction that is no account settlement of any generation, which makes no S6 claim.
//
// The budget bounds the whole capture (RB10-F6): every request carries the budget's deadline, a pass over the candidate
// blocks and providers stops when the budget ends, and a provider not yet asked by then is named as such. The headers
// after the settlement block are read once each: the linked chain is extended, never read again for another candidate
// block, provider or pass.
func CaptureReplayGuard(ctx context.Context, cfg ReplayCaptureConfig, txHash common.Hash) *ReplayGuardEvidence {
	src := cfg.Source
	clock := cfg.clock()
	deadline := clock.Now().Add(cfg.budget())
	bctx, cancel := clock.WithDeadline(ctx, deadline)
	defer cancel()
	// The capture slot is the After phase's: freed when After is in hand, and in any case when the capture ends.
	afterOver := func() {}
	if cfg.afterDone != nil {
		var once sync.Once
		afterOver = func() { once.Do(cfg.afterDone) }
	}
	defer afterOver()
	state := &ReplayNamedState{ChainID: cfg.ChainID, TxHash: txHash}
	finish := func(st, reason, format string, args ...interface{}) *ReplayGuardEvidence {
		state.State, state.Reason, state.Detail = st, reason, RedactEndpoints(fmt.Sprintf(format, args...))
		cfg.logf("⚠️ [S6-REPLAY] chain %d tx %s: %s{reason=%s}: %s", cfg.ChainID, txHash.Hex(), st, reason, state.Detail)
		return &ReplayGuardEvidence{Version: ReplayGuardDomain, State: state}
	}
	// ended says why the capture stopped asking: its caller cancelled it, or its budget ended.
	ended := func() string {
		if ctx.Err() != nil {
			return fmt.Sprintf("the capture was cancelled (%v)", ctx.Err())
		}
		return fmt.Sprintf("the capture budget of %s ended", cfg.budget())
	}
	if src == nil {
		return finish(ReplayUnproven, ReasonStateUnavailable, "no provider that serves state proofs is configured for chain %d", cfg.ChainID)
	}

	// The receipt, as soon as the agreeing providers have it.
	var rc *types.Receipt
	for {
		r, err := src.TransactionReceipt(bctx, txHash)
		if err == nil && r != nil && r.BlockNumber != nil {
			rc = r
			break
		}
		if bctx.Err() != nil || !clock.Sleep(bctx, cfg.poll()) {
			return finish(ReplayUnproven, ReasonReceiptUnavailable, "no agreed receipt for the settlement before %s (last: %v)", ended(), err)
		}
	}
	state.BlockNumber, state.BlockHash = rc.BlockNumber.Uint64(), rc.BlockHash
	if rc.Status != 1 {
		return finish(ReplayUnproven, ReasonSettlementNotExecuted, "the receipt is status %d: no consumption happened", rc.Status)
	}

	// The transaction, from any provider that has it; verification later holds it to the proven one.
	var tx *types.Transaction
	var txErrs []string
	providers := src.StateProviders()
	for _, p := range providers {
		t, _, err := p.TransactionByHash(bctx, txHash)
		if err == nil && t != nil && t.Hash() == txHash {
			tx = t
			break
		}
		txErrs = append(txErrs, fmt.Sprintf("%s: %v", p.Name(), err))
	}
	if tx == nil {
		return finish(ReplayUnproven, ReasonReceiptUnavailable, "no provider served the settlement transaction (%s)", strings.Join(txErrs, "; "))
	}
	if tx.To() == nil {
		return finish(ReplayUnproven, ReasonAccountGeneration, "the settlement is a contract creation")
	}
	contract := *tx.To()
	state.Contract = contract
	gen, isSettlement := SettlementCallGeneration(tx.Data())
	if !isSettlement {
		// Not an account settlement of any generation (an anchor transaction, say): there is no S6 claim to make.
		return nil
	}
	layout, pinned := replayLayouts[gen]
	if !pinned {
		return finish(ReplayUnproven, ReasonAccountGeneration, "the settlement calls a %s: its replay-guard layout is not pinned", gen)
	}

	// The event, which names the key.
	var leaf common.Hash
	found := false
	for _, lg := range rc.Logs {
		if lg != nil && lg.Address == contract && len(lg.Topics) == 3 && lg.Topics[0] == LeafConsumedTopic {
			leaf, found = lg.Topics[2], true
			break
		}
	}
	if !found {
		return finish(ReplayEventMissing, ReasonNoEvent, "the receipt of the call to %s holds no LeafConsumed it emitted (%d logs)", contract.Hex(), len(rc.Logs))
	}
	slot := ReplaySlotFor(leaf, layout.base)

	headerN, err := agreedHeaderByHash(bctx, src, rc.BlockHash, clock, deadline, cfg.poll())
	if err != nil {
		return finish(ReplayUnproven, ReasonStateUnavailable, "the settlement block %s has no agreed header: %v", rc.BlockHash.Hex(), err)
	}
	n := headerN.Number.Uint64()

	// After: the newest block any provider can prove the slot at.
	failures := newProviderFailures()
	headers := &linkedHeaderChain{src: src, base: headerN}
	var after *SlotProof
	var chain []*types.Header // N+1 .. H
	var provenAt *types.Header
	var latestSeen uint64
	for after == nil {
		latest, lerr := src.HeaderByNumber(bctx, big.NewInt(int64(rpc.LatestBlockNumber)))
		if lerr == nil && latest != nil && latest.Number != nil {
			top := latest.Number.Uint64()
			latestSeen = top
			if top < n {
				top = n
			}
			pastBound := false
			if top > n+MaxReplayHeaderChain {
				top, pastBound = n+MaxReplayHeaderChain, true
			}
			low := n
			if top >= n+replayAfterCandidates {
				low = top - replayAfterCandidates + 1
			}
		pass:
			// V-R10B2 note: the newest candidate block is asked of every provider before an older one is asked of any, and
			// the first verified proof ends the pass, so a provider that cannot serve costs one request, not one per
			// candidate, before the provider that can.
			for h := top; ; h-- {
				if bctx.Err() != nil {
					break pass
				}
				hdrs, herr := headers.upTo(bctx, h)
				if herr != nil {
					for _, p := range providers {
						failures.note(p.Name(), fmt.Sprintf("block %d: %v", h, herr))
					}
				} else {
					hdrH := headerN
					if len(hdrs) > 0 {
						hdrH = hdrs[len(hdrs)-1]
					}
					for _, p := range providers {
						if bctx.Err() != nil {
							break pass
						}
						sp, res, perr := proveAt(bctx, p, contract, slot, hdrH)
						switch {
						case perr != nil:
							failures.note(p.Name(), fmt.Sprintf("block %d: %v", h, perr))
						case res.Value != common.BigToHash(big.NewInt(1)):
							failures.note(p.Name(), fmt.Sprintf("block %d: serves the slot as %s, not consumed", h, res.Value.Hex()))
						case !res.Account.HasCode():
							failures.note(p.Name(), fmt.Sprintf("block %d: %s holds no code", h, contract.Hex()))
						default:
							after, chain, provenAt = sp, hdrs, hdrH
							break pass
						}
					}
				}
				if h == low {
					break
				}
			}
			// V-R10B D2: past the bound the candidate blocks stay pinned at N+MaxReplayHeaderChain and only age as the head
			// moves on: a later pass asks the same blocks of the same providers, so one complete pass that proves nothing
			// decides the capture.
			if after == nil && pastBound && bctx.Err() == nil {
				failures.notAsked(providers, "the capture gave up after one pass")
				state.Providers = failures.list()
				return finish(ReplayUnproven, ReasonStateUnavailable,
					"no provider could prove the slot %s of %s at blocks %d..%d, the newest a proof may reach (settlement block %d + %d headers); the head %d is past the header-chain bound by %d blocks, so no later pass can reach a newer block",
					slot.Hex(), contract.Hex(), low, top, n, MaxReplayHeaderChain, latestSeen, latestSeen-top)
			}
		} else {
			failures.note("(agreeing providers)", fmt.Sprintf("no agreed latest header: %v", lerr))
		}
		if after != nil {
			break
		}
		if bctx.Err() != nil || !clock.Sleep(bctx, cfg.poll()) {
			failures.notAsked(providers, ended())
			state.Providers = failures.list()
			return finish(ReplayUnproven, ReasonStateUnavailable,
				"no provider could prove the slot %s of %s at any of the newest %d blocks (settlement block %d, newest seen %d) before %s",
				slot.Hex(), contract.Hex(), replayAfterCandidates, n, latestSeen, ended())
		}
	}

	proof := &ReplayGuardProof{
		Version: ReplayGuardDomain, ChainID: cfg.ChainID, Generation: gen, Contract: contract,
		Slot:            ReplaySlot{Key: leaf, Base: layout.base, Derivation: ReplayDerivation, Slot: slot},
		SettlementBlock: BlockRef{Number: n, Hash: headerN.Hash()},
		ProvenAt:        BlockRef{Number: provenAt.Number.Uint64(), Hash: provenAt.Hash()},
		Headers:         []hexutil.Bytes{},
		After:           *after,
	}
	for _, h := range chain {
		raw, rerr := rlp.EncodeToBytes(h)
		if rerr != nil {
			return finish(ReplayUnproven, ReasonProofDoesNotVerify, "encode header %d: %v", h.Number.Uint64(), rerr)
		}
		proof.Headers = append(proof.Headers, raw)
	}
	// Everything the After proof needs is in hand: the Before phase below is a low-rate read that waits for a state some
	// providers never serve, and holds no capture slot (V-R10B3 D1).
	afterOver()

	// Before: the same slot in the state of the settlement block's parent, asked of every provider in turn and asked
	// again until the budget ends, as After is (RB10-F7: a provider's backends differ, and one that refuses the parent now
	// can serve it seconds later).
	before := newProviderFailures()
	parent, perr := agreedHeaderByHash(bctx, src, headerN.ParentHash, clock, deadline, cfg.poll())
	if perr != nil {
		before.note("(agreeing providers)", fmt.Sprintf("the parent header %s: %v", headerN.ParentHash.Hex(), perr))
	} else {
		parentRLP, _ := rlp.EncodeToBytes(parent)
		for proof.Before == nil && bctx.Err() == nil {
			for _, p := range providers {
				if bctx.Err() != nil {
					break
				}
				sp, res, berr := proveAt(bctx, p, contract, slot, parent)
				if berr != nil {
					before.note(p.Name(), fmt.Sprintf("block %d: %v", parent.Number.Uint64(), berr))
					continue
				}
				if res.Value == common.BigToHash(big.NewInt(1)) {
					state.Before = &ReplayBefore{ParentHeader: parentRLP, Proof: *sp}
					return finish(ReplayRefuted, ReasonSlotSetAtParent, "%s proves the slot %s already 1 at block %d, the settlement block's parent",
						p.Name(), slot.Hex(), parent.Number.Uint64())
				}
				if res.Value != (common.Hash{}) {
					before.note(p.Name(), fmt.Sprintf("block %d: serves the slot as %s, neither 0 nor 1", parent.Number.Uint64(), res.Value.Hex()))
					continue
				}
				proof.Before = &ReplayBefore{ParentHeader: parentRLP, Proof: *sp}
				break
			}
			if proof.Before == nil && !clock.Sleep(bctx, cfg.poll()) {
				break
			}
		}
		if proof.Before == nil {
			before.notAsked(providers, ended())
		}
	}
	if proof.Before == nil {
		proof.BeforeUnavailable = &ReplayBeforeUnavailable{
			Reason:    RedactEndpoints(fmt.Sprintf("no provider served the state of block %d, the settlement block's parent, before %s", n-1, ended())),
			Providers: before.list(),
		}
	}

	// The proof is checked here as a reader will, with what was observed; the proven settlement binds it later.
	if _, verr := proof.VerifyAgainst(headerN, tx, true, rc.Logs); verr != nil {
		if re, ok := verr.(*ReplayError); ok {
			return finish(re.State, re.Reason, "%s", re.Detail)
		}
		return finish(ReplayUnproven, ReasonProofDoesNotVerify, "%v", verr)
	}
	cfg.logf("🔎 [S6-REPLAY] chain %d tx %s: %s slot %s of %s proven consumed at block %d (settlement block %d, %d headers); before-state: %v",
		cfg.ChainID, txHash.Hex(), gen, slot.Hex(), contract.Hex(), proof.ProvenAt.Number, n, len(proof.Headers), proof.Before != nil)
	return &ReplayGuardEvidence{Version: ReplayGuardDomain, Proof: proof}
}

// providerFailures is each provider's latest error, in the order the providers first failed.
type providerFailures struct {
	order []string
	msg   map[string]string
}

func newProviderFailures() *providerFailures { return &providerFailures{msg: map[string]string{}} }

func (f *providerFailures) note(host, msg string) {
	// The text is a provider's error and may carry its URL: only the host is kept (RB10-B11).
	host, msg = RedactEndpoints(host), RedactEndpoints(msg)
	if _, ok := f.msg[host]; !ok {
		f.order = append(f.order, host)
	}
	f.msg[host] = msg
}

// notAsked names every provider without an error yet: the capture ended before asking it.
func (f *providerFailures) notAsked(providers []ReplayStateProvider, why string) {
	for _, p := range providers {
		if _, ok := f.msg[p.Name()]; !ok {
			f.note(p.Name(), "not asked: "+why)
		}
	}
}

func (f *providerFailures) list() []ReplayProviderFailure {
	var out []ReplayProviderFailure
	for _, h := range f.order {
		out = append(out, ReplayProviderFailure{Host: h, Error: f.msg[h]})
	}
	return out
}

// agreedHeaderByHash reads a header by hash from the agreeing providers, asking again until the deadline.
func agreedHeaderByHash(ctx context.Context, src ReplayCaptureSource, hash common.Hash, clock ReplayClock, deadline time.Time, poll time.Duration) (*types.Header, error) {
	for {
		h, err := src.HeaderByHash(ctx, hash)
		if err == nil && h != nil && h.Number != nil && h.Hash() == hash {
			return h, nil
		}
		if err == nil {
			err = fmt.Errorf("the served header is not block %s", hash.Hex())
		}
		if ctx.Err() != nil || clock.Now().After(deadline) {
			return nil, err
		}
		if !clock.Sleep(ctx, poll) {
			return nil, err
		}
	}
}

// linkedHeaderChain is the agreed headers of the blocks after the settlement block (base), each linked to the one before
// by parentHash: read once each, and extended as later blocks are asked for.
type linkedHeaderChain struct {
	src   ReplayCaptureSource
	base  *types.Header
	chain []*types.Header // base+1 .. base+len(chain)
}

// upTo is the linked headers after base up to number h (empty when h is base's number). A header that does not follow
// the chain held (a reorg) drops the chain held, which the next ask reads again.
func (c *linkedHeaderChain) upTo(ctx context.Context, h uint64) ([]*types.Header, error) {
	n := c.base.Number.Uint64()
	if h < n {
		return nil, fmt.Errorf("block %d is before the settlement block %d", h, n)
	}
	for uint64(len(c.chain)) < h-n {
		// V-R10B D2: the deadline is checked before every read, so a slow source cannot hold the capture for the chain.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("header %d not read: %w", n+uint64(len(c.chain))+1, err)
		}
		i := n + uint64(len(c.chain)) + 1
		prev := c.base
		if len(c.chain) > 0 {
			prev = c.chain[len(c.chain)-1]
		}
		hd, err := c.src.HeaderByNumber(ctx, new(big.Int).SetUint64(i))
		if err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}
		if hd == nil || hd.Number == nil || hd.Number.Uint64() != i || hd.ParentHash != prev.Hash() {
			c.chain = nil
			return nil, fmt.Errorf("the agreed header %d does not follow the settlement block's chain (reorg)", i)
		}
		c.chain = append(c.chain, hd)
	}
	return append([]*types.Header(nil), c.chain[:h-n]...), nil
}

// =============================================================================
// The store, and the non-blocking begin / bind the observers call
// =============================================================================

type replayKey struct {
	chain int64
	tx    common.Hash
}

type replayEntry struct {
	ev    *ReplayGuardEvidence
	bound bool
	size  int
	key   replayKey
	done  chan struct{}
}

// ReplayGuardStore holds the replay-guard evidence of settlements beside them, by (chain, transaction): bounded, oldest
// first out. It is the single place the evidence builders read from.
type ReplayGuardStore struct {
	mu       sync.Mutex
	max      int
	maxBytes int
	bytes    int
	order    []replayKey
	m        map[replayKey]*replayEntry
	slots    map[int64]chan struct{}
}

// DefaultReplayGuardBytes bounds the evidence bytes a store holds (V-R10B note: a proof may carry 512 headers, so a
// count bound alone is several hundred MB to GB in the worst case).
const DefaultReplayGuardBytes = 256 << 20

// DefaultReplayGuards is the process-wide store the observers and the evidence builders share.
var DefaultReplayGuards = NewReplayGuardStore(8192)

// NewReplayGuardStore returns a store holding at most max settlements' evidence and DefaultReplayGuardBytes bytes of it.
func NewReplayGuardStore(max int) *ReplayGuardStore {
	return NewReplayGuardStoreBytes(max, DefaultReplayGuardBytes)
}

// NewReplayGuardStoreBytes returns a store holding at most max settlements' evidence and maxBytes bytes of it
// (ReplayEvidenceSize); the oldest leave first.
func NewReplayGuardStoreBytes(max, maxBytes int) *ReplayGuardStore {
	if max <= 0 {
		max = 1024
	}
	if maxBytes <= 0 {
		maxBytes = DefaultReplayGuardBytes
	}
	return &ReplayGuardStore{max: max, maxBytes: maxBytes, m: map[replayKey]*replayEntry{}}
}

// MaxBytes is the store's byte bound.
func (s *ReplayGuardStore) MaxBytes() int { return s.maxBytes }

// Bytes is the evidence bytes the store holds now.
func (s *ReplayGuardStore) Bytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// ReplayEvidenceSize is the size the store charges for evidence: the bytes of its proofs (headers, trie nodes) and named
// state text, plus a fixed overhead per entry.
func ReplayEvidenceSize(ev *ReplayGuardEvidence) int {
	const overhead = 512
	if ev == nil {
		return overhead
	}
	n := overhead
	nodes := func(sp *SlotProof) {
		if sp == nil {
			return
		}
		for _, b := range sp.AccountProof {
			n += len(b)
		}
		for _, b := range sp.StorageProof {
			n += len(b)
		}
	}
	before := func(b *ReplayBefore) {
		if b != nil {
			n += len(b.ParentHeader)
			nodes(&b.Proof)
		}
	}
	if p := ev.Proof; p != nil {
		for _, h := range p.Headers {
			n += len(h)
		}
		nodes(&p.After)
		before(p.Before)
		if p.BeforeUnavailable != nil {
			n += len(p.BeforeUnavailable.Reason)
			for _, f := range p.BeforeUnavailable.Providers {
				n += len(f.Host) + len(f.Error)
			}
		}
	}
	if st := ev.State; st != nil {
		n += len(st.Detail) + len(st.Reason)
		for _, f := range st.Providers {
			n += len(f.Host) + len(f.Error)
		}
		before(st.Before)
	}
	return n
}

// Put stores evidence for a settlement directly (bound as given), as a finished capture would.
func (s *ReplayGuardStore) Put(chain int64, tx common.Hash, ev *ReplayGuardEvidence, bound bool) {
	e, first := s.begin(chain, tx)
	s.put(e, ev, bound)
	if first {
		close(e.done)
	}
}

// evict drops the oldest entries while the store is over either bound; keep is never dropped.
func (s *ReplayGuardStore) evict(keep replayKey) {
	for len(s.order) > 0 && (len(s.order) > s.max || s.bytes > s.maxBytes) {
		k := s.order[0]
		if k == keep {
			if len(s.order) == 1 {
				return
			}
			s.order = append(s.order[1:], k)
			continue
		}
		if e, ok := s.m[k]; ok {
			s.bytes -= e.size
		}
		delete(s.m, k)
		s.order = s.order[1:]
	}
}

// begin registers a capture; first is true for the caller that must run it.
func (s *ReplayGuardStore) begin(chain int64, tx common.Hash) (*replayEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{chain, tx}
	if e, ok := s.m[k]; ok {
		return e, false
	}
	e := &replayEntry{key: k, done: make(chan struct{})}
	s.m[k] = e
	s.order = append(s.order, k)
	s.evict(k)
	return e, true
}

func (s *ReplayGuardStore) put(e *replayEntry, ev *ReplayGuardEvidence, bound bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ev, e.bound = ev, bound
	size := ReplayEvidenceSize(ev)
	if s.m[e.key] == e {
		s.bytes += size - e.size
		e.size = size
		s.evict(e.key)
		return
	}
	e.size = size // already evicted: charged to no one
}

// Get is the evidence stored for the settlement, and whether it has been held to the proven settlement (bound). ok is
// false when no capture was begun or it has not finished.
func (s *ReplayGuardStore) Get(chain int64, tx common.Hash) (ev *ReplayGuardEvidence, bound, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.m[replayKey{chain, tx}]
	if !found || e.ev == nil {
		return nil, false, false
	}
	return e.ev, e.bound, true
}

// Wait is Get once the capture has finished (or ctx ends).
func (s *ReplayGuardStore) Wait(ctx context.Context, chain int64, tx common.Hash) (*ReplayGuardEvidence, bool, error) {
	s.mu.Lock()
	e, found := s.m[replayKey{chain, tx}]
	s.mu.Unlock()
	if !found {
		return nil, false, fmt.Errorf("no replay-guard capture was begun for %s on chain %d", tx.Hex(), chain)
	}
	select {
	case <-e.done:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	ev, bound, _ := s.Get(chain, tx)
	return ev, bound, nil
}

// DefaultReplayCaptureConcurrency is how many captures of one chain run at once when the configuration does not say.
const DefaultReplayCaptureConcurrency = 4

// captureSlots is the semaphore bounding the captures of one chain that are in their After phase at once (V-R10B2 note: each pass of a capture
// asks every provider, and a restart backlog of settlements would otherwise multiply that load on the providers the
// observation itself uses). The size is fixed by the first capture of the chain.
func (s *ReplayGuardStore) captureSlots(chain int64, n int) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots == nil {
		s.slots = map[int64]chan struct{}{}
	}
	ch, ok := s.slots[chain]
	if !ok {
		ch = make(chan struct{}, n)
		s.slots[chain] = ch
	}
	return ch
}

// ReplayGuardCapturer starts captures at inclusion and binds them to the proven settlement; both calls return at once.
type ReplayGuardCapturer struct {
	cfg   ReplayCaptureConfig
	store *ReplayGuardStore
	// verifySettlement is the one verification of a proven settlement this capturer makes per Bind or Resolve.
	verifySettlement func(*Settlement) (*types.Header, *ReceiptLeaf, error)
	// bindWait is the longest Bind waits for a capture that has not finished: zero means its budget and two minutes.
	bindWait time.Duration
}

// NewReplayGuardCapturer returns a capturer writing to store (DefaultReplayGuards when nil).
func NewReplayGuardCapturer(cfg ReplayCaptureConfig, store *ReplayGuardStore) *ReplayGuardCapturer {
	if store == nil {
		store = DefaultReplayGuards
	}
	return &ReplayGuardCapturer{cfg: cfg, store: store, verifySettlement: (*Settlement).Verify}
}

// Begin starts the capture of txHash's replay guard in the background, once per transaction. It never blocks and never
// fails the caller: whatever happens is stored as evidence or as a named state. At most the configured number of captures
// of the chain are in the After phase at once (the receipt, the transaction, the header chain and the After proof: the
// reads that must happen within a block or two of inclusion); a capture holds its slot for that phase only, and asks for the
// Before state (which head-only providers never serve) without one, so a settlement is never made to wait for a slot by
// captures that are merely waiting for a state that will not be served (RB10-B10). One waiting for a slot has begun spending
// its budget, and names the wait when the budget ends before a slot frees, or frees with less than a poll of it left.
func (c *ReplayGuardCapturer) Begin(txHash common.Hash) {
	e, first := c.store.begin(c.cfg.ChainID, txHash)
	if !first {
		return
	}
	clock := c.cfg.clock()
	deadline := clock.Now().Add(c.cfg.budget())
	go func() {
		var ev *ReplayGuardEvidence
		defer func() {
			if r := recover(); r != nil {
				ev = &ReplayGuardEvidence{Version: ReplayGuardDomain, State: &ReplayNamedState{State: ReplayUnproven, Reason: ReasonStateUnavailable,
					ChainID: c.cfg.ChainID, TxHash: txHash, Detail: RedactEndpoints(fmt.Sprintf("the capture failed: %v", r))}}
			}
			if ev == nil {
				c.store.discard(c.cfg.ChainID, txHash) // no S6 claim: not an account settlement
			} else {
				c.store.put(e, ev, false)
			}
			close(e.done)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.budget()+time.Minute)
		defer cancel()
		slots := c.store.captureSlots(c.cfg.ChainID, c.cfg.concurrent())
		// slotWait is the named state of a capture that never read the chain because it waited for a slot.
		slotWait := func(why string) *ReplayGuardEvidence {
			c.cfg.logf("⚠️ [S6-REPLAY] chain %d tx %s: %s", c.cfg.ChainID, txHash.Hex(), why)
			return &ReplayGuardEvidence{Version: ReplayGuardDomain, State: &ReplayNamedState{State: ReplayUnproven, Reason: ReasonStateUnavailable,
				ChainID: c.cfg.ChainID, TxHash: txHash, Detail: RedactEndpoints(why) + " (the settlements observed at once exceed what the providers are asked for at once)"}}
		}
		waited := false
		select {
		case slots <- struct{}{}:
		default:
			waited = true
			wctx, wcancel := clock.WithDeadline(ctx, deadline)
			select {
			case slots <- struct{}{}:
				wcancel()
			case <-wctx.Done():
				wcancel()
				ev = slotWait(fmt.Sprintf("the capture waited for one of the %d capture slots of chain %d and none freed within its budget of %s",
					cap(slots), c.cfg.ChainID, c.cfg.budget()))
				return
			}
		}
		// The slot is the After phase's (V-R10B3 D1): the capture frees it when its After proof is in hand, and in any case
		// when it ends or panics.
		var once sync.Once
		free := func() { once.Do(func() { <-slots }) }
		defer free()
		remaining := deadline.Sub(clock.Now()) // the budget not spent waiting for the slot
		if waited && remaining < c.cfg.poll() {
			// V-R10B3 D2: a capture that got its slot with (all but) no budget left cannot read the chain on its own behalf: it
			// is the slot wait, not a receipt it failed to find.
			free()
			ev = slotWait(fmt.Sprintf("the capture waited for one of the %d capture slots of chain %d and one freed with %s of its budget of %s left, less than the poll of %s, too little to read the chain",
				cap(slots), c.cfg.ChainID, max(remaining, 0), c.cfg.budget(), c.cfg.poll()))
			return
		}
		cfg := c.cfg
		cfg.Budget = remaining
		if cfg.Budget <= 0 {
			cfg.Budget = time.Nanosecond // a zero budget would mean the default one
		}
		cfg.afterDone = free
		ev = CaptureReplayGuard(ctx, cfg, txHash)
	}()
}

// discard forgets a registration that turned out to be no settlement.
func (s *ReplayGuardStore) discard(chain int64, tx common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{chain, tx}
	if e, ok := s.m[k]; ok {
		s.bytes -= e.size
	}
	delete(s.m, k)
	for i, o := range s.order {
		if o == k {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// Bind holds the capture of the proven settlement s to it, in the background: the evidence is verified against s, and
// what does not verify is replaced by the named state saying why. A settlement whose capture was never begun (first seen
// at finality) is stored as s6_replay_unproven{capture_not_attempted_in_window}.
func (c *ReplayGuardCapturer) Bind(s *Settlement) {
	if s == nil || s.Tx == nil {
		return
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(s.Tx.LeafValue); err != nil {
		return
	}
	if _, ok := SettlementCallGeneration(tx.Data()); !ok {
		return // no account settlement: no S6 claim
	}
	go func() {
		var e *replayEntry
		// V-R10B note: whatever fails in here is the settlement's named state, never a crash of the observer. V-R10B2: the
		// state is built from what is known without verifying the settlement again, which may be what failed.
		defer func() {
			if r := recover(); r != nil && e != nil {
				c.store.put(e, c.panicState(s, r), true)
			}
		}()
		wait := c.bindWait
		if wait <= 0 {
			wait = c.cfg.budget() + 2*time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		e, first := c.store.begin(c.cfg.ChainID, s.TxHash)
		if first {
			l := c.look(s)
			c.noteLookError(s, l, "the settlement was first observed at finality and does not verify")
			c.store.put(e, c.namedState(l, s, ReplayUnproven, ReasonCaptureNotAttempted,
				"the settlement was first observed at finality; no proof of the replay guard was captured at inclusion, and no provider serves that state any longer"), true)
			close(e.done)
			return
		}
		select {
		case <-e.done:
		case <-ctx.Done():
			l := c.look(s)
			c.noteLookError(s, l, "the capture did not finish and the settlement does not verify")
			c.store.put(e, c.namedState(l, s, ReplayUnproven, ReasonStateUnavailable, "the capture did not finish: "+ctx.Err().Error()), true)
			return
		}
		c.store.mu.Lock()
		ev := e.ev
		c.store.mu.Unlock()
		if ev == nil {
			return
		}
		out, refusal := c.holdTo(ev, s)
		if refusal != "" {
			c.cfg.logf("⚠️ [S6-REPLAY] chain %d tx %s: the captured evidence does not hold against the proven settlement: %s",
				c.cfg.ChainID, s.TxHash.Hex(), refusal)
		}
		c.store.put(e, out, true)
	}()
}

// Resolve is the evidence of the proven settlement s as the capture stands now, held to s: nil while the capture has not
// finished (or none was begun), the verified evidence, or the named state saying why it does not hold. It never waits, and
// it never panics: it runs in the observation's own path.
func (c *ReplayGuardCapturer) Resolve(s *Settlement) (out *ReplayGuardEvidence) {
	if s == nil || s.Tx == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			c.note("⚠️ [S6-REPLAY] chain %d tx %s: Resolve recovered from a panic: %v", c.cfg.ChainID, s.TxHash.Hex(), r)
			out = c.panicState(s, r)
		}
	}()
	ev, _, ok := c.store.Get(c.cfg.ChainID, s.TxHash)
	if !ok {
		return nil
	}
	out, refusal := c.holdTo(ev, s)
	if refusal != "" {
		c.note("⚠️ [S6-REPLAY] chain %d tx %s: Resolve: the captured evidence does not hold against the proven settlement: %s",
			c.cfg.ChainID, s.TxHash.Hex(), refusal)
	}
	return out
}

// note logs on the observation's own path: a logger that fails is never what fails the observation or changes its evidence.
func (c *ReplayGuardCapturer) note(format string, args ...interface{}) {
	defer func() { _ = recover() }() // the logger is what failed: there is nowhere left to report it
	c.cfg.logf(format, args...)
}

// noteLookError logs why a proven settlement does not verify (a verification failure or a recovered panic), which the
// named state built from the look does not carry.
func (c *ReplayGuardCapturer) noteLookError(s *Settlement, l settlementLook, what string) {
	if l.err != nil {
		c.note("⚠️ [S6-REPLAY] chain %d tx %s: %s: %v", c.cfg.ChainID, s.TxHash.Hex(), what, l.err)
	}
}

// settlementLook is the one look at a proven settlement a Bind or a Resolve takes: its verified header and receipt, its
// transaction, and why they cannot be had.
type settlementLook struct {
	hdr    *types.Header
	rcpt   *ReceiptLeaf
	tx     *types.Transaction // decoded from the settlement's transaction leaf, whether or not the settlement verified
	err    error              // why the settlement does not verify, a panic in its verification included
	number uint64             // the settlement block's number, when it is known
}

// look verifies the settlement once. A panic in the verification is its error: it is neither raised nor repeated.
func (c *ReplayGuardCapturer) look(s *Settlement) (l settlementLook) {
	l.tx = settlementTx(s)
	defer func() {
		if r := recover(); r != nil {
			l.hdr, l.rcpt = nil, nil
			l.err = fmt.Errorf("verifying the settlement panicked: %v", r)
			l.number = settledNumber(s)
		}
	}()
	hdr, rcpt, err := c.verifySettlement(s)
	if err != nil {
		l.err = err
		return l
	}
	l.hdr, l.rcpt, l.number = hdr, rcpt, hdr.Number.Uint64()
	return l
}

// settlementTx is the transaction the settlement carries, nil when it does not decode.
func settlementTx(s *Settlement) (tx *types.Transaction) {
	defer func() {
		if recover() != nil {
			tx = nil
		}
	}()
	if s == nil || s.Tx == nil {
		return nil
	}
	var t types.Transaction
	if t.UnmarshalBinary(s.Tx.LeafValue) != nil {
		return nil
	}
	return &t
}

// settledNumber is the number of the settlement block, read without verifying the settlement: only a header that hashes
// to the block the settlement names states it, and 0 otherwise.
func settledNumber(s *Settlement) (n uint64) {
	defer func() {
		if recover() != nil {
			n = 0
		}
	}()
	if s == nil || len(s.Header) == 0 || crypto.Keccak256Hash(s.Header) != s.BlockHash {
		return 0
	}
	var h types.Header
	if rlp.DecodeBytes(s.Header, &h) != nil || h.Number == nil {
		return 0
	}
	return h.Number.Uint64()
}

// holdTo holds the captured evidence to the proven settlement s. It returns the evidence to keep: the capture's own when it
// holds; the capture's named state with the block and contract it could not state at the time filled in from the proven
// settlement (never replacing a block or contract it did state), when that holds; else the named state of why it does not
// hold, with a note of it. The settlement is verified once, and a panic anywhere in here is a named state built from what is
// already known.
func (c *ReplayGuardCapturer) holdTo(ev *ReplayGuardEvidence, s *Settlement) (out *ReplayGuardEvidence, refusal string) {
	l := c.look(s)
	defer func() {
		if r := recover(); r != nil {
			refusal = fmt.Sprintf("verifying the evidence panicked: %v", r)
			out = c.namedState(l, s, ReplayUnproven, ReasonProofDoesNotVerify, refusal)
		}
	}()
	if l.err != nil {
		refusal = fmt.Sprintf("the settlement does not verify: %v", l.err)
		return c.namedState(l, s, ReplayUnproven, ReasonSettlementUnproven, refusal), refusal
	}
	if l.tx == nil {
		refusal = "the proven transaction does not decode"
		return c.namedState(l, s, ReplayUnproven, ReasonSettlementUnproven, refusal), refusal
	}
	cand := restateUnknowns(ev, l)
	if _, err := cand.VerifyAgainst(l.hdr, l.tx, l.rcpt.Succeeded(), l.rcpt.Logs); err != nil {
		state, reason, detail := ReplayUnproven, ReasonProofDoesNotVerify, err.Error()
		if re, ok := err.(*ReplayError); ok {
			state, reason, detail = re.State, re.Reason, re.Detail
		}
		return c.refusalState(l, s, ev, state, reason, detail), fmt.Sprintf("%s{reason=%s}: %s", state, reason, detail)
	}
	return cand, ""
}

// restateUnknowns is the capture's named state about this transaction with what the capture could not state - the block
// (it never saw the receipt) and the contract (it never read the transaction) - taken from the proven settlement (RB10-B8
// D2): the capture keeps its reason, detail and providers. A block or contract it did state is never replaced, so a state of
// another block or contract is still the mismatch the verifier names. Any other evidence is returned as it is - evidence
// that carries a proof as well as a state included, which the verifier refuses by name (exactly one of the two): restating
// its state would drop the proof and make it verify (RB10-B10).
func restateUnknowns(ev *ReplayGuardEvidence, l settlementLook) *ReplayGuardEvidence {
	if ev == nil || ev.Proof != nil || ev.State == nil || l.hdr == nil || l.tx == nil || ev.State.TxHash != l.tx.Hash() {
		return ev
	}
	st := *ev.State
	changed := false
	if st.BlockNumber == 0 && st.BlockHash == (common.Hash{}) {
		st.BlockNumber, st.BlockHash, changed = l.hdr.Number.Uint64(), l.hdr.Hash(), true
	}
	if st.Contract == (common.Address{}) && l.tx.To() != nil {
		st.Contract, changed = *l.tx.To(), true
	}
	if !changed {
		return ev
	}
	return &ReplayGuardEvidence{Version: ev.Version, State: &st}
}

// namedState is the named state of the settlement s, stating the block and contract as the look found them.
func (c *ReplayGuardCapturer) namedState(l settlementLook, s *Settlement, state, reason, detail string) *ReplayGuardEvidence {
	st := &ReplayNamedState{State: state, Reason: reason, ChainID: c.cfg.ChainID, TxHash: s.TxHash, BlockHash: s.BlockHash, BlockNumber: l.number, Detail: RedactEndpoints(detail)}
	if l.tx != nil && l.tx.To() != nil {
		st.Contract = *l.tx.To()
	}
	return &ReplayGuardEvidence{Version: ReplayGuardDomain, State: st}
}

// panicState is the named state of a panic in a Bind or a Resolve, built without verifying the settlement (which may be
// what panicked): its block is read from the header only when that hashes to the block the settlement names.
func (c *ReplayGuardCapturer) panicState(s *Settlement, r interface{}) *ReplayGuardEvidence {
	l := settlementLook{tx: settlementTx(s), number: settledNumber(s)}
	return c.namedState(l, s, ReplayUnproven, ReasonStateUnavailable, fmt.Sprintf("the replay-guard evidence could not be held to the settlement: %v", r))
}

// refusalState is the named state of evidence that does not hold against the proven settlement s. A refutation
// slot_set_at_parent carries the Before that refutes, so that a reader verifies it (V-R10B note).
func (c *ReplayGuardCapturer) refusalState(l settlementLook, s *Settlement, ev *ReplayGuardEvidence, state, reason, detail string) *ReplayGuardEvidence {
	out := c.namedState(l, s, state, reason, detail)
	if state == ReplayRefuted && reason == ReasonSlotSetAtParent && ev != nil {
		switch {
		case ev.Proof != nil && ev.Proof.Before != nil:
			out.State.Before = ev.Proof.Before
		case ev.State != nil && ev.State.Before != nil:
			out.State.Before = ev.State.Before
		}
	}
	return out
}
