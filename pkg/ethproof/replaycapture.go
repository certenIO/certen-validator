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
	if c.Logf != nil {
		c.Logf(format, args...)
	}
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
	state := &ReplayNamedState{ChainID: cfg.ChainID, TxHash: txHash}
	finish := func(st, reason, format string, args ...interface{}) *ReplayGuardEvidence {
		state.State, state.Reason, state.Detail = st, reason, fmt.Sprintf(format, args...)
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
			if top > n+MaxReplayHeaderChain {
				top = n + MaxReplayHeaderChain
			}
			low := n
			if top >= n+replayAfterCandidates {
				low = top - replayAfterCandidates + 1
			}
		pass:
			for _, p := range providers {
				for h := top; ; h-- {
					if bctx.Err() != nil {
						break pass
					}
					hdrs, herr := headers.upTo(bctx, h)
					if herr != nil {
						failures.note(p.Name(), fmt.Sprintf("block %d: %v", h, herr))
					} else {
						hdrH := headerN
						if len(hdrs) > 0 {
							hdrH = hdrs[len(hdrs)-1]
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
						}
					}
					if after != nil || h == low {
						break
					}
				}
				if after != nil {
					break
				}
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
			Reason:    fmt.Sprintf("no provider served the state of block %d, the settlement block's parent, before %s", n-1, ended()),
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
	done  chan struct{}
}

// ReplayGuardStore holds the replay-guard evidence of settlements beside them, by (chain, transaction): bounded, oldest
// first out. It is the single place the evidence builders read from.
type ReplayGuardStore struct {
	mu    sync.Mutex
	max   int
	order []replayKey
	m     map[replayKey]*replayEntry
}

// DefaultReplayGuards is the process-wide store the observers and the evidence builders share.
var DefaultReplayGuards = NewReplayGuardStore(8192)

// NewReplayGuardStore returns a store holding at most max settlements' evidence.
func NewReplayGuardStore(max int) *ReplayGuardStore {
	if max <= 0 {
		max = 1024
	}
	return &ReplayGuardStore{max: max, m: map[replayKey]*replayEntry{}}
}

// begin registers a capture; first is true for the caller that must run it.
func (s *ReplayGuardStore) begin(chain int64, tx common.Hash) (*replayEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{chain, tx}
	if e, ok := s.m[k]; ok {
		return e, false
	}
	e := &replayEntry{done: make(chan struct{})}
	s.m[k] = e
	s.order = append(s.order, k)
	for len(s.order) > s.max {
		delete(s.m, s.order[0])
		s.order = s.order[1:]
	}
	return e, true
}

func (s *ReplayGuardStore) put(e *replayEntry, ev *ReplayGuardEvidence, bound bool) {
	s.mu.Lock()
	e.ev, e.bound = ev, bound
	s.mu.Unlock()
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

// ReplayGuardCapturer starts captures at inclusion and binds them to the proven settlement; both calls return at once.
type ReplayGuardCapturer struct {
	cfg   ReplayCaptureConfig
	store *ReplayGuardStore
}

// NewReplayGuardCapturer returns a capturer writing to store (DefaultReplayGuards when nil).
func NewReplayGuardCapturer(cfg ReplayCaptureConfig, store *ReplayGuardStore) *ReplayGuardCapturer {
	if store == nil {
		store = DefaultReplayGuards
	}
	return &ReplayGuardCapturer{cfg: cfg, store: store}
}

// Begin starts the capture of txHash's replay guard in the background, once per transaction. It never blocks and never
// fails the caller: whatever happens is stored as evidence or as a named state.
func (c *ReplayGuardCapturer) Begin(txHash common.Hash) {
	e, first := c.store.begin(c.cfg.ChainID, txHash)
	if !first {
		return
	}
	go func() {
		var ev *ReplayGuardEvidence
		defer func() {
			if r := recover(); r != nil {
				ev = &ReplayGuardEvidence{Version: ReplayGuardDomain, State: &ReplayNamedState{State: ReplayUnproven, Reason: ReasonStateUnavailable,
					ChainID: c.cfg.ChainID, TxHash: txHash, Detail: fmt.Sprintf("the capture failed: %v", r)}}
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
		ev = CaptureReplayGuard(ctx, c.cfg, txHash)
	}()
}

// discard forgets a registration that turned out to be no settlement.
func (s *ReplayGuardStore) discard(chain int64, tx common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{chain, tx}
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
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.budget()+2*time.Minute)
		defer cancel()
		e, first := c.store.begin(c.cfg.ChainID, s.TxHash)
		if first {
			c.store.put(e, c.settlementState(s, ReplayUnproven, ReasonCaptureNotAttempted,
				"the settlement was first observed at finality; no proof of the replay guard was captured at inclusion, and no provider serves that state any longer"), true)
			close(e.done)
			return
		}
		select {
		case <-e.done:
		case <-ctx.Done():
			c.store.put(e, c.settlementState(s, ReplayUnproven, ReasonStateUnavailable, "the capture did not finish: "+ctx.Err().Error()), true)
			return
		}
		c.store.mu.Lock()
		ev := e.ev
		c.store.mu.Unlock()
		if ev == nil {
			return
		}
		if _, err := ev.Verify(s); err != nil {
			st, reason := ReplayUnproven, ReasonProofDoesNotVerify
			detail := err.Error()
			if re, ok := err.(*ReplayError); ok {
				st, reason, detail = re.State, re.Reason, re.Detail
			}
			c.cfg.logf("⚠️ [S6-REPLAY] chain %d tx %s: the captured evidence does not hold against the proven settlement: %s{reason=%s}: %s",
				c.cfg.ChainID, s.TxHash.Hex(), st, reason, detail)
			c.store.put(e, c.settlementState(s, st, reason, detail), true)
			return
		}
		c.store.put(e, ev, true)
	}()
}

// Resolve is the evidence of the proven settlement s as the capture stands now, held to s: nil while the capture has not
// finished (or none was begun), the verified evidence, or the named state saying why it does not hold. It never waits.
func (c *ReplayGuardCapturer) Resolve(s *Settlement) *ReplayGuardEvidence {
	if s == nil || s.Tx == nil {
		return nil
	}
	ev, _, ok := c.store.Get(c.cfg.ChainID, s.TxHash)
	if !ok {
		return nil
	}
	if _, err := ev.Verify(s); err != nil {
		st, reason, detail := ReplayUnproven, ReasonProofDoesNotVerify, err.Error()
		if re, ok := err.(*ReplayError); ok {
			st, reason, detail = re.State, re.Reason, re.Detail
		}
		return c.settlementState(s, st, reason, detail)
	}
	return ev
}

func (c *ReplayGuardCapturer) settlementState(s *Settlement, state, reason, detail string) *ReplayGuardEvidence {
	st := &ReplayNamedState{State: state, Reason: reason, ChainID: c.cfg.ChainID, TxHash: s.TxHash, BlockHash: s.BlockHash, Detail: detail}
	if hdr, _, err := s.Verify(); err == nil {
		st.BlockNumber = hdr.Number.Uint64()
	}
	var tx types.Transaction
	if s.Tx != nil && tx.UnmarshalBinary(s.Tx.LeafValue) == nil && tx.To() != nil {
		st.Contract = *tx.To()
	}
	return &ReplayGuardEvidence{Version: ReplayGuardDomain, State: st}
}
