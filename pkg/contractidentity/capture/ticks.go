// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/metrics"
)

// E1b, the hop ticks (V2_SPEC_S8 r3.3 Q2, step 16, A5). A tick is a block T read AT THE HEAD together with the EIP-2935 slot proof of the
// previous tick under the state root of T; a chain of ticks, at most floor(W/2) blocks apart, ties an attestation block B_v to a settlement
// block more than W blocks later. The first link of an anchor is the slot proof of B_v under the first tick after B_v.
//
// Rows (insert-only, V2_SPEC_S8 Q2 WHERE stored):
//
//	global tick chain  Key{chain, tickAnchor(chain, epoch), hash(T), "tick/<T>/<P>"}      -> CTK1 {T, hash, P, header, nodes of slot P}
//	per-anchor link    Key{chain, anchorID, hash(B_v), "hop/first/<T>"}                    -> CFL1 {B_v, T, header, nodes of slot B_v}
//
// P is the previous tick (0 for a start tick: the first of a chain, or a tick that follows a gap of more than W blocks, which no history
// proof can bridge). One Put is one row: a crash cannot leave half a tick. The key carries T and P, so two validators that tick different
// blocks, or the same block against different previous ticks, never conflict; the same key holds the same bytes (canonical node order).
const (
	ItemTickPrefix  = "tick/"
	ItemFirstPrefix = "hop/first/"
	tickMagic       = "CTK1"
	firstMagic      = "CFL1"
	// maxTickKeys bounds the keys one epoch listing may return; a store that returns more is hostile or broken (named error).
	maxTickKeys = 4096
	// MaxTracked bounds the anchors one ticker follows.
	MaxTracked = 4096
	// epochTicks is how many tick spacings one tick epoch (one anchor id of the tick chain) spans: a listing then holds at most a few
	// dozen ticks, and a leg (reach 17 W) reads at most a few epochs.
	epochTicks = 64
	// TickWorkingSetBytes is what one tick reserves: one provider answer being parsed and its pool.
	TickWorkingSetBytes = MaxResponseBytes + (1 << 20)
	// DefaultTickPoll is how often the loop looks at the head.
	DefaultTickPoll = 2 * time.Second
)

var (
	ErrTickConflict     = errors.New("capture: a tick row exists with different bytes")
	ErrTickRowMalformed = errors.New("capture: a tick row is malformed")
	ErrTickListTooLarge = errors.New("capture: a tick listing exceeds its bound")
	ErrTooManyTracked   = errors.New("capture: too many anchors are tracked")
	ErrNoTickWindow     = errors.New("capture: the chain has no EIP-2935 window")
)

func num20(n uint64) string { return fmt.Sprintf("%020d", n) }

// tickAnchor is the anchor id under which the global tick chain of a chain keeps the ticks of one epoch (domain separated, so it can never
// be an anchor id of a batch).
func tickAnchor(chain, epoch uint64) [32]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], chain)
	binary.BigEndian.PutUint64(b[8:], epoch)
	return crypto.Keccak256Hash([]byte("certen/s8/ticks/v1"), b[:])
}

func epochOf(h, n uint64) uint64 { return n / (epochTicks * h) }

// TickSpacing is floor(W/2) of the chain's EIP-2935 window.
func TickSpacing(m *ci.Manifest, chain uint64) (h, w uint64, err error) {
	e, ok := m.EIP2935(chain)
	if !ok || e.Window < 2 {
		return 0, 0, fmt.Errorf("%w: chain %d", ErrNoTickWindow, chain)
	}
	return e.Window / 2, e.Window, nil
}

// ---- rows ----

type tickRow struct {
	Number uint64
	Hash   [32]byte
	Prev   uint64
	Header []byte
	Nodes  [][]byte
}

type firstRow struct {
	Bv     ci.BlockRef
	Tick   uint64
	Header []byte
	Nodes  [][]byte
}

func putNodes(w *wbuf, nodes [][]byte) {
	w.u32(len(nodes))
	for _, n := range nodes {
		w.lp(n)
	}
}

func getNodes(r *rbuf) [][]byte {
	n := r.u32()
	if r.err != nil || n < 0 || n > ci.DefaultLimits().MaxNodes {
		if r.err == nil {
			r.err = errors.New("too many nodes")
		}
		return nil
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, r.lp())
	}
	return out
}

// headerOf decodes a header row member and returns it when it re-encodes to its hash.
func headerOf(raw []byte) (*types.Header, error) {
	var h types.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil || h.Number == nil || !h.Number.IsUint64() {
		return nil, fmt.Errorf("%w: header", ErrTickRowMalformed)
	}
	if crypto.Keccak256Hash(raw) != h.Hash() {
		return nil, fmt.Errorf("%w: header does not re-encode to its hash", ErrTickRowMalformed)
	}
	return &h, nil
}

func encodeTick(r *tickRow) []byte {
	var w wbuf
	w.raw([]byte(tickMagic))
	w.u64(r.Number)
	w.raw(r.Hash[:])
	w.u64(r.Prev)
	w.lp(r.Header)
	putNodes(&w, sortNodes(r.Nodes))
	return w.b
}

func decodeTick(raw []byte) (*tickRow, error) {
	r := &rbuf{b: raw}
	if string(r.take(4)) != tickMagic {
		return nil, fmt.Errorf("%w: magic", ErrTickRowMalformed)
	}
	t := &tickRow{Number: r.u64()}
	copy(t.Hash[:], r.take(32))
	t.Prev = r.u64()
	t.Header = r.lp()
	t.Nodes = getNodes(r)
	if r.err != nil || len(r.b) != 0 {
		return nil, fmt.Errorf("%w: layout", ErrTickRowMalformed)
	}
	h, err := headerOf(t.Header)
	if err != nil {
		return nil, err
	}
	if h.Number.Uint64() != t.Number || h.Hash() != common.Hash(t.Hash) || (t.Prev != 0 && t.Prev >= t.Number) {
		return nil, fmt.Errorf("%w: header, number, hash or previous tick disagree", ErrTickRowMalformed)
	}
	return t, nil
}

func encodeFirst(r *firstRow) []byte {
	var w wbuf
	w.raw([]byte(firstMagic))
	w.u64(r.Bv.Number)
	w.raw(r.Bv.Hash[:])
	w.u64(r.Tick)
	w.lp(r.Header)
	putNodes(&w, sortNodes(r.Nodes))
	return w.b
}

func decodeFirst(raw []byte) (*firstRow, error) {
	r := &rbuf{b: raw}
	if string(r.take(4)) != firstMagic {
		return nil, fmt.Errorf("%w: magic", ErrTickRowMalformed)
	}
	f := &firstRow{}
	f.Bv.Number = r.u64()
	copy(f.Bv.Hash[:], r.take(32))
	f.Tick = r.u64()
	f.Header = r.lp()
	f.Nodes = getNodes(r)
	if r.err != nil || len(r.b) != 0 {
		return nil, fmt.Errorf("%w: layout", ErrTickRowMalformed)
	}
	h, err := headerOf(f.Header)
	if err != nil {
		return nil, err
	}
	if h.Number.Uint64() != f.Tick || f.Tick <= f.Bv.Number {
		return nil, fmt.Errorf("%w: first link header or order", ErrTickRowMalformed)
	}
	return f, nil
}

// parseTickItem reads "tick/<T>/<P>".
func parseTickItem(item string) (t, p uint64, ok bool) {
	rest := strings.TrimPrefix(item, ItemTickPrefix)
	if rest == item {
		return 0, 0, false
	}
	a, b, found := strings.Cut(rest, "/")
	if !found || len(a) != 20 || len(b) != 20 {
		return 0, 0, false
	}
	var err1, err2 error
	t, err1 = strconv.ParseUint(a, 10, 64)
	p, err2 = strconv.ParseUint(b, 10, 64)
	return t, p, err1 == nil && err2 == nil
}

func parseFirstItem(item string) (uint64, bool) {
	rest := strings.TrimPrefix(item, ItemFirstPrefix)
	if rest == item || len(rest) != 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	return n, err == nil
}

// tickRef is a stored tick as its key names it.
type tickRef struct {
	Number, Prev uint64
	Key          Key
}

// listTicks returns the ticks of the epochs from..to (inclusive), at most maxTickKeys per epoch.
func listTicks(ctx context.Context, st Store, chain, h, from, to uint64) ([]tickRef, error) {
	var out []tickRef
	for ep := from; ep <= to; ep++ {
		keys, err := st.ListByAnchor(ctx, chain, tickAnchor(chain, ep))
		if err != nil {
			return nil, err
		}
		if len(keys) > maxTickKeys {
			return nil, fmt.Errorf("%w: %d keys in epoch %d", ErrTickListTooLarge, len(keys), ep)
		}
		for _, k := range keys {
			if t, p, ok := parseTickItem(k.Item); ok && epochOf(h, t) == ep {
				out = append(out, tickRef{Number: t, Prev: p, Key: k})
			}
		}
		if ep == ^uint64(0) {
			break
		}
	}
	return out, nil
}

// ---- the ticker ----

// TickConfig configures the tick chain of one chain. Config.Source needs HeaderByNumber (also the latest tag) and Providers; Budget bounds
// ONE tick.
type TickConfig struct {
	Config
	Store Store
	Poll  time.Duration // default DefaultTickPoll, on Config.Clock
	// Reserve takes the memory a tick needs (the runtime's byte budget); the returned release is called once on every path. Nil = no budget.
	Reserve func() (release func(), ok bool)
	// Deadline is the memberChainDeadline of an anchor (pkg/execution): past it the anchor is no longer followed. Optional; when absent the
	// anchor is followed until it is settled or out of reach (B_v + 16 ticks + W).
	Deadline func(anchorID [32]byte) (time.Time, bool)
}

// TrackedAnchor is an attested, unsettled anchor whose legs may be settled after more than W blocks.
type TrackedAnchor struct {
	AnchorID [32]byte
	Bv       ci.BlockRef
	Deadline time.Time // zero: none known
}

// Step outcomes.
const (
	StepIdle       = "idle"              // nothing is tracked
	StepNotDue     = "not_due"           // the next tick is not yet due
	StepTicked     = "ticked"            // a tick row was stored
	StepNoBudget   = "memory_budget"     // the byte budget was full; nothing read, retry at the next poll
	StepNoSlot     = "no_capture_slot"   // the chain's gate was full
	StepUnreadable = "state_unavailable" // no provider served the proofs of the tick within the budget; nothing stored
)

// StepResult is what one iteration of the loop did.
type StepResult struct {
	Kind       string
	Head, Tick uint64
	Prev       uint64   // the previous tick this tick links to (0: a start tick)
	Firsts     []uint64 // B_v of the first links stored
	Dropped    map[string]int
	Mismatches int // slot proofs whose value was not the hash of the block asked for (a reorged block): skipped
}

// Ticker is the tick chain of one chain. Step is the loop body; Run is the loop. Both are safe to call from one goroutine; Track and
// Untrack may be called from any.
type Ticker struct {
	cfg  TickConfig
	h, w uint64
	hist common.Address

	mu      sync.Mutex
	tracked map[[32]byte]*TrackedAnchor
	hasLink map[[32]byte]bool
}

// NewTicker validates the configuration. A chain without an EIP-2935 row has no tick chain (its legs use the spine).
func NewTicker(cfg TickConfig) (*Ticker, error) {
	if err := cfg.Config.check(); err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errors.New("capture: TickConfig.Store is nil")
	}
	h, w, err := TickSpacing(cfg.Manifest, cfg.Chain)
	if err != nil {
		return nil, err
	}
	e, _ := cfg.Manifest.EIP2935(cfg.Chain)
	return &Ticker{cfg: cfg, h: h, w: w, hist: common.HexToAddress(e.Address), tracked: map[[32]byte]*TrackedAnchor{}, hasLink: map[[32]byte]bool{}}, nil
}

// Track starts following an anchor. It is idempotent (a re-observation after a restart re-registers).
func (t *Ticker) Track(a TrackedAnchor) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.tracked[a.AnchorID]; ok {
		return nil
	}
	if len(t.tracked) >= MaxTracked {
		return ErrTooManyTracked
	}
	c := a
	t.tracked[a.AnchorID] = &c
	return nil
}

// Untrack stops following an anchor (it is settled).
func (t *Ticker) Untrack(anchorID [32]byte) {
	t.mu.Lock()
	delete(t.tracked, anchorID)
	delete(t.hasLink, anchorID)
	t.mu.Unlock()
}

// Tracked is the number of anchors followed.
func (t *Ticker) Tracked() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tracked)
}

func (t *Ticker) snapshot() []TrackedAnchor {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TrackedAnchor, 0, len(t.tracked))
	for _, a := range t.tracked {
		out = append(out, *a)
	}
	return out
}

// reach is the last block at which a tick still serves an anchor attested at bv: 16 ticks, then one window.
func (t *Ticker) reach(bv uint64) uint64 {
	return bv + uint64(ci.DefaultLimits().MaxAttestHops)*t.h + t.w
}

func (t *Ticker) poll() time.Duration {
	if t.cfg.Poll <= 0 {
		return DefaultTickPoll
	}
	return t.cfg.Poll
}

// Run is the loop: Step, wait one poll, until ctx ends. A step error is logged and the loop goes on (the next step re-derives everything
// from the store).
func (t *Ticker) Run(ctx context.Context) {
	clock := t.cfg.clock()
	for ctx.Err() == nil {
		if _, err := t.Step(ctx); err != nil && ctx.Err() == nil {
			t.cfg.logf("⚠️ [CONTRACT-IDENTITY] chain %d tick: %v", t.cfg.Chain, err)
		}
		if !clock.Sleep(ctx, t.poll()) {
			return
		}
	}
}

func (t *Ticker) drop(res *StepResult, a TrackedAnchor, reason string) {
	t.Untrack(a.AnchorID)
	if res.Dropped == nil {
		res.Dropped = map[string]int{}
	}
	res.Dropped[reason]++
	metrics.ContractIdentityCaptureDropped(t.cfg.Chain, "tick", reason)
}

// firstLinked reports whether the store holds a first link of the anchor.
func (t *Ticker) firstLinked(ctx context.Context, a TrackedAnchor) (bool, error) {
	t.mu.Lock()
	ok := t.hasLink[a.AnchorID]
	t.mu.Unlock()
	if ok {
		return true, nil
	}
	keys, err := t.cfg.Store.ListByAnchor(ctx, t.cfg.Chain, a.AnchorID)
	if err != nil {
		return false, err
	}
	if len(keys) > maxTickKeys {
		return false, fmt.Errorf("%w: %d keys of anchor %x", ErrTickListTooLarge, len(keys), a.AnchorID[:4])
	}
	for _, k := range keys {
		if k.BlockHash == a.Bv.Hash {
			if _, isFirst := parseFirstItem(k.Item); isFirst {
				t.mu.Lock()
				t.hasLink[a.AnchorID] = true
				t.mu.Unlock()
				return true, nil
			}
		}
	}
	return false, nil
}

// lastTick is the newest stored tick at or below head (epochs of head and the one before it).
func (t *Ticker) lastTick(ctx context.Context, head uint64) (tickRef, []tickRef, bool, error) {
	ep := epochOf(t.h, head)
	from := ep
	if ep > 0 {
		from = ep - 1
	}
	ts, err := listTicks(ctx, t.cfg.Store, t.cfg.Chain, t.h, from, ep)
	if err != nil {
		return tickRef{}, nil, false, err
	}
	var best tickRef
	found := false
	for _, r := range ts {
		if r.Number <= head && (!found || r.Number > best.Number) {
			best, found = r, true
		}
	}
	return best, ts, found, nil
}

// Step is one iteration of the loop. It stores at most one tick row and the first links that tick serves; everything it needs it derives
// from the store, so a crash at any point loses nothing: the rows already put stay, the missing ones are made by the next step (a first link
// whose Put did not happen is still missing, so the next tick, a block or more later, makes it).
func (t *Ticker) Step(ctx context.Context) (res StepResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = StepResult{Kind: StepUnreadable}, &PanicError{Value: asciiText(fmt.Sprint(r))}
		}
	}()
	now := t.cfg.clock().Now()
	var live []TrackedAnchor
	for _, a := range t.snapshot() {
		if !a.Deadline.IsZero() && !now.Before(a.Deadline) {
			t.drop(&res, a, "deadline")
			continue
		}
		if t.cfg.Deadline != nil {
			if d, ok := t.cfg.Deadline(a.AnchorID); ok && !now.Before(d) {
				t.drop(&res, a, "deadline")
				continue
			}
		}
		live = append(live, a)
	}
	if len(live) == 0 {
		res.Kind = StepIdle
		return res, nil
	}
	src := t.cfg.Source
	latest, herr := src.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if herr != nil || latest == nil || latest.Number == nil {
		return StepResult{Kind: StepUnreadable}, unreadable("head", herr)
	}
	head := latest.Number.Uint64()
	res.Head = head
	var serve []TrackedAnchor // anchors waiting for a first link that T = head can give
	alive := 0
	for _, a := range live {
		if head > t.reach(a.Bv.Number) {
			t.drop(&res, a, "reach")
			continue
		}
		alive++
		linked, lerr := t.firstLinked(ctx, a)
		if lerr != nil {
			return res, lerr
		}
		if !linked && head > a.Bv.Number && head-a.Bv.Number <= t.w {
			serve = append(serve, a)
		}
	}
	if alive == 0 {
		res.Kind = StepIdle
		return res, nil
	}
	last, listed, hasLast, lerr := t.lastTick(ctx, head)
	if lerr != nil {
		return res, lerr
	}
	due := !hasLast || head-last.Number >= t.h
	if !due && len(serve) == 0 {
		res.Kind = StepNotDue
		return res, nil
	}
	if t.cfg.Reserve != nil {
		release, ok := t.cfg.Reserve()
		if !ok {
			metrics.ContractIdentityCaptureDropped(t.cfg.Chain, "tick", "memory_budget")
			res.Kind = StepNoBudget
			return res, nil
		}
		defer release()
	}
	clock := t.cfg.clock()
	parent := ctx
	ctx, cancel := clock.WithDeadline(ctx, clock.Now().Add(t.cfg.budget()))
	defer cancel()
	if t.cfg.Gate != nil {
		release, gerr := t.cfg.Gate.Acquire(ctx)
		if gerr != nil {
			if parent.Err() != nil {
				return res, parent.Err()
			}
			res.Kind = StepNoSlot
			return res, nil
		}
		defer release()
	}
	hdr, herr := src.HeaderByNumber(ctx, new(big.Int).SetUint64(head))
	if herr != nil || hdr == nil || hdr.Number == nil || hdr.Number.Uint64() != head {
		return StepResult{Kind: StepUnreadable, Head: head}, unreadable("tick header", herr)
	}
	// what this tick proves: the previous tick (when within W) and B_v of every anchor still waiting for its first link
	want := map[uint64]common.Hash{}
	prev := uint64(0)
	switch {
	case hasLast && head > last.Number && head-last.Number <= t.w:
		prev = last.Number
		want[prev] = common.Hash(last.Key.BlockHash)
	case hasLast && head == last.Number && last.Prev != 0:
		// the tick of this very block was stored (a first link is still missing, e.g. after a crash): make the same row again
		for _, r := range listed {
			if r.Number == last.Prev {
				prev = r.Number
				want[prev] = common.Hash(r.Key.BlockHash)
				break
			}
		}
	}
	var firsts []TrackedAnchor
	for _, a := range serve {
		if head-a.Bv.Number <= t.w {
			want[a.Bv.Number] = common.Hash(a.Bv.Hash)
			firsts = append(firsts, a)
		}
	}
	nodes, mism, rerr := t.readSlots(ctx, hdr, want)
	if rerr != nil {
		var ue *UnavailableError
		if parent.Err() != nil {
			return res, parent.Err()
		}
		if errors.As(rerr, &ue) {
			res.Kind, res.Tick = StepUnreadable, head
			return res, nil
		}
		return res, rerr
	}
	res.Mismatches = len(mism)
	raw, rerr2 := rlp.EncodeToBytes(hdr)
	if rerr2 != nil || crypto.Keccak256Hash(raw) != hdr.Hash() {
		return res, errors.New("capture: the agreed tick header does not re-encode to its hash")
	}
	row := &tickRow{Number: head, Hash: [32]byte(hdr.Hash()), Header: raw}
	if _, bad := mism[prev]; prev != 0 && !bad {
		row.Prev, row.Nodes = prev, nodes[prev]
	}
	key := Key{Chain: t.cfg.Chain, AnchorID: tickAnchor(t.cfg.Chain, epochOf(t.h, head)), BlockHash: row.Hash, Item: ItemTickPrefix + num20(head) + "/" + num20(row.Prev)}
	if perr := t.cfg.Store.Put(ctx, key, encodeTick(row)); perr != nil {
		if errors.Is(perr, ErrCaptureConflict) {
			return res, fmt.Errorf("%w: %s", ErrTickConflict, key)
		}
		return res, perr
	}
	res.Kind, res.Tick, res.Prev = StepTicked, head, row.Prev
	for _, a := range firsts {
		if _, bad := mism[a.Bv.Number]; bad {
			continue
		}
		fr := &firstRow{Bv: a.Bv, Tick: head, Header: raw, Nodes: nodes[a.Bv.Number]}
		fk := Key{Chain: t.cfg.Chain, AnchorID: a.AnchorID, BlockHash: a.Bv.Hash, Item: ItemFirstPrefix + num20(head)}
		if perr := t.cfg.Store.Put(ctx, fk, encodeFirst(fr)); perr != nil {
			return res, perr
		}
		t.mu.Lock()
		t.hasLink[a.AnchorID] = true
		t.mu.Unlock()
		res.Firsts = append(res.Firsts, a.Bv.Number)
	}
	return res, nil
}

// readSlots reads, in ONE eth_getProof per contract, the EIP-2935 slots of the wanted blocks under the root of hdr, runs the plan's own hop
// read (planner.hop) strictly over the verified nodes to find exactly the nodes each hop visits, and checks every slot holds the hash of the
// block it was asked for. A block whose slot holds another hash was reorged away: it is returned in mism and gets no proof.
func (t *Ticker) readSlots(ctx context.Context, hdr *types.Header, want map[uint64]common.Hash) (nodes map[uint64][][]byte, mism map[uint64]bool, err error) {
	nodes, mism = map[uint64][][]byte{}, map[uint64]bool{}
	if len(want) == 0 {
		return nodes, mism, nil
	}
	cfg := t.cfg.Config
	m := cfg.Manifest
	facts := func(prev uint64) *Facts {
		return &Facts{Chain: cfg.Chain, Manifest: m, Link: ci.LinkHops, HopNumbers: []uint64{prev, hdr.Number.Uint64()}}
	}
	num := hdr.Number.Uint64()
	col := newCollector(&cfg, map[string]blockAt{HopStation(1): {num, hdr.Root}})
	if err := col.run(ctx, func(rd Reader) (bool, error) {
		pending := false
		for prev := range want {
			p := &planner{rd: rd, f: facts(prev)}
			p.hop(0)
			if p.err != nil {
				return false, p.err
			}
			pending = pending || p.pending
		}
		return pending, nil
	}); err != nil {
		return nil, nil, err
	}
	pool := make([][]byte, 0, len(col.pool))
	for _, n := range col.pool {
		pool = append(pool, n)
	}
	e, _ := m.EIP2935(cfg.Chain)
	for prev, hash := range want {
		ns, nerr := ci.NewNodeSet(sortNodes(pool))
		if nerr != nil {
			return nil, nil, nerr
		}
		st := newStrict(ns, map[string]common.Hash{HopStation(1): hdr.Root}, nil)
		p := &planner{rd: st, f: facts(prev)}
		p.hop(0)
		if p.err != nil || p.pending {
			return nil, nil, &PlanError{Station: HopStation(1), Reason: "verified_pool_does_not_replay", Err: p.err}
		}
		v, verr := st.Slot(HopStation(1), t.hist, common.BigToHash(new(big.Int).SetUint64(prev%e.Window)))
		if verr != nil {
			return nil, nil, verr
		}
		if v != hash {
			mism[prev] = true
			continue
		}
		nodes[prev] = sortNodes(ns.VisitedNodes())
	}
	return nodes, mism, nil
}
