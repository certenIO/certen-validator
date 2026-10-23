// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// ---- helpers ----

// rtHeader is a raw RLP execution header of block n and its hash (15 items: every positional slot ReadHeader needs).
func rtHeader(t testing.TB, n uint64) ([]byte, [32]byte) {
	t.Helper()
	raw, err := rlp.EncodeToBytes(&types.Header{Number: new(big.Int).SetUint64(n), Difficulty: big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	return raw, [32]byte(crypto.Keccak256Hash(raw))
}

// rtScript is the scripted clock of a loop: After records the wait it is asked for and answers at once; the stopAfter-th wait
// cancels the context, so a loop under test ends deterministically and never really sleeps.
type rtScript struct {
	waits     []time.Duration
	stopAfter int
	cancel    context.CancelFunc
}

func (s *rtScript) After(d time.Duration) <-chan time.Time {
	s.waits = append(s.waits, d)
	if len(s.waits) >= s.stopAfter {
		s.cancel()
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

// rtStatus is a BuilderStatusStore that keeps the rows.
type rtStatus struct {
	mu   sync.Mutex
	rows map[string]finality.BuilderStatus
	n    int
}

func (s *rtStatus) UpsertStatus(_ context.Context, b finality.BuilderStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[string]finality.BuilderStatus{}
	}
	s.rows[fmt.Sprintf("%s/%d", b.ProofID, b.TargetLevel)] = b
	s.n++
	return nil
}

func (s *rtStatus) GetStatus(context.Context, string, finality.Level) (finality.BuilderStatusView, bool, error) {
	return finality.BuilderStatusView{}, false, nil
}

func (s *rtStatus) row(proofID string, target finality.Level) (finality.BuilderStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[fmt.Sprintf("%s/%d", proofID, target)]
	return b, ok
}

type rtLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *rtLog) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}

func (l *rtLog) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---- Base posted ----

var rtInbox = [20]byte{0xba, 0x5e, 0x1b, 0x0c}

// rtBaseL1 is a baseposted.L1Source: a head, blocks without batch-inbox transactions, and blocks that hold one whose
// SystemConfig proof can never be had (the provider window is missed).
type rtBaseL1 struct {
	t       testing.TB
	head    uint64
	headErr error
	failing map[uint64]bool
	calls   map[uint64]int // Block calls per number
	order   []uint64
	onBlock func(n uint64) // told of every block read, after it was counted (tests that stop the process mid-round)
}

func (f *rtBaseL1) Head(context.Context) (uint64, error) { return f.head, f.headErr }

func (f *rtBaseL1) Block(ctx context.Context, n uint64) (baseposted.L1BlockData, error) {
	if err := ctx.Err(); err != nil { // a provider call made after the process was told to stop fails, as it does in production
		return baseposted.L1BlockData{}, err
	}
	if f.calls == nil {
		f.calls = map[uint64]int{}
	}
	f.calls[n]++
	f.order = append(f.order, n)
	if f.onBlock != nil {
		f.onBlock(n)
	}
	if !f.failing[n] {
		return baseposted.L1BlockData{Number: n}, nil // no transactions: nothing to capture
	}
	hdr, hash := rtHeader(f.t, n)
	return baseposted.L1BlockData{Number: n, Hash: hash, HeaderRLP: hdr, Timestamp: 1_700_000_000,
		TxRaw: [][]byte{{0x02}}, TxTo: [][20]byte{rtInbox}, TxHasTo: []bool{true}, TxBlobHash: [][][32]byte{nil}}, nil
}

func (f *rtBaseL1) Proof(context.Context, [20]byte, [][32]byte, uint64) (baseposted.StateProof, error) {
	return baseposted.StateProof{}, errors.New("eth_getProof: missing trie node (state is pruned)")
}

func rtBaseLoop(t testing.TB, l1 *rtBaseL1, st finality.BuilderStatusStore) (*BasePostedLoop, *finality.MemCaptureStore, *rtLog) {
	t.Helper()
	l1.t = t
	mem := finality.NewMemCaptureStore()
	lg := &rtLog{}
	c := &baseposted.Capturer{Chain: finality.ChainBaseSepolia, Pins: &baseposted.Pins{BatchInbox: rtInbox}, L1: l1, Store: mem, SlotSeconds: 12}
	return &BasePostedLoop{Cap: c, Store: mem, Status: st, Every: 12 * time.Second, StartBack: 2, Logf: lg.logf,
		retry: map[uint64]*retryEntry{}, lastState: map[uint64]*finality.StateError{}}, mem, lg
}

func TestRTBaseLoopCursorAdvancesToTheScannedBlockIsPersistedAndTheNextTickContinuesAfterIt(t *testing.T) {
	l1 := &rtBaseL1{head: 100}
	loop, mem, _ := rtBaseLoop(t, l1, nil)
	ctx := context.Background()
	if err := loop.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(l1.order) != "[98 99 100]" {
		t.Fatalf("first tick scanned %v, want [98 99 100] (StartBack 2 below the head)", l1.order)
	}
	if cur, ok, err := readCursor(ctx, mem, finality.ChainBaseSepolia); err != nil || !ok || cur != 100 {
		t.Fatalf("cursor %d %v %v, want 100 persisted", cur, ok, err)
	}
	l1.head, l1.order = 105, nil
	if err := loop.Tick(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(l1.order) != "[101 102 103 104 105]" {
		t.Fatalf("second tick scanned %v, want [101..105]: it must start at cursor+1", l1.order)
	}
	// a restart (a new loop over the same durable store) continues where the cursor is, not at the head
	loop2, _, _ := rtBaseLoop(t, l1, nil)
	loop2.Store, loop2.Cap.Store = mem, mem
	l1.head, l1.order = 107, nil
	if err := loop2.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(l1.order) != "[106 107]" {
		t.Fatalf("after a restart the scan was %v, want [106 107]", l1.order)
	}
	// MaxPerTick bounds one round; the cursor stops at the range end and the lag is the rest
	loop2.MaxPerTick = 10
	l1.head, l1.order = 200, nil
	if err := loop2.Tick(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if len(l1.order) != 10 || l1.order[0] != 108 || l1.order[9] != 117 {
		t.Fatalf("bounded tick scanned %v, want 108..117", l1.order)
	}
	if cur, _, _ := readCursor(ctx, mem, finality.ChainBaseSepolia); cur != 117 {
		t.Fatalf("cursor %d after a bounded tick, want 117", cur)
	}
}

func TestRTBaseLoopAMissedWindowIsANamedStatusRowOfTheChainsCapturePseudoProof(t *testing.T) {
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	st := &rtStatus{}
	loop, _, lg := rtBaseLoop(t, l1, st)
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	row, ok := st.row(CaptureStatusProofID(finality.ChainBaseSepolia), finality.LevelL1Posted)
	if !ok {
		t.Fatalf("no status row under %s: a missed provider window must be a recorded state", CaptureStatusProofID(finality.ChainBaseSepolia))
	}
	if row.Class != finality.BuilderUnavailable || row.Chain != finality.ChainBaseSepolia || row.State == nil ||
		row.State.Code != "batcher_state_unavailable" || row.State.Fields["l1_block"] != uint64(99) {
		t.Fatalf("row %+v state %v, want unavailable / batcher_state_unavailable{l1_block 99}", row, row.State)
	}
	if !IsCaptureStatusProofID(row.ProofID) {
		t.Fatalf("%s is not recognised as a capture pseudo proof id", row.ProofID)
	}
	if !lg.has("batcher_state_unavailable") {
		t.Fatal("the named state was not logged")
	}
	// the blocks without inbox transactions left no status
	if st.n != 1 {
		t.Fatalf("%d status writes, want exactly 1", st.n)
	}
}

func TestRTBaseLoopRetryGapDoublesAndEndsOutsideTheWindowWithoutAnArchiveProvider(t *testing.T) {
	// the gap doubles: the failing block is read again at ticks 1 (scan), 2, 4, 8, 16
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, _, _ := rtBaseLoop(t, l1, nil)
	var at []int
	prev := 0
	for tick := 1; tick <= 16; tick++ {
		l1.head = 99 + uint64(tick)
		if err := loop.Tick(context.Background(), tick); err != nil {
			t.Fatal(err)
		}
		if l1.calls[99] != prev {
			at = append(at, tick)
			prev = l1.calls[99]
		}
	}
	if fmt.Sprint(at) != "[1 2 4 8 16]" {
		t.Fatalf("block 99 was read at ticks %v, want [1 2 4 8 16] (gaps 1,2,4,8)", at)
	}

	// no archive provider: outside ProofWindow the loop hands the block to the durable gap backfill (RB12-CAPTURE-GAP: nothing is given up),
	// logs it by name, and stops reading it itself
	l1 = &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, _, lg := rtBaseLoop(t, l1, nil)
	loop.ProofWindow = 10
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	l1.head = 111 // 99 is now 12 blocks old, outside the 10-block window
	for tick := 2; tick <= 12; tick++ {
		if err := loop.Tick(context.Background(), tick); err != nil {
			t.Fatal(err)
		}
	}
	if l1.calls[99] != 1 {
		t.Fatalf("block 99 was read %d times, want 1: the loop does not retry a block outside the window with no archive (the backfill does)", l1.calls[99])
	}
	if !lg.has("handed to the gap backfill at head 111") || !lg.has("archive provider configured: false") {
		t.Fatalf("the handover was not logged by name: %v", lg.lines)
	}
	if _, held := loop.retry[99]; held {
		t.Fatal("a handed-over block is still held for retry by the loop")
	}

	// an archive provider keeps the block retryable until MaxRetryAge
	l1 = &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, _, lg = rtBaseLoop(t, l1, nil)
	loop.ProofWindow, loop.HasArchive, loop.MaxRetryAge = 10, true, 50
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	l1.head = 111
	if err := loop.Tick(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if l1.calls[99] != 2 {
		t.Fatalf("with an archive provider block 99 was read %d times by tick 2, want 2 (retried outside the window)", l1.calls[99])
	}
	l1.head = 151 // 52 blocks old: beyond MaxRetryAge
	for tick := 3; tick <= 8; tick++ {
		if err := loop.Tick(context.Background(), tick); err != nil {
			t.Fatal(err)
		}
	}
	if l1.calls[99] != 2 {
		t.Fatalf("block 99 was read %d times, want 2: beyond MaxRetryAge the loop hands it to the gap backfill", l1.calls[99])
	}
	if !lg.has("handed to the gap backfill at head 151") || !lg.has("archive provider configured: true") {
		t.Fatalf("the handover was not logged by name: %v", lg.lines)
	}
}

func TestRTBaseLoopRunWaitsEveryIntervalOncePerTickNeverSpinsAndEndsNilOnCancel(t *testing.T) {
	for _, every := range []time.Duration{12 * time.Second, 0, 100 * time.Millisecond} {
		t.Run(every.String(), func(t *testing.T) {
			l1 := &rtBaseL1{head: 100}
			loop, _, _ := rtBaseLoop(t, l1, nil)
			loop.Every = every
			loop.retry, loop.lastState = nil, nil // Run initialises its own state
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sc := &rtScript{stopAfter: 4, cancel: cancel}
			loop.Clock = loopClock{After: sc.After}
			done := make(chan error, 1)
			go func() { done <- loop.Run(ctx) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run returned %v after cancel, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not end after its context was cancelled")
			}
			if len(sc.waits) != 4 {
				t.Fatalf("%d waits, want 4 (one per tick)", len(sc.waits))
			}
			want := every
			if want < finality.MinPoll {
				want = finality.MinPoll // a configured interval below the floor is raised to it
			}
			for i, w := range sc.waits {
				if w != want || w <= 0 {
					t.Fatalf("wait %d was %v, want %v and never zero", i, w, want)
				}
			}
		})
	}
}

func TestRTBaseLoopAnUnavailableHeadIsATickErrorAndRunKeepsWaiting(t *testing.T) {
	l1 := &rtBaseL1{head: 100, headErr: errors.New("eth_blockNumber via https://p.example: HTTP 503")}
	loop, _, lg := rtBaseLoop(t, l1, nil)
	if err := loop.Tick(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "head is unavailable") {
		t.Fatalf("Tick error %v, want the head-unavailable error", err)
	}
	loop.retry, loop.lastState = nil, nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := &rtScript{stopAfter: 3, cancel: cancel}
	loop.Clock = loopClock{After: sc.After}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil on cancel", err)
	}
	if len(sc.waits) != 3 {
		t.Fatalf("%d waits for 3 failing ticks, want 3: a failing head must neither stop nor spin the loop", len(sc.waits))
	}
	if !lg.has("tick 1:") || !lg.has("tick 3:") {
		t.Fatalf("the failed ticks were not logged: %v", lg.lines)
	}
}

// Tick is exported: a caller that never went through Run (a test, a one-shot tool) must not crash on a failed block. The retry
// state is created where it is first used.
func TestRTBaseLoopTickWithoutRunDoesNotPanicOnAFailedBlock(t *testing.T) {
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, _, _ := rtBaseLoop(t, l1, nil)
	loop.retry, loop.lastState = nil, nil
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Tick panicked on a failed block when called without Run: %v", r)
		}
	}()
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
}

// ---- Arbitrum posted ----

type rtArbL1 struct {
	t      testing.TB
	head   uint64
	event  capture.Log
	tx     capture.Tx
	hdrErr error
	headEr error
	heads  int
}

func (f *rtArbL1) HeadNumber(context.Context) (uint64, error) {
	f.heads++
	return f.head, f.headEr
}

func (f *rtArbL1) Header(_ context.Context, n uint64) (capture.Header, error) {
	if f.hdrErr != nil {
		return capture.Header{}, f.hdrErr
	}
	raw, hash := rtHeader(f.t, n)
	return capture.Header{Number: n, Hash: hash, RLP: raw}, nil
}

func (f *rtArbL1) Logs(_ context.Context, _ [20]byte, topic0 [32]byte, _ *[32]byte, from, to uint64) ([]capture.Log, error) {
	if f.event.BlockNumber != 0 && topic0 == [32]byte(capture.TopicBatchDelivered) && f.event.BlockNumber >= from && f.event.BlockNumber <= to {
		return []capture.Log{f.event}, nil
	}
	return nil, nil
}

func (f *rtArbL1) TxByHash(context.Context, [32]byte) (capture.Tx, error) { return f.tx, nil }

func (f *rtArbL1) GetProof(context.Context, [20]byte, [][32]byte, uint64, func(*capture.Proof) error) (*capture.Proof, error) {
	return nil, errors.New("eth_getProof: missing trie node (state is pruned)")
}

// rtBatchEvent builds a SequencerBatchDelivered log of batch n at L1 block `block` with no data (location 2), whose afterAcc is
// consistent with its inputs, so the capturer accepts it.
func rtBatchEvent(t testing.TB, n, block uint64) (capture.Log, capture.Tx) {
	t.Helper()
	_, hash := rtHeader(t, block)
	var w = func(v uint64) []byte { b := make([]byte, 32); new(big.Int).SetUint64(v).FillBytes(b); return b }
	lg := capture.Log{BlockNumber: block, BlockHash: hash, TxHash: [32]byte{0x77}, TxIndex: 0, LogIndex: 0}
	var nt [32]byte
	new(big.Int).SetUint64(n).FillBytes(nt[:])
	before := [32]byte{0xbe}
	lg.Topics = [][32]byte{[32]byte(capture.TopicBatchDelivered), nt, before, {}}
	data := make([]byte, 0, 224)
	delayed := [32]byte{0xde}
	data = append(data, delayed[:]...)
	for _, v := range []uint64{0, 100, 200, 10, 20, 2} { // afterDelayedMessagesRead, min/max time, min/max block, location NoData
		data = append(data, w(v)...)
	}
	lg.Data = data
	rec, err := capture.ParseBatchDelivered(lg)
	if err != nil {
		t.Fatal(err)
	}
	dh := rec.DataHash(nil)
	acc := crypto.Keccak256Hash(before[:], dh[:], delayed[:])
	lg.Topics[3] = [32]byte(acc)
	return lg, capture.Tx{Hash: lg.TxHash, BlockHash: hash, BlockNumber: block, Index: 0, Raw: []byte{0x02}}
}

func rtArbLoop(t testing.TB, l1 *rtArbL1, st finality.BuilderStatusStore) (*ArbPostedLoop, *rtLog) {
	t.Helper()
	l1.t = t
	lg := &rtLog{}
	cp := capture.NewCapturer(finality.NewMemCaptureStore(), l1, nil, capture.Config{StartBack: 5, Logf: lg.logf})
	return &ArbPostedLoop{Cap: cp, Providers: []string{"https://p1.example", "https://p2.example"}, Status: st, Every: 12 * time.Second, Logf: lg.logf}, lg
}

func TestRTArbLoopRunWaitsEveryIntervalNeverSpinsAndKeepsGoingAfterATickError(t *testing.T) {
	for _, every := range []time.Duration{12 * time.Second, 0} {
		t.Run(every.String(), func(t *testing.T) {
			l1 := &rtArbL1{head: 100}
			loop, lg := rtArbLoop(t, l1, nil)
			loop.Every = every
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sc := &rtScript{stopAfter: 3, cancel: cancel}
			loop.Clock = loopClock{After: sc.After}
			if err := loop.Run(ctx); err != nil {
				t.Fatalf("Run returned %v after cancel, want nil", err)
			}
			want := every
			if want < finality.MinPoll {
				want = finality.MinPoll
			}
			if len(sc.waits) != 3 || l1.heads != 3 {
				t.Fatalf("%d waits and %d ticks, want 3 and 3: exactly one wait per tick", len(sc.waits), l1.heads)
			}
			for i, w := range sc.waits {
				if w != want {
					t.Fatalf("wait %d was %v, want %v", i, w, want)
				}
			}
			_ = lg
		})
	}
	// a failing head: logged, waited, retried; never a tight loop
	l1 := &rtArbL1{head: 100, headEr: errors.New("HTTP 429")}
	loop, lg := rtArbLoop(t, l1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := &rtScript{stopAfter: 3, cancel: cancel}
	loop.Clock = loopClock{After: sc.After}
	if err := loop.Run(ctx); err != nil || len(sc.waits) != 3 || l1.heads != 3 {
		t.Fatalf("failing head: err %v, %d waits, %d ticks, want nil, 3, 3", err, len(sc.waits), l1.heads)
	}
	if !lg.has("tick:") {
		t.Fatalf("the failed ticks were not logged: %v", lg.lines)
	}
}

func TestRTArbLoopAProofWindowMissIsAChainLevelNamedStatusRow(t *testing.T) {
	l1 := &rtArbL1{head: 100}
	l1.t = t
	l1.event, l1.tx = rtBatchEvent(t, 7, 98)
	st := &rtStatus{}
	loop, lg := rtArbLoop(t, l1, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := &rtScript{stopAfter: 1, cancel: cancel}
	loop.Clock = loopClock{After: sc.After}
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	row, ok := st.row(CaptureStatusProofID(finality.ChainArbitrumSepolia), finality.LevelL1Posted)
	if !ok {
		t.Fatalf("no chain-level status row; log: %v", lg.lines)
	}
	if row.Class != finality.BuilderUnavailable || row.Chain != finality.ChainArbitrumSepolia || row.State == nil ||
		row.State.Code != "l1_proof_window_unavailable" || row.State.Fields["l1_block"] != uint64(100) {
		t.Fatalf("row %+v state %v, want unavailable / l1_proof_window_unavailable{l1_block 100 (the head it was judged at)}", row, row.State)
	}
	if !strings.Contains(fmt.Sprint(row.State.Fields["providers"]), "p1.example") {
		t.Fatalf("state text %q must name the providers by host", row.State.Error())
	}
	if !lg.has("l1_proof_window_unavailable") {
		t.Fatal("the named state was not logged")
	}
}
