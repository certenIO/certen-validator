// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// RB12-CAPTURE-GAP, the capture loops (F13, live 2026-10-23). The loop gave up on every block it could not capture within 96 blocks and
// advanced its cursor: ~684 blocks were lost with only a log line to say so. Nothing a capturer cannot capture is silent any more.

func gapKeys(t *testing.T, st finality.CaptureStore, prefix string) []finality.CaptureKey {
	t.Helper()
	ks, err := st.ListByRange(context.Background(), finality.ChainBaseSepolia, 0, finality.MaxCaptureBlock, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestRB12LoopRecordsADurableGapForEveryBlockItCannotCapture(t *testing.T) {
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, mem, _ := rtBaseLoop(t, l1, nil)
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ks := gapKeys(t, mem, "gap/")
	if len(ks) != 1 || ks[0].L1Block != 99 || ks[0].Item != "gap/99/state_proof_unavailable" {
		t.Fatalf("a block whose state proof could not be had is a durable gap row, got %v", ks)
	}
	if notes := gapKeys(t, mem, "gapnote/"); len(notes) != 1 || notes[0].L1Block != 99 {
		t.Fatalf("the provider text is kept as a note: %v", notes)
	}
	// the same failure on the next tick adds nothing: the record is idempotent and written once per process
	before := len(gapKeys(t, mem, ""))
	l1.head = 101
	_ = loop.Tick(context.Background(), 2)
	_ = loop.Tick(context.Background(), 3)
	if after := len(gapKeys(t, mem, "gap")); after != 2 { // the gap row and its note
		t.Fatalf("rows with the gap prefix: %d (all rows %d before)", after, before)
	}
}

func TestRB12LoopNeverGivesUpABlockItHandsItToTheDurableBackfill(t *testing.T) {
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	loop, mem, lg := rtBaseLoop(t, l1, nil)
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
	if lg.has("given up") {
		t.Fatalf("no block is given up any more: %v", lg.lines)
	}
	if !lg.has("handed to the gap backfill") || !lg.has("L1 block 99") {
		t.Fatalf("the handover names the block: %v", lg.lines)
	}
	if ks := gapKeys(t, mem, "gap/"); len(ks) != 1 || ks[0].Item != "gap/99/state_proof_unavailable" {
		t.Fatalf("the block stays an OPEN gap for the backfill: %v", ks)
	}
	if fills := gapKeys(t, mem, "gapfill/"); len(fills) != 0 {
		t.Fatalf("nothing closed it: %v", fills)
	}
	if l1.calls[99] != 1 {
		t.Fatalf("the loop itself stops retrying outside the window (the backfill continues with the archive and backoff): %d reads", l1.calls[99])
	}
}

// A block that failed and then succeeds on the loop's retry closes its own gap.
func TestRB12LoopRetrySuccessClosesTheGapWithAFillThatNamesTheBlockHash(t *testing.T) {
	l1 := newRtProvingL1(t, 100)
	l1.failProofFor = map[uint64]int{99: 1} // the first proof of block 99 fails, the second works
	loop, mem := rtProvingLoop(t, l1)
	ctx := context.Background()
	if err := loop.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if ks := gapKeys(t, mem, "gap/"); len(ks) != 1 || gapKeys(t, mem, "gapfill/") != nil && len(gapKeys(t, mem, "gapfill/")) != 0 {
		t.Fatalf("block 99 is an open gap after its first attempt: %v", ks)
	}
	l1.head = 101
	if err := loop.Tick(ctx, 2); err != nil { // the retry is due at tick 2
		t.Fatal(err)
	}
	fills := gapKeys(t, mem, "gapfill/")
	if len(fills) != 1 || fills[0].L1Block != 99 || fills[0].L1Hash != l1.hashes[99] {
		t.Fatalf("the fill names the hash of the block it closed: %v", fills)
	}
}

// A cursor that is far behind the head is not crawled block by block through blocks no near-head provider can prove: the missed range
// is recorded as one gap for the backfill and the loop resumes at the window.
func TestRB12LoopALagBeyondTheWindowIsRecordedAsAGapAndTheScanResumesNearTheHead(t *testing.T) {
	l1 := &rtBaseL1{head: 100}
	loop, mem, lg := rtBaseLoop(t, l1, nil)
	ctx := context.Background()
	if err := loop.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	// the validator was down: the head is 5,000 blocks on
	l1.head, l1.order = 5100, nil
	if err := loop.Tick(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if len(l1.order) == 0 || l1.order[0] != 5100-96 {
		t.Fatalf("the scan resumed at %v, want the first block of the 96-block window (%d)", l1.order, 5100-96)
	}
	ks := gapKeys(t, mem, "gap/")
	if len(ks) != 1 || ks[0].L1Block != 101 || ks[0].Item != fmt.Sprintf("gap/%d/outage_unscanned", 5100-96-1) {
		t.Fatalf("the missed range [101, %d] is one outage_unscanned gap row, got %v", 5100-96-1, ks)
	}
	if !lg.has("101-5003") || !lg.has("outage_unscanned") {
		t.Fatalf("the range is logged by name: %v", lg.lines)
	}
}

// A shutdown in the middle of a round must not move the cursor over blocks that were never tried.
func TestRB12LoopShutdownMidRoundLeavesTheCursorBehindTheUntriedBlocks(t *testing.T) {
	l1 := &rtBaseL1{head: 100}
	loop, mem, _ := rtBaseLoop(t, l1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := loop.Tick(context.Background(), 1); err != nil { // cursor at 100
		t.Fatal(err)
	}
	l1.head = 120
	l1.onBlock = func(n uint64) {
		if n == 105 {
			cancel() // the process is told to stop while block 105 is being read
		}
	}
	_ = loop.Tick(ctx, 2)
	cur, _, _ := readCursor(context.Background(), mem, finality.ChainBaseSepolia)
	if cur > 105 {
		t.Fatalf("the cursor moved to %d over blocks 106-120 that were never scanned", cur)
	}
	// and nothing is lost: the next process continues from the cursor
	l1.onBlock, l1.order = nil, nil
	loop2, _, _ := rtBaseLoop(t, l1, nil)
	loop2.Store, loop2.Cap.Store = mem, mem
	if err := loop2.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if len(l1.order) == 0 || l1.order[0] > 106 {
		t.Fatalf("the next process resumed at %v; blocks after %d were never scanned", l1.order, cur)
	}
}

// ---- helpers: a Base L1 that can prove ----

// rtProvingL1 serves blocks with one inbox transaction each (calldata, no blob) whose transaction trie root is the header's, and answers
// the SystemConfig proofs, failing the first n proofs of a block when told to.
type rtProvingL1 struct {
	t            testing.TB
	head         uint64
	blocks       map[uint64]baseposted.L1BlockData
	hashes       map[uint64][32]byte
	failProofFor map[uint64]int
	proofAsks    map[uint64]int
}

func newRtProvingL1(t testing.TB, head uint64) *rtProvingL1 {
	return &rtProvingL1{t: t, head: head, blocks: map[uint64]baseposted.L1BlockData{}, hashes: map[uint64][32]byte{}, proofAsks: map[uint64]int{}}
}

func (f *rtProvingL1) Head(context.Context) (uint64, error) { return f.head, nil }

func (f *rtProvingL1) Block(_ context.Context, n uint64) (baseposted.L1BlockData, error) {
	if b, ok := f.blocks[n]; ok {
		return b, nil
	}
	if n != 98 && n != 99 { // only blocks 98 and 99 hold inbox transactions
		return baseposted.L1BlockData{Number: n}, nil
	}
	raws := [][]byte{{0x02, 0xc0, byte(n)}}
	hdr, err := rlp.EncodeToBytes(&types.Header{Number: new(big.Int).SetUint64(n), Difficulty: big.NewInt(0), TxHash: ethproof.TrieRoot(raws)})
	if err != nil {
		f.t.Fatal(err)
	}
	h := [32]byte(crypto.Keccak256Hash(hdr))
	f.hashes[n] = h
	b := baseposted.L1BlockData{Number: n, Hash: h, HeaderRLP: hdr, Timestamp: 1_700_000_000, TxRaw: raws, TxTo: [][20]byte{rtInbox}, TxHasTo: []bool{true}, TxBlobHash: [][][32]byte{nil}}
	f.blocks[n] = b
	return b, nil
}

func (f *rtProvingL1) Proof(_ context.Context, addr [20]byte, slots [][32]byte, block uint64) (baseposted.StateProof, error) {
	f.proofAsks[block]++
	if f.proofAsks[block] <= f.failProofFor[block] {
		return baseposted.StateProof{}, errors.New("eth_getProof: historical state is not available")
	}
	sp := baseposted.StateProof{Nodes: [][]byte{[]byte("node")}, Values: map[[32]byte][32]byte{}}
	if len(slots) > 0 {
		var v [32]byte
		v[31] = 7
		sp.Values[rtImplSlot] = v
	}
	return sp, nil
}

func rtProvingLoop(t testing.TB, l1 *rtProvingL1) (*BasePostedLoop, *finality.MemCaptureStore) {
	t.Helper()
	mem := finality.NewMemCaptureStore()
	lg := &rtLog{}
	c := &baseposted.Capturer{Chain: finality.ChainBaseSepolia, Pins: &baseposted.Pins{BatchInbox: rtInbox}, L1: l1, Store: mem, SlotSeconds: 12}
	return &BasePostedLoop{Cap: c, Store: mem, Every: 12 * time.Second, StartBack: 2, Logf: lg.logf,
		retry: map[uint64]*retryEntry{}, lastState: map[uint64]*finality.StateError{}}, mem
}

// the EIP-1967 implementation slot
var rtImplSlot = [32]byte{0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d, 0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc}
