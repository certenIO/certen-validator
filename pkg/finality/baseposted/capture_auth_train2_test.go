// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/synthstate"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-GO-INT D2 (V-T2): the capture STORES what an untrusted provider serves, and rows are insert-only, so what it stores it must have
// authenticated: the SystemConfig proof under the header's own state root, and the sender of every inbox transaction against the batcher
// that proof establishes (the rule of verify.go verifyChannel, "Authentication"). A transaction the batcher did not send is skipped and
// counted; a block whose state proof does not verify is stored NOT AT ALL and the gap stays open. The same CaptureBlock serves the live
// loop and the backfill (CapturerOf), so the same hostile inputs are tried through both.

// calldataBlock is a synthetic L1 block whose inbox transactions are plain calldata transactions signed by the given labels.
func calldataBlock(t *testing.T, number uint64, root common.Hash, labels ...string) L1BlockData {
	t.Helper()
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	var raws [][]byte
	var tos [][20]byte
	var has []bool
	var bh [][][32]byte
	for i, l := range labels {
		tx, err := types.SignNewTx(testKey(l), signer, &types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: uint64(i), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10),
			Gas: 21000, To: &testInbox, Data: []byte{byte(i), 1, 2, 3}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
		tos = append(tos, [20]byte(testInbox))
		has = append(has, true)
		bh = append(bh, nil)
	}
	h := &types.Header{Number: new(big.Int).SetUint64(number), TxHash: ethproof.TrieRoot(raws), Root: root, ParentHash: common.Hash{8}, Time: 1655733600 + 12*5000,
		Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
	hdr, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return L1BlockData{Number: number, Hash: [32]byte(crypto.Keccak256Hash(hdr)), HeaderRLP: hdr, Timestamp: h.Time, TxRaw: raws, TxTo: tos, TxHasTo: has, TxBlobHash: bh}
}

func authCapturer(blk L1BlockData, l1 L1Source, rec func(uint64, *finality.StateError)) (*Capturer, *MemStore) {
	st := NewMemStore()
	if l1 == nil {
		l1 = &fakeL1{blk: blk}
	}
	return &Capturer{Chain: 84532, Pins: newPins(), L1: l1, Beacon: fakeBeacon{}, Store: st, GenesisTime: 1655733600, SlotSeconds: 12, Record: rec}, st
}

func hasRow(t *testing.T, st *MemStore, blk L1BlockData, item string) bool {
	t.Helper()
	_, ok, err := st.Get(context.Background(), CaptureKey{Chain: 84532, L1Block: blk.Number, L1Hash: blk.Hash, Item: item})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func foreignCount(t *testing.T) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == "certen_finality_capture_foreign_inbox_tx_total" {
			var sum float64
			for _, m := range f.GetMetric() {
				sum += m.GetCounter().GetValue()
			}
			return sum
		}
	}
	return 0
}

// A valid-looking row signed by someone who is not the batcher is not stored as the batcher's: it is skipped and counted, and the
// batcher's own transaction of the same block is stored.
func TestRB12GOINTTheCaptureSkipsAndCountsAnInboxTransactionTheBatcherDidNotSend(t *testing.T) {
	metrics.RegisterMetrics()
	blk := calldataBlock(t, 1000, common.Hash(testProvable().st.Root), "attacker", "batcher")
	c, st := authCapturer(blk, nil, nil)
	before := foreignCount(t)
	ok, err := c.CaptureBlock(context.Background(), 1000)
	if err != nil || !ok {
		t.Fatalf("capture: %v %v", ok, err)
	}
	if hasRow(t, st, blk, ItemTx(0)) || hasRow(t, st, blk, ItemTxNodes(0)) {
		t.Fatal("a transaction signed by a key that is not SystemConfig.batcherHash was stored as an inbox transaction")
	}
	if !hasRow(t, st, blk, ItemTx(1)) || !hasRow(t, st, blk, ItemTxNodes(1)) {
		t.Fatal("the batcher's own transaction of the block must be stored")
	}
	row, _, _ := st.Get(context.Background(), CaptureKey{Chain: 84532, L1Block: 1000, L1Hash: blk.Hash, Item: ItemInbox})
	r := finality.NewReader(row, finality.DefaultLimits())
	n, err := r.Count("inbox", 16, 4)
	if err != nil || n != 1 {
		t.Fatalf("the inbox row lists %d transactions (%v), want only the batcher's one", n, err)
	}
	if got := foreignCount(t); got != before+1 {
		t.Fatalf("certen_finality_capture_foreign_inbox_tx_total %v -> %v, want +1", before, got)
	}
}

// A block whose inbox transactions were all sent by others holds nothing to capture: nothing is stored, and it is no error.
func TestRB12GOINTABlockOfForeignInboxTransactionsOnlyStoresNothing(t *testing.T) {
	blk := calldataBlock(t, 1000, common.Hash(testProvable().st.Root), "attacker", "attacker2")
	c, st := authCapturer(blk, nil, nil)
	ok, err := c.CaptureBlock(context.Background(), 1000)
	if err != nil || ok {
		t.Fatalf("(%v, %v): a block with only foreign inbox transactions has nothing to capture", ok, err)
	}
	if ks, _ := finality.CaptureKeysOfItem(context.Background(), st, 84532, ItemHeader); len(ks) != 0 {
		t.Fatal("rows of a block with no authorized inbox transaction were stored")
	}
}

// A state proof that does not verify under the header's state root (a wrong root, one flipped byte, an implementation that is not pinned,
// another batcher's state) stores nothing, names batcher_state_unavailable and leaves the gap open; through the live capture and the backfill.
func TestRB12GOINTAStateProofThatDoesNotVerifyStoresNothingAndNamesIt(t *testing.T) {
	good := testProvable().st
	other := synthstate.New(testSysConfig, testImpl, [32]byte(testImplCode), [20]byte{0xde, 0xad})
	for _, tc := range []struct {
		name string
		root common.Hash
		l1   func(blk L1BlockData) L1Source
		pins func(*Pins)
	}{
		{"a state root that is not the proof's", common.Hash{9}, nil, nil},
		{"a flipped byte in the first proof node", common.Hash(good.Root), func(blk L1BlockData) L1Source { return &flippedL1{inner: &fakeL1{blk: blk}} }, nil},
		{"an implementation whose code hash is not pinned", common.Hash(good.Root), nil, func(p *Pins) { p.SystemConfigImplHashes = map[[32]byte]bool{{1}: true} }},
		{"the proof of another state under this header's root", common.Hash(good.Root), func(blk L1BlockData) L1Source { return &stateL1{blk: blk, st: other} }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blk := calldataBlock(t, 1000, tc.root, "batcher")
			var l1 L1Source
			if tc.l1 != nil {
				l1 = tc.l1(blk)
			}
			var recorded []*finality.StateError
			c, st := authCapturer(blk, l1, func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) })
			if tc.pins != nil {
				tc.pins(c.Pins)
			}
			ok, err := c.CaptureBlock(context.Background(), 1000)
			if ok || err == nil {
				t.Fatalf("a proof that does not verify must fail the capture: (%v, %v)", ok, err)
			}
			if len(recorded) != 1 || recorded[0].Code != "batcher_state_unavailable" {
				t.Fatalf("recorded %v", recorded)
			}
			if ks, _ := finality.CaptureKeysOfItem(context.Background(), st, 84532, ItemHeader); len(ks) != 0 {
				t.Fatal("rows were stored for a block whose state proof does not verify")
			}
			// the backfill's capture is this capture: the same inputs fail through it, with the named state and the proof class
			c2, st2 := authCapturer(blk, l1, nil)
			if tc.pins != nil {
				tc.pins(c2.Pins)
			}
			_, _, err = CapturerOf(c2).CaptureBlockHash(context.Background(), 1000)
			if err == nil || ClassOfFailure(err) != finality.GapStateProofUnavailable {
				t.Fatalf("through the backfill: %v (class %s)", err, ClassOfFailure(err))
			}
			if ks, _ := finality.CaptureKeysOfItem(context.Background(), st2, 84532, ItemHeader); len(ks) != 0 {
				t.Fatal("the backfill stored rows of a block whose state proof does not verify")
			}
		})
	}
}

// The backfill path: a block served by the archive provider with a transaction from a non-batcher is captured WITHOUT it.
func TestRB12GOINTTheBackfillCapturesOnlyTheBatchersTransactions(t *testing.T) {
	blk := calldataBlock(t, 1000, common.Hash(testProvable().st.Root), "attacker", "batcher")
	c, st := authCapturer(blk, nil, nil)
	h, inbox, err := CapturerOf(c).CaptureBlockHash(context.Background(), 1000)
	if err != nil || !inbox || h != blk.Hash {
		t.Fatalf("%x %v %v", h, inbox, err)
	}
	if hasRow(t, st, blk, ItemTx(0)) || !hasRow(t, st, blk, ItemTx(1)) {
		t.Fatal("the backfill stored a foreign transaction or lost the batcher's")
	}
}

// D7 (second half): the capture verifies the header hash and the transaction list against the header for EVERY block, also one that holds
// no inbox transaction, so "this block holds nothing to capture" (which closes a gap) is a verified statement: a provider that serves
// another header than the hash it names, or transactions that are not the header's, is refused.
func TestRB12GOINTAnEmptyBlockIsVerifiedBeforeItCountsAsScanned(t *testing.T) {
	blk := calldataBlock(t, 1000, common.Hash(testProvable().st.Root), "batcher")
	empty := calldataBlock(t, 1000, common.Hash(testProvable().st.Root)) // no transactions, a real header
	for _, tc := range []struct {
		name string
		blk  L1BlockData
		ok   bool
	}{
		{"a true empty block", empty, true},
		{"a header that does not hash to the named block hash", func() L1BlockData { b := empty; b.Hash[0] ^= 1; return b }(), false},
		{"transactions that are not the header's (a block claimed empty that is not)", func() L1BlockData {
			b := blk
			b.TxRaw, b.TxTo, b.TxHasTo, b.TxBlobHash = nil, nil, nil, nil
			return b
		}(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, st := authCapturer(tc.blk, nil, nil)
			h, inbox, err := CapturerOf(c).CaptureBlockHash(context.Background(), 1000)
			if tc.ok {
				if err != nil || inbox || h != tc.blk.Hash {
					t.Fatalf("%x %v %v", h, inbox, err)
				}
				return
			}
			if err == nil {
				t.Fatal("an unverified block was accepted as scanned")
			}
			if ks, _ := finality.CaptureKeysOfItem(context.Background(), st, 84532, ItemHeader); len(ks) != 0 {
				t.Fatal("rows were stored")
			}
		})
	}
}

// stateL1 serves the proofs of one synthetic state (a hostile or another provider's).
type stateL1 struct {
	blk L1BlockData
	st  *synthstate.State
}

func (s *stateL1) Head(context.Context) (uint64, error) { return s.blk.Number, nil }
func (s *stateL1) Block(_ context.Context, n uint64) (L1BlockData, error) {
	if n != s.blk.Number {
		return emptyBlockAt(n), nil
	}
	return s.blk, nil
}
func (s *stateL1) Proof(_ context.Context, addr [20]byte, slots [][32]byte, _ uint64) (StateProof, error) {
	nodes, values := s.st.Proof(addr, slots)
	return StateProof{Nodes: nodes, Values: values}, nil
}

// flippedL1 serves the good proofs with one byte of the first node of every answer flipped.
type flippedL1 struct{ inner *fakeL1 }

func (f *flippedL1) Head(ctx context.Context) (uint64, error) { return f.inner.Head(ctx) }
func (f *flippedL1) Block(ctx context.Context, n uint64) (L1BlockData, error) {
	return f.inner.Block(ctx, n)
}
func (f *flippedL1) Proof(ctx context.Context, addr [20]byte, slots [][32]byte, b uint64) (StateProof, error) {
	sp, err := f.inner.Proof(ctx, addr, slots, b)
	if err == nil && len(sp.Nodes) > 0 {
		n := append([]byte(nil), sp.Nodes[0]...)
		n[len(n)/2] ^= 1
		sp.Nodes = append([][]byte{n}, sp.Nodes[1:]...)
	}
	return sp, err
}

// The test slots equal the production ones.
func TestRB12GOINTSynthstateSlotsAreTheProductionSlots(t *testing.T) {
	if synthstate.BatcherHashSlot != batcherHashSlot || synthstate.ImplSlot != eip1967ImplSlot {
		t.Fatal("the synthetic state uses other storage slots than the verifier")
	}
}
