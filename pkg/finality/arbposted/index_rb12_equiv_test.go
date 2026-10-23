// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

const ixT0 = 1_790_000_000

// ixPopulation builds the store most tests share: ten blob batches 96 s apart, each holding four messages of its own; one message that two
// batches hold (the first by N must be served), a reorg twin (N=105 under two blocks that both hold the same message), a calldata batch, a
// batch that is no payload, a batch with no data, and a batch whose time bounds are narrow.
func ixPopulation(t *testing.T) (*ixWorld, map[string][][]byte) {
	t.Helper()
	w := newIxWorld(t)
	legs := map[string][][]byte{}
	tx := func(i, j int) []byte { return ixTx(1000*i + j) }
	for i := 0; i < 10; i++ {
		N := uint64(200 + i)
		var msgs [][][]byte
		for j := 0; j < 4; j++ {
			msgs = append(msgs, ixMsg(tx(i, j)))
			legs[keyOf(i, j)] = [][]byte{tx(i, j)}
		}
		msgs = append(msgs, ixMsg(tx(i, 8), tx(i, 9))) // a kind-3 batch message of two transactions
		legs[keyOf(i, 8)] = [][]byte{tx(i, 8), tx(i, 9)}
		switch i {
		case 2, 4:
			msgs = append(msgs, ixMsg(ixTx(555))) // held by batch 202 and batch 204
		case 5:
			msgs = append(msgs, ixMsg(ixTx(777))) // held by both twins of N=205
		}
		w.add(ixBatch{N: N, Block: 1000 + uint64(8*i), T: ixT0 + uint64(96*i), Msgs: msgs})
		if i == 5 {
			w.add(ixBatch{N: N, Block: 1000 + uint64(8*i), T: ixT0 + uint64(96*i), Tag: 1, Msgs: msgs}) // the orphan twin: same N, same height, another hash
		}
	}
	legs["dup"] = [][]byte{ixTx(555)}
	legs["twin"] = [][]byte{ixTx(777)}
	// N=210: calldata (TxInput) holding a message; N=211: calldata (separate event); N=212: not a payload; N=213: no data; N=214: narrow bounds
	w.add(ixBatch{N: 210, Block: 1100, T: ixT0 + 1000, Loc: capture.LocTxInput, Msgs: [][][]byte{ixMsg(ixTx(21000))}})
	legs["cd0"] = [][]byte{ixTx(21000)}
	w.add(ixBatch{N: 211, Block: 1108, T: ixT0 + 1096, Loc: capture.LocSeparateBatchEvent, Msgs: [][][]byte{ixMsg(ixTx(21100))}})
	legs["cd1"] = [][]byte{ixTx(21100)}
	w.add(ixBatch{N: 212, Block: 1116, T: ixT0 + 1192, Garbage: true, Msgs: [][][]byte{ixMsg(ixTx(21200))}})
	legs["garbage"] = [][]byte{ixTx(21200)}
	w.add(ixBatch{N: 213, Block: 1124, T: ixT0 + 1288, Loc: capture.LocNoData})
	w.add(ixBatch{N: 214, Block: 1132, T: ixT0 + 1384, MinTs: ixT0 + 1384 - 100, MaxTs: ixT0 + 1384 + 50, Msgs: [][][]byte{ixMsg(ixTx(21400))}})
	legs["narrow"] = [][]byte{ixTx(21400)}
	legs["absent"] = [][]byte{ixTx(99999)}
	return w, legs
}

func keyOf(i, j int) string { return string(rune('a'+i)) + string(rune('0'+j)) }

// The indexed reader serves exactly the batch the reference reader serves, for every leg of the population and every timestamp that matters.
func TestRB12ArbIndexLocatesExactlyWhatTheReferenceLocates(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	r := w.reader()
	found := 0
	for name, txs := range legs {
		for _, ts := range []uint64{ixT0, ixT0 + 500, ixT0 + 1000, ixT0 + 1384, ixT0 + 1384 + 50, ixT0 + 1384 + 51, ixT0 + 1384 - 100, ixT0 + 1384 - 101, ixT0 - 86400 + 1, ixT0 + 5000} {
			want, got := w.ref(ts, txs), w.idx(r, ts, txs)
			if want != got {
				t.Errorf("leg %s ts %d: reference %s, index %s", name, ts, want, got)
			}
			if want.N != 0 {
				found++
			}
		}
	}
	if found < 100 {
		t.Fatalf("only %d of the legs were found by the reference: the population does not exercise the readers", found)
	}
}

// The batch the readers choose when several hold the message: the lowest N, and for an N captured under two blocks (a reorg) the lowest block.
func TestRB12ArbIndexKeepsTheReferenceOrderOfBatches(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	r := w.reader()
	if o := w.idx(r, ixT0+300, legs["dup"]); o.N != 202 || o != w.ref(ixT0+300, legs["dup"]) {
		t.Fatalf("a message held by batches 202 and 204 is served from %s", o)
	}
	o := w.idx(r, ixT0+300, legs["twin"])
	if o.N != 205 || o.Block != 1040 || o != w.ref(ixT0+300, legs["twin"]) {
		t.Fatalf("the twin: %s", o)
	}
	// the twin that is served is the one with the lower hash at the same height when both blocks are equal
	keys := w.keys[205]
	if len(keys) != 2 || keys[0].L1Block != keys[1].L1Block {
		t.Fatalf("the world has no twin: %v", keys)
	}
	want := keys[0]
	if string(keys[1].L1Hash[:]) < string(keys[0].L1Hash[:]) {
		want = keys[1]
	}
	b := &Builder{Store: w.store, Pins: w.pins, Index: r}
	loc, _, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 300}, standardTxs(legs["twin"]), w.arb)
	if err != nil || loc == nil || loc.rec.L1Hash != want.L1Hash {
		t.Fatalf("the twin served is %x, the lower hash is %x (%v)", loc.rec.L1Hash[:4], want.L1Hash[:4], err)
	}
}

// Boundaries of the candidate rule (class 10): a batch is a candidate for ts exactly when minTs <= ts <= maxTs. N passes, N+1 does not, in both readers.
func TestRB12ArbIndexWindowBoundariesAreExact(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	r := w.reader()
	min, max := uint64(ixT0+1384-100), uint64(ixT0+1384+50)
	for _, c := range []struct {
		ts   uint64
		want uint64
	}{{min - 1, 0}, {min, 214}, {max, 214}, {max + 1, 0}} {
		ref, idx := w.ref(c.ts, legs["narrow"]), w.idx(r, c.ts, legs["narrow"])
		if ref != idx || ref.N != c.want {
			t.Errorf("ts %d: reference %s, index %s, want N=%d", c.ts, ref, idx, c.want)
		}
	}
}

// A batch the reference skips (a payload that does not read, no data, an unknown location) is skipped by the index with the same outcome.
func TestRB12ArbIndexSkipsWhatTheReferenceSkips(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	r := w.reader()
	for _, name := range []string{"garbage", "absent"} {
		ref, idx := w.ref(ixT0+1192, legs[name]), w.idx(r, ixT0+1192, legs[name])
		if ref != idx || ref.State != PendingAwaitingBatchPost {
			t.Errorf("%s: reference %s, index %s", name, ref, idx)
		}
	}
	// calldata batches are located and the calldata is what the located batch carries
	for _, name := range []string{"cd0", "cd1"} {
		ref, idx := w.ref(ixT0+1100, legs[name]), w.idx(r, ixT0+1100, legs[name])
		if ref != idx || ref.N == 0 {
			t.Errorf("%s: reference %s, index %s", name, ref, idx)
		}
	}
}

// A block without a signed standard transaction is in no batch the verifier can match: pending in both readers, without a lookup.
func TestRB12ArbIndexAnswersABlockWithoutStandardTransactionsLikeTheReference(t *testing.T) {
	w, _ := ixPopulation(t)
	w.index(IndexConfig{})
	r := w.reader()
	internal := []byte{0x6a, 0xc0}
	if ref, idx := w.ref(ixT0+10, [][]byte{internal}), w.idx(r, ixT0+10, [][]byte{internal}); ref != idx || ref.State != PendingAwaitingBatchPost {
		t.Fatalf("reference %s, index %s", ref, idx)
	}
}

// No answer without an index: a store the indexer has not processed is a named pending that says so, never a found batch.
func TestRB12ArbIndexWithoutRowsIsANamedPendingNotAnAnswer(t *testing.T) {
	w, legs := ixPopulation(t)
	w.cursor(w.top + 1)
	r := w.reader()
	b := &Builder{Store: w.store, Pins: w.pins, Index: r}
	loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 300}, standardTxs(legs["a0"]), w.arb)
	if err != nil || loc != nil || pend == nil || pend.Reason != PendingAwaitingBatchPost || pend.Judged["index_behind"] != true {
		t.Fatalf("loc=%v pend=%v err=%v", loc, pend, err)
	}
	if !strings.Contains(string(pend.State().Canonical()), "index_behind") {
		t.Fatalf("the pending does not say the index is behind: %s", pend.State().Canonical())
	}
}
