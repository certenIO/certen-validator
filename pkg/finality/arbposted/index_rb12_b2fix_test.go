// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// V-INDEX-B B1 (class 11): the index writer does not consult the authorization. Whether a Bridge proof of a record HAS ARRIVED is not a fact of the
// captured rows at the time of indexing, so an orphan twin indexed before its proof must get the same entry and the same digest as one indexed after
// it; every reader authorizes at read time. Fail-before @d313b708: 'same key, different bytes' on the digest and 'row only the early indexer wrote'.
func TestRB12ArbIndexBytesDoNotDependOnWhenTheBridgeProofArrived(t *testing.T) {
	build := func() *ixWorld {
		w := newIxWorld(t)
		msgs := [][][]byte{ixMsg(ixTx(33000))}
		w.add(ixBatch{N: 300, Block: 1000, T: ixT0, Msgs: msgs, AccTag: 0})
		w.add(ixBatch{N: 300, Block: 1000, T: ixT0, Tag: 1, Msgs: msgs, AccTag: 1}) // the orphan twin: another beforeAcc, another hash, the same height
		w.add(ixBatch{N: 301, Block: 1008, T: ixT0 + 96, Msgs: [][][]byte{ixMsg(ixTx(33001))}})
		return w
	}
	held := func(w *ixWorld) finality.CaptureKey { return w.keys[300][1] } // the Bridge holds the second twin; the first is the orphan

	// early: indexed with no proof, then the proof arrives, then the index is stepped again (as a running validator would)
	early := build()
	early.index(IndexConfig{})
	early.proof(300, early.recs[held(early)].AfterAcc, 1005)
	// late: the proof is captured first, then the index is built (another validator, or a rebuilt generation)
	late := build()
	late.proof(300, late.recs[held(late)].AfterAcc, 1005)
	late.index(IndexConfig{})
	equalRows(t, early.indexRows(), late.indexRows())

	// the self-check of the early store, after the proof arrived, finds nothing wrong: nothing is wrong
	res, err := early.indexer(IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20}).SelfCheckReport(context.Background(), 100)
	if err != nil || res.Mismatches != 0 || res.Entries == 0 || res.Digests == 0 {
		t.Fatalf("a clean store fails its self-check after a proof arrived: %v %+v", err, res)
	}
	res, err = late.indexer(IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20}).SelfCheckReport(context.Background(), 100)
	if err != nil || res.Mismatches != 0 {
		t.Fatalf("self-check of the late store: %v %+v", err, res)
	}

	// the readers still refuse the orphan twin, whichever world they read
	for name, w := range map[string]*ixWorld{"early": early, "late": late} {
		leg := [][]byte{ixTx(33000)}
		if o := w.idx(w.reader(), ixT0+10, leg); o.N != 300 || o.Block != 1000 {
			t.Fatalf("%s: %s", name, o)
		}
		b := &Builder{Store: w.store, Pins: w.pins, Index: w.reader()}
		loc, _, err := b.Index.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 10}, standardTxs(leg), w.arb)
		if err != nil || loc == nil || loc.rec.L1Hash != held(w).L1Hash {
			t.Fatalf("%s: the index serves the orphan twin %v %v", name, loc, err)
		}
	}
}
