// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// meter counts what a lookup reads of a store: the bytes of the rows it Gets, the rows it Gets and the keys its listings return.
type meter struct {
	finality.CaptureStore
	bytes, gets, keys atomic.Int64
}

func (m *meter) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	b, ok, err := m.CaptureStore.Get(ctx, k)
	m.bytes.Add(int64(len(b)))
	m.gets.Add(1)
	return b, ok, err
}

func (m *meter) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	ks, err := m.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
	m.keys.Add(int64(len(ks)))
	return ks, err
}

func (m *meter) reset() { m.bytes.Store(0); m.gets.Store(0); m.keys.Store(0) }

// A history of twelve days with an outage of three days in the middle (batch numbers go on, time does not): the indexed reader serves what the
// reference serves for legs everywhere in it - before the first batch, inside runs, at the ends of the outage, after the last - and a lookup lists
// the names of the entries of ITS window, not of the history.
func TestRB12ArbIndexTimeMapFindsTheWindowInALongHistoryAndOutages(t *testing.T) {
	w := newIxWorld(t)
	const batches = 300
	T := func(i int) uint64 {
		t := uint64(ixT0 + 3600*i)
		if i >= 150 {
			t += 259_200 // the outage: no batch for three days
		}
		return t
	}
	legs := map[int][][]byte{}
	for i := 0; i < batches; i++ {
		tx := ixTx(60000 + i)
		legs[i] = [][]byte{tx}
		w.add(ixBatch{N: uint64(700 + i), Block: uint64(5000 + 8*i), T: T(i), Msgs: [][][]byte{ixMsg(tx)}})
	}
	w.index(IndexConfig{BlocksPerStep: 1 << 20})
	m := &meter{CaptureStore: w.store}
	r, err := NewIndexReader(m, w.pins, 0)
	if err != nil {
		t.Fatal(err)
	}
	var maxKeys, earlyKeys int64
	for _, i := range []int{0, 1, 7, 29, 30, 31, 60, 100, 148, 149, 150, 151, 152, 200, 270, 298, 299} {
		for _, ts := range []uint64{T(i), T(i) + 100, T(i) + 770 /* past maxTs of batch i: the next batch posts it */} {
			ref := w.ref(ts, legs[i])
			m.reset()
			b := &Builder{Store: m, Pins: w.pins, Index: r}
			loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(legs[i]), w.arb)
			var got outcome
			switch {
			case err != nil:
				got = outcome{State: stateOf(err)}
			case pend != nil:
				got = outcome{State: pend.Reason}
			default:
				got = outcome{N: loc.rec.N, Block: loc.rec.L1Block}
			}
			if got != ref {
				t.Errorf("batch %d ts %d: reference %s, index %s", i, ts, ref, got)
			}
			k := m.keys.Load()
			if i < 10 && k > earlyKeys {
				earlyKeys = k
			}
			if i >= 10 && k > maxKeys {
				maxKeys = k
			}
		}
	}
	// The window of a lookup holds about (delay cap + future cap) / 3600 s = 29 batches: its entry names, its batch names and its digest names are
	// about 90 keys, and the two searches of the time map about 1-2 keys per probe. A history of 300 batches is not listed. The first batches of
	// the capture are dearer: the searches probe the 512 empty blocks below the first batch, 20-40 digest names a probe.
	t.Logf("the most key names one lookup listed: %d (the first ten batches: %d; history %d batches)", maxKeys, earlyKeys, batches)
	if maxKeys > 130 || earlyKeys > 400 {
		t.Fatalf("a lookup listed %d key names (%d at the start of the capture) in a history of %d batches", maxKeys, earlyKeys, batches)
	}
	// legs before the first batch and after the last are pending in both readers
	for _, ts := range []uint64{ixT0 - 200_000, T(batches-1) + 500_000} {
		if ref, idx := w.ref(ts, legs[10]), w.idx(r, ts, legs[10]); ref != idx || ref.N != 0 {
			t.Errorf("ts %d: reference %s, index %s", ts, ref, idx)
		}
	}
}
