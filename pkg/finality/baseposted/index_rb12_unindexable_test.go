// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX Note (a): a captured block whose rows the indexer cannot read (a transaction row that does not parse, an inbox row over 4096
// transactions or malformed, a blob row that is not a blob row, blob rows that are not the blobs the transaction names) used to stop the
// indexer at that height for ever (a plain error, only the lag alert said so). It is now a NAMED, insert-only record
// (idx/g<G>/bi/u at the block) that lets the cursor pass, and the leg whose window contains it is told by name when its channel is not found.

// putRawBlock writes the given rows of one captured block (plus a header and SystemConfig row that establish nothing).
func putRawBlock(t testing.TB, st finality.CaptureStore, number uint64, rows map[string][]byte) {
	t.Helper()
	h := shapeHash(number, 0)
	rows[ItemHeader] = make([]byte, 600)
	rows[ItemSysCfg] = make([]byte, 3000)
	for item, b := range rows {
		if err := st.Put(context.Background(), finality.CaptureKey{Chain: uint64(Chain), L1Block: number, L1Hash: h, Item: item}, b); err != nil {
			t.Fatal(err)
		}
	}
}

func inboxRow(n int) []byte {
	var w finality.Writer
	w.Count(n)
	for i := 0; i < n; i++ {
		w.U32(uint32(i))
	}
	return w.Bytes()
}

func blobRow(t testing.TB, payload []byte) []byte {
	t.Helper()
	blob, err := encodeBlob(payload)
	if err != nil {
		t.Fatal(err)
	}
	var bw finality.Writer
	bw.LP(blob)
	bw.Fixed(make([]byte, 48))
	bw.Fixed(make([]byte, 48))
	return bw.Bytes()
}

func TestRB12UnreadableBlockIsANamedRecordAndNeverStallsTheCursor(t *testing.T) {
	metrics.RegisterMetrics()
	_, bp := idxPins(t)
	good := channelFrames("G", 1_790_500_000, 10, 1000, 1)
	for _, c := range []struct {
		name, reason string
		rows         func(t testing.TB) map[string][]byte
	}{
		{"transaction row does not parse", "tx_unparseable", func(testing.TB) map[string][]byte {
			return map[string][]byte{ItemInbox: inboxRow(1), ItemTx(0): []byte{0xff, 0xfe, 0xfd, 1, 2, 3, 4, 5, 6, 7, 8, 9}}
		}},
		{"inbox row over 4096 transactions", "inbox_over_limit", func(testing.TB) map[string][]byte {
			return map[string][]byte{ItemInbox: inboxRow(4097)}
		}},
		{"inbox row malformed", "inbox_malformed", func(testing.TB) map[string][]byte {
			return map[string][]byte{ItemInbox: []byte{0, 0, 0, 3, 1}}
		}},
		{"blob row malformed", "blob_row_malformed", func(testing.TB) map[string][]byte {
			return map[string][]byte{ItemInbox: inboxRow(1), ItemTx(0): blobTxRaw(bp, 1, 1), ItemBlob(0, 0): []byte{1, 2, 3}}
		}},
		{"blob indices not contiguous", "blob_rows_inconsistent", func(t testing.TB) map[string][]byte {
			return map[string][]byte{ItemInbox: inboxRow(1), ItemTx(0): blobTxRaw(bp, 1, 3), ItemBlob(0, 0): blobRow(t, payloadOf(good[0])), ItemBlob(0, 2): blobRow(t, payloadOf(good[0]))}
		}},
	} {
		t.Run(c.reason, func(t *testing.T) {
			st := NewMemStore()
			E := uint64(1000)
			H := channelFrames("before", 1_790_100_000, 10, E, 1)
			I := channelFrames("after", 1_790_200_000, 10, E, 1)
			vPutBlock(t, st, bp, 1010, []Frame{H[0]})
			putRawBlock(t, st, 1015, c.rows(t))
			vPutBlock(t, st, bp, 1020, []Frame{I[0]})
			metricsBefore, _ := vGather(t, "certen_finality_index_unindexable_blocks_total")
			rep := stepAll(t, newIdx(st, bp, IndexConfig{}), 1500) // a plain error here is the stall
			if after, _ := vGather(t, "certen_finality_index_unindexable_blocks_total"); after-metricsBefore != 1 {
				t.Errorf("the unreadable block is counted once: %v", after-metricsBefore)
			}
			if rep.Through != 1500 {
				t.Fatalf("the cursor must pass the unreadable block: through %d", rep.Through)
			}
			if !hasDigest(t, st, 1010) || !hasDigest(t, st, 1020) || !entryClosingAt(t, st, 1020, chanLabelID("after")) || hasDigest(t, st, 1015) {
				t.Fatal("the blocks around it are indexed and the unreadable one has no digest")
			}
			var rec []byte
			for k, v := range indexRows(t, st) {
				if k.L1Block == 1015 && strings.HasSuffix(k.Item, "/u") {
					rec = v
				}
			}
			if rec == nil {
				t.Fatal("the unreadable block must have its record idx/g1/bi/u")
			}
			// a leg served by a channel elsewhere is served
			if sr, err := ixSearch(t, st, bp, E, 1_790_100_004); err != nil || sr.ch == nil {
				t.Fatalf("a leg whose channel is indexed is served: %v %v", sr.ch, err)
			}
			// a leg whose window holds the block and whose channel is not found is told by name
			_, err := ixSearch(t, st, bp, E, 1_790_999_000)
			se, ok := finality.AsNamed(err)
			if !ok || se.Code != "index_block_unindexable" || se.Fields["reason"] != c.reason || se.Fields["block"] != uint64(1015) {
				t.Fatalf("want index_block_unindexable{block 1015, reason %s}, got %v", c.reason, err)
			}
			if msg := regConforms(t, se.Code, se.Fields); msg != "" {
				t.Errorf("registry: %s", msg)
			}
			// a leg whose window starts after the block is not told
			if sr, err := ixSearch(t, st, bp, 1016, 1_790_999_000); err != nil || sr.ch != nil {
				t.Fatalf("a window without the block is not affected: %v %v", sr.ch, err)
			}
			// idempotent: a second indexer over the same rows writes nothing new and does not stall
			rows := indexRows(t, st)
			stepAll(t, newIdx(st, bp, IndexConfig{ReconcileEvery: 1}), 1500)
			if after, _ := vGather(t, "certen_finality_index_unindexable_blocks_total"); after-metricsBefore != 1 {
				t.Errorf("a second pass does not count the record again: %v", after-metricsBefore)
			}
			if d := sameRows(rows, indexRows(t, st)); d != "" {
				t.Fatalf("a second pass changed the index: %s", d)
			}
		})
	}
}

func ixSearch(t testing.TB, st finality.CaptureStore, bp *Pins, origin, ts uint64) (searched, error) {
	t.Helper()
	b := &Builder{Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}, Index: NewIndexReader(st, bp, 0)}
	return b.search(context.Background(), bp, finality.HeaderFields{Number: 5, Timestamp: ts}, nil)
}
