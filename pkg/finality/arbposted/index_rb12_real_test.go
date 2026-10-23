// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// ixRealFixture is the recorded live vector (batch 883,753, three real blobs, real KZG proofs, a real Bridge proof) stored the way the capturer
// stores it: the batch's L1 block has a header row whose hash is its key, the rows sit at that key, and the capture's cursor rows bracket it.
func ixRealFixture(t *testing.T) (*bFixture, *capture.MemStore, uint64) {
	t.Helper()
	f := bLoad(t)
	const E = uint64(11_953_990)
	T := f.ev.Header40[1] - 768
	hdr, hash := ixHeader(E, T, common.Hash{0xaa})
	s := capture.NewMemStore()
	key := finality.CaptureKey{Chain: ixChain, L1Block: E, L1Hash: hash}
	put := func(k finality.CaptureKey, b []byte) {
		t.Helper()
		if err := s.Put(context.Background(), k, b); err != nil {
			t.Fatal(err)
		}
	}
	put(withItem(key, capture.ItemHeader), hdr)
	rec := f.batch
	rec.L1Block, rec.L1Hash = E, hash
	put(withItem(key, capture.ItemBatch(rec.N)), rec.Encode())
	for j := range rec.VersionedHashes {
		b, _, _ := f.store.Get(context.Background(), capture.Key{Chain: ixChain, L1Block: f.batch.L1Block, L1Hash: f.batch.L1Hash, Item: capture.ItemBlob(rec.N, j)})
		put(withItem(key, capture.ItemBlob(rec.N, j)), b)
	}
	keys, _ := f.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, "proof/")
	for _, k := range keys {
		b, _, _ := f.store.Get(context.Background(), k)
		put(k, b)
	}
	for _, c := range []uint64{E - 1, f.ev.StateBlock + 1} {
		h, hh := ixHeader(c, 1_790_000_000+c, common.Hash{0xcc})
		ck := finality.CaptureKey{Chain: ixChain, L1Block: c, L1Hash: hh}
		put(withItem(ck, capture.ItemHeader), h)
		put(withItem(ck, capture.ItemCursor), append(binary.BigEndian.AppendUint64(nil, c), hh[:]...))
	}
	return f, s, f.ev.StateBlock + 1
}

// On the recorded live vector the indexed build and the reference build produce THE SAME container, byte for byte, and it is the recorded one.
func TestRB12ArbIndexRealVectorBuildIsByteIdenticalToTheReferenceAndTheRecordedEvidence(t *testing.T) {
	f, s, upTo := ixRealFixture(t)
	ix, err := NewIndexer(s, f.pins, 0, IndexConfig{})
	if err != nil {
		t.Fatal(err)
	}
	stepAll(t, ix, upTo)
	r, err := NewIndexReader(s, f.pins, 0)
	if err != nil {
		t.Fatal(err)
	}

	ref := f.bBuilder()
	ref.Store = s
	want, p, err := ref.BuildFor(context.Background(), f.ref)
	if err != nil || p != nil {
		t.Fatalf("the reference build: %v %s", err, bPend(p))
	}
	if !bytes.Equal(want.Evidence, f.evBytes) {
		t.Fatal("the reference build is not the recorded evidence")
	}
	idx := f.bBuilder()
	idx.Store, idx.Index = s, r
	got, p, err := idx.BuildFor(context.Background(), f.ref)
	if err != nil || p != nil {
		t.Fatalf("the indexed build: %v %s", err, bPend(p))
	}
	if !bytes.Equal(got.Evidence, want.Evidence) {
		t.Fatalf("the indexed container (%d B) differs from the reference container (%d B)", len(got.Evidence), len(want.Evidence))
	}
	// the indexed build never lists the whole batch table (LoadBatches' question): its listings are bounded by the leg's window
	m := &ioMeter{CaptureStore: s}
	idx.Store, idx.Index = m, &IndexReader{Store: m, Gen: r.Gen, arb: r.arb, pins: r.pins}
	if _, _, err := idx.BuildFor(context.Background(), f.ref); err != nil {
		t.Fatal(err)
	}
	if m.wholeTable {
		t.Fatal("the indexed build listed the batch rows over the whole table")
	}
}

// ioMeter records whether a build lists the batch rows of the whole table.
type ioMeter struct {
	finality.CaptureStore
	wholeTable bool
}

func (m *ioMeter) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	if strings.HasPrefix(prefix, "batch") && from == 0 && to == finality.MaxCaptureBlock {
		m.wholeTable = true
	}
	return m.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

// The indexed build of the real vector names what is missing exactly as the reference does: a blob row gone is l1_blob_unavailable in both.
func TestRB12ArbIndexRealVectorMissingBlobIsNamedLikeTheReference(t *testing.T) {
	f, s, upTo := ixRealFixture(t)
	ix, err := NewIndexer(s, f.pins, 0, IndexConfig{})
	if err != nil {
		t.Fatal(err)
	}
	stepAll(t, ix, upTo)
	o := newOverlay(s)
	ks, _ := s.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, "blob/")
	o.hide[ks[1]] = true
	r, _ := NewIndexReader(o, f.pins, 0)
	ref := f.bBuilder()
	ref.Store = o
	idx := f.bBuilder()
	idx.Store, idx.Index = o, r
	_, _, e1 := ref.BuildFor(context.Background(), f.ref)
	_, _, e2 := idx.BuildFor(context.Background(), f.ref)
	if !strings.Contains(bState(e1), `"code":"l1_blob_unavailable"`) || bState(e1) != bState(e2) {
		t.Fatalf("reference %s, index %s", bState(e1), bState(e2))
	}
}
