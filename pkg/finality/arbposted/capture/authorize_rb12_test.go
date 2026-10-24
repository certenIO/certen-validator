// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

type rangeRecorder struct {
	finality.CaptureStore
	ranges [][2]uint64
}

func (r *rangeRecorder) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	r.ranges = append(r.ranges, [2]uint64{from, to})
	return r.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

func putProofRow(t *testing.T, s CaptureStore, n, block uint64) {
	t.Helper()
	p := ProofRecord{Kind: ProofBatchAcc, Index: n, ProofBlock: block, ProofBlockHash: [32]byte{byte(block), byte(block >> 8), 1}}
	if err := s.Put(context.Background(), Key{Chain: ChainArbitrumSepolia, L1Block: block, L1Hash: p.ProofBlockHash, Item: ItemProof(n)}, p.Encode()); err != nil {
		t.Fatal(err)
	}
}

// The proofs of a batch are found by a range scan of the L1 blocks just above its own block, widening only when none lies there: the common
// case lists at most 65 blocks, never the whole table; a proof below the batch's block is never loaded; a late proof is still found.
func TestRB12ProofListingIsBoundedAboveTheBatchBlockAndWidensOnlyWhenEmpty(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		blocks []uint64
		want   []uint64 // the proof blocks loaded
		widest uint64   // the widest range listed
	}{
		{"near", []uint64{998, 1002, 1030}, []uint64{1002, 1030}, 64},
		{"at the batch block", []uint64{1000}, []uint64{1000}, 64},
		{"below only", []uint64{999, 998}, nil, 1 << 62},
		{"late (after an outage)", []uint64{1000 + 500}, []uint64{1500}, 1024},
		{"much later", []uint64{1000 + 9000}, []uint64{10000}, 1 << 14},
	} {
		inner := NewMemStore()
		for _, b := range c.blocks {
			putProofRow(t, inner, 77, b)
		}
		putProofRow(t, inner, 770, 1001) // another batch whose number shares the prefix
		rec := &rangeRecorder{CaptureStore: inner}
		got, err := LoadProofsFrom(ctx, rec, ChainArbitrumSepolia, 77, 1000)
		if err != nil || len(got) != len(c.want) {
			t.Fatalf("%s: %v %d proofs, want %d", c.name, err, len(got), len(c.want))
		}
		for i, p := range got {
			if p.ProofBlock != c.want[i] {
				t.Errorf("%s: proof %d is at %d, want %d", c.name, i, p.ProofBlock, c.want[i])
			}
		}
		var widest uint64
		for _, r := range rec.ranges {
			if w := r[1] - r[0]; w > widest {
				widest = w
			}
			if r[0] < 1000 {
				t.Errorf("%s: listed from block %d, below the batch's block", c.name, r[0])
			}
		}
		if c.widest < 1<<62 && widest > c.widest {
			t.Errorf("%s: listed a range of %d blocks, want at most %d", c.name, widest, c.widest)
		}
	}
}
