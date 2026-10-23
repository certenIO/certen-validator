// Copyright 2026 Certen Protocol

package runtime

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-FIX Note (b): the blocks the capture adds below the index cursor reach the indexer. The gap backfill's hook forwards every
// block it filled, the Base capture loop notes a block it captured on retry, and the wiring connects the hook exactly when the index is on.

type noterIndex struct {
	finality.CaptureIndexer
	noted []uint64
}

func (n *noterIndex) NoteLate(b uint64) { n.noted = append(n.noted, b) }

func TestRTLateBlocksReachTheIndexer(t *testing.T) {
	if lateNoter(nil) != nil {
		t.Fatal("no indexer, no hook")
	}
	ix := &noterIndex{}
	hook := lateNoter(ix)
	hook([]uint64{11, 12, 13})
	if len(ix.noted) != 3 || ix.noted[0] != 11 || ix.noted[2] != 13 {
		t.Fatalf("every filled block is noted: %v", ix.noted)
	}
	l := &BasePostedLoop{Index: ix}
	l.noteLate(99)
	if len(ix.noted) != 4 || ix.noted[3] != 99 {
		t.Fatalf("a block captured on retry is noted: %v", ix.noted)
	}
	(&BasePostedLoop{}).noteLate(1) // no indexer: nothing to tell
}

func TestRTTheGapBackfillIsConnectedToTheIndexExactlyWhenTheIndexIsOn(t *testing.T) {
	rtProviderEnv(t)
	for _, c := range []struct {
		setting string
		want    bool
	}{{"off", false}, {"", true}} {
		t.Setenv(EnvBaseIndex, c.setting)
		_, reg, _ := rtWire(t)
		found := false
		for _, cp := range reg.Capturers() {
			if g, ok := cp.(*GapBackfillLoop); ok {
				found = true
				if (g.OnFilled != nil) != c.want {
					t.Errorf("BASE_INDEX=%q: OnFilled set %v, want %v", c.setting, g.OnFilled != nil, c.want)
				}
			}
		}
		if !found {
			t.Fatal("the Base gap backfill loop is registered")
		}
	}
}
