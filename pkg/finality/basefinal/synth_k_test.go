// Copyright 2026 Certen Protocol

package basefinal

import (
	"strings"
	"testing"
)

// BuildSynth is test support, but a spec it cannot honour is an error, not an index panic: outputRootIndex K names the K-th of the pinned
// row's n intermediate roots, so K above n has no root to hold the claim.
func TestBuildSynthRefusesAnOutputRootIndexAboveTheIntermediateRootCount(t *testing.T) {
	p := loadPins(t)
	var n uint32
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.2.0" {
			n = uint32(r.NIntermediate)
		}
	}
	if n == 0 {
		t.Fatal("no pinned game_impl 0.2.0")
	}
	for _, k := range []uint32{n + 1, n + 2, 1 << 31, ^uint32(0)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("K=%d panicked: %v", k, r)
				}
			}()
			o, err := BuildSynth(p, SynthSpec{K: k})
			if err == nil || o != nil || !strings.Contains(err.Error(), "outputRootIndex") {
				t.Errorf("K=%d: out %v err %v", k, o != nil, err)
			}
		}()
	}
	// the boundary K = n is a world (the claim is the last intermediate root)
	if o, err := BuildSynth(p, SynthSpec{K: n}); err != nil || o == nil {
		t.Errorf("K=n=%d: %v", n, err)
	}
}
