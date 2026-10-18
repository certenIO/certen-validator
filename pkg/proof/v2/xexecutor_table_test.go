// Copyright 2026 Certen Protocol

package proofv2

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The table's values are the ones RB8's govsig gate pins (research R8 M5), value for value: a change here is a change of a trust input and
// must be made with the same change there.
func TestExecutorTableIsPinned(t *testing.T) {
	want := map[string]uint64{"directory": 9_538_105, "bvn1": 12_491_272, "bvn2": 12_492_057, "bvn3": 12_491_127}
	got := KermitExecutorActivations()
	if len(got) != len(want) {
		t.Fatalf("the table has %d rows, want %d", len(got), len(want))
	}
	for k, b := range want {
		a, ok := got[k]
		if !ok || a.Block != b || a.Version != protocol.ExecutorVersionV2Kourou {
			t.Errorf("%s: %+v, want kourou at %d", k, a, b)
		}
	}
	// A copy: changing it does not change the pin.
	got["bvn1"] = ExecutorActivation{}
	if a := KermitExecutorActivations()["bvn1"]; a.Block != 12_491_272 {
		t.Fatal("the accessor returned the table itself")
	}
}

// The floor is proven only for blocks after the activation block, for known partitions, whatever the spelling of the partition.
func TestExecutorFloorAt(t *testing.T) {
	for _, c := range []struct {
		partition string
		block     uint64
		ok        bool
	}{
		{"acc://bvn-BVN1.acme", 12_491_273, true},
		{"acc://bvn-BVN1.acme", 12_491_272, false}, // the activation block itself is not established
		{"bvn-BVN1", 12_491_271, false},
		{"BVN2", 12_492_058, true},
		{"bvn2", 12_492_057, false},
		{"acc://bvn-bvn3.acme/", 12_491_128, true},
		{"bvn3", 12_491_127, false},
		{"acc://dn.acme", 9_538_106, true},
		{"dn", 9_538_105, false},
		{"Directory", 20_000_000, true},
		{"acc://bvn-BVN9.acme", 99_000_000, false}, // not in the table: unknown, never assumed
		{"", 99_000_000, false},
	} {
		v, ok := ExecutorFloorAt(c.partition, c.block)
		if ok != c.ok || (ok && v != protocol.ExecutorVersionV2Kourou) || (!ok && v != 0) {
			t.Errorf("%q block %d: %v %v, want ok=%v", c.partition, c.block, v, ok, c.ok)
		}
		if ok && !v.V2BaikonurEnabled() {
			t.Errorf("%q block %d: floor %v is below Baikonur", c.partition, c.block, v)
		}
	}
}
