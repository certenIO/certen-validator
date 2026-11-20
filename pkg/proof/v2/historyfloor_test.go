// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"errors"
	"testing"
)

type fakeRetention map[string][2]uint64

func (f fakeRetention) Retained(_ context.Context, p string) (uint64, uint64, error) {
	r, ok := f[p]
	if !ok {
		return 0, 0, errors.New("consensus status of " + p + ": unreachable")
	}
	return r[0], r[1], nil
}

var kermitParts = []string{"Directory", "BVN1", "BVN2", "BVN3"}

func floorCode(t *testing.T, err error) string {
	t.Helper()
	var fe *FloorError
	if !errors.As(err, &fe) {
		t.Fatalf("want a *FloorError, got %v", err)
	}
	return fe.Code
}

func TestParseHistoryFloor(t *testing.T) {
	f, err := ParseHistoryFloor(" Directory=13445000, BVN1=17574000,BVN2=17570000,BVN3=17561000 ")
	if err != nil {
		t.Fatal(err)
	}
	if f["BVN3"] != 17561000 || len(f) != 4 {
		t.Fatalf("parsed %v", f)
	}
	if got := f.String(); got != "BVN1=17574000,BVN2=17570000,BVN3=17561000,Directory=13445000" {
		t.Fatalf("String() = %s", got)
	}
	for raw, code := range map[string]string{
		"":                          FloorUnset,
		"   ":                       FloorUnset,
		"BVN1":                      FloorMalformed,
		"BVN1=":                     FloorMalformed,
		"BVN1=-5":                   FloorMalformed,
		"BVN1=0":                    FloorMalformed,
		"BVN1=007":                  FloorMalformed,
		"BVN1=1e6":                  FloorMalformed,
		"BVN1=99999999999999999999": FloorMalformed,
		"bvn-1=5":                   FloorMalformed,
		"BVN1=5,BVN1=6":             FloorMalformed,
		"BVN1=5,":                   FloorMalformed,
	} {
		if _, err := ParseHistoryFloor(raw); err == nil {
			t.Errorf("%q: accepted", raw)
		} else if c := floorCode(t, err); c != code {
			t.Errorf("%q: code %s, want %s", raw, c, code)
		}
	}
}

// AGT-F104: the public Kermit node as measured 2026-11-20 (about 700 retained blocks per partition) is refused, naming the
// partition, for a floor the full-history node would have kept.
func TestHistoryFloorRefusesAPruningNode(t *testing.T) {
	floor := HistoryFloor{"Directory": 13440000, "BVN1": 17570000, "BVN2": 17565000, "BVN3": 17540539}
	public := fakeRetention{
		"Directory": {13445201, 13445749}, "BVN1": {17574589, 17575293}, "BVN2": {17570888, 17571592}, "BVN3": {17561366, 17562071},
	}
	err := floor.Check(context.Background(), public, kermitParts)
	if c := floorCode(t, err); c != FloorUnmet {
		t.Fatalf("code %s (%v)", c, err)
	}
	var fe *FloorError
	errors.As(err, &fe)
	if fe.Partition != "BVN1" { // sorted order: the first partition judged that fails
		t.Fatalf("partition %s", fe.Partition)
	}
}

func TestHistoryFloorPassesAFullHistoryNode(t *testing.T) {
	floor := HistoryFloor{"Directory": 13440000, "BVN1": 17570000, "BVN2": 17565000, "BVN3": 17540539}
	full := fakeRetention{
		"Directory": {13440000, 13445749}, "BVN1": {17569000, 17575293}, "BVN2": {17565000, 17571592}, "BVN3": {17540000, 17562071},
	}
	if err := floor.Check(context.Background(), full, kermitParts); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryFloorPartitionsMustMatchTheNetwork(t *testing.T) {
	full := fakeRetention{"Directory": {1, 100}, "BVN1": {1, 100}, "BVN2": {1, 100}, "BVN3": {1, 100}, "BVN4": {1, 100}}
	missing := HistoryFloor{"Directory": 5, "BVN1": 5, "BVN2": 5}
	if c := floorCode(t, missing.Check(context.Background(), full, kermitParts)); c != FloorPartitionMissing {
		t.Fatalf("missing: %s", c)
	}
	extra := HistoryFloor{"Directory": 5, "BVN1": 5, "BVN2": 5, "BVN3": 5, "BVN4": 5}
	if c := floorCode(t, extra.Check(context.Background(), full, kermitParts)); c != FloorPartitionUnknown {
		t.Fatalf("extra: %s", c)
	}
	above := HistoryFloor{"Directory": 5, "BVN1": 5, "BVN2": 500, "BVN3": 5}
	if c := floorCode(t, above.Check(context.Background(), full, kermitParts)); c != FloorAboveHead {
		t.Fatalf("above: %s", c)
	}
}

// A failed read of the node is an error the caller may retry, never a pass and never a definitive refusal.
func TestHistoryFloorUnreadableNodeIsNotAPass(t *testing.T) {
	floor := HistoryFloor{"Directory": 5, "BVN1": 5, "BVN2": 5, "BVN3": 5}
	partial := fakeRetention{"Directory": {1, 100}, "BVN1": {1, 100}, "BVN2": {1, 100}}
	err := floor.Check(context.Background(), partial, kermitParts)
	if err == nil {
		t.Fatal("an unreadable partition passed")
	}
	var fe *FloorError
	if errors.As(err, &fe) {
		t.Fatalf("a read failure was made definitive: %v", err)
	}
	if err := floor.Check(context.Background(), partial, nil); err == nil {
		t.Fatal("no partitions passed")
	}
}
