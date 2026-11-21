// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

type floorRet map[string][2]uint64

func (f floorRet) Retained(_ context.Context, p string) (uint64, uint64, error) {
	r, ok := f[p]
	if !ok {
		return 0, 0, errors.New("unreachable")
	}
	return r[0], r[1], nil
}

func floorDeps(ret floorRet, partsErr error, sleeps *int) historyFloorDeps {
	return historyFloorDeps{
		partitions: func(context.Context) ([]string, error) {
			if partsErr != nil {
				return nil, partsErr
			}
			return []string{"BVN1", "BVN2", "BVN3", "Directory"}, nil
		},
		retention: ret,
		sleep:     func(time.Duration) { *sleeps++ },
	}
}

const agtFloor = "Directory=13440000,BVN1=17570000,BVN2=17565000,BVN3=17540539"

// AGT-F104: the validator does not start proof v2 against the public Kermit node as measured 2026-11-20 (about 700 retained
// blocks per partition), nor with no floor configured; it starts against a node that keeps the floor.
func TestProofV2StartRefusesANodeThatPrunes(t *testing.T) {
	n := 0
	public := floorRet{"Directory": {13445201, 13445749}, "BVN1": {17574589, 17575293}, "BVN2": {17570888, 17571592}, "BVN3": {17561366, 17562071}}
	_, err := startupHistoryFloor(agtFloor, floorDeps(public, nil, &n))
	var fe *proofv2.FloorError
	if !errors.As(err, &fe) || fe.Code != proofv2.FloorUnmet {
		t.Fatalf("pruning node: %v", err)
	}
	if n != 0 {
		t.Fatalf("a definitive refusal was retried %d times", n)
	}
	if _, err := startupHistoryFloor("", floorDeps(public, nil, &n)); !errors.As(err, &fe) || fe.Code != proofv2.FloorUnset {
		t.Fatalf("unset floor: %v", err)
	}
	full := floorRet{"Directory": {13440000, 13445749}, "BVN1": {17569000, 17575293}, "BVN2": {17565000, 17571592}, "BVN3": {17540000, 17562071}}
	if _, err := startupHistoryFloor(agtFloor, floorDeps(full, nil, &n)); err != nil {
		t.Fatalf("full-history node: %v", err)
	}
}

// A node that cannot be read is retried within the budget and then refused: never a pass.
func TestProofV2StartRefusesAnUnreadableNodeAfterItsBudget(t *testing.T) {
	old := historyFloorReadBudget
	historyFloorReadBudget = 0
	defer func() { historyFloorReadBudget = old }()
	n := 0
	_, err := startupHistoryFloor(agtFloor, floorDeps(floorRet{}, errors.New("network-status: connection refused"), &n))
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("unreadable node: %v", err)
	}
	var fe *proofv2.FloorError
	if errors.As(err, &fe) {
		t.Fatalf("a read failure was made definitive: %v", err)
	}
}

func TestProofV2HistoryCheckUsage(t *testing.T) {
	var out, errw bytes.Buffer
	if code := runProofV2HistoryCheck(nil, &out, &errw); code != 2 || !strings.Contains(errw.String(), "usage") {
		t.Fatalf("code %d, %q", code, errw.String())
	}
}
