// Copyright 2026 Certen Protocol

package contractidentity

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
)

// c2KeysDigest against an independent computation of the spec formula (node, design/vectors/s8/cie1.mjs keccak256):
// keccak256(lp("certen:validator-keys:v1") || u32(n) || for each address ascending: B20 || lp(key)); the inputs are given out of order.
func TestC2KeysDigestMatchesTheSpecFormula(t *testing.T) {
	addrs := []common.Address{common.HexToAddress("0x02"), common.HexToAddress("0x01")}
	keys := [][]byte{{0xbb, 0xbb, 0xbb}, {0xaa, 0xaa}}
	want := common.HexToHash("0x7b08001f53e7db573b8b74af606d3b504a613ca52b73d856c0d6bf64881de420")
	if got := c2KeysDigest(addrs, keys); got != want {
		t.Fatalf("keysDigest %s, want %s", got, want)
	}
	// the order of the inputs does not matter, the keys follow their addresses
	if got := c2KeysDigest([]common.Address{addrs[1], addrs[0]}, [][]byte{keys[1], keys[0]}); got != want {
		t.Fatalf("keysDigest of the sorted input %s, want %s", got, want)
	}
	// a swapped key changes it
	if got := c2KeysDigest(addrs, [][]byte{keys[1], keys[0]}); got == want {
		t.Fatal("keysDigest ignores which key belongs to which address")
	}
}

func TestC2ExpectedSubsets(t *testing.T) {
	cases := []struct {
		name          string
		powers        []uint64
		total, num, d uint64
		want          int // -1: nil
	}{
		{"n=7 equal powers 2/3 (21+7+1)", []uint64{10, 10, 10, 10, 10, 10, 10}, 70, 2, 3, 29},
		{"n=3 equal 2/3: two or three of three", []uint64{1, 1, 1}, 3, 2, 3, 4},
		{"exact ratio is inclusive: 6*3 >= 9*2", []uint64{3, 3, 3}, 9, 2, 3, 4},
		{"2/3 of 10 needs 7: 5+2 twice, 5+2+2, 5+2+1 twice, all four", []uint64{5, 2, 2, 1}, 10, 2, 3, 6},
		{"n=20 is enumerated", make([]uint64, 20), 1, 1, 2, 0},
		{"n=21 is not", make([]uint64, 21), 1, 1, 2, -1},
		{"no validators: the empty subset is not a set of signers", nil, 0, 2, 3, 0},
	}
	for _, c := range cases {
		got := c2ExpectedSubsets(c.powers, c.total, c.num, c.d)
		switch {
		case c.want < 0 && got != nil:
			t.Errorf("%s: %d, want nil", c.name, *got)
		case c.want >= 0 && (got == nil || *got != uint64(c.want)):
			if got != nil {
				t.Errorf("%s: %d, want %d", c.name, *got, c.want)
				continue
			}
			t.Errorf("%s: %v, want %d", c.name, got != nil, c.want)
		}
	}
}

func TestC2FinalizedStatus(t *testing.T) {
	leg := BlockRef{Number: 7, Hash: [32]byte{1}}
	fin := func(l finality.LevelStatus) *finality.Report {
		return &finality.Report{Levels: map[finality.Level]finality.LevelStatus{finality.LevelFinalized: l}}
	}
	ok := fin(finality.LevelStatus{Status: finality.StatusVerified})
	ok.FinalizedBlock = &finality.FinalizedBlock{Number: 7, Hash: leg.Hash}
	other := fin(finality.LevelStatus{Status: finality.StatusVerified})
	other.FinalizedBlock = &finality.FinalizedBlock{Number: 7, Hash: [32]byte{2}}
	hidden := fin(finality.LevelStatus{Status: finality.StatusVerified})
	hidden.FinalizedBlockState = &finality.StateError{Code: "finality_block_unavailable"}
	cases := []struct {
		name string
		rep  *finality.Report
		want string
		auth bool
	}{
		{"verified for this block", ok, S7StatusVerified, true},
		{"verified for another block", other, S7StatusVerifiedOtherBlock, false},
		{"verified, block not exposed", fin(finality.LevelStatus{Status: finality.StatusVerified}), S7StatusVerifiedBlockNotShown, false},
		{"verified, block not exposed with its state", hidden, S7StatusVerifiedBlockNotShown + ":finality_block_unavailable", false},
		{"pending", fin(finality.LevelStatus{Status: finality.StatusPending}), S7StatusPending, false},
		{"not applicable", fin(finality.LevelStatus{Status: finality.StatusNotApplicable}), S7StatusNotApplicable, false},
		{"refused", fin(finality.LevelStatus{Status: finality.StatusRefused, State: &finality.StateError{Code: "finality_x"}}), "refused:finality_x", false},
		{"no finalized level", &finality.Report{}, S7StatusAbsent, false},
		{"unsupported chain", &finality.Report{Unsupported: &finality.StateError{Code: finality.CodeChainUnsupported}}, "refused:finality_chain_unsupported", false},
		{"broken chain", &finality.Report{Broken: &finality.StateError{Code: "finality_chain_broken"}}, "refused:finality_chain_broken", false},
	}
	for _, c := range cases {
		got, auth := c2FinalizedStatus(c.rep, leg)
		if got != c.want || auth != c.auth {
			t.Errorf("%s: %q auth=%v, want %q auth=%v", c.name, got, auth, c.want, c.auth)
		}
	}
}
