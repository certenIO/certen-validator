package contracts

import (
	"encoding/hex"
	"strings"
	"testing"
)

func fullGovInputs() AccumulateGovRootInputs {
	fill := func(b byte) (o [32]byte) {
		for i := range o {
			o[i] = b
		}
		return
	}
	return AccumulateGovRootInputs{
		L1AccountHash: fill(1), L2BPTRoot: fill(2), L3BlockHash: fill(3), L4ConsensusProofH: fill(4),
		G0CanonicalHash: fill(5), G1CanonicalHash: fill(6), G2CanonicalHash: fill(7),
		KeypageURLHash: fill(8), KeybookURLHash: fill(9), OperationID: fill(10),
	}
}

// govRoot v2 is its own domain: the same slots never produce a v1 value, and the pinned vector fixes the layout.
func TestGovRootV2_DomainAndVector(t *testing.T) {
	in := fullGovInputs()
	v2, err := ComputeAccumulateGovRootV2(in)
	if err != nil {
		t.Fatal(err)
	}
	if v2 == ComputeAccumulateGovRoot(in) {
		t.Fatal("govRoot v2 equals v1 over the same slots")
	}
	// Independently recomputed in Python (RUNLOG_RB5 2026-09-30).
	const want = "82c6a5f0d99bdf7c6b9db54dcf49af2fa9df7d389e8b50dbfe9de35d26ad1b7d"
	if got := hex.EncodeToString(v2[:]); got != want {
		t.Fatalf("govRoot v2 vector: got %s want %s", got, want)
	}
}

// Every slot is required, and the refusal names the same first missing slot every time.
func TestGovRootV2_EverySlotRequiredDeterministically(t *testing.T) {
	names := []string{"L1", "L2", "L3", "L4", "G0", "G1", "G2", "key page", "key book", "operation id"}
	for i, name := range names {
		in := fullGovInputs()
		switch i {
		case 0:
			in.L1AccountHash = [32]byte{}
		case 1:
			in.L2BPTRoot = [32]byte{}
		case 2:
			in.L3BlockHash = [32]byte{}
		case 3:
			in.L4ConsensusProofH = [32]byte{}
		case 4:
			in.G0CanonicalHash = [32]byte{}
		case 5:
			in.G1CanonicalHash = [32]byte{}
		case 6:
			in.G2CanonicalHash = [32]byte{}
		case 7:
			in.KeypageURLHash = [32]byte{}
		case 8:
			in.KeybookURLHash = [32]byte{}
		case 9:
			in.OperationID = [32]byte{}
		}
		for run := 0; run < 20; run++ {
			_, err := ComputeAccumulateGovRootV2(in)
			if err == nil || !strings.Contains(err.Error(), "the "+name+" slot") {
				t.Fatalf("missing %s: %v", name, err)
			}
		}
	}
	// With several missing, always the first in slot order.
	in := AccumulateGovRootInputs{}
	for run := 0; run < 50; run++ {
		if _, err := ComputeAccumulateGovRootV2(in); err == nil || !strings.Contains(err.Error(), "the L1 slot") {
			t.Fatalf("all missing: %v", err)
		}
	}
}

func TestGovernanceHashV2_LevelsAndEmpty(t *testing.T) {
	a, err := GovernanceHashV2(0, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GovernanceHashV2(1, []byte(`{}`))
	if a == b {
		t.Fatal("the level is not bound")
	}
	if a == CanonicalHashGovernance("certen:g0:v1", []byte(`{}`)) {
		t.Fatal("v2 G0 equals v1 G0")
	}
	for _, bad := range []int{-1, 3} {
		if _, err := GovernanceHashV2(bad, []byte(`{}`)); err == nil {
			t.Fatalf("level %d accepted", bad)
		}
	}
	if _, err := GovernanceHashV2(1, nil); err == nil {
		t.Fatal("an empty G1 was accepted")
	}
}
