package contracts

import (
	"encoding/hex"
	"strings"
	"testing"
)

// govRoot v4 is its own domain over the same ten slots: never a v3 (or earlier) value, and the pinned vector, recomputed
// independently in Python (pycryptodome keccak256) on 2026-10-17, fixes the layout.
func TestGovRootV4_DomainAndVector(t *testing.T) {
	in := fullGovInputs()
	v4, err := ComputeAccumulateGovRootV4(in)
	if err != nil {
		t.Fatal(err)
	}
	v3, _ := ComputeAccumulateGovRootV3(in)
	v2, _ := ComputeAccumulateGovRootV2(in)
	if v4 == v3 || v4 == v2 || v4 == ComputeAccumulateGovRoot(in) {
		t.Fatal("govRoot v4 equals an earlier version over the same slots")
	}
	const want = "0347a3796bd783c54c9477cdba455690280bc7a00150aa7566d621572b3e3d6e"
	if got := hex.EncodeToString(v4[:]); got != want {
		t.Fatalf("govRoot v4 vector: got %s want %s", got, want)
	}
}

// The G1 slot of v4 is under its own tag and commits the votes root beside the pages root; the pinned vector is the same
// Python recomputation.
func TestGovRootV4_G1SlotVector(t *testing.T) {
	g1 := GovRootV4G1(fill32(14), fill32(15), fill32(17))
	const want = "7d75a78f6ac6e7e3ae45827d6a8ff6ade221c4a10cb9f5362a4be27a99bb3bb1"
	if got := hex.EncodeToString(g1[:]); got != want {
		t.Fatalf("G1 v4 slot: got %s want %s", got, want)
	}
	if GovRootV3SlotHash(GovRootV3TagG1, nil) == GovRootV3SlotHash(GovRootV4TagG1, nil) {
		t.Fatal("the v4 G1 tag is the v3 one")
	}
	if g1 == GovRootV3G1(fill32(14), fill32(15)) {
		t.Fatal("the v4 G1 slot equals the v3 slot")
	}
	// The votes root is committed: another one is another slot.
	if GovRootV4G1(fill32(14), fill32(15), fill32(18)) == g1 {
		t.Fatal("the G1 slot does not depend on the votes root")
	}
}

// Every slot is required, and the refusal names the same first missing slot every time.
func TestGovRootV4_EverySlotRequiredDeterministically(t *testing.T) {
	names := []string{"L1", "L2", "L3", "L4", "G0", "G1", "G2", "key page", "key book", "operation id"}
	for i, name := range names {
		in := fullGovInputs()
		*[]*[32]byte{&in.L1AccountHash, &in.L2BPTRoot, &in.L3BlockHash, &in.L4ConsensusProofH, &in.G0CanonicalHash,
			&in.G1CanonicalHash, &in.G2CanonicalHash, &in.KeypageURLHash, &in.KeybookURLHash, &in.OperationID}[i] = [32]byte{}
		for run := 0; run < 20; run++ {
			_, err := ComputeAccumulateGovRootV4(in)
			if err == nil || !strings.Contains(err.Error(), "govRoot v4: the "+name+" slot") {
				t.Fatalf("missing %s: %v", name, err)
			}
		}
	}
}
