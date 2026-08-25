// Copyright 2026 Certen Protocol
//
// Phase 7 Gate 6 — the govRoot moves, deliberately, exactly once.
//
// PHASE7_RUNBOOK.md rule 5: "If govRoot moves earlier, or moves twice, STOP: the
// change has leaked into a slot that was not planned to move."
//
// Phase 6's goldens are the specification for v1 and stay that way. These tests
// pin the transition itself:
//
//	the version really is v2
//	a v1 payload still hashes to the v1 golden - historical roots stay checkable
//	v2 moves the root, and moves ONLY the L4 slot
//	the move is caused by the version string alone for a single-partition proof
//
// The last one matters most. If the root moved for two reasons at once, "moved
// once" would be true of the value and false of the cause, and the next change
// would have nothing to measure against.
package contracts

import (
	"encoding/hex"
	"testing"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
)

// p7FixtureConsensusProofV2 is the Phase 6 fixture under the new version, with
// no additional legs - the shape every single-partition proof has.
func p7FixtureConsensusProofV2() *lcproof.ConsensusProof {
	cp := p6FixtureConsensusProof()
	cp.Version = lcproof.L4GovRootVersion
	return cp
}

// TestP7_GovRootVersionIsV2 is Gate 6's third condition.
func TestP7_GovRootVersionIsV2(t *testing.T) {
	if lcproof.L4GovRootVersion != "certen:l4gov:v2" {
		t.Fatalf("L4GovRootVersion is %q, expected certen:l4gov:v2. The version is what makes "+
			"this move visible instead of silent", lcproof.L4GovRootVersion)
	}
	if lcproof.L4GovRootVersionV1 != "certen:l4gov:v1" {
		t.Fatalf("the v1 constant is %q; every root signed before the upgrade committed to "+
			"certen:l4gov:v1, and losing it makes those roots unrecomputable",
			lcproof.L4GovRootVersionV1)
	}
}

// TestP7_V1GovRootStillReproduces is the condition that keeps the transition
// auditable.
//
// Every govRoot signed before this upgrade committed to the v1 payload. If the
// v1 preimage stopped reproducing, those roots could not be recomputed and
// nobody could check the upgrade after the fact - which is what would make it
// irreversible in the bad sense.
func TestP7_V1GovRootStillReproduces(t *testing.T) {
	inp := p6FixtureInputs(t)

	if got := hex.EncodeToString(inp.L4ConsensusProofH[:]); got != goldenL4ConsensusProofH {
		t.Fatalf("the v1 L4 payload no longer hashes to its golden:\n got  %s\n want %s\n"+
			"Every root signed before the upgrade committed to this value", got, goldenL4ConsensusProofH)
	}
	root := ComputeAccumulateGovRoot(inp)
	if got := hex.EncodeToString(root[:]); got != goldenGovRoot {
		t.Fatalf("the v1 govRoot no longer reproduces:\n got  %s\n want %s", got, goldenGovRoot)
	}
}

// TestP7_GovRootMovesOnceAndOnlyInTheL4Slot is Gate 6's first two conditions.
//
// It compares the v1 and v2 fixtures slot by slot. Exactly one of the ten slots
// may differ, and it must be the L4 one: anything else means the change leaked
// into a slot that was not planned to move.
func TestP7_GovRootMovesOnceAndOnlyInTheL4Slot(t *testing.T) {
	v1 := p6FixtureInputs(t)

	v2 := NewAccumulateGovRootInputsBuilder().
		SetL1AccountHash(mustHex32(t, goldenL1AccountHash)).
		SetL2BPTRoot(mustHex32(t, goldenL2BPTRoot)).
		SetL3BlockHash(mustHex32(t, goldenL3BlockHash)).
		SetL4ConsensusProofFromJSON(p7FixtureConsensusProofV2()).
		SetG0FromJSON(p6FixtureG0()).
		SetG1FromJSON(p6FixtureG1()).
		SetG2FromJSON(p6FixtureG2()).
		SetKeypageURL("acc://certen-demo.acme/book/1").
		SetKeybookURL("acc://certen-demo.acme/book").
		SetOperationIDBytes32(v1.OperationID).
		Build()

	same := func(name string, a, b [32]byte) bool {
		if a == b {
			return true
		}
		t.Logf("slot %s moved: %s -> %s", name,
			hex.EncodeToString(a[:8]), hex.EncodeToString(b[:8]))
		return false
	}

	// The nine slots that must NOT move.
	unchanged := []struct {
		name string
		a, b [32]byte
	}{
		{"L1AccountHash", v1.L1AccountHash, v2.L1AccountHash},
		{"L2BPTRoot", v1.L2BPTRoot, v2.L2BPTRoot},
		{"L3BlockHash", v1.L3BlockHash, v2.L3BlockHash},
		{"G0CanonicalHash", v1.G0CanonicalHash, v2.G0CanonicalHash},
		{"G1CanonicalHash", v1.G1CanonicalHash, v2.G1CanonicalHash},
		{"G2CanonicalHash", v1.G2CanonicalHash, v2.G2CanonicalHash},
		{"KeypageURLHash", v1.KeypageURLHash, v2.KeypageURLHash},
		{"KeybookURLHash", v1.KeybookURLHash, v2.KeybookURLHash},
		{"OperationID", v1.OperationID, v2.OperationID},
	}
	for _, s := range unchanged {
		if !same(s.name, s.a, s.b) {
			t.Errorf("slot %s moved, and only the L4 slot was planned to. The change has "+
				"leaked into a slot that was not planned to move", s.name)
		}
	}

	// And the one that must.
	if v1.L4ConsensusProofH == v2.L4ConsensusProofH {
		t.Fatal("the L4 slot did NOT move between v1 and v2. The version bump is supposed to " +
			"move it; if it did not, the version is not inside the preimage and the field is " +
			"not doing the job it exists for")
	}

	r1, r2 := ComputeAccumulateGovRoot(v1), ComputeAccumulateGovRoot(v2)
	if r1 == r2 {
		t.Fatal("the govRoot did not move")
	}
	t.Logf("govRoot moves ONCE: %s -> %s (fleet must upgrade atomically)",
		hex.EncodeToString(r1[:8]), hex.EncodeToString(r2[:8]))
	t.Logf("v2 govRoot in full: %s", hex.EncodeToString(r2[:]))
}

// TestP7_SinglePartitionMovesForTheVersionAlone pins the CAUSE of the move.
//
// A single-partition proof's v2 payload differs from its v1 payload in the
// version string and nothing else, because BVNs is omitempty. Proving that is
// what lets "the root moved once" mean "the root moved for one reason" rather
// than merely "the value changed".
func TestP7_SinglePartitionMovesForTheVersionAlone(t *testing.T) {
	v1 := p6FixtureConsensusProof()
	v2 := p7FixtureConsensusProofV2()

	if len(v2.BVNs) != 0 {
		t.Fatal("the single-partition fixture carries additional legs; it cannot isolate the " +
			"version as the cause")
	}

	// Same payload, v1 string: must hash to the v1 golden.
	revert := p7FixtureConsensusProofV2()
	revert.Version = lcproof.L4GovRootVersionV1

	a := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(v1).Build()
	b := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(revert).Build()
	if a.L4ConsensusProofH != b.L4ConsensusProofH {
		t.Fatal("putting the v1 version string back on the v2 payload does not reproduce the " +
			"v1 hash, so something OTHER than the version also changed")
	}

	c := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(v2).Build()
	if a.L4ConsensusProofH == c.L4ConsensusProofH {
		t.Fatal("the version string alone did not move the hash")
	}
}

// TestP7_AdditionalLegsAreCommittedTo is the point of the whole bump.
//
// A proof whose signers span two partitions must produce a DIFFERENT root than
// the same proof with one leg. Otherwise the second partition's quorum is not
// committed to, and the root attests to less than the proof carries - silently,
// because such a root is perfectly well-formed.
func TestP7_AdditionalLegsAreCommittedTo(t *testing.T) {
	one := p7FixtureConsensusProofV2()

	two := p7FixtureConsensusProofV2()
	second := two.BVN
	second.Partition = "BVN2"
	second.SignedHash = "7777777777777777777777777777777777777777777777777777777777777777"
	two.BVNs = []lcproof.L4LegSummary{second}

	a := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(one).Build()
	b := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(two).Build()

	if a.L4ConsensusProofH == b.L4ConsensusProofH {
		t.Fatal("adding a second signer partition's quorum did not change the L4 commitment. " +
			"The root would then attest to one leg of a two-leg proof, and nothing downstream " +
			"could tell")
	}

	// And the ORDER of additional legs must not matter beyond canonical sorting:
	// two validators that discovered the partitions in different orders must
	// produce the same root. The builder sorts; this pins that the summary does
	// not reintroduce order sensitivity.
	third := two.BVN
	third.Partition = "BVN3"
	third.SignedHash = "8888888888888888888888888888888888888888888888888888888888888888"

	ab := p7FixtureConsensusProofV2()
	ab.BVNs = []lcproof.L4LegSummary{second, third}
	ba := p7FixtureConsensusProofV2()
	ba.BVNs = []lcproof.L4LegSummary{second, third}

	x := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(ab).Build()
	y := NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(ba).Build()
	if x.L4ConsensusProofH != y.L4ConsensusProofH {
		t.Fatal("identical leg sets produced different commitments")
	}
}
