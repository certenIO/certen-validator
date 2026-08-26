// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 7, Gates 4 and 5 - multi-partition proofs.
//
// These are OFFLINE. Every input is a real proof captured from Kermit and kept
// in testdata; nothing here contacts the network, which is the whole point of
// L4 carrying its own evidence.

func loadFixtureProof(t *testing.T, name string) *ChainedProof {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s not available: %v", name, err)
	}
	var p ChainedProof
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("fixture %s does not parse: %v", name, err)
	}
	return &p
}

// TestP7_4_SinglePartitionBytesAreUnchanged is Gate 4's byte-identity
// condition, and it is the reason the multi-leg shape is "primary plus
// additional" rather than a list.
//
// Every proof on record has exactly one BVN leg. If widening the struct changed
// what such a proof marshals to, every stored proof and every fixture would
// become unreadable and the offline verification Phase 6 had just established
// for them would quietly retire.
func TestP7_4_SinglePartitionBytesAreUnchanged(t *testing.T) {
	for _, name := range []string{"proof_bvn1.json", "proof_bvn3.json"} {
		t.Run(name, func(t *testing.T) {
			original, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Skipf("fixture not available: %v", err)
			}

			var p ChainedProof
			if err := json.Unmarshal(original, &p); err != nil {
				t.Fatalf("fixture does not parse: %v", err)
			}
			if len(p.AdditionalLegs) != 0 {
				t.Fatalf("a stored single-partition proof came back with %d additional leg(s)",
					len(p.AdditionalLegs))
			}

			// Re-marshalled, the proof must not have grown a key. json.Marshal
			// orders keys by struct field, so comparing against a re-marshal of
			// the ORIGINAL parse isolates "did the shape change" from "is the
			// fixture pretty-printed".
			round, err := json.Marshal(&p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(round), "additionalLegs") {
				t.Fatal("a single-partition proof marshals with an additionalLegs key. " +
					"omitempty is load-bearing here: every stored proof and fixture would " +
					"gain a field, and Gate 4's byte-identity condition would fail")
			}

			var reparsed ChainedProof
			if err := json.Unmarshal(round, &reparsed); err != nil {
				t.Fatalf("round trip does not re-parse: %v", err)
			}
			again, err := json.Marshal(&reparsed)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(again) != string(round) {
				t.Fatal("a proof does not round-trip to identical bytes")
			}
		})
	}
}

// TestP7_4_LegsPresentsThePrincipalLeg checks the unified view sees the
// first-written leg, so nothing downstream has to know which leg came first.
func TestP7_4_LegsPresentsThePrincipalLeg(t *testing.T) {
	p := loadFixtureProof(t, "proof_bvn1.json")

	legs := p.Legs()
	if len(legs) != 1 {
		t.Fatalf("a single-partition proof presents %d legs", len(legs))
	}
	if legs[0].Layer4BVN == nil {
		t.Fatal("the principal's leg has no L4 evidence")
	}
	if !strings.EqualFold(legs[0].Partition, p.Layer4BVN.Partition) {
		t.Fatalf("Legs() reports partition %q, the signed leg says %q",
			legs[0].Partition, p.Layer4BVN.Partition)
	}
	if legs[0].Layer1.Leaf != p.Layer1.Leaf {
		t.Fatal("Legs() did not carry the principal's L1")
	}
}

// TestP7_4_CanonicalOrderingIsIndependentOfDiscoveryOrder is P7.10.
//
// Partition discovery order depends on which signature resolved first, which is
// not stable between two validators reading identical chain data. If that order
// reached the bytes, the two would produce different proofs and therefore
// different govRoots - an intermittent, unreproducible TX2 revert, which is
// close to the worst failure mode available here.
func TestP7_4_CanonicalOrderingIsIndependentOfDiscoveryOrder(t *testing.T) {
	base := loadFixtureProof(t, "proof_bvn1.json")
	other := loadFixtureProof(t, "proof_bvn3.json")

	makeLeg := func(part string, src *ChainedProof) PartitionLeg {
		return PartitionLeg{
			Partition: part,
			Account:   src.Input.Account,
			Layer1:    src.Layer1,
			Layer2:    src.Layer2,
			Layer4BVN: src.Layer4BVN,
		}
	}

	// Two legs beyond the principal's, added in both possible orders. Only the
	// ORDER differs; the content is identical.
	legA := makeLeg("BVN2", other)
	legB := makeLeg("BVN3", other)

	first := *base
	first.AdditionalLegs = nil
	if err := first.AddLeg(legA); err != nil {
		t.Fatalf("add leg: %v", err)
	}
	if err := first.AddLeg(legB); err != nil {
		t.Fatalf("add leg: %v", err)
	}

	second := *base
	second.AdditionalLegs = nil
	if err := second.AddLeg(legB); err != nil {
		t.Fatalf("add leg: %v", err)
	}
	if err := second.AddLeg(legA); err != nil {
		t.Fatalf("add leg: %v", err)
	}

	a, err := json.Marshal(&first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b, err := json.Marshal(&second)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("two discovery orders produced different bytes. Unordered legs make two " +
			"validators reading identical chain data disagree about govRoot, which reverts " +
			"TX2 intermittently and unreproducibly")
	}

	// And the unified view is sorted, not merely stable.
	parts := first.SignerPartitions()
	for i := 1; i < len(parts); i++ {
		if strings.ToLower(parts[i-1]) > strings.ToLower(parts[i]) {
			t.Fatalf("legs are not in canonical partition order: %v", parts)
		}
	}
}

// TestP7_4_DuplicatePartitionIsRefused: a proof carries at most one leg per
// partition. Two would be counted twice by anything walking the legs, and since
// a leg carries a validator quorum, two disagreeing legs for one partition is
// exactly what a proof must not paper over.
func TestP7_4_DuplicatePartitionIsRefused(t *testing.T) {
	base := loadFixtureProof(t, "proof_bvn1.json")
	other := loadFixtureProof(t, "proof_bvn3.json")

	leg := PartitionLeg{
		Partition: "BVN3",
		Account:   other.Input.Account,
		Layer1:    other.Layer1,
		Layer2:    other.Layer2,
		Layer4BVN: other.Layer4BVN,
	}
	if err := base.AddLeg(leg); err != nil {
		t.Fatalf("first add should succeed: %v", err)
	}
	if err := base.AddLeg(leg); err == nil {
		t.Fatal("a second leg for the same partition was accepted")
	}

	// And a leg with no signed anchor is refused outright: a partition leg
	// without a quorum is not proof-grade.
	naked := leg
	naked.Partition = "BVN2"
	naked.Layer4BVN = nil
	if err := base.AddLeg(naked); err == nil {
		t.Fatal("a leg with no L4 evidence was accepted")
	}
}

// TestP7_5_EveryLegIsVerified is Gate 5's core condition: corrupting leg i must
// fail, FOR EVERY i. Not a spot check - the loop is the test.
//
// The failure this guards against is a verifier that checks the first leg and
// trusts the rest, which would accept a proof whose second partition's evidence
// is forged or grafted from somewhere else.
func TestP7_5_EveryLegIsVerified(t *testing.T) {
	base := loadFixtureProof(t, "proof_bvn1.json")
	other := loadFixtureProof(t, "proof_bvn3.json")
	ctx := context.Background()

	// A second leg that shares this proof's Directory anchor, so the composed
	// proof differs from the single-partition one ONLY in having two legs. A leg
	// anchored at a different DN block is refused for that reason instead, which
	// would make this test pass for the wrong reason.
	second := PartitionLeg{
		Partition: "BVN3",
		Account:   other.Input.Account,
		Layer1:    other.Layer1,
		Layer2:    other.Layer2,
		Layer4BVN: other.Layer4BVN,
	}
	second.Layer2.DNRootChainAnchor = base.Layer2.DNRootChainAnchor
	second.Layer2.DNMinorBlockIndex = base.Layer2.DNMinorBlockIndex

	composed := *base
	composed.AdditionalLegs = nil
	if err := composed.AddLeg(second); err != nil {
		t.Fatalf("add leg: %v", err)
	}

	legs := composed.Legs()
	if len(legs) < 2 {
		t.Fatalf("composed proof has %d leg(s); this test needs at least 2", len(legs))
	}

	pv := NewProofVerifier(false)

	// Every leg, corrupted in turn, in each of the ways a leg can be wrong.
	mutations := map[string]func(*PartitionLeg){
		"state tree anchor": func(l *PartitionLeg) {
			l.Layer4BVN = cloneLayer4(l.Layer4BVN)
			l.Layer4BVN.StateTreeAnchor = flipHex(l.Layer4BVN.StateTreeAnchor)
		},
		"root chain anchor": func(l *PartitionLeg) {
			l.Layer4BVN = cloneLayer4(l.Layer4BVN)
			l.Layer4BVN.RootChainAnchor = flipHex(l.Layer4BVN.RootChainAnchor)
		},
		"minor block index": func(l *PartitionLeg) {
			l.Layer4BVN = cloneLayer4(l.Layer4BVN)
			l.Layer4BVN.MinorBlockIndex++
		},
		"partition relabelled": func(l *PartitionLeg) {
			l.Layer4BVN = cloneLayer4(l.Layer4BVN)
			l.Layer4BVN.Partition = "BVN9"
		},
		"L4 removed": func(l *PartitionLeg) { l.Layer4BVN = nil },
	}

	for i := range legs {
		for name, mutate := range mutations {
			t.Run(legs[i].Partition+"/"+name, func(t *testing.T) {
				p := composed
				p.AdditionalLegs = append([]PartitionLeg{}, composed.AdditionalLegs...)

				// Leg 0 in canonical order may be the principal's, which lives in
				// the top-level fields rather than in AdditionalLegs.
				target := legs[i]
				mutate(&target)

				if strings.EqualFold(target.Partition, p.principalPartition()) {
					p.Layer4BVN = target.Layer4BVN
					p.Layer1 = target.Layer1
					p.Layer2 = target.Layer2
				} else {
					replaced := false
					for j := range p.AdditionalLegs {
						if strings.EqualFold(p.AdditionalLegs[j].Partition, target.Partition) {
							p.AdditionalLegs[j] = target
							replaced = true
						}
					}
					if !replaced {
						t.Fatalf("could not find leg %s to corrupt", target.Partition)
					}
				}

				if err := pv.Verify(ctx, &p); err == nil {
					t.Fatalf("corrupting leg %d of %d (%s) still verified - this leg is not "+
						"being checked", i+1, len(legs), name)
				}
			})
		}
	}
}

// TestP7_5_CrossBindIsRefusedAtNLegs generalises the two-leg cross-bind
// protection: a valid leg from ANOTHER proof must not be graftable into any
// position.
//
// The leg being grafted is entirely genuine - real signatures, a real quorum,
// a real anchor. It is simply evidence about a different proof, and a verifier
// that accepts it is one that checks each leg's internal consistency without
// checking that the leg belongs here.
func TestP7_5_CrossBindIsRefusedAtNLegs(t *testing.T) {
	base := loadFixtureProof(t, "proof_bvn1.json")
	other := loadFixtureProof(t, "proof_bvn3.json")
	ctx := context.Background()
	pv := NewProofVerifier(false)

	if err := pv.Verify(ctx, base); err != nil {
		t.Fatalf("the unmodified fixture must verify first: %v", err)
	}

	// Graft the other proof's genuine BVN leg into the principal's position.
	grafted := *base
	grafted.Layer4BVN = other.Layer4BVN
	if err := pv.Verify(ctx, &grafted); err == nil {
		t.Fatal("a genuine L4 leg from another proof was accepted in the principal's " +
			"position - the leg is internally consistent but is not evidence about THIS proof")
	}

	// And into an additional position, where the leg's own L1/L2 come with it
	// but its Directory anchor does not match this proof.
	appended := *base
	appended.AdditionalLegs = nil
	err := appended.AddLeg(PartitionLeg{
		Partition: "BVN3",
		Account:   other.Input.Account,
		Layer1:    other.Layer1,
		Layer2:    other.Layer2,
		Layer4BVN: other.Layer4BVN,
	})
	if err != nil {
		t.Fatalf("add leg: %v", err)
	}
	if err := pv.Verify(ctx, &appended); err == nil {
		t.Fatal("a leg anchored into a different Directory block was accepted; its path to " +
			"this proof's proven Directory state is asserted, not shown")
	} else {
		t.Logf("refused, as it must be: %v", err)
	}
}

// TestP7_5_SinglePartitionProofsStillVerify is the regression guard.
//
// Every proof on record is single-partition. Nothing in Phase 7 may change what
// happens to them.
func TestP7_5_SinglePartitionProofsStillVerify(t *testing.T) {
	ctx := context.Background()
	pv := NewProofVerifier(false)

	for _, name := range []string{"proof_bvn1.json", "proof_bvn3.json"} {
		t.Run(name, func(t *testing.T) {
			p := loadFixtureProof(t, name)
			if err := pv.Verify(ctx, p); err != nil {
				t.Fatalf("a single-partition proof no longer verifies: %v", err)
			}
			if len(p.Legs()) != 1 {
				t.Fatalf("presents %d legs", len(p.Legs()))
			}
		})
	}
}

func cloneLayer4(l *Layer4) *Layer4 {
	if l == nil {
		return nil
	}
	c := *l
	return &c
}

// flipHex changes a hex string into a different, still-valid hex string.
func flipHex(s string) string {
	if s == "" {
		return "00"
	}
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

// TestP7_5_LegsMustShareOneDirectoryRoot is the invariant that makes a
// cross-partition proof a single claim rather than two stapled together.
//
// Every leg's L2 receipt is a merkle path up to a Directory root, and L3 proves
// ONE root into the DN state tree. If two legs terminate at different roots, the
// second has no proven path to the state the proof is about - and the proof
// would still look complete, because each leg is internally valid.
//
// The builder now brings them together by asking every leg's receipt for the
// same DN minor root chain height (see dn_root_height.go). This pins the check
// the verifier applies regardless, so a builder regression cannot slip a
// mismatched pair through.
func TestP7_5_LegsMustShareOneDirectoryRoot(t *testing.T) {
	base := loadFixtureProof(t, "proof_bvn1.json")
	other := loadFixtureProof(t, "proof_bvn3.json")
	ctx := context.Background()
	pv := NewProofVerifier(false)

	// A leg that agrees on the Directory root verifies.
	agreeing := PartitionLeg{
		Partition: "BVN3",
		Account:   other.Input.Account,
		Layer1:    other.Layer1,
		Layer2:    other.Layer2,
		Layer4BVN: other.Layer4BVN,
	}
	agreeing.Layer2.DNRootChainAnchor = base.Layer2.DNRootChainAnchor
	agreeing.Layer2.DNMinorBlockIndex = base.Layer2.DNMinorBlockIndex

	ok := *base
	ok.AdditionalLegs = nil
	if err := ok.AddLeg(agreeing); err != nil {
		t.Fatalf("add leg: %v", err)
	}
	if err := pv.Verify(ctx, &ok); err != nil {
		t.Fatalf("two legs sharing a Directory root must verify: %v", err)
	}

	// The same leg, disagreeing by one bit in the root, must not.
	disagreeing := agreeing
	disagreeing.Layer2.DNRootChainAnchor = flipHex(base.Layer2.DNRootChainAnchor)

	bad := *base
	bad.AdditionalLegs = nil
	if err := bad.AddLeg(disagreeing); err != nil {
		t.Fatalf("add leg: %v", err)
	}
	if err := pv.Verify(ctx, &bad); err == nil {
		t.Fatal("a leg witnessing a different Directory root was accepted. Its path to the " +
			"state this proof proves is asserted, not shown, and the proof would still look " +
			"complete because the leg is internally valid")
	}
}
