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
	"testing"
)

func loadFixture(t *testing.T, name string) *ChainedProof {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Skipf("fixture %s missing", name)
	}
	p := new(ChainedProof)
	if err := json.Unmarshal(raw, p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The binding claim under test:
//
//	A threshold-signed anchor's signatures must not be pairable with a state
//	root they did not sign.
//
// Every leg below is INDIVIDUALLY VALID - real signatures, real quorum, real
// validator set. The forgery is in the pairing. If the verifier only checked
// "signatures verify" plus "stored stateTreeAnchor equals the layer", these
// would all pass.
func TestCrossBind_ValidLegFromAnotherProofIsRejected(t *testing.T) {
	a := loadFixture(t, "proof_bvn1.json")
	b := loadFixture(t, "proof_bvn3.json")
	pv := NewProofVerifier(false)
	ctx := context.Background()

	// Both fixtures must verify on their own, or nothing below means anything.
	if err := pv.Verify(ctx, a); err != nil {
		t.Fatalf("fixture A does not verify: %v", err)
	}
	if err := pv.Verify(ctx, b); err != nil {
		t.Fatalf("fixture B does not verify: %v", err)
	}

	// Each leg must be individually valid, so that a rejection below is
	// attributable to the BINDING and not to a broken leg.
	for name, leg := range map[string]*Layer4{
		"A.BVN": a.Layer4BVN, "A.DN": a.Layer4DN,
		"B.BVN": b.Layer4BVN, "B.DN": b.Layer4DN,
	} {
		if err := leg.VerifyOffline(); err != nil {
			t.Fatalf("%s is not individually valid: %v", name, err)
		}
	}

	t.Run("graft B's valid DN leg onto A", func(t *testing.T) {
		p := loadFixture(t, "proof_bvn1.json")
		p.Layer4DN = b.Layer4DN
		if err := p.Layer4DN.VerifyOffline(); err != nil {
			t.Fatalf("grafted leg should still be individually valid: %v", err)
		}
		if err := pv.Verify(ctx, p); err == nil {
			t.Fatal("CRITICAL DEFECT: a valid DN anchor from a DIFFERENT proof was accepted")
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	t.Run("graft B's valid BVN leg onto A", func(t *testing.T) {
		p := loadFixture(t, "proof_bvn1.json")
		p.Layer4BVN = b.Layer4BVN
		if err := p.Layer4BVN.VerifyOffline(); err != nil {
			t.Fatalf("grafted leg should still be individually valid: %v", err)
		}
		if err := pv.Verify(ctx, p); err == nil {
			t.Fatal("CRITICAL DEFECT: a valid BVN anchor from a DIFFERENT proof was accepted")
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	// The sharpest form: a SELF-CONSISTENT forgery. Take B's valid DN leg AND
	// rewrite A's Layer3 to agree with it, so the cross-layer equality check
	// passes. The only thing left standing between this and acceptance is that
	// L3's own receipts still recompute to A's DN root.
	t.Run("self-consistent graft: B's DN leg plus a matching Layer3", func(t *testing.T) {
		p := loadFixture(t, "proof_bvn1.json")
		p.Layer4DN = b.Layer4DN
		p.Layer3.DNStateTreeAnchor = b.Layer4DN.StateTreeAnchor
		p.Layer2.DNRootChainAnchor = b.Layer4DN.RootChainAnchor
		p.Layer2.DNMinorBlockIndex = b.Layer4DN.MinorBlockIndex
		p.Layer3.DNAnchorMinorBlockIndex = b.Layer4DN.MinorBlockIndex
		p.Layer3.DNConsensusHeight = b.Layer4DN.MinorBlockIndex + 1
		if err := pv.Verify(ctx, p); err == nil {
			t.Fatal("CRITICAL DEFECT: self-consistent cross-proof forgery was accepted")
		} else {
			t.Logf("rejected: %v", err)
		}
	})

	// The specific gap in L4_DESIGN.md section 3.4: signatures verified over
	// AnchorTxHash, StateTreeAnchor merely asserted alongside. Simulate a
	// verifier that trusted the stored field by pairing A's real signed
	// message with B's state root in the stored fields only.
	t.Run("stored stateTreeAnchor swapped, signed message untouched", func(t *testing.T) {
		p := loadFixture(t, "proof_bvn1.json")
		p.Layer4DN.StateTreeAnchor = b.Layer4DN.StateTreeAnchor
		p.Layer3.DNStateTreeAnchor = b.Layer4DN.StateTreeAnchor
		if err := pv.Verify(ctx, p); err == nil {
			t.Fatal("CRITICAL DEFECT: signatures were paired with a state root they did not sign")
		} else {
			t.Logf("rejected: %v", err)
		}
	})
}
