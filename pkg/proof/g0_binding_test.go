// Copyright 2026 Certen Protocol

package proof

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// A real pair: the two-partition chained proof recorded from Kermit by
// `p7corpus -stage multileg -proof-out`, and govproof's G0 for the same
// transaction (certen-p7f-alpha.acme/data a934d885...), run separately against
// Kermit. Their receipts are the same 13-step path to the same root, at the
// block the BVN quorum signed.
func loadG0BindingPair(t *testing.T) (*G0Result, *chained_proof.ChainedProof) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "g0_multileg_bvn1_bvn2.json"))
	if err != nil {
		t.Fatalf("G0 fixture: %v", err)
	}
	g0 := new(G0Result)
	if err := json.Unmarshal(raw, g0); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join("..", "..", "accumulate-lite-client-2", "liteclient", "proof",
		"working-proof_do_not_edit", "testdata", "proof_multileg_bvn1_bvn2.json"))
	if err != nil {
		t.Fatalf("chained proof fixture: %v", err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(raw, cp); err != nil {
		t.Fatal(err)
	}
	return g0, cp
}

func TestG0Binding_RealPairBinds(t *testing.T) {
	g0, cp := loadG0BindingPair(t)
	if err := BindG0ToChainedProof(g0, ChainedProofToCompleteProof(cp)); err != nil {
		t.Fatalf("G0 and the chained proof of the same transaction must bind: %v", err)
	}
}

func TestG0Binding_RefusesEveryMismatch(t *testing.T) {
	other := strings.Repeat("ab", 32)
	cases := map[string]struct {
		g0   func(*G0Result)
		cp   func(*chained_proof.ChainedProof)
		want string
	}{
		"witness from another root": {
			g0:   func(g *G0Result) { g.ExecWitness, g.Receipt.Anchor = other, other },
			want: "must reach the same root",
		},
		"witness not its own receipt's anchor": {
			g0:   func(g *G0Result) { g.ExecWitness = other },
			want: "is not the anchor of G0's own receipt",
		},
		"execution block off by one": {
			g0:   func(g *G0Result) { g.ExecMBI++ },
			want: "is not the block the BVN quorum signed",
		},
		"another entry": {
			g0:   func(g *G0Result) { g.EntryHashExec, g.Receipt.Start = other, other },
			want: "the chained proof's L1 proves",
		},
		"receipt not starting at the entry": {
			g0:   func(g *G0Result) { g.Receipt.Start = other },
			want: "not at its entry",
		},
		"signed anchor names another root": {
			cp:   func(c *chained_proof.ChainedProof) { c.Layer4BVN.RootChainAnchor = other },
			want: "is not the root chain anchor the BVN quorum signed",
		},
		"no signed BVN anchor": {
			cp:   func(c *chained_proof.ChainedProof) { c.Layer4BVN = nil },
			want: "no signed BVN anchor",
		},
		"empty witness": {
			g0:   func(g *G0Result) { g.ExecWitness = "" },
			want: "not a 32-byte hash",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g0, cp := loadG0BindingPair(t)
			if c.g0 != nil {
				c.g0(g0)
			}
			if c.cp != nil {
				c.cp(cp)
			}
			err := BindG0ToChainedProof(g0, ChainedProofToCompleteProof(cp))
			if err == nil {
				t.Fatalf("CRITICAL DEFECT: %s bound", name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for the wrong reason:\n  got:  %v\n  want: ...%s...", err, c.want)
			}
		})
	}
	if err := BindG0ToChainedProof(nil, nil); err == nil {
		t.Fatal("binding nothing to nothing succeeded")
	}
}

// storedPairLevels is the real G0 as governance_proof_levels stores it: the
// canonical result, and the receipt evidence with its merkle path.
func storedPairLevels(t *testing.T) []StoredGovernanceLevel {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "g0_multileg_bvn1_bvn2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var withPath struct {
		Receipt GovReceiptEvidence `json:"receipt"`
	}
	if err := json.Unmarshal(raw, &withPath); err != nil {
		t.Fatal(err)
	}
	withPath.Receipt.Level = "G0"
	return []StoredGovernanceLevel{{Level: "G0", Result: raw, Receipt: &withPath.Receipt}}
}

func TestStoredG0Binding(t *testing.T) {
	_, cp := loadG0BindingPair(t)

	levels := storedPairLevels(t)
	if !levels[0].HasEvidence() || levels[0].Receipt.VerifyMerkle() != nil {
		t.Fatal("the stored G0 receipt must itself recompute")
	}
	if err := VerifyStoredG0Binding(levels, cp); err != nil {
		t.Fatalf("the stored real pair must bind: %v", err)
	}

	t.Run("stored result names another witness", func(t *testing.T) {
		levels := storedPairLevels(t)
		levels[0].Result = []byte(strings.Replace(string(levels[0].Result),
			`"exec_witness":"fb4f`, `"exec_witness":"0b4f`, 1))
		if err := VerifyStoredG0Binding(levels, cp); err == nil {
			t.Fatal("a stored G0 result with another witness bound")
		}
	})
	t.Run("stored receipt from another root", func(t *testing.T) {
		levels := storedPairLevels(t)
		levels[0].Result = nil
		levels[0].Receipt.Anchor = strings.Repeat("ab", 32)
		if err := VerifyStoredG0Binding(levels, cp); err == nil {
			t.Fatal("a stored G0 receipt ending elsewhere bound")
		}
	})
	t.Run("stored receipt at another block", func(t *testing.T) {
		levels := storedPairLevels(t)
		levels[0].Result = nil
		levels[0].Receipt.LocalBlock--
		if err := VerifyStoredG0Binding(levels, cp); err == nil {
			t.Fatal("a stored G0 receipt at another block bound")
		}
	})
	t.Run("nothing stored is uncheckable, not verified", func(t *testing.T) {
		err := VerifyStoredG0Binding([]StoredGovernanceLevel{{Level: "G0"}}, cp)
		if !errors.Is(err, ErrG0BindingUncheckable) {
			t.Fatalf("want ErrG0BindingUncheckable, got %v", err)
		}
	})
}
