package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// RB12-DBFIX-FIX (verifier finding F1): migration 00029 binds an addendum's block number to the proof's recorded settlement block, but
// a proof that records no settlement yet, or a lie in the block HASH, can still be stored as a self-consistent chain about a bogus
// block. The reader that holds the Settlement refuses it by name. This pins that closure at the verifier: the chain's evidence headers
// AND its hashes (D0) both name the bogus block, the file's carried leg names either the bogus or the actual block.
func TestFinalityFileWhoseChainIsSelfConsistentAboutABogusBlockIsRefusedByName(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	pid := uuid.New()
	leg := &legSettlement{chain: finality.ChainBaseSepolia, s: s.Included, source: "test"}
	actual := s.Block()
	bogusNumber, bogusHash := actual, actual
	bogusNumber.Number += 7
	bogusHash.Hash[5] ^= 0x5a

	chainAbout := func(b finality.BlockRef) []finality.Addendum {
		var out []finality.Addendum
		for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
			ev, err := finality.Container{Header: finality.ContainerHeader{Kind: baseKinds[l], Chain: b.Chain, Level: l, BlockNumber: b.Number, BlockHash: b.Hash}, Body: []byte("b")}.Encode()
			if err != nil {
				t.Fatal(err)
			}
			a, err := finality.NewAddendum(finality.LegBindingOf(b), pid, out, b.Chain, l, baseKinds[l], ev)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, a)
		}
		return out
	}
	doc := func(carried finality.BlockRef, chain []finality.Addendum) string {
		raw, _ := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": finality.NewSection(carried, chain)})
		return writeDoc(t, raw)
	}

	for name, bogus := range map[string]finality.BlockRef{"another block number": bogusNumber, "another block hash": bogusHash} {
		t.Run(name+"/the file carries the real leg: own_hash under the Settlement's binding fails", func(t *testing.T) {
			code, out := verifyFileWith(t, doc(actual, chainAbout(bogus)), baseRegistry(), leg)
			if code != exitFailed || !strings.Contains(out, finality.CodeChainBroken) || !strings.Contains(out, finality.CheckOwnHash) {
				t.Fatalf("exit %d\n%s", code, out)
			}
		})
		t.Run(name+"/the file carries the bogus leg too: finality_chain_broken{leg_binding}", func(t *testing.T) {
			code, out := verifyFileWith(t, doc(bogus, chainAbout(bogus)), baseRegistry(), leg)
			if code != exitFailed || !strings.Contains(out, finality.CodeChainBroken) || !strings.Contains(out, finality.CheckLegBinding) {
				t.Fatalf("exit %d\n%s", code, out)
			}
		})
	}
	t.Run("the same chain about the real block verifies", func(t *testing.T) {
		code, out := verifyFileWith(t, doc(actual, chainAbout(actual)), baseRegistry(), leg)
		if code != exitVerified || !strings.Contains(out, "level reached: finalized") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}
