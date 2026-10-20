// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// realSettlement builds the L6 settlement of a captured real block, exactly as the settlement gate reads one from two agreeing
// providers, and the finality Settlement a leg of it would hand the worker.
func realSettlement(t *testing.T, name string) Settlement {
	t.Helper()
	f := ethprooftest.Load(t, name)
	r, err := ethrpc.NewAgreeingReader(context.Background(), f.ChainID,
		ethprooftest.URLs(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f, NoBlockReceipts: true}), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ethproof.ReadBlock(context.Background(), r, f.BlockHash())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	proof, err := b.Prove(f.SettlementTx, f.SettlementIndex())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	subject, err := SubjectOfSettlement(proof)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return Settlement{Chain: uint64(f.ChainID), Subject: subject, Included: proof}
}

var realBlocks = map[string]uint64{
	"sepolia_11792612":           ChainSepolia,
	"base_sepolia_47368146":      ChainBaseSepolia,
	"arbitrum_sepolia_312921216": ChainArbitrumSepolia,
	"telcoin_adiri_498759":       ChainAdiri,
}

// Level 1 is derived from the original proof's Settlement on all four chains: S6 verifies, the block number is read
// positionally from the header, and the leg's block is the one every other level binds to. It has no addendum.
func TestIncludedIsDerivedFromTheSettlementOnRealBlocksOfAllFourChains(t *testing.T) {
	for name, chain := range realBlocks {
		t.Run(name, func(t *testing.T) {
			s := realSettlement(t, name)
			if s.Chain != chain {
				t.Fatalf("fixture chain %d, want %d", s.Chain, chain)
			}
			b, err := DeriveIncluded(chain, s.Included)
			if err != nil {
				t.Fatal(err)
			}
			h, err := ReadHeader(s.Included.Header)
			if err != nil {
				t.Fatal(err)
			}
			if b.Chain != chain || b.Number != s.BlockNumber || b.Hash != s.BlockHash || h.Number != b.Number || h.Hash != b.Hash {
				t.Fatalf("%+v vs %+v", b, s.Subject)
			}
			// the same through the report: included is verified and nothing is stored
			rep := NewRegistry().Verify(chain, s.Included, b, nil, nil)
			if rep.Headline != LevelIncluded || rep.Levels[LevelIncluded].Status != StatusVerified {
				t.Fatalf("%+v", rep)
			}
		})
	}
}

func TestIncludedRefusesAnotherTransactionAndATamperedHeader(t *testing.T) {
	s := realSettlement(t, "base_sepolia_47368146")
	wrong := *s.Included
	wrong.TxHash[0] ^= 0xFF
	if _, err := DeriveIncluded(ChainBaseSepolia, &wrong); err == nil || stateOf(t, err).Code != CodeIncludedInvalid {
		t.Fatalf("another transaction's hash derived a block: %v", err)
	}
	torn := *s.Included
	torn.Header = append([]byte(nil), torn.Header...)
	torn.Header[len(torn.Header)-1] ^= 1
	if _, err := DeriveIncluded(ChainBaseSepolia, &torn); err == nil {
		t.Fatal("a header that does not hash to the block hash derived a block")
	}
	if _, err := DeriveIncluded(ChainBaseSepolia, nil); err == nil || stateOf(t, err).Code != CodeIncludedUnavailable {
		t.Fatalf("a missing settlement: %v", err)
	}
	rep := NewRegistry().Verify(ChainBaseSepolia, &wrong, BlockRef{}, nil, nil)
	if st := rep.Levels[LevelIncluded]; st.Status != StatusRefused || rep.Headline != LevelNone {
		t.Fatalf("%+v", rep)
	}
}
