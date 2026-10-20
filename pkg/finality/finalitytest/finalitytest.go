// Copyright 2026 Certen Protocol

// Package finalitytest builds finality settlements from the real captured blocks of pkg/ethproof/ethprooftest, for tests of
// the finality framework, the chain packages that register provers and verifiers, the repository and the verifier tools.
// Imported only by tests.
package finalitytest

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// Blocks are the captured real blocks, one per live chain, by fixture name.
var Blocks = map[string]uint64{
	"sepolia_11792612":           finality.ChainSepolia,
	"base_sepolia_47368146":      finality.ChainBaseSepolia,
	"arbitrum_sepolia_312921216": finality.ChainArbitrumSepolia,
	"telcoin_adiri_498759":       finality.ChainAdiri,
}

// Settlement is the settlement of a captured real block, with the L6 evidence built exactly as the settlement gate builds it
// (two agreeing providers, every entry of the block proven against the header's roots).
func Settlement(t testing.TB, fixture string) finality.Settlement {
	t.Helper()
	f := ethprooftest.Load(t, fixture)
	r, err := ethrpc.NewAgreeingReader(context.Background(), f.ChainID,
		ethprooftest.URLs(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f, NoBlockReceipts: true}), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ethproof.ReadBlock(context.Background(), r, f.BlockHash())
	if err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}
	proof, err := b.Prove(f.SettlementTx, f.SettlementIndex())
	if err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}
	subject, err := finality.SubjectOfSettlement(proof)
	if err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}
	return finality.Settlement{Chain: uint64(f.ChainID), Subject: subject, Included: proof}
}
