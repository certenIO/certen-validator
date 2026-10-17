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

// Level 1 is today's L6 evidence re-expressed, and its verifier is registered for all four chains.
func TestIncludedLevelOnRealBlocksOfAllFourChains(t *testing.T) {
	for name, chain := range realBlocks {
		t.Run(name, func(t *testing.T) {
			s := realSettlement(t, name)
			if s.Chain != chain {
				t.Fatalf("fixture chain %d, want %d", s.Chain, chain)
			}
			provers := Default.Provers(chain)
			if len(provers) == 0 {
				t.Fatal("no prover registered for the chain")
			}
			ev, level, err := provers[0].Build(context.Background(), s)
			if err != nil || level != LevelIncluded {
				t.Fatalf("build: level %v err %v", level, err)
			}
			if got, err := Verify(chain, s, ev, nil); err != nil || got != LevelIncluded {
				t.Fatalf("verify: %v %v", got, err)
			}

			// as the first addendum of a chain, which verifies end to end
			original := [32]byte{0xA1}
			a, err := NewAddendum(original, "proof-"+name, nil, chain, LevelIncluded, ev)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyChain(original, []Addendum{a}); err != nil {
				t.Fatal(err)
			}
			if got, err := Default.VerifyAddendum(a, nil); err != nil || got != LevelIncluded {
				t.Fatalf("addendum: %v %v", got, err)
			}

			// refusals, each named
			mutate := func(edit func(ev *Evidence), want string) {
				t.Helper()
				bad := ev
				bad.Body = append([]byte(nil), ev.Body...)
				edit(&bad)
				_, err := Verify(chain, s, bad, nil)
				if err == nil {
					t.Fatal("a tampered included evidence verified")
				}
				if n, ok := AsNamed(err); !ok || (want != "" && n.Code() != want) {
					t.Fatalf("want %s, got %v", want, err)
				}
			}
			mutate(func(e *Evidence) { e.Body[10] ^= 0x01 }, CodeIncludedInvalid)                // a bit in the header
			mutate(func(e *Evidence) { e.Body = e.Body[:len(e.Body)-1] }, CodeEvidenceMalformed) // truncated
			mutate(func(e *Evidence) { e.Body = append(e.Body, 0) }, CodeEvidenceMalformed)      // trailing byte
			mutate(func(e *Evidence) { e.Subject.BlockNumber++ }, CodeSubjectMismatch)           // another block number
			mutate(func(e *Evidence) { e.Subject.TxHash[0] ^= 1 }, CodeSubjectMismatch)          // another transaction
			mutate(func(e *Evidence) { e.Kind = "included.eth-mpt/v2" }, CodeKindUnknown)        // unknown kind
		})
	}
}

// A transaction that is not in the block the evidence carries is refused even when the subject says it is: the subject is
// what the verifier is asked about, the body is what proves it.
func TestIncludedRefusesAnotherTransactionAndAnotherChainsRegistration(t *testing.T) {
	s := realSettlement(t, "base_sepolia_47368146")
	ev, _, err := Default.Provers(ChainBaseSepolia)[0].Build(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	other := s
	other.TxHash[5] ^= 0xFF
	ev.Subject.TxHash = other.TxHash
	if _, err := Verify(ChainBaseSepolia, other, ev, nil); err == nil {
		t.Fatal("evidence proving one transaction verified for another")
	}
	// built for one settlement, offered on a chain it does not belong to: refused by the settlement's chain
	if _, err := Verify(ChainAdiri, s, ev, nil); err == nil {
		t.Fatal("base evidence verified for an Adiri settlement")
	}
	// no L6 evidence held: a named unavailability, no level
	bare := s
	bare.Included = nil
	if _, lvl, err := Default.Provers(ChainBaseSepolia)[0].Build(context.Background(), bare); err == nil || lvl != LevelNone {
		t.Fatalf("built included without evidence: %v %v", lvl, err)
	} else if n, _ := AsNamed(err); n == nil || n.Code() != CodeIncludedUnavailable {
		t.Fatalf("%v", err)
	}
}
