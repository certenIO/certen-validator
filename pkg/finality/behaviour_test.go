// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// ---- D1: a container about another block of the same height, or another chain, is refused even when a kind would accept it ----

func TestAContainerForAnotherBlockHashIsRefusedEvenWhenTheKindWouldVerifyIt(t *testing.T) {
	b := testBase()
	other := b
	other.Hash = fill(0x99) // same chain, same number, another block
	r, _, fin := baseRegistry(t, nil, nil)
	a := Addendum{ProofID: testProofID, Seq: 1, Level: LevelFinalized, Chain: b.Chain, Kind: kBaseFin, Evidence: containerFor(t, kBaseFin, other, LevelFinalized, "x")}
	a.OwnHash = OwnHash(LegBindingOf(b), a)
	rep := r.VerifyLeg(b, b, []Addendum{a}, nil)
	st := rep.Levels[LevelFinalized]
	if st.Status != StatusRefused || st.State.Code != CodeBlockMismatch || st.State.Fields["field"] != "blockHash" ||
		st.State.Fields["want"] != b.Hash || st.State.Fields["got"] != other.Hash {
		t.Fatalf("%+v %v", st, st.State)
	}
	if fin.calls != 0 {
		t.Fatal("the kind was asked to verify evidence about another block")
	}
	if rep.Headline != LevelIncluded {
		t.Fatalf("headline %s", rep.Headline)
	}
}

func TestAnAddendumAndContainerBothCarryingAnotherChainAreRefusedForThisLeg(t *testing.T) {
	b := testBase()
	r, _, _ := baseRegistry(t, nil, nil)
	arb := &fakeKind{chain: ChainArbitrumSepolia, name: "arb-sepolia/finalized/v1", level: LevelFinalized}
	if err := r.RegisterKind(arb); err != nil {
		t.Fatal(err)
	}
	about := BlockRef{Chain: ChainArbitrumSepolia, Number: b.Number, Hash: b.Hash}
	a := Addendum{ProofID: testProofID, Seq: 1, Level: LevelFinalized, Chain: ChainArbitrumSepolia, Kind: arb.name,
		Evidence: containerFor(t, arb.name, about, LevelFinalized, "x")}
	a.OwnHash = OwnHash(LegBindingOf(b), a) // the hash chain and the table row are consistent for 421614
	rep := r.VerifyLeg(b, b, []Addendum{a}, nil)
	st := rep.Levels[LevelFinalized]
	if st.Status != StatusRefused || st.State.Code != CodeBlockMismatch || st.State.Fields["field"] != "chain" ||
		st.State.Fields["want"] != ChainBaseSepolia || st.State.Fields["got"] != ChainArbitrumSepolia {
		t.Fatalf("%+v %v", st, st.State)
	}
	if arb.calls != 0 {
		t.Fatal("the other chain's kind was asked to verify a leg of this chain")
	}
}

// ---- R6: finalized_block is never silently omitted ----

func TestAVerifiedFinalizedLegWhoseHeaderCannotBeReadRaisesANamedState(t *testing.T) {
	r, _, _ := baseRegistry(t, nil, nil)
	b := testBase() // no header
	rep := r.VerifyLeg(b, b, buildChain(t, b, LevelFinalized), nil)
	if rep.Levels[LevelFinalized].Status != StatusVerified || rep.FinalizedBlock != nil || rep.FinalizedBlockState == nil {
		t.Fatalf("%+v", rep)
	}
	if s := rep.FinalizedBlockState; s.Code != CodeFinalizedBlockUnavailable || s.Fields["reason"] != FinalizedBlockNoHeader ||
		s.Fields["chain"] != b.Chain || s.Fields["number"] != b.Number {
		t.Fatalf("%v", s)
	}

	// a header whose item 3 is an RLP list: it hashes to the block hash, but its state root cannot be read
	items := [][]byte{}
	for i := 0; i < 17; i++ {
		switch i {
		case 0, 4, 5, 16:
			h := fill(byte(0x40 + i))
			items = append(items, h[:])
		case 3:
			items = append(items, nil)
		case 8:
			items = append(items, []byte{0x2a})
		case 11:
			items = append(items, []byte{0x01, 0x02})
		default:
			items = append(items, []byte{byte(i)})
		}
	}
	raw := rlpList(items)
	// replace item 3 (an empty string, 0x80) by an empty RLP list (0xc0)
	pos := 2 // the long-list header: 0xf8 and one length byte
	for i := 0; i < 3; i++ {
		it := items[i]
		if len(it) == 1 && it[0] < 0x80 {
			pos++
		} else {
			pos += 1 + len(it)
		}
	}
	raw[pos] = 0xc0
	bad := BlockRef{Chain: ChainBaseSepolia, Number: 0x2a, Hash: [32]byte(crypto.Keccak256Hash(raw)), HeaderRLP: raw}
	rep = r.VerifyLeg(bad, bad, buildChain(t, bad, LevelFinalized), nil)
	if rep.Levels[LevelFinalized].Status != StatusVerified || rep.FinalizedBlock != nil || rep.FinalizedBlockState == nil {
		t.Fatalf("%+v", rep)
	}
	if s := rep.FinalizedBlockState; s.Fields["reason"] != FinalizedBlockHeaderUnreadable || s.Fields["index"] != uint64(3) {
		t.Fatalf("%v", s)
	}
}

// ---- D7 and the chains without a prover ----

// The upgrader's D0 comes from DeriveIncluded of the verified settlement. A leg source whose stored Subject names another
// block than the L6 evidence proves cannot move the binding: the chain is appended under, and verifies against, the proven block.
func TestUpgraderDerivesD0FromTheVerifiedSettlementNotFromTheSourcesSubject(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	st := f.src.settlements[legID]
	proven, err := DeriveIncluded(ChainBaseSepolia, st.Included)
	if err != nil {
		t.Fatal(err)
	}
	st.Subject.BlockNumber += 7
	st.Subject.BlockHash = fill(0xee)
	f.src.settlements[legID] = st
	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 2 || rep.Failed != 0 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	chain, _ := f.store.Chain(context.Background(), legID)
	if err := VerifyChain(LegBindingOf(proven), chain); err != nil {
		t.Fatalf("the chain is not bound to the proven block: %v", err)
	}
	lie := LegBinding(ChainBaseSepolia, st.Subject.BlockNumber, st.Subject.BlockHash)
	if VerifyChain(lie, chain) == nil {
		t.Fatal("the chain verifies under the source's Subject")
	}
}

type loadCounting struct {
	*memSource
	loads atomic.Int64
}

func (s *loadCounting) LegSettlement(ctx context.Context, ref LegRef) (Settlement, error) {
	s.loads.Add(1)
	return s.memSource.LegSettlement(ctx, ref)
}

func TestUpgraderDoesNotReloadOrVerifyTheLegsOfAChainWithNoRegisteredProver(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	src := &loadCounting{memSource: f.src}
	u, err := NewUpgrader(src, f.store, f.reg, nil, UpgraderConfig{Logf: f.logs.Logf, Now: f.clock.Now, Recorder: f.rec, PendingRetry: 1})
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 3; pass++ {
		f.clock.Advance(10_000_000_000)
		rep := u.RunOnce(context.Background())
		if rep.NoProver != 1 || rep.Attempts != 0 || rep.Unusable != 0 || rep.Failed != 0 {
			t.Fatalf("pass %d: %+v", pass, rep)
		}
	}
	if src.loads.Load() != 0 {
		t.Fatalf("the L6 evidence of a chain with no prover was loaded %d times", src.loads.Load())
	}
	if n := strings_count(f.logs.Joined(), "has no registered prover"); n != 1 {
		t.Fatalf("announced %d times, want once per chain:\n%s", n, f.logs.Joined())
	}
}

func strings_count(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
