package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB5 D4 §1b: each member's outcome leaf, derived from the chain alone - and "not yet" whenever the chain has not
// decided, never a guess.

// fakeOutcomeChain is a chain whose block n is at time base+12n, finalized up to fin.
type fakeOutcomeChain struct {
	chainID     int64
	base        uint64
	fin         uint64
	forked      map[uint64]bool // heights whose canonical block is not the one a consumption names
	consumed    map[[32]byte]*LeafConsumption
	asOf        uint64
	executions  map[common.Hash]fakeExecution
	attempts    map[common.Hash]*ExternalChainResult
	notAttempts map[common.Hash]bool
	readFails   bool
}

type fakeExecution struct {
	missing, unset []CommittedEffect
	err            error
}

func (f *fakeOutcomeChain) header(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: f.base + 12*n, Difficulty: big.NewInt(0),
		ReceiptHash: crypto.Keccak256Hash([]byte(fmt.Sprintf("receipts-%d", n)))}
}

func (f *fakeOutcomeChain) ChainID() int64 { return f.chainID }
func (f *fakeOutcomeChain) FinalizedHeader(context.Context) (*types.Header, error) {
	if f.readFails {
		return nil, readErr(errors.New("provider down"))
	}
	return f.header(f.fin), nil
}
func (f *fakeOutcomeChain) HeaderAt(_ context.Context, n uint64) (*types.Header, error) {
	if n > f.fin+100 {
		return nil, fmt.Errorf("no block %d", n)
	}
	return f.header(n), nil
}
func (f *fakeOutcomeChain) LeafConsumption(_ context.Context, _ common.Address, leaf [32]byte, _ time.Time) (*LeafConsumption, uint64, error) {
	if c := f.consumed[leaf]; c != nil {
		return c, f.asOf, nil
	}
	return nil, f.asOf, nil
}
func (f *fakeOutcomeChain) MemberExecution(_ context.Context, tx common.Hash, _ []CommittedLeg, _ [32]byte, _ common.Address) (*ExternalChainResult, []CommittedEffect, []CommittedEffect, error) {
	e := f.executions[tx]
	if e.err != nil {
		return nil, nil, nil, e.err
	}
	for _, c := range f.consumed {
		if c.Tx == tx {
			return &ExternalChainResult{TxHash: tx, BlockNumber: new(big.Int).SetUint64(c.Block), BlockHash: c.BlockHash, Status: 1}, e.missing, e.unset, nil
		}
	}
	return nil, nil, nil, errors.New("no such execution")
}
func (f *fakeOutcomeChain) RevertedAttempt(_ context.Context, tx common.Hash, _ []CommittedLeg, _ [32]byte, _ common.Address) (*ExternalChainResult, error) {
	if f.notAttempts[tx] {
		return nil, fmt.Errorf("%w: %s did not revert", ErrNotAnAttempt, tx.Hex())
	}
	if r := f.attempts[tx]; r != nil {
		return r, nil
	}
	return nil, outcomeNotYet("%s is not final", tx.Hex())
}

// consumeAt records leaf consumed by tx under anchor in block n of the canonical chain.
func (f *fakeOutcomeChain) consumeAt(leaf, anchor [32]byte, tx common.Hash, n uint64) {
	f.consumed[leaf] = &LeafConsumption{Anchor: anchor, Tx: tx, Block: n, BlockHash: f.header(n).Hash()}
}

// derivationFixture is a two-member kept tree on Base Sepolia and a chain whose block 1000 is the first member's deadline.
func derivationFixture(t *testing.T) (*OutcomeTree, *fakeOutcomeChain) {
	t.Helper()
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	a := outcomeTestMember(t, 84532, "alpha", f77CallLeg(84532, true))
	b := outcomeTestMember(t, 84532, "beta", f77NativeLeg(84532, "7"))
	tree, byOp := outcomeTestTree(t, 84532, a, b)
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	deadline := uint64(kept.Members[0].Deadline)
	return kept, &fakeOutcomeChain{chainID: 84532, base: deadline - 12*1000, fin: 2000, asOf: 2010,
		consumed: map[[32]byte]*LeafConsumption{}, executions: map[common.Hash]fakeExecution{},
		attempts: map[common.Hash]*ExternalChainResult{}, notAttempts: map[common.Hash]bool{}}
}

func TestAnExecutedMemberIsStatusOneWithItsCommittedEffects(t *testing.T) {
	kept, f := derivationFixture(t)
	settle := common.HexToHash("0x5e771e")
	f.consumeAt(kept.Members[0].Leaf, kept.BundleID, settle, 900)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	out, err := DeriveOutcome(context.Background(), f, kept, nil)
	if err != nil {
		t.Fatal(err)
	}
	l := out.Leaves[0]
	legs := kept.Members[0].CommittedLegs()
	want := CommittedEffectsHash(legEvents(legs), legState(legs))
	if l.Status != OutcomeExecuted || l.Tx != settle || l.BlockNumber != 900 || l.BlockHash != f.header(900).Hash() ||
		l.ReceiptsRoot != f.header(900).ReceiptHash || l.EffectsHash != want || want == ([32]byte{}) {
		t.Fatalf("leaf %+v", l)
	}
	// A native transfer committed no effect: executed, effects hash zero.
	if out.Leaves[1].Status != OutcomeExecuted || out.Leaves[1].EffectsHash != ([32]byte{}) {
		t.Fatalf("native member %+v", out.Leaves[1])
	}
	if root, _ := OutcomeRoot(out.Leaves, 2); root != out.Root || out.ResolvedAt.Unix() != int64(f.header(901).Time) {
		t.Fatalf("root %x resolved %v", out.Root, out.ResolvedAt)
	}
}

func TestAnExecutionWithAnAbsentEffectIsStatusTwo(t *testing.T) {
	kept, f := derivationFixture(t)
	settle := common.HexToHash("0x5e771e")
	f.consumeAt(kept.Members[0].Leaf, kept.BundleID, settle, 900)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	f.executions[settle] = fakeExecution{missing: []CommittedEffect{{Leg: 0, Index: 0}}}
	out, err := DeriveOutcome(context.Background(), f, kept, nil)
	if err != nil {
		t.Fatal(err)
	}
	legs := kept.Members[0].CommittedLegs()
	want, _ := ShortfallEffectsHash(CommittedEffectsHash(legEvents(legs), legState(legs)), []CommittedEffect{{Leg: 0, Index: 0}}, nil)
	if l := out.Leaves[0]; l.Status != OutcomeEffectsNotProven || l.EffectsHash != want {
		t.Fatalf("leaf %+v", l)
	}
}

func TestALeafConsumedUnderAnotherAnchorIsStatusFour(t *testing.T) {
	kept, f := derivationFixture(t)
	other := common.HexToHash("0x0a0a")
	f.consumeAt(kept.Members[0].Leaf, other, common.HexToHash("0xe15e"), 800)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	out, err := DeriveOutcome(context.Background(), f, kept, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l := out.Leaves[0]; l.Status != OutcomeConsumedElsewhere || l.Tx != common.HexToHash("0xe15e") || l.BlockNumber != 800 || l.EffectsHash != ([32]byte{}) {
		t.Fatalf("leaf %+v", l)
	}
}

func TestAnUnconsumedMemberPastItsDeadlineIsStatusThreeAtTheFirstBlockPastIt(t *testing.T) {
	kept, f := derivationFixture(t)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	// Two reverted attempts and a transaction that is not one: the later attempt is named.
	early, late, stray := common.HexToHash("0xa1"), common.HexToHash("0xa2"), common.HexToHash("0xa3")
	f.attempts[early] = &ExternalChainResult{TxHash: early, BlockNumber: big.NewInt(950), TxIndex: 3}
	f.attempts[late] = &ExternalChainResult{TxHash: late, BlockNumber: big.NewInt(960), TxIndex: 0}
	f.notAttempts[stray] = true
	op := kept.Members[0].OperationID
	out, err := DeriveOutcome(context.Background(), f, kept, map[[32]byte][]common.Hash{op: {stray, late, early, late}})
	if err != nil {
		t.Fatal(err)
	}
	// The deadline is block 1000's time; the horizon 120 s (ten blocks) later; the first block past it is 1011.
	l := out.Leaves[0]
	if l.Status != OutcomeNotSettled || l.BlockNumber != 1011 || l.BlockHash != f.header(1011).Hash() || l.Tx != late ||
		l.EffectsHash != ([32]byte{}) {
		t.Fatalf("leaf %+v", l)
	}
	if len(out.Attempts[op]) != 3 {
		t.Fatalf("attempts considered %v", out.Attempts[op])
	}
	// No attempt known: the leaf names no transaction.
	out, err = DeriveOutcome(context.Background(), f, kept, nil)
	if err != nil || out.Leaves[0].Tx != (common.Hash{}) || out.Leaves[0].BlockNumber != 1011 {
		t.Fatalf("(%+v, %v)", out.Leaves[0], err)
	}
}

func TestAMemberTheChainHasNotDecidedIsNotYetNeverAGuess(t *testing.T) {
	for name, set := range map[string]func(*OutcomeTree, *fakeOutcomeChain){
		// Reverted alone is not final: before the deadline the leaf is still spendable.
		"reverted, deadline not passed": func(k *OutcomeTree, f *fakeOutcomeChain) {
			f.fin = 1005
			f.attempts[common.HexToHash("0xa1")] = &ExternalChainResult{BlockNumber: big.NewInt(950)}
		},
		"consumed in a block not final yet": func(k *OutcomeTree, f *fakeOutcomeChain) {
			f.consumeAt(k.Members[0].Leaf, k.BundleID, common.HexToHash("0x5e771e"), 2050)
		},
		"consumed in a block the finalized chain replaced": func(k *OutcomeTree, f *fakeOutcomeChain) {
			f.consumed[k.Members[0].Leaf] = &LeafConsumption{Anchor: k.BundleID, Tx: common.HexToHash("0x5e771e"), Block: 900,
				BlockHash: common.HexToHash("0xf0f0")}
		},
		"unconsumed only as of a block before the claim": func(k *OutcomeTree, f *fakeOutcomeChain) { f.asOf = 1005 },
		"an attempt not final yet":                       func(k *OutcomeTree, f *fakeOutcomeChain) {},
		"the providers cannot be read":                   func(k *OutcomeTree, f *fakeOutcomeChain) { f.readFails = true },
	} {
		t.Run(name, func(t *testing.T) {
			kept, f := derivationFixture(t)
			f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
			set(kept, f)
			hints := map[[32]byte][]common.Hash{}
			if name == "an attempt not final yet" {
				hints[kept.Members[0].OperationID] = []common.Hash{common.HexToHash("0xa9")}
			}
			out, err := DeriveOutcome(context.Background(), f, kept, hints)
			if err == nil || !IsOutcomeRetryable(err) {
				t.Fatalf("stated %+v (%v); want a retryable not-yet", out, err)
			}
		})
	}
}

func TestAConsumptionUnderThisAnchorThatIsNotTheMembersExecutionIsNamedNotStated(t *testing.T) {
	kept, f := derivationFixture(t)
	settle := common.HexToHash("0x5e771e")
	f.consumeAt(kept.Members[0].Leaf, kept.BundleID, settle, 900)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	f.executions[settle] = fakeExecution{err: errors.New("settlement executed calls the intent did not commit")}
	_, err := DeriveOutcome(context.Background(), f, kept, nil)
	if err == nil || IsOutcomeRetryable(err) || !strings.Contains(err.Error(), "not established as its execution") {
		t.Fatalf("a contradiction: %v", err)
	}
}

func TestDerivationRefusesAnotherChainsReader(t *testing.T) {
	kept, f := derivationFixture(t)
	f.chainID = 1
	if _, err := DeriveOutcome(context.Background(), f, kept, nil); err == nil {
		t.Fatal("a reader of another chain derived an outcome")
	}
}
