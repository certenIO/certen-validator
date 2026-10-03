package execution

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB5 D4: the outcome leaf and root, pinned to values computed independently with Foundry's own ABI encoder
// (`cast abi-encode` + `cast keccak`, RUNLOG_RB5 2026-10-03). The same vectors are in certen-contracts
// test/vectors/outcome_leaf_test_vectors.json and asserted by the Solidity library's test. Never update one side only.

func ovh(s string) [32]byte { return common.HexToHash(s) }

func vectorLeaves() []OutcomeLeaf {
	bundle := ovh("0x1111111111111111111111111111111111111111111111111111111111111111")
	committed := CommittedEffectsHash(
		[][]ExpectedEvent{{{Contract: common.HexToAddress("0xc000000000000000000000000000000000000001"),
			Topic0: ovh("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), DataHash: ovh("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}}},
		[][]ExpectedStateSlot{{{Account: common.HexToAddress("0xc000000000000000000000000000000000000002"),
			Slot: ovh("0x01"), Value: ovh("0x02")}}})
	shortfall, err := ShortfallEffectsHash(committed, []CommittedEffect{{Leg: 0, Index: 0}}, nil)
	if err != nil {
		panic(err)
	}
	mk := func(i uint64, p byte, status OutcomeStatus, tx [32]byte, block uint64, effects [32]byte) OutcomeLeaf {
		return OutcomeLeaf{ChainID: 84532, BundleID: bundle, LeafIndex: i, BatchLeaf: [32]byte{p | 0x0a}, OperationID: [32]byte{p | 0x0b},
			Status: status, Tx: tx, BlockNumber: block, BlockHash: [32]byte{p | 0x0d}, ReceiptsRoot: [32]byte{p | 0x0e}, EffectsHash: effects}
	}
	return []OutcomeLeaf{
		mk(0, 0x00, OutcomeExecuted, [32]byte{0x0c}, 100, committed),
		mk(1, 0x10, OutcomeEffectsNotProven, [32]byte{0x1c}, 101, shortfall),
		mk(2, 0x20, OutcomeNotSettled, [32]byte{}, 102, [32]byte{}),
		mk(3, 0x30, OutcomeConsumedElsewhere, [32]byte{0x3c}, 103, [32]byte{}),
	}
}

func TestOutcomeLeafVectors(t *testing.T) {
	ls := vectorLeaves()
	if got, want := ls[0].EffectsHash, ovh("0x04a20a3498336ae43074df4a22e2e00bd0e1143a2563adef5f51a2defa62035b"); got != want {
		t.Fatalf("committed-effects hash %s, cast says %s", outcomeHex(got), outcomeHex(want))
	}
	if got, want := ls[1].EffectsHash, ovh("0x455a1200c07bd851875997e953872354daea27f1ff22f504e3335ea71a60a0d8"); got != want {
		t.Fatalf("shortfall hash %s, cast says %s", outcomeHex(got), outcomeHex(want))
	}
	for i, want := range []string{
		"0x74a65b700412236f23294849ede4681625e3db2b166d96fb7ba7aaf61e3fc7d4",
		"0x26a085f04cf89661e2c49d0436545015a8b8a90a5c0ac9be8e66621bdb10e724",
		"0x53d8d588ef033084f06665a367a3771d791ad69610537c9693eab743b5320343",
		"0x5e728fa44356afcf59e9ebe173404a7d6683121bf749b617061385be26215c37",
	} {
		got, err := ls[i].Hash()
		if err != nil || got != ovh(want) {
			t.Fatalf("leaf %d = %s (%v), cast says %s", i, outcomeHex(got), err, want)
		}
	}
	if root, err := OutcomeRoot(ls, 4); err != nil || root != ovh("0x9150ba00b9daf1a60239c12dd34c814ded3fec2fa7596b736c68a1e2615c2224") {
		t.Fatalf("4-leaf root %s (%v)", outcomeHex(root), err)
	}
	if root, err := OutcomeRoot(ls[:3], 3); err != nil || root != ovh("0x052c9ade200c11fa5983d7bd0e260d3dc1e0852e8ec16c8ba5c40fd4d627e15a") {
		t.Fatalf("3-leaf root (odd promotion) %s (%v)", outcomeHex(root), err)
	}
}

func TestAnOutcomeIsRefusedWhenItDoesNotStateEveryMemberExactly(t *testing.T) {
	ls := vectorLeaves()
	for name, c := range map[string]struct {
		leaves []OutcomeLeaf
		count  uint64
	}{
		"a member missing":     {ls[:3], 4},
		"a member too many":    {ls, 3},
		"out of tree order":    {[]OutcomeLeaf{ls[1], ls[0], ls[2], ls[3]}, 4},
		"another anchor mixed": {func() []OutcomeLeaf { x := append([]OutcomeLeaf(nil), ls...); x[2].BundleID = [32]byte{9}; return x }(), 4},
	} {
		if _, err := OutcomeRoot(c.leaves, c.count); !errors.Is(err, ErrOutcome) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*OutcomeLeaf){
		"executed without its tx":       func(l *OutcomeLeaf) { l.Tx = [32]byte{} },
		"no finalized block":            func(l *OutcomeLeaf) { l.BlockHash = [32]byte{} },
		"an unknown status":             func(l *OutcomeLeaf) { l.Status = 9 },
		"not settled with effects hash": func(l *OutcomeLeaf) { l.Status = OutcomeNotSettled; l.Tx = [32]byte{} },
	} {
		l := ls[0]
		mutate(&l)
		if _, err := l.Hash(); !errors.Is(err, ErrOutcome) {
			t.Fatalf("%s was hashed: %v", name, err)
		}
	}
	if _, err := ShortfallEffectsHash([32]byte{1}, nil, nil); !errors.Is(err, ErrOutcome) {
		t.Fatal("a shortfall naming no missing effect was hashed")
	}
	if _, err := ShortfallEffectsHash([32]byte{}, []CommittedEffect{{}}, nil); !errors.Is(err, ErrOutcome) {
		t.Fatal("a shortfall of a member that committed nothing was hashed")
	}
}
