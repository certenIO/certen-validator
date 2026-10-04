// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB5-F15 x RB5-F57: a member of a v4 chain has a v4 batch leaf, which binds its window [notBefore, deadline]. Its outcome
// evidence states the version and the window, and the offline verifier recomputes the leaf as that version and no other.

const synthNotBefore = 1_789_990_000

// asV4 re-forms the synthetic member's batch leaf as v4 with the window [synthNotBefore, its deadline].
func (m *synthMember) asV4(t *testing.T) *synthMember {
	t.Helper()
	calls, err := memberLegCalls(m.ev.Legs)
	if err != nil {
		t.Fatal(err)
	}
	m.leaf.BatchLeaf = ComputeBatchLeafV4(m.chainID, BatchLeafInput{ADIURL: m.ev.ADIURL,
		ExecutionCommitment: memberExecutionCommitment(m.chainID, calls), OperationID: m.leaf.OperationID,
		AuthorityBook: common.HexToHash(m.ev.AuthorityBook), AuthorityPage: m.ev.AuthorityPage,
		NotBefore: synthNotBefore, NotAfter: uint64(m.ev.Deadline)})
	m.anchor.batchRoot = m.leaf.BatchLeaf
	m.ev.LeafVersion, m.ev.NotBefore = AccountLeafV4, synthNotBefore
	return m
}

func TestAV4MembersOutcomeVerifiesAsV4AndNoOtherVersion(t *testing.T) {
	event := outcomeTreeEvent{Contract: common.HexToAddress("0x00000000000000000000000000000000000000aa"), Topic0: common.Hash{0xe1},
		DataHash: crypto.Keccak256Hash([]byte("paid"))}
	emitted := &types.Log{Address: event.Contract, Topics: []common.Hash{event.Topic0}, Data: []byte("paid")}
	committed := CommittedEffectsHash([][]ExpectedEvent{{{Contract: event.Contract, Topic0: event.Topic0, DataHash: event.DataHash}}}, nil)
	executed := func(t *testing.T, edit func(m *synthMember)) error {
		m := newSynthMember(t, []outcomeTreeEvent{event}).asV4(t)
		m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
			[]*types.Log{m.consumedLog(m.anchor.bundleID), emitted}), OutcomeExecuted, committed)
		edit(m)
		return m.verify()
	}
	cases := []struct {
		name string
		run  func(t *testing.T) error
		want string // "" = verifies
	}{
		{"v4, executed", func(t *testing.T) error { return executed(t, func(*synthMember) {}) }, ""},
		{"v4, not settled at the first block past the deadline", func(t *testing.T) error {
			return stateNotSettled(t, newSynthMember(t, nil).asV4(t), 1_790_000_100, 1_790_000_130, nil)
		}, ""},
		{"a v4 leaf stated as v3", func(t *testing.T) error {
			return executed(t, func(m *synthMember) { m.ev.LeafVersion, m.ev.NotBefore = "", 0 })
		}, "as v3, the outcome leaf names"},
		{"a v4 leaf with another notBefore", func(t *testing.T) error {
			return executed(t, func(m *synthMember) { m.ev.NotBefore++ })
		}, "as v4, the outcome leaf names"},
		{"a v4 leaf with another deadline", func(t *testing.T) error {
			return executed(t, func(m *synthMember) { m.ev.Deadline++ })
		}, "as v4, the outcome leaf names"},
		{"a v4 leaf stating no notBefore", func(t *testing.T) error {
			return executed(t, func(m *synthMember) { m.ev.NotBefore = 0 })
		}, "states no notBefore"},
		{"a v3 leaf stating a notBefore", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			m.ev.NotBefore = synthNotBefore
			return stateNotSettled(t, m, 1_790_000_100, 1_790_000_130, nil)
		}, "a v3 leaf binds no window"},
		{"an unknown leaf version", func(t *testing.T) error {
			return executed(t, func(m *synthMember) { m.ev.LeafVersion = "v5" })
		}, "leaf version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("consistent evidence refused: %v", err)
			case c.want != "" && (!errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("want a failure naming %q, got %v", c.want, err)
			}
		})
	}
}

// headerSource serves the claim block and its parent, which is all a not-settled member's evidence reads.
type headerSource struct {
	OutcomeEvidenceSource
	headers map[uint64]*types.Header
}

func (s headerSource) HeaderAt(_ context.Context, n uint64) (*types.Header, error) {
	if h, ok := s.headers[n]; ok {
		return h, nil
	}
	return nil, errors.New("no such header")
}

func TestTheEvidenceOfAV4TreesMemberStatesItsVersionAndWindowAndVerifies(t *testing.T) {
	m := newSynthMember(t, nil).asV4(t)
	parent := &types.Header{Number: big.NewInt(199), Time: 1_790_000_100, Difficulty: big.NewInt(0)}
	claim := &types.Header{ParentHash: parent.Hash(), Number: big.NewInt(200), Time: 1_790_000_130, Difficulty: big.NewInt(0),
		ReceiptHash: common.Hash{0xcc}}
	m.leaf.Status, m.leaf.BlockNumber, m.leaf.BlockHash, m.leaf.ReceiptsRoot = OutcomeNotSettled, 200, claim.Hash(), claim.ReceiptHash
	member := OutcomeTreeMember{LeafIndex: 0, Leaf: m.leaf.BatchLeaf, OperationID: m.leaf.OperationID, ADIURL: m.ev.ADIURL,
		Account: common.HexToAddress(m.ev.Account), AuthorityBook: common.HexToHash(m.ev.AuthorityBook), AuthorityPage: m.ev.AuthorityPage,
		Legs: m.ev.Legs, Deadline: m.ev.Deadline, NotBefore: synthNotBefore}
	src := headerSource{headers: map[uint64]*types.Header{199: parent, 200: claim}}

	ev, err := buildMemberEvidence(context.Background(), src, keptLeafVersion(AccountLeafV4), member, m.leaf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.LeafVersion != AccountLeafV4 || ev.NotBefore != synthNotBefore {
		t.Fatalf("the evidence states leaf version %q and notBefore %d, want v4 and %d", ev.LeafVersion, ev.NotBefore, synthNotBefore)
	}
	m.ev = ev
	if err := m.verify(); err != nil {
		t.Fatalf("the built evidence of a v4 member does not verify offline: %v", err)
	}

	// A v3 tree's member states neither, so every evidence built before RB5-F57 stays byte-identical.
	v3 := newSynthMember(t, nil)
	v3.leaf.Status, v3.leaf.BlockNumber, v3.leaf.BlockHash, v3.leaf.ReceiptsRoot = OutcomeNotSettled, 200, claim.Hash(), claim.ReceiptHash
	member.Leaf, member.NotBefore = v3.leaf.BatchLeaf, 0
	ev, err = buildMemberEvidence(context.Background(), src, keptLeafVersion(AccountLeafV3), member, v3.leaf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.LeafVersion != "" || ev.NotBefore != 0 {
		t.Fatalf("a v3 member's evidence states leaf version %q and notBefore %d, want neither", ev.LeafVersion, ev.NotBefore)
	}
	v3.ev = ev
	if err := v3.verify(); err != nil {
		t.Fatalf("the built evidence of a v3 member does not verify offline: %v", err)
	}
}
