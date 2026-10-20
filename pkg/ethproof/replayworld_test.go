// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// The synthetic chain of the S6 replay-guard tests is built by pkg/ethproof/replayworld (shared with the conformance-
// vector generator cmd/s6replayvectors); this file keeps the tests' vocabulary over it.

type account struct {
	addr    common.Address
	code    []byte
	storage map[common.Hash]*big.Int
}

// state is a built state trie: its root, and the means to prove any account and slot against it.
type state struct {
	t    *testing.T
	root common.Hash
	st   *replayworld.State
}

func buildState(t *testing.T, accts ...account) *state {
	t.Helper()
	in := make([]replayworld.Account, len(accts))
	for i, a := range accts {
		in[i] = replayworld.Account{Addr: a.addr, Code: a.code, Storage: a.storage}
	}
	st := replayworld.BuildState(t, in...)
	return &state{t: t, root: st.Root, st: st}
}

// prove is eth_getProof for one slot, as a SlotProof.
func (s *state) prove(addr common.Address, slot common.Hash) ethproof.SlotProof {
	s.t.Helper()
	return s.st.Prove(addr, slot)
}

var (
	testContract = replayworld.Contract
	testOther    = replayworld.Other
	testCode     = replayworld.Code
	testAnchor   = replayworld.Anchor
	testLeaf     = replayworld.Leaf
	testOpID     = replayworld.OpID
	v73Execute   = replayworld.V73Execute
	v73Batch     = replayworld.V73Batch
)

const testChainID = replayworld.ChainID
const testN = replayworld.N

// world is one settlement and the chain around it.
type world struct {
	t          *testing.T
	contract   common.Address
	leaf, slot common.Hash
	settlement *ethproof.Settlement
	headerN    *types.Header
	parent     *types.Header
	tx         *types.Transaction
	receipt    *types.Receipt
	chain      []*types.Header // N+1 .. H
	before     *state
	after      *state
	proof      *ethproof.ReplayGuardProof
}

type worldOpts struct {
	after       int // headers after the settlement block
	selector    []byte
	to          *common.Address // the transaction's target (default the contract)
	eventFrom   *common.Address // the LeafConsumed emitter (default the contract)
	reverted    bool            // the receipt is status 0
	noBeforeAcc bool            // the contract is not yet in the parent's state
}

func newWorld(t *testing.T, o worldOpts) *world {
	t.Helper()
	rw := replayworld.New(t, replayworld.Opts{After: o.after, Selector: o.selector, To: o.to, EventFrom: o.eventFrom,
		Reverted: o.reverted, NoBeforeAcc: o.noBeforeAcc})
	return &world{t: t, contract: rw.Contract, leaf: rw.Leaf, slot: rw.Slot, settlement: rw.Settlement, headerN: rw.HeaderN,
		parent: rw.Parent, tx: rw.Tx, receipt: rw.Receipt, chain: rw.Chain,
		before: &state{t: t, root: rw.Before.Root, st: rw.Before}, after: &state{t: t, root: rw.After.Root, st: rw.After},
		proof: rw.Proof}
}

func rawHeader(t *testing.T, h *types.Header) hexutil.Bytes {
	t.Helper()
	return replayworld.RawHeader(t, h)
}

func (w *world) buildProof(top *types.Header) *ethproof.ReplayGuardProof {
	p := &ethproof.ReplayGuardProof{
		Version: ethproof.ReplayGuardDomain, ChainID: testChainID, Generation: ethproof.AccountGenerationV7_3, Contract: w.contract,
		Slot:            ethproof.ReplaySlot{Key: w.leaf, Base: 4, Derivation: ethproof.ReplayDerivation, Slot: w.slot},
		SettlementBlock: ethproof.BlockRef{Number: testN, Hash: w.headerN.Hash()},
		ProvenAt:        ethproof.BlockRef{Number: top.Number.Uint64(), Hash: top.Hash()},
		Headers:         []hexutil.Bytes{},
		After:           w.after.prove(w.contract, w.slot),
		Before:          &ethproof.ReplayBefore{ParentHeader: rawHeader(w.t, w.parent), Proof: w.before.prove(w.contract, w.slot)},
	}
	for _, h := range w.chain {
		p.Headers = append(p.Headers, rawHeader(w.t, h))
	}
	return p
}

// clone is a deep copy of the proof, through its JSON.
func (w *world) clone() *ethproof.ReplayGuardProof {
	w.t.Helper()
	enc, err := json.Marshal(w.proof)
	if err != nil {
		w.t.Fatal(err)
	}
	var out ethproof.ReplayGuardProof
	if err := json.Unmarshal(enc, &out); err != nil {
		w.t.Fatal(err)
	}
	return &out
}

// refusedAs requires err to be the named refusal.
func refusedAs(t *testing.T, what string, err error, state, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: verified, but must be refused as %s{%s}", what, state, reason)
	}
	var re *ethproof.ReplayError
	if !asReplayError(err, &re) {
		t.Fatalf("%s: refused, but not by a named state: %v", what, err)
	}
	if re.State != state || re.Reason != reason {
		t.Fatalf("%s: refused as %s{%s}, want %s{%s}: %s", what, re.State, re.Reason, state, reason, re.Detail)
	}
}

func asReplayError(err error, target **ethproof.ReplayError) bool { return errors.As(err, target) }
