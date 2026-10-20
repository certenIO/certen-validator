// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// RB10-B14b: the capture stores only the proof nodes the verification walk used. VerifyStorage keys every supplied node by
// its own hash and ignores the unused ones, so a provider can pad an eth_getProof answer (a 3 MiB node, thousands of small
// ones, duplicates, nodes of other trees, any order) and the padded proof still verifies; the capture used to copy the answer
// into the evidence wholesale. It now keeps the nodes the walk read, root to leaf, which is what an honest provider serves.

// b14bEditingProvider serves an eth_getProof answer whose account and storage node lists are rewritten by edit.
type b14bEditingProvider struct {
	*fakeProvider
	edit func(kind string, nodes [][]byte) [][]byte
}

func b14bBytes(in []hexutil.Bytes) [][]byte {
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

func b14bHex(in [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

func (p b14bEditingProvider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	raw, err := p.fakeProvider.GetProof(ctx, account, keys, block)
	if err != nil {
		return nil, err
	}
	var ans map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, err
	}
	var acct []hexutil.Bytes
	if err := json.Unmarshal(ans["accountProof"], &acct); err != nil {
		return nil, err
	}
	if ans["accountProof"], err = json.Marshal(b14bHex(p.edit("account", b14bBytes(acct)))); err != nil {
		return nil, err
	}
	var sto []map[string]json.RawMessage
	if err := json.Unmarshal(ans["storageProof"], &sto); err != nil {
		return nil, err
	}
	var nodes []hexutil.Bytes
	if err := json.Unmarshal(sto[0]["proof"], &nodes); err != nil {
		return nil, err
	}
	if sto[0]["proof"], err = json.Marshal(b14bHex(p.edit("storage", b14bBytes(nodes)))); err != nil {
		return nil, err
	}
	if ans["storageProof"], err = json.Marshal(sto); err != nil {
		return nil, err
	}
	return json.Marshal(ans)
}

type b14bEditedSource struct {
	*fakeChain
	edit func(kind string, nodes [][]byte) [][]byte
}

func (s b14bEditedSource) StateProviders() []ethproof.ReplayStateProvider {
	var out []ethproof.ReplayStateProvider
	for _, p := range s.fakeChain.providers {
		out = append(out, b14bEditingProvider{p, s.edit})
	}
	return out
}

// b14bForeign is every node of the proofs of the world's other slots and accounts, in the state before and after the
// settlement: valid nodes of the same trees (siblings of the path), and of trees with another root.
func b14bForeign(f *fakeChain) [][]byte {
	var out [][]byte
	for _, st := range []*state{f.w.before, f.w.after} {
		for _, q := range []struct {
			addr common.Address
			slot common.Hash
		}{
			{f.w.contract, f.w.slot},
			{f.w.contract, common.BigToHash(big.NewInt(3))},
			{f.w.contract, ethproof.ReplaySlotFor(replayworld.OtherLeaf, 4)},
			{testOther, f.w.slot},
		} {
			sp := st.prove(q.addr, q.slot)
			out = append(out, b14bBytes(sp.AccountProof)...)
			out = append(out, b14bBytes(sp.StorageProof)...)
		}
	}
	return out
}

func b14bSameNodes(a, b []hexutil.Bytes) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func b14bSameSlotProof(t *testing.T, what string, got, want ethproof.SlotProof) {
	t.Helper()
	if !b14bSameNodes(got.AccountProof, want.AccountProof) {
		t.Fatalf("%s: the account proof is %d nodes, want the %d the walk reads, in order", what, len(got.AccountProof), len(want.AccountProof))
	}
	if !b14bSameNodes(got.StorageProof, want.StorageProof) {
		t.Fatalf("%s: the storage proof is %d nodes, want the %d the walk reads, in order", what, len(got.StorageProof), len(want.StorageProof))
	}
	if got.AccountAbsent != want.AccountAbsent || got.StorageHash != want.StorageHash || got.CodeHash != want.CodeHash || got.Value != want.Value {
		t.Fatalf("%s: absent/storageHash/codeHash/value %v/%s/%s/%s, want %v/%s/%s/%s", what,
			got.AccountAbsent, got.StorageHash.Hex(), got.CodeHash.Hex(), got.Value.Hex(), want.AccountAbsent, want.StorageHash.Hex(), want.CodeHash.Hex(), want.Value.Hex())
	}
}

type b14bVariant struct {
	name string
	edit func(rng *rand.Rand, foreign [][]byte, kind string, honest [][]byte) [][]byte
}

func b14bSmallNodes(rng *rand.Rand, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		b := make([]byte, 40)
		rng.Read(b)
		out[i] = b
	}
	return out
}

func b14bShuffled(rng *rand.Rand, in [][]byte) [][]byte {
	out := append([][]byte(nil), in...)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

var b14bVariants = []b14bVariant{
	{"a 3 MiB node in the storage proof", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		if kind == "storage" {
			return append(append([][]byte(nil), h...), make([]byte, 3<<20))
		}
		return h
	}},
	{"a 3 MiB node in the account proof", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		if kind == "account" {
			return append(append([][]byte(nil), h...), make([]byte, 3<<20))
		}
		return h
	}},
	{"a 3 MiB node before the honest nodes", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		return append([][]byte{make([]byte, 3<<20)}, h...)
	}},
	{"20000 small extra nodes in each proof", func(rng *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		return append(append([][]byte(nil), h...), b14bSmallNodes(rng, 20000)...)
	}},
	{"every node served three times", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		var out [][]byte
		for k := 0; k < 3; k++ {
			out = append(out, h...)
		}
		return out
	}},
	{"each node twice in a row", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		var out [][]byte
		for _, n := range h {
			out = append(out, n, n)
		}
		return out
	}},
	{"the nodes in reversed order", func(_ *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		out := make([][]byte, len(h))
		for i, n := range h {
			out[len(h)-1-i] = n
		}
		return out
	}},
	{"the nodes in shuffled order", func(rng *rand.Rand, _ [][]byte, kind string, h [][]byte) [][]byte {
		return b14bShuffled(rng, h)
	}},
	{"nodes of other trees and of other paths of the same trees", func(_ *rand.Rand, foreign [][]byte, kind string, h [][]byte) [][]byte {
		return append(append([][]byte(nil), foreign...), h...)
	}},
	{"the other trees' nodes after the honest ones", func(_ *rand.Rand, foreign [][]byte, kind string, h [][]byte) [][]byte {
		return append(append([][]byte(nil), h...), foreign...)
	}},
	{"everything at once, shuffled", func(rng *rand.Rand, foreign [][]byte, kind string, h [][]byte) [][]byte {
		all := append(append(append([][]byte(nil), h...), h...), foreign...)
		all = append(all, b14bSmallNodes(rng, 3000)...)
		all = append(all, make([]byte, 3<<20))
		return b14bShuffled(rng, all)
	}},
}

func b14bBudgeted(f *fakeChain) ethproof.ReplayCaptureConfig {
	cfg := cfgFor(f)
	cfg.Budget, cfg.Poll = 30*time.Second, 5*time.Millisecond
	return cfg
}

// A provider answer padded with a 3 MiB node, thousands of small ones, duplicates, nodes of other trees, or served in any
// order is stored as the honest proof of the same slot: the nodes the verification walk reads, root to leaf, byte for
// byte; it is a proof (not a named state), under 1 MiB, and it verifies.
func TestB14b_APaddedOrReorderedProviderAnswerIsStoredAsTheHonestWalk(t *testing.T) {
	f := newChain(t, worldOpts{after: 2}, testN+2)
	f.add("windowed.example", testN-1, testN+2)
	tx := f.w.tx.Hash()
	wantAfter := f.w.after.prove(f.w.contract, f.w.slot)
	wantBefore := f.w.before.prove(f.w.contract, f.w.slot)
	if len(wantAfter.AccountProof) < 2 || len(wantAfter.StorageProof) < 2 || len(wantBefore.AccountProof) < 2 {
		t.Fatalf("the world's proofs are too short to tell an order (after: account %d, storage %d; before: account %d)", len(wantAfter.AccountProof), len(wantAfter.StorageProof), len(wantBefore.AccountProof))
	}
	honest := ethproof.CaptureReplayGuard(context.Background(), b14bBudgeted(f), tx)
	if honest == nil || honest.Proof == nil || honest.Proof.Before == nil {
		t.Fatalf("the honest capture is not a proof of both states: %+v", honest)
	}
	b14bSameSlotProof(t, "the honest After", honest.Proof.After, wantAfter)
	b14bSameSlotProof(t, "the honest Before", honest.Proof.Before.Proof, wantBefore)
	foreign := b14bForeign(f)

	for i, v := range b14bVariants {
		v, seed := v, int64(1400+i)
		t.Run(v.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			served := 0
			edit := func(kind string, nodes [][]byte) [][]byte {
				out := v.edit(rng, foreign, kind, nodes)
				served++
				return out
			}
			cfg := b14bBudgeted(f)
			cfg.Source = b14bEditedSource{f, edit}
			ev := ethproof.CaptureReplayGuard(context.Background(), cfg, tx)
			if served == 0 {
				t.Fatal("the editing provider was never asked")
			}
			if ev == nil || ev.Proof == nil || ev.State != nil {
				t.Fatalf("not a proof: %+v", ev)
			}
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) >= 1<<20 {
				t.Fatalf("the evidence is %d bytes, a proof of the honest nodes is a few KB", len(raw))
			}
			b14bSameSlotProof(t, "After", ev.Proof.After, wantAfter)
			if ev.Proof.Before == nil {
				t.Fatalf("no Before proof: %+v", ev.Proof.BeforeUnavailable)
			}
			b14bSameSlotProof(t, "Before", ev.Proof.Before.Proof, wantBefore)
			chk, err := ev.Verify(f.w.settlement)
			if err != nil || chk.State != ethproof.ReplayProven || !chk.BeforeVerified {
				t.Fatalf("the stored evidence does not verify to a proven guard with its Before: %v %+v", err, chk)
			}
			// What the store and the observers' entry points hold is the same.
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(cfg, store)
			cp.Begin(tx)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, tx); err != nil {
				t.Fatal(err)
			}
			got := cp.Resolve(f.w.settlement)
			if got == nil || got.Proof == nil {
				t.Fatalf("Resolve is not a proof: %+v", got)
			}
			b14bSameSlotProof(t, "Resolve After", got.Proof.After, wantAfter)
			if got.Proof.Before == nil {
				t.Fatal("Resolve holds no Before")
			}
			b14bSameSlotProof(t, "Resolve Before", got.Proof.Before.Proof, wantBefore)
		})
	}
}

// An exclusion proof (the contract is not yet in the parent's state) is pruned to the nodes of the walk too, and the
// storage proof of an absent account stays empty.
func TestB14b_AnExclusionProofIsPrunedAndStaysAnExclusionProof(t *testing.T) {
	f := newChain(t, worldOpts{after: 2, noBeforeAcc: true}, testN+2)
	f.add("windowed.example", testN-1, testN+2)
	tx := f.w.tx.Hash()
	wantBefore := f.w.before.prove(f.w.contract, f.w.slot)
	if !wantBefore.AccountAbsent || len(wantBefore.AccountProof) == 0 {
		t.Fatalf("the world's Before is not an exclusion proof: %+v", wantBefore)
	}
	foreign := b14bForeign(f)
	for i, v := range b14bVariants {
		v, seed := v, int64(1500+i)
		t.Run(v.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			edit := func(kind string, nodes [][]byte) [][]byte {
				if kind == "storage" {
					return nodes // the storage proof of an absent account is empty, and the verifier refuses anything in it
				}
				return v.edit(rng, foreign, kind, nodes)
			}
			cfg := b14bBudgeted(f)
			cfg.Source = b14bEditedSource{f, edit}
			ev := ethproof.CaptureReplayGuard(context.Background(), cfg, tx)
			if ev == nil || ev.Proof == nil || ev.Proof.Before == nil {
				t.Fatalf("not a proof with its Before: %+v", ev)
			}
			bp := ev.Proof.Before.Proof
			b14bSameSlotProof(t, "Before", bp, wantBefore)
			if !bp.AccountAbsent || len(bp.StorageProof) != 0 {
				t.Fatalf("the exclusion proof is %+v", bp)
			}
			if _, err := ev.Verify(f.w.settlement); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// What pruning cannot change: a proof the verifier refuses is still refused by name, with the provider and block, and a
// padded answer whose real nodes are missing is not repaired from the padding of another tree.
func TestB14b_APaddedAnswerWithoutTheRealNodesIsStillRefused(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("only-foreign.example", testN, testN)
	foreign := b14bForeign(f)
	// The honest storage nodes are dropped: only nodes of other paths remain, 3 MiB of padding beside them.
	honest := f.w.after.prove(f.w.contract, f.w.slot)
	real := map[string]bool{}
	for _, n := range honest.StorageProof {
		real[string(n)] = true
	}
	var others [][]byte
	for _, n := range foreign {
		if !real[string(n)] {
			others = append(others, n)
		}
	}
	cfg := b14bBudgeted(f)
	cfg.Budget = 200 * time.Millisecond
	cfg.Source = b14bEditedSource{f, func(kind string, nodes [][]byte) [][]byte {
		if kind == "storage" {
			return append(append([][]byte(nil), others...), make([]byte, 3<<20))
		}
		return nodes
	}}
	ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
	if ev == nil || ev.Proof != nil || ev.State == nil || ev.State.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("a storage proof without its nodes is not a named state: %+v", ev)
	}
}
