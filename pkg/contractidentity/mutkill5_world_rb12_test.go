// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// RB12 EPSILON stage 2, part B: world tests for the survivors of steps 18 and 22 (steps_2b2.go): the real steps run over H0 with the least change
// that reaches the line, and the exact verdict or fact is asserted.

func mk5Part(r ci.Report, part string) ci.PartResult {
	for _, p := range r.Parts {
		if p.Part == part {
			return p
		}
	}
	return ci.PartResult{}
}

func TestMutKill5B2ChangedRowsAreReportedInKeyOrder(t *testing.T) {
	f0 := b2New(t, 11155111, world.VariantH0)
	f0.verify()
	A, V := f0.addr(f0.spec.Roles.Anchor), f0.addr(f0.spec.Roles.Verifier)
	other := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000a7")
	f := b2New(t, 11155111, world.VariantH0,
		world.SetStorage(world.StationPost, A, ci.SlotIndex(0), ci.SlotIndex(1)),
		world.SetStorage(world.StationPost, V, ci.SlotIndex(0), other),
		world.SetCode(world.StationPost, A, world.CodeSpec{Hex: "0x00"}))
	f.verify()
	var got []string
	for _, d := range f.facts.B2.Changed {
		got = append(got, d.Row)
	}
	want := []string{"A01", "C01:A", "V01"}
	if len(got) != len(want) {
		t.Fatalf("changed rows %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("changed rows %v, want %v", got, want)
		}
	}
}

// mk5DropScan finds, with the given world mutations applied first, the first node of the container whose removal makes the report satisfy each
// predicate (all steps of packages 2a, 2b-1 and 2b-2 are the real ones; only the three steps of package 2c report their parts as verified). It
// returns the fixture and the index of the first match of every predicate.
func mk5DropScan(t *testing.T, muts []ci.Mutation, preds ...func(f *b2fx, r ci.Report) bool) ([]*b2fx, []int) {
	t.Helper()
	base := b2New(t, 11155111, world.VariantH0, muts...)
	n := len(base.built.World.Container.Nodes)
	found, at := make([]*b2fx, len(preds)), make([]int, len(preds))
	left := len(preds)
	start := time.Now()
	for i := n - 1; i >= 0 && left > 0; i-- {
		ix := i
		f := b2New(t, 11155111, world.VariantH0, append(append([]ci.Mutation(nil), muts...), ci.Mutation{Op: "drop_node", Target: "container", Index: &ix})...)
		in := f.built.Inputs
		rep, _, err := f.verifier().VerifyTrace(in.Ctx, in.Container, f.m)
		if err != nil {
			continue
		}
		for k, p := range preds {
			if found[k] == nil && p(f, rep) {
				found[k], at[k] = f, ix
				left--
			}
		}
	}
	t.Logf("scanned %d nodes in %s", n, time.Since(start))
	return found, at
}

func mk5ProofInvalidAt(s *ci.StateError, roots ...string) bool {
	if s == nil || s.Code != ci.CodeProofInvalid {
		return false
	}
	for _, r := range roots {
		if s.Fields["root"] == r {
			return true
		}
	}
	return false
}

func TestMutKill5B2StationAndOwnerReadFailures(t *testing.T) {
	stationFailure := func(f *b2fx, r ci.Report) bool {
		a, c := mk5Part(r, ci.JudgedAuthorizationAttest), mk5Part(r, ci.JudgedCodeIdentity)
		return a.Status == ci.StatusRefused && c.Status == ci.StatusRefused && mk5ProofInvalidAt(a.State, "attest_pre", "attest_post") && mk5ProofInvalidAt(c.State, "attest_pre", "attest_post")
	}
	ownerAt := func(root string) func(f *b2fx, r ci.Report) bool {
		return func(f *b2fx, r ci.Report) bool {
			w := mk5Part(r, ci.JudgedIntraBlockWindow)
			return w.Status == ci.StatusRefused && mk5ProofInvalidAt(w.State, root) && f.facts.B2.IB.Evaluated
		}
	}
	got, _ := mk5DropScan(t, nil, stationFailure, ownerAt("attest_pre"))
	// a read failure at the post station only needs a node that the post state alone holds: the owner's account leaf, once its nonce differs
	f0 := b2New(t, 11155111, world.VariantH0)
	f0.verify()
	O := f0.addr(f0.spec.Roles.Owner)
	n := f0.spec.Stations[world.StationPre].Accounts[strings.ToLower(O.Hex())].Nonce
	post, _ := mk5DropScan(t, []ci.Mutation{world.SetNonce(world.StationPost, O, n+1)}, ownerAt("attest_post"))
	got = append(got, post[0])
	if got[0] == nil {
		t.Error("no dropped node makes the AUTH-word read of a station fail with the header linked")
	}
	for k, root := range map[int]string{1: "attest_pre", 2: "attest_post"} {
		if got[k] == nil {
			t.Errorf("no dropped node makes the owner read of step 22 fail at %s", root)
		} else if ib := got[k].facts.B2.IB; ib.Verified || ib.State == nil || ib.State.Code != ci.CodeProofInvalid || ib.State.Fields["root"] != root {
			t.Errorf("rule IB after a failed owner read at %s: %+v", root, ib)
		}
	}
}
func TestMutKill5B2OwnerReadFailureWithAnUnlinkedHeader(t *testing.T) {
	ownerPre := func(f *b2fx, r ci.Report) bool {
		w := mk5Part(r, ci.JudgedIntraBlockWindow)
		return w.Status == ci.StatusRefused && mk5ProofInvalidAt(w.State, "attest_pre") && f.facts.B2.IB.Evaluated
	}
	_, at := mk5DropScan(t, nil, ownerPre)
	f := b2New(t, 11155111, world.VariantH0)
	raw := f.edit(func(c *ci.Container) {
		sp := append([]byte(nil), c.Attest.Attest.Spine[1]...)
		sp[len(sp)-1] ^= 1
		c.Attest.Attest.Spine[1] = sp
		c.Nodes = append(c.Nodes[:at[0]:at[0]], c.Nodes[at[0]+1:]...)
	})
	in := f.built.Inputs
	rep, _, err := f.verifier().VerifyTrace(in.Ctx, raw, f.m)
	if err != nil {
		t.Fatal(err)
	}
	if f.facts.B1.HeaderLinked {
		t.Fatal("the altered spine header must leave the header chain unlinked")
	}
	if w := mk5Part(rep, ci.JudgedIntraBlockWindow); w.Status != ci.StatusUnproven {
		t.Errorf("window part over an unlinked header and a failed owner read: %s %v", w.Status, w.State)
	}
	if f.facts.B2.IB.Evaluated {
		t.Errorf("rule IB is not evaluated over an unlinked header: %+v", f.facts.B2.IB)
	}
}

func TestMutKill5B2RuleViolationOverAFailedOwnerRead(t *testing.T) {
	f0 := b2New(t, 11155111, world.VariantH0)
	f0.verify()
	A := f0.addr(f0.spec.Roles.Anchor)
	muts := []ci.Mutation{
		world.SetStorage(world.StationPre, A, ci.SlotIndex(6), common.Hash{}),
		world.SetStorage(world.StationPost, A, ci.SlotIndex(6), common.Hash{}),
	}
	both := func(f *b2fx, r ci.Report) bool {
		w, a := mk5Part(r, ci.JudgedIntraBlockWindow), mk5Part(r, ci.JudgedAuthorizationAttest)
		return w.Status == ci.StatusRefused && mk5ProofInvalidAt(w.State, "attest_pre", "attest_post") && a.Status == ci.StatusRefused && mk5ProofInvalidAt(a.State, "attest_pre", "attest_post")
	}
	got, _ := mk5DropScan(t, muts, both)
	if got[0] == nil {
		t.Fatal("no dropped node leaves both a rule violation and a failed owner read")
	}
	if ib := got[0].facts.B2.IB; ib.Verified || ib.State == nil || ib.State.Code != ci.CodeProofInvalid {
		t.Errorf("rule IB: %+v", ib)
	}
}
