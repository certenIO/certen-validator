// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The two negative controls of the specification (Test and vector plan, items 5 and 13): faithful implementations of the verifiers the design
// replaced. They must ACCEPT the bad worlds below, which proves that the vectors bite: the bad worlds are bad exactly in the way the real
// verifier refuses them (steps 18, 19 and 22 of package 2b-2, run by the integration package over the same published vectors).
//
//	NaiveSettlementOnly: the runbook's first draft - the authorization words are judged at the settlement block N only.
//	NaivePrePost: judges the words at the two attestation stations (pre, post) and requires them equal, but does not ask whether the owner
//	acted inside B_v (no rule IB): a change made and restored inside the block leaves every word equal.

type naiveWorld struct {
	f   *fixture
	env *ci.Env
	pol ci.Policy
}

func newNaive(t *testing.T, f *fixture, in ci.Inputs) *naiveWorld {
	env, st, err := ci.Prelude(in.Ctx, in.Container, f.m)
	if err != nil || st != nil {
		t.Fatalf("prelude: %v %v", st, err)
	}
	return &naiveWorld{f, env, f.m.Policy()}
}

func one(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n)) }

func (n *naiveWorld) ownerOK(role string, block uint64, w common.Hash) bool {
	for _, r := range n.f.m.OwnerCovering(n.env.Ctx.Chain, role, block) {
		if w == word(common.HexToAddress(r.Address)) {
			return true
		}
	}
	return false
}

// naiveSettlementOnly reads the anchor and the verifier at N and applies the policy rules there.
func (n *naiveWorld) settlementOnly() (bool, string) {
	env, sp := n.env, n.f.spec
	h, err := env.Header(env.Ctx.Settlement.Header)
	if err != nil {
		return false, "header"
	}
	A, V := hexAddr(sp.Roles.Anchor), hexAddr(sp.Roles.Verifier)
	a, err := ci.ReadAccount(common.Hash(h.StateRoot), env.Nodes, A)
	if err != nil {
		return false, err.Error()
	}
	v, err := ci.ReadAccount(common.Hash(h.StateRoot), env.Nodes, V)
	if err != nil {
		return false, err.Error()
	}
	slot := func(acct ci.AccountState, i uint64) common.Hash {
		w, e := ci.ReadSlot(acct.StorageRoot, env.Nodes, ci.SlotIndex(i))
		if e != nil {
			err = e
		}
		return w
	}
	s30 := slot(a, 30)
	checks := []struct {
		name string
		ok   bool
	}{
		{"paused", slot(a, 0) == common.Hash{}},
		{"binding", slot(a, 6) == one(1)},
		{"enabled", s30[11] == 1},
		{"min_governance_level", s30[10] >= n.pol.MinimumGovernanceLevel},
		{"threshold", slot(a, 15) == one(n.pol.BLSThreshold.Numerator) && slot(a, 16) == one(n.pol.BLSThreshold.Denominator)},
		{"verifier_threshold", slot(v, 0) == one(n.pol.VerifierThreshold.Numerator) && slot(v, 1) == one(n.pol.VerifierThreshold.Denominator)},
		{"governance_verifier", slot(a, 29) == common.Hash{}},
		{"anchor_owner", n.ownerOK("anchor", h.Number, slot(a, 27))},
	}
	if err != nil {
		return false, err.Error()
	}
	for _, c := range checks {
		if !c.ok {
			return false, c.name
		}
	}
	return true, ""
}

// prePost reads the AUTH words at the two attestation stations with the stand-in reads of the fixture and accepts when they are equal and
// satisfy the same predicates; nothing about the owner's activity inside the block is asked.
func (n *naiveWorld) prePost() (bool, string) {
	env, sp := n.env, n.f.spec
	att := env.Container.Attest.Attest
	hv, e1 := env.Header(att.HeaderV)
	hp, e2 := env.Header(att.HeaderVParent)
	if e1 != nil || e2 != nil {
		return false, "headers"
	}
	env.Facts.B1.PKC = common.HexToHash(sp.Attestation.Blob[13])
	pre, _, err := n.f.words2c(env, common.Hash(hp.StateRoot))
	if err != nil {
		return false, err.Error()
	}
	post, _, err := n.f.words2c(env, common.Hash(hv.StateRoot))
	if err != nil {
		return false, err.Error()
	}
	for k, w := range pre {
		if post[k] != w {
			return false, "differs:" + k
		}
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{"paused", post["A01"] == common.Hash{}},
		{"binding", post["A08"] == one(1)},
		{"enabled", post["A19"] == one(1)},
		{"min_governance_level", post["A20"].Big().Uint64() >= uint64(n.pol.MinimumGovernanceLevel)},
		{"threshold", post["A12"] == one(n.pol.BLSThreshold.Numerator) && post["A13"] == one(n.pol.BLSThreshold.Denominator)},
		{"governance_verifier", post["A17"] == common.Hash{}},
		{"anchor_owner", n.ownerOK("anchor", hv.Number, post["A16"])},
		{"commitment_authorized", post["A05"] == one(1)},
	}
	for _, c := range checks {
		if !c.ok {
			return false, c.name
		}
	}
	return true, ""
}

func (n *naiveWorld) ownerNonces() (pre, post uint64, err error) {
	env := n.env
	att := env.Container.Attest.Attest
	hv, _ := env.Header(att.HeaderV)
	hp, _ := env.Header(att.HeaderVParent)
	O := hexAddr(n.f.spec.Roles.Owner)
	a, err := ci.ReadAccount(common.Hash(hp.StateRoot), env.Nodes, O)
	if err != nil {
		return 0, 0, err
	}
	b, err := ci.ReadAccount(common.Hash(hv.StateRoot), env.Nodes, O)
	if err != nil {
		return 0, 0, err
	}
	return a.Nonce, b.Nonce, nil
}

func (a *author2c) controlVectors() []ci.Vector {
	sp := a.f.spec
	anchor, owner := hexAddr(sp.Roles.Anchor), hexAddr(sp.Roles.Owner)
	var out []ci.Vector
	// VS8-090 (the N-only hole): the pubkey binding is disabled at B_v (both stations) and enabled again at N. Real verifier: step 19b
	// R authorization_mismatch{field:binding}; headline refused.
	out = append(out, ci.Vector{ID: "VS8-090.n_only_hole", Base: "H0", Expected: exp(ci.HeadlineRefused, only(ci.JudgedAuthorizationAttest, "refused")),
		Mutations: []ci.Mutation{setWord(world.StationPre, anchor, 6, common.Hash{}), setWord(world.StationPost, anchor, 6, common.Hash{})}})
	// VS8-100 (the owner acted inside B_v): every AUTH word is equal at pre and post and satisfies every rule, but the owner's nonce moved
	// (the owner EOA sent a transaction inside B_v: setBLSZKVerificationEnabled(false) before and (true) after the attestation). Real verifier:
	// rule IB (step 22) U owner_active_in_block on intra_block_window; no rule is violated, so authorization_attest stays verified (the part carries the IB code only for a violated rule: VS8-138, step 19 precedence (b)); headline unproven.
	out = append(out, ci.Vector{ID: "VS8-100.owner_active_in_block", Base: "H0", Expected: exp(ci.HeadlineUnproven, map[string]string{ci.JudgedAuthorizationAttest: "verified", ci.JudgedIntraBlockWindow: "unproven"}),
		Mutations: []ci.Mutation{world.SetNonce(world.StationPost, owner, 7777)}})
	return out
}

const vectorSet2cControls = "s8_2c_2"

func TestNegativeControlsAcceptTheBadWorldsAndTheRealCheckWouldNot(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	vectors := a.controlVectors()
	if _, err := os.Stat(setDir(vectorSet2cControls)); err != nil && os.Getenv("CERTEN_WRITE_S8_2C") == "1" {
		if err := world.WriteSet(setDir(vectorSet2cControls), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSet2cControls))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSet2cControls, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	checkPublishedBytes(t, f, vectorSet2cControls, vectors)

	// both controls are faithful: they accept the honest world H0
	h0 := newNaive(t, f, f.built.Inputs)
	if ok, why := h0.settlementOnly(); !ok {
		t.Fatalf("NaiveSettlementOnly refuses H0 (%s): not a faithful control", why)
	}
	if ok, why := h0.prePost(); !ok {
		t.Fatalf("NaivePrePost refuses H0 (%s): not a faithful control", why)
	}
	for _, v := range set.Vectors {
		in, has := set.Inputs[v.ID]
		if !has {
			t.Fatalf("%s: no materialised inputs", v.ID)
		}
		nw := newNaive(t, f, in)
		switch v.ID {
		case "VS8-090.n_only_hole":
			if ok, why := nw.settlementOnly(); !ok {
				t.Errorf("NaiveSettlementOnly refuses %s (%s): the vector does not bite the control", v.ID, why)
			}
			// the world really violates the rule at B_v: both stations carry binding 0, N carries 1
			att := nw.env.Container.Attest.Attest
			hv, _ := nw.env.Header(att.HeaderV)
			nw.env.Facts.B1.PKC = common.HexToHash(f.spec.Attestation.Blob[13])
			post, _, err := f.words2c(nw.env, common.Hash(hv.StateRoot))
			if err != nil || post["A08"] != (common.Hash{}) {
				t.Errorf("%s: binding at B_v-post is %v (%v), the world is not the N-only hole", v.ID, post["A08"], err)
			}
			if ok, why := nw.prePost(); ok || why != "binding" {
				t.Errorf("NaivePrePost on %s: %v %q, want the binding refusal (the pre/post control sees this hole)", v.ID, ok, why)
			}
		case "VS8-100.owner_active_in_block":
			if ok, why := nw.prePost(); !ok {
				t.Errorf("NaivePrePost refuses %s (%s): the vector does not bite the control", v.ID, why)
			}
			if ok, why := nw.settlementOnly(); !ok {
				t.Errorf("NaiveSettlementOnly refuses %s (%s)", v.ID, why)
			}
			pre, post, err := nw.ownerNonces()
			if err != nil || pre == post {
				t.Errorf("%s: owner nonce pre %d post %d (%v): the owner did not act inside B_v", v.ID, pre, post, err)
			}
		default:
			t.Errorf("unexpected control vector %s", v.ID)
		}
	}
}
