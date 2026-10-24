// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/finality"
)

// Package 2c is tested on the synthetic worlds with the REAL steps 1c-14 (package 2a) and the REAL steps 21, 23, 24, and with TEST-ONLY
// stand-ins for the steps of packages 2b-1 and 2b-2 (they do not exist on this branch). A stand-in derives the facts from the world's own
// proofs (the same reads as the world's plan, so step 22b accounts for every node) and fills Facts.B1/B2 with the word spelling that step 21
// documents (S8_FREEZE 6.11). What these tests prove is therefore the behaviour of steps 21, 23 and 24 given those facts; the vectors that need
// the real 2b-1/2b-2 facts to pass are named in the check-in.

type c2Hook func(env *ci.Env, id ci.StepID, out *ci.StepOutput)

func newFixtureFn(t *testing.T, chain uint64, variant string, muts func(sp *world.Spec) []ci.Mutation) *fixture {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := world.Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	var ms []ci.Mutation
	if muts != nil {
		ms = muts(spec)
	}
	b, err := world.Apply(m, spec, ms, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t, m, spec, b}
}

// words2c reads, at one attestation station, every AUTH word step 21 needs, with the spelling documented in S8_FREEZE 6.11, plus the
// validator records (the Facts.B2.Validators of the real step 18).
func (f *fixture) words2c(env *ci.Env, root common.Hash) (map[string]common.Hash, []ci.ValidatorRow, error) {
	sp := f.spec
	A, V, G, O := f.addr(sp.Roles.Anchor), f.addr(sp.Roles.Verifier), f.addr(sp.Roles.Groth16), f.addr(sp.Roles.Owner)
	acct := map[common.Address]ci.AccountState{}
	for _, a := range []common.Address{A, V, G, O} {
		s, err := ci.ReadAccount(root, env.Nodes, a)
		if err != nil {
			return nil, nil, err
		}
		acct[a] = s
	}
	words := map[string]common.Hash{}
	rd := func(id string, a common.Address, s common.Hash) (common.Hash, error) {
		w, err := ci.ReadSlot(acct[a].StorageRoot, env.Nodes, s)
		if id != "" {
			words[id] = w
		}
		return w, err
	}
	anchorID := common.HexToHash(sp.Settlement.AnchorID)
	pkc := env.Facts.B1.PKC
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	for k := uint64(0); k < 13; k++ {
		if _, err := rd("", A, ci.MemberSlot(rec, k)); err != nil {
			return nil, nil, err
		}
	}
	for _, c := range []struct {
		id string
		s  common.Hash
	}{{"A01", ci.SlotIndex(0)}, {"", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2)}, {"", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3)},
		{"A05", ci.MappingSlotAt(ci.KeyBytes32(pkc), 4)}, {"A07", ci.SlotIndex(5)}, {"A08", ci.SlotIndex(6)}} {
		if _, err := rd(c.id, A, c.s); err != nil {
			return nil, nil, err
		}
	}
	nw, err := rd("A10", A, ci.SlotIndex(13))
	if err != nil {
		return nil, nil, err
	}
	var vals []ci.ValidatorRow
	for i := uint64(0); i < nw.Big().Uint64(); i++ {
		el, _, _ := ci.ArrayElementSlot(13, i, 20)
		v, err := rd(fmt.Sprintf("A10:%d", i), A, el)
		if err != nil {
			return nil, nil, err
		}
		a := common.BytesToAddress(v[12:])
		lk := "A09:" + lower(a)
		base := ci.MappingSlotAt(ci.KeyAddress(a), 12)
		reg, err := rd(lk+":0", A, base)
		if err != nil {
			return nil, nil, err
		}
		pw, err := rd(lk+":1", A, ci.MemberSlot(base, 1))
		if err != nil {
			return nil, nil, err
		}
		if _, err := rd(lk+":3", A, ci.MemberSlot(base, 3)); err != nil {
			return nil, nil, err
		}
		key, err := ci.ReadBytes(acct[A].StorageRoot, env.Nodes, ci.MemberSlot(base, 2), 256)
		if err != nil {
			return nil, nil, err
		}
		words[lk+":key"] = crypto.Keccak256Hash(key)
		vals = append(vals, ci.ValidatorRow{Address: a, Registered: reg == common.BigToHash(big.NewInt(1)), Power: pw, BLSKey: key})
	}
	for _, c := range []struct {
		id string
		n  uint64
	}{{"A11", 14}, {"A12", 15}, {"A13", 16}, {"A14", 17}, {"A16", 27}, {"A17", 29}} {
		if _, err := rd(c.id, A, ci.SlotIndex(c.n)); err != nil {
			return nil, nil, err
		}
	}
	// rows A06 on the manifest_history route: the flag of every commitment of the row's pkcList (read when the list has the shape step 21c requires)
	if row, ok := env.Manifest.SetRootRowFor(env.Ctx.Chain, env.Facts.B1.HeaderV.Number, lower0x(words["A14"])); ok && row.PKCList != nil && row.PKCCount != nil {
		if list, ok := shapedList(*row.PKCList, *row.PKCCount); ok {
			for _, c := range list {
				if _, err := rd("A06:"+lower0x(c), A, ci.MappingSlotAt(ci.KeyBytes32(c), 4)); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	w30, err := rd("", A, ci.SlotIndex(30))
	if err != nil {
		return nil, nil, err
	}
	words["A18"] = common.BytesToHash(w30[12:])
	words["A19"], words["A20"], words["A21"] = common.BigToHash(big.NewInt(int64(w30[11]))), common.BigToHash(big.NewInt(int64(w30[10]))), common.BigToHash(big.NewInt(int64(w30[9])))
	if _, err := rd("", A, ci.MappingSlotAt(ci.KeyBytes32(common.Hash(env.Ctx.Batch.OperationID)), 18)); err != nil {
		return nil, nil, err
	}
	for n := uint64(0); n < 3; n++ {
		id := ""
		if n == 2 {
			id = "V03"
		}
		if _, err := rd(id, V, ci.SlotIndex(n)); err != nil {
			return nil, nil, err
		}
	}
	return words, vals, nil
}

func lower0x(h common.Hash) string { return strings.ToLower(h.Hex()) }

// shapedList is the pkcList of a row if it has the shape step 21c(iii) requires: as many entries as pkcCount, at most 256, 32-byte 0x hex,
// strictly ascending.
func shapedList(raw []string, count uint64) ([]common.Hash, bool) {
	if uint64(len(raw)) != count || len(raw) > 256 {
		return nil, false
	}
	out := make([]common.Hash, len(raw))
	for i, s := range raw {
		if len(s) != 66 || !strings.HasPrefix(s, "0x") {
			return nil, false
		}
		out[i] = common.HexToHash(s)
		if i > 0 && strings.Compare(string(out[i-1][:]), string(out[i][:])) >= 0 {
			return nil, false
		}
	}
	return out, true
}

func lower(a common.Address) string {
	h := []byte(a.Hex())
	for i, c := range h {
		if c >= 'A' && c <= 'F' {
			h[i] = c + 32
		}
	}
	return string(h)
}

// run2c runs the real 2a and 2c steps and the stand-ins of the other packages; hook may adjust a stand-in's facts and output after it ran.
// build2c composes the real steps of 2a and 2c with the stand-ins of the other packages.
func (f *fixture) build2c(hook c2Hook) *ci.StepVerifier {
	f.t.Helper()
	reg := ci.NewStepRegistry()
	for _, r := range []ci.Registrar{ci.RegisterSteps2a, ci.RegisterSteps2c} {
		if err := r(reg); err != nil {
			f.t.Fatal(err)
		}
	}
	for _, id := range ci.RegistrableSteps() {
		if o, _ := ci.Spec(id); o.Owner == ci.Owner2a || o.Owner == ci.Owner2c {
			continue
		}
		id := id
		base := f.fake(id, false)
		wrapped := func(env *ci.Env) (ci.StepOutput, error) {
			out, err := base(env)
			if err != nil {
				return out, err
			}
			att := env.Container.Attest
			captured := att.Tag == ci.TagCaptured
			switch id {
			case ci.Step16:
				if captured {
					if hv, err := env.Header(att.Attest.HeaderV); err == nil {
						env.Facts.B1.HeaderV, env.Facts.B1.HeaderLinked = hv, true
					}
				}
			case ci.Step18:
				if captured && len(env.Facts.B2.Pre.Words) > 0 {
					pre, _, err := f.words2c(env, common.Hash(env.Facts.B1.StateRootPre))
					if err != nil {
						return out, err
					}
					post, vals, err := f.words2c(env, common.Hash(env.Facts.B1.StateRootPost))
					if err != nil {
						return out, err
					}
					env.Facts.B2.Pre = ci.AuthStation{StateRoot: env.Facts.B1.StateRootPre, Words: pre}
					env.Facts.B2.Post = ci.AuthStation{StateRoot: env.Facts.B1.StateRootPost, Words: post}
					env.Facts.B2.Validators = vals
				}
			case ci.Step22:
				env.Facts.B2.IB = ci.IBResult{Evaluated: captured, Verified: captured}
				if captured {
					O := f.addr(f.spec.Roles.Owner)
					a, e1 := ci.ReadAccount(common.Hash(env.Facts.B1.StateRootPre), env.Nodes, O)
					b, e2 := ci.ReadAccount(common.Hash(env.Facts.B1.StateRootPost), env.Nodes, O)
					if e1 == nil && e2 == nil && a.Nonce != b.Nonce {
						env.Facts.B2.IB = ci.IBResult{Evaluated: true, State: ci.Must(ci.CodeUnproven, ci.RowUnprovenOwnerActiveInBlock, map[string]any{
							"part": ci.JudgedIntraBlockWindow, "address": O, "pre": common.BigToHash(new(big.Int).SetUint64(a.Nonce)), "post": common.BigToHash(new(big.Int).SetUint64(b.Nonce))})}
					}
				}
			}
			if hook != nil {
				hook(env, id, &out)
			}
			return out, nil
		}
		if err := reg.Register(id, wrapped); err != nil {
			f.t.Fatal(err)
		}
	}
	v, err := ci.NewVerifier(reg)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *fixture) run2c(tweak func(*ci.LegContext), hook c2Hook) (ci.Report, ci.Trace, error) {
	f.t.Helper()
	v := f.build2c(hook)
	ctx := f.built.Inputs.Ctx
	if tweak != nil {
		tweak(&ctx)
	}
	return runTrace(v, ctx, f)
}

func runTrace(v *ci.StepVerifier, ctx ci.LegContext, f *fixture) (ci.Report, ci.Trace, error) {
	return v.VerifyTrace(ctx, f.built.Inputs.Container, f.m)
}

func (f *fixture) must2c(tweak func(*ci.LegContext), hook c2Hook) (ci.Report, ci.Trace) {
	f.t.Helper()
	r, tr, err := f.run2c(tweak, hook)
	if err != nil {
		f.t.Fatalf("the verifier returned an error: %v", err)
	}
	return r, tr
}

func setWord(station string, who common.Address, slot uint64, w common.Hash) ci.Mutation {
	return world.SetStorage(station, who, ci.SlotIndex(slot), w)
}

// H0 on every chain: all eleven parts verified, registry_link via S9, the registry object complete, step 22b accounts for every node,
// rules_not_judged and the residuals printed.
func TestC2H0VerifiesOnEveryChain(t *testing.T) {
	for _, chain := range []uint64{11155111, 84532, 421614, 2017} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			f := newFixtureFn(t, chain, world.VariantH0, nil)
			r, tr := f.must2c(nil, nil)
			if r.Headline.Kind != ci.HeadlineVerified || r.Headline.RegistryLink != "via S9" || r.Headline.JudgedAtLevel != "finalized" {
				t.Fatalf("headline %+v (first %v)", r.Headline, r.Headline.First)
			}
			for _, p := range ci.JudgedParts {
				if p != ci.JudgedS6Link && p != ci.JudgedStateAtSettlement {
					f.expect(r, want{part: p, status: "verified"})
				}
			}
			if !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
				t.Fatalf("node accounting %+v", tr.NodesCheck)
			}
			o := r.Registry
			if o == nil || o.Owner != f.addr(f.spec.Roles.Owner) || o.Count != 7 || len(o.Members) != 7 || o.AuthorizedCount != 29 || !o.PKCAuthorized ||
				!o.Binding || o.ThresholdNum != 2 || o.ThresholdDen != 3 || o.Verifier != f.addr(f.spec.Roles.Verifier) || o.MinimumGovernanceLvl != 1 || o.Paused ||
				o.GovernanceVerifier != (common.Address{}) || o.TotalVotingPower.Int64() != 70 {
				t.Fatalf("registry object %+v", o)
			}
			if o.ExpectedSubsetCount == nil || *o.ExpectedSubsetCount != 29 {
				t.Fatalf("expected_subset_count %v, want 29 (21+7+1)", o.ExpectedSubsetCount)
			}
			for i, m := range o.Members {
				if !m.Registered || m.Power.Int64() != 10 || len(m.BLSKey) != 192 {
					t.Fatalf("member %d: %+v", i, m)
				}
			}
			if fmt.Sprint(r.RulesNotJudged) != fmt.Sprint(ci.FixedRulesNotJudged()) || len(r.RulesNotJudged) != 4 {
				t.Fatalf("rules_not_judged %v", r.RulesNotJudged)
			}
			if !containsStr(r.RulesJudged, "OWNER") || fmt.Sprint(r.Residuals) != fmt.Sprint(ci.FixedResiduals()) {
				t.Fatalf("rules_judged %v residuals %v", r.RulesJudged, r.Residuals)
			}
			if !r.StateRootAuthenticated || r.S7FinalizedStatus != ci.S7StatusVerified || r.JudgedAtLevel != "finalized" {
				t.Fatalf("level binding: %v %q %q", r.StateRootAuthenticated, r.S7FinalizedStatus, r.JudgedAtLevel)
			}
			if _, err := r.Canonical(); err != nil {
				t.Fatalf("canonical form: %v", err)
			}
		})
	}
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// VS8-150: the owner pin. Both stations carry the same foreign owner -> R with the first failing station; only one station -> U (the owner changed
// the word inside B_v); rule IB not verified -> the part carries the U of rule IB.
func TestC2OwnerPin(t *testing.T) {
	decoy := word(hexAddr("0x1111111111111111111111111111111111111111"))
	both := func(slot uint64, who func(sp *world.Spec) string) func(sp *world.Spec) []ci.Mutation {
		return func(sp *world.Spec) []ci.Mutation {
			a := hexAddr(who(sp))
			return []ci.Mutation{setWord(world.StationPre, a, slot, decoy), setWord(world.StationPost, a, slot, decoy)}
		}
	}
	anchor := func(sp *world.Spec) string { return sp.Roles.Anchor }
	verifier := func(sp *world.Spec) string { return sp.Roles.Verifier }
	cases := []struct {
		name  string
		muts  func(sp *world.Spec) []ci.Mutation
		hook  c2Hook
		want  want
		field string
	}{
		{"anchor owner in no row", both(27, anchor), nil, want{part: ci.JudgedAuthorizationAttest, status: "refused", code: "authorization_mismatch", key: "field", val: "anchor_owner"}, ""},
		{"verifier owner differs", both(2, verifier), nil, want{part: ci.JudgedAuthorizationAttest, status: "refused", code: "authorization_mismatch", key: "field", val: "verifier_owner"}, ""},
		{"owner changed after the attestation (post only)", func(sp *world.Spec) []ci.Mutation {
			return []ci.Mutation{setWord(world.StationPost, hexAddr(sp.Roles.Anchor), 27, decoy)}
		}, nil, want{part: ci.JudgedAuthorizationAttest, status: "unproven", code: "unproven", key: "reason", val: "state_changed_in_block"}, ""},
		{"owner changed before the attestation (pre only)", func(sp *world.Spec) []ci.Mutation {
			return []ci.Mutation{setWord(world.StationPre, hexAddr(sp.Roles.Verifier), 2, decoy)}
		}, nil, want{part: ci.JudgedAuthorizationAttest, status: "unproven", code: "unproven", key: "field", val: "V03"}, ""},
		{"foreign owner but the owner was active in B_v (rule IB unproven)", both(27, anchor), func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
			if id == ci.Step22 {
				env.Facts.B2.IB = ci.IBResult{Evaluated: true, State: ci.Must(ci.CodeUnproven, ci.RowUnprovenOwnerActiveInBlock, map[string]any{"part": ci.JudgedIntraBlockWindow, "address": hexAddr("0x91c7"), "pre": common.Hash{}, "post": common.Hash{}})}
			}
		}, want{part: ci.JudgedAuthorizationAttest, status: "unproven", code: "unproven", key: "part", val: ci.JudgedAuthorizationAttest}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureFn(t, 11155111, world.VariantH0, c.muts)
			r, _ := f.must2c(nil, c.hook)
			f.expect(r, c.want)
			if c.want.status == "refused" {
				p := part(t, r, ci.JudgedAuthorizationAttest)
				if p.State.Fields["at"] != ci.AtAttestPre || p.State.Fields["onchain"] != hexAddr("0x1111111111111111111111111111111111111111") {
					t.Fatalf("state %v", p.State.Fields)
				}
				if r.Headline.Kind != ci.HeadlineRefused {
					t.Fatalf("headline %s", r.Headline.Kind)
				}
			} else if r.Headline.Kind != ci.HeadlineUnproven {
				t.Fatalf("headline %s, want unproven", r.Headline.Kind)
			}
			if len(r.RulesNotJudged) != 4 {
				t.Fatalf("rules_not_judged not printed in the %s outcome", r.Headline.Kind)
			}
		})
	}
}

// VS8-151: Registry9 against the proven registry, one fault each; the field is the first differing item in the order of the spec text.
func TestC2Registry9Mismatch(t *testing.T) {
	cp := func(c *ci.LegContext) *ci.Registry9 {
		r := *c.Registry9
		r.Members = append([]ci.RegistryMember(nil), r.Members...)
		c.Registry9 = &r
		return &r
	}
	anchorA14 := func(who string, stations ...string) func(sp *world.Spec) []ci.Mutation {
		return func(sp *world.Spec) []ci.Mutation {
			var ms []ci.Mutation
			for _, s := range stations {
				ms = append(ms, setWord(s, hexAddr(sp.Roles.Anchor), 17, common.HexToHash("0xabc")))
			}
			return ms
		}
	}
	cases := []struct {
		name  string
		muts  func(sp *world.Spec) []ci.Mutation
		tweak func(c *ci.LegContext)
		field string
	}{
		{"one key byte differs", nil, func(c *ci.LegContext) {
			r := cp(c)
			k := []byte(r.Members[2].BLSKey)
			if k[5] == '0' {
				k[5] = '1'
			} else {
				k[5] = '0'
			}
			r.Members[2].BLSKey = string(k)
		}, "member_key"},
		{"a power differs", nil, func(c *ci.LegContext) { cp(c).Members[1].Power++ }, "member_power"},
		{"an address differs", nil, func(c *ci.LegContext) {
			cp(c).Members[0].Address = hexAddr("0x0000000000000000000000000000000000000001")
		}, "member_address"},
		{"a validator is missing", nil, func(c *ci.LegContext) { r := cp(c); r.Members = r.Members[:len(r.Members)-1] }, "count"},
		{"an extra validator", nil, func(c *ci.LegContext) {
			r := cp(c)
			x := r.Members[len(r.Members)-1]
			x.Address = hexAddr("0xffffffffffffffffffffffffffffffffffffffff")
			r.Members = append(r.Members, x)
		}, "count"},
		{"the threshold differs", nil, func(c *ci.LegContext) { cp(c).Num = 1 }, "threshold"},
		{"the root of the chain differs from the one recomputed", anchorA14("A", world.StationPre, world.StationPost), nil, "set_root"},
		{"certenSetRoot differs", nil, func(c *ci.LegContext) { cp(c).CertenSetRoot[0] ^= 1 }, "certen_set_root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureFn(t, 11155111, world.VariantH0, c.muts)
			r, _ := f.must2c(c.tweak, nil)
			f.expect(r, want{part: ci.JudgedRegistryLink, status: "refused", code: "registry_mismatch", key: "field", val: c.field})
			if r.Headline.Kind != ci.HeadlineRefused {
				t.Fatalf("headline %s", r.Headline.Kind)
			}
			if r.Registry == nil && c.name != "the root of the chain differs from the one recomputed" {
				t.Fatalf("the registry object is part of every report with a captured attestation")
			}
		})
	}
}

// VS8-160 / VS8-161: the pkc cross-check and the absent S9 commitment.
func TestC2PkcCrossCheck(t *testing.T) {
	f := newFixtureFn(t, 11155111, world.VariantH0, nil)
	r, _ := f.must2c(func(c *ci.LegContext) {
		x := *c.Registry9
		x.SignerCommitment[31] ^= 1
		c.Registry9 = &x
	}, nil)
	f.expect(r, want{part: ci.JudgedRegistryLink, status: "refused", code: "pkc_mismatch"})
	p := part(t, r, ci.JudgedRegistryLink)
	if p.State.Fields["s9"] == p.State.Fields["onchain"] {
		t.Fatalf("pkc_mismatch with equal values: %v", p.State.Fields)
	}
	if r.Headline.Kind != ci.HeadlineRefused {
		t.Fatalf("headline %s", r.Headline.Kind)
	}

	r, _ = f.must2c(func(c *ci.LegContext) { x := *c.Registry9; x.SignerCommitment = [32]byte{}; c.Registry9 = &x }, nil)
	f.expect(r, want{part: ci.JudgedRegistryLink, status: "verified"})
	open := r.OpenEntries()
	if r.Headline.Kind != ci.HeadlineVerifiedCore || len(open) != 1 || open[0].State.Fields["part"] != "pkc_signer_check" || open[0].State.Fields["reason"] != "no_s9_commitment" || open[0].Part != ci.JudgedRegistryLink {
		t.Fatalf("headline %s open %v", r.Headline.Kind, open)
	}
}

// Without a Registry9 and without a manifest row the link is the Open entry no_registry_in_file (VS8-153): the part is open, the headline
// verified_core, and no registry_link value is reported.
func TestC2NoRegistryNoRow(t *testing.T) {
	f := newFixtureFn(t, 11155111, world.VariantH0, nil)
	r, _ := f.must2c(func(c *ci.LegContext) { c.Registry9 = nil }, nil)
	f.expect(r, want{part: ci.JudgedRegistryLink, status: "open"})
	open := r.OpenEntries()
	if r.Headline.Kind != ci.HeadlineVerifiedCore || len(open) != 1 || open[0].State.Fields["part"] != "registry_link" || open[0].State.Fields["reason"] != "no_registry_in_file" {
		t.Fatalf("headline %s open %v", r.Headline.Kind, open)
	}
	if r.Registry == nil {
		t.Fatal("the registry object is emitted in every report with a captured attestation, with or without Registry9")
	}
}

// Step 24 and the headline rows that depend on it (VS8-182 / VS8-190): S7 finalized for another block, refused, pending, an unsupported chain;
// a judgement R is `refused` under an authenticated root and `pending` with findings otherwise (n2).
func TestC2LevelBinding(t *testing.T) {
	cpS7 := func(c *ci.LegContext) *finality.Report {
		s := *c.S7
		s.Levels = map[finality.Level]finality.LevelStatus{}
		for k, v := range c.S7.Levels {
			s.Levels[k] = v
		}
		c.S7 = &s
		return &s
	}
	other := func(c *ci.LegContext) {
		s := cpS7(c)
		fb := *c.S7.FinalizedBlock
		fb.Hash[0] ^= 1
		s.FinalizedBlock = &fb
	}
	refused := func(c *ci.LegContext) {
		s := cpS7(c)
		s.Levels[finality.LevelFinalized] = finality.LevelStatus{Status: finality.StatusRefused, State: &finality.StateError{Code: "finality_header_unverified"}}
		s.FinalizedBlock = nil
	}
	pending := func(c *ci.LegContext) {
		s := cpS7(c)
		s.Levels[finality.LevelFinalized] = finality.LevelStatus{Status: finality.StatusPending}
		s.FinalizedBlock = nil
	}
	unsupported := func(c *ci.LegContext) {
		s := cpS7(c)
		s.Unsupported = &finality.StateError{Code: finality.CodeChainUnsupported, Fields: map[string]any{"chain": uint64(999)}}
		s.Levels, s.FinalizedBlock = map[finality.Level]finality.LevelStatus{}, nil
	}
	f := newFixtureFn(t, 11155111, world.VariantH0, nil)
	for _, c := range []struct {
		name   string
		tweak  func(*ci.LegContext)
		status string
	}{{"finalized for another block", other, ci.S7StatusVerifiedOtherBlock}, {"finalized refused", refused, "refused:finality_header_unverified"}, {"finalized pending", pending, ci.S7StatusPending}} {
		t.Run(c.name, func(t *testing.T) {
			r, _ := f.must2c(c.tweak, nil)
			h := r.Headline
			if h.Kind != ci.HeadlinePending || h.LevelReached != "included" || h.S7FinalizedStatus != c.status || r.StateRootAuthenticated || len(h.Findings) != 0 {
				t.Fatalf("headline %+v", h)
			}
			if st, err := h.State(); err != nil || st.Fields["s7_finalized_status"] != c.status || st.Fields["next_level"] != "finalized" {
				t.Fatalf("pending state %v %v", st, err)
			}
			if len(r.Parts) != len(ci.JudgedParts) || len(r.RulesNotJudged) != 4 || len(r.RulesJudged) == 0 {
				t.Fatalf("every part and the rules are printed in a pending outcome: %d parts, %d rules not judged, %d judged", len(r.Parts), len(r.RulesNotJudged), len(r.RulesJudged))
			}
		})
	}
	t.Run("unsupported chain", func(t *testing.T) {
		r, _ := f.must2c(unsupported, nil)
		if r.Headline.Kind != ci.HeadlineUnproven || len(r.Headline.Parts) != 10 || r.S7FinalizedStatus != "refused:"+finality.CodeChainUnsupported || r.StateRootAuthenticated {
			t.Fatalf("headline %+v status %q", r.Headline, r.S7FinalizedStatus)
		}
		for _, p := range ci.JudgedParts {
			f.expect(r, want{part: p, status: "unproven", code: "unproven", key: "reason", val: "s7_chain_unsupported"})
		}
		if len(r.OpenEntries()) != 0 || len(r.RulesNotJudged) != 4 {
			t.Fatalf("open %v, rules not judged %d", r.OpenEntries(), len(r.RulesNotJudged))
		}
		p := part(t, r, ci.JudgedCodeIdentity)
		if p.State.Fields["part"] != ci.UnprovenPartAll || p.State.Fields["chain"] != uint64(11155111) {
			t.Fatalf("state %v", p.State.Fields)
		}
	})
	// n2: the same judgement R is refused under an authenticated root and pending, with the R in findings, otherwise
	decoy := word(hexAddr("0x1111111111111111111111111111111111111111"))
	fr := newFixtureFn(t, 11155111, world.VariantH0, func(sp *world.Spec) []ci.Mutation {
		a := hexAddr(sp.Roles.Anchor)
		return []ci.Mutation{setWord(world.StationPre, a, 27, decoy), setWord(world.StationPost, a, 27, decoy)}
	})
	r, _ := fr.must2c(nil, nil)
	if r.Headline.Kind != ci.HeadlineRefused || len(r.Headline.Parts) != 1 || r.Headline.Parts[0] != ci.JudgedAuthorizationAttest || r.Headline.First.Code != ci.Prefix+"authorization_mismatch" {
		t.Fatalf("authenticated: headline %+v", r.Headline)
	}
	r, _ = fr.must2c(other, nil)
	if r.Headline.Kind != ci.HeadlinePending || len(r.Headline.Findings) != 1 || r.Headline.Findings[0].Part != ci.JudgedAuthorizationAttest ||
		r.Headline.Findings[0].State.Code != ci.Prefix+"authorization_mismatch" || r.Headline.LevelReached != "included" {
		t.Fatalf("not authenticated: headline %+v", r.Headline)
	}
	fr.expect(r, want{part: ci.JudgedAuthorizationAttest, status: "refused", code: "authorization_mismatch"})
}

// A station of Facts.B2 whose words lack a key step 21 reads is a defect of the package that fills it: an error, never a verdict. A bound that
// is not established (B_v not linked, a station not read) is a named registry_link state and never `verified`.
func TestC2FactsContract(t *testing.T) {
	f := newFixtureFn(t, 11155111, world.VariantH0, nil)
	for _, k := range []string{"A12", "A16", "V03", "A10:3", "A19"} {
		_, _, err := f.run2c(nil, func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
			if id == ci.Step18 {
				delete(env.Facts.B2.Post.Words, k)
			}
		})
		var miss *ci.RegistryWordsMissingError
		if !errors.As(err, &miss) || miss.Station != "Post" || len(miss.Missing) != 1 || miss.Missing[0] != k {
			t.Errorf("without %s: %v", k, err)
		}
	}
	_, _, err := f.run2c(nil, func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step18 {
			env.Facts.B2.Pre.Words = nil
		}
	})
	var miss *ci.RegistryWordsMissingError
	if !errors.As(err, &miss) || miss.Station != "Pre" {
		t.Errorf("a station with a state root and no words: %v", err)
	}
	// Validators that do not hash to the proven key word
	_, _, err = f.run2c(nil, func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step18 {
			env.Facts.B2.Validators[2].BLSKey = append([]byte{1}, env.Facts.B2.Validators[2].BLSKey...)
		}
	})
	if !errors.As(err, &miss) || miss.Station != "Validators" {
		t.Errorf("validator key bytes that do not hash to the proven word: %v", err)
	}
	// B_v not linked: the registry link is unproven (attest_absent), never verified, and no word read under B_v is used
	r, _ := f.must2c(nil, func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step16 {
			env.Facts.B1.HeaderLinked = false
			st := ci.Must(ci.CodeUnproven, ci.RowUnprovenAttestAbsent, map[string]any{"part": ci.JudgedAuthorizationAttest})
			out.Parts = []ci.PartResult{{Part: ci.JudgedAuthorizationAttest, Status: ci.StatusUnproven, State: st}}
		}
	})
	f.expect(r, want{part: ci.JudgedRegistryLink, status: "unproven", code: "unproven", key: "part", val: ci.JudgedRegistryLink})
	if r.Registry != nil || r.Headline.Kind != ci.HeadlineUnproven {
		t.Fatalf("an unlinked B_v: registry %v, headline %s", r.Registry, r.Headline.Kind)
	}
	// the attestation is Stated: step 15 decides all three parts, step 21 has nothing to say and emits no registry object
	s := newFixtureFn(t, 11155111, world.VariantH0, nil)
	r, _ = s.must2c(func(c *ci.LegContext) {}, func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step15 {
			env.Facts.B1.AttestCaptured = false
			st := ci.Must(ci.CodeUnproven, ci.RowUnprovenAttestAbsent, map[string]any{"part": ci.JudgedRegistryLink})
			out.Parts = []ci.PartResult{{Part: ci.JudgedRegistryLink, Status: ci.StatusUnproven, State: st}}
			for _, p := range []string{ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow} {
				out.Parts = append(out.Parts, ci.PartResult{Part: p, Status: ci.StatusUnproven, State: ci.Must(ci.CodeUnproven, ci.RowUnprovenAttestAbsent, map[string]any{"part": p})})
			}
		}
	})
	if r.Registry != nil || r.Headline.Kind != ci.HeadlineUnproven {
		t.Fatalf("Stated attestation: registry %v, headline %s", r.Registry, r.Headline.Kind)
	}
}

// F17: registry_mismatch and pkc_mismatch obey the verdict precedence of the "Policy rules" table. R only when the compared words are equal at
// attest_pre and attest_post AND rule IB is verified; a changed word is U state_changed_in_block; an equal word with rule IB unproven carries the
// U of rule IB on registry_link; a rule IB without a verdict is attest_absent.
func TestC2RegistryAndPkcObeyTheVerdictPrecedence(t *testing.T) {
	ownerActive := func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step22 {
			env.Facts.B2.IB = ci.IBResult{Evaluated: true, State: ci.Must(ci.CodeUnproven, ci.RowUnprovenOwnerActiveInBlock, map[string]any{"part": ci.JudgedIntraBlockWindow, "address": hexAddr("0x91c7"), "pre": common.Hash{}, "post": common.Hash{}})}
		}
	}
	noVerdict := func(env *ci.Env, id ci.StepID, out *ci.StepOutput) {
		if id == ci.Step22 {
			env.Facts.B2.IB = ci.IBResult{}
		}
	}
	badPower := func(c *ci.LegContext) {
		r := *c.Registry9
		r.Members = append([]ci.RegistryMember(nil), r.Members...)
		r.Members[1].Power++
		c.Registry9 = &r
	}
	badPkc := func(c *ci.LegContext) { r := *c.Registry9; r.SignerCommitment[31] ^= 1; c.Registry9 = &r }
	powerSlot := func(sp *world.Spec) common.Hash {
		a := hexAddr(sp.Context.Registry9.Members[1].Address)
		return ci.MemberSlot(ci.MappingSlotAt(ci.KeyAddress(a), 12), 1)
	}
	hv := func(f *fixture) uint64 {
		h, err := finality.ReadHeader(f.built.World.Container.Attest.Attest.HeaderV)
		if err != nil {
			t.Fatal(err)
		}
		return h.Number
	}
	cases := []struct {
		name          string
		muts          func(sp *world.Spec) []ci.Mutation
		tweak         func(*ci.LegContext)
		hook          c2Hook
		reason, field string
		status        string
	}{
		{"pre-only root change: message_root can only be a changed word", func(sp *world.Spec) []ci.Mutation {
			return []ci.Mutation{setWord(world.StationPre, hexAddr(sp.Roles.Anchor), 17, common.HexToHash("0xabc"))}
		}, nil, nil, "state_changed_in_block", "A14", "unproven"},
		{"roster record changed inside B_v", func(sp *world.Spec) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPost, hexAddr(sp.Roles.Anchor), powerSlot(sp), common.BigToHash(big.NewInt(11)))}
		}, badPower, nil, "state_changed_in_block", "A09:", "unproven"},
		{"equal words, mismatch, the owner was active in B_v", nil, badPower, ownerActive, "owner_active_in_block", "", "unproven"},
		{"equal words, mismatch, rule IB has no verdict", nil, badPower, noVerdict, "attest_absent", "", "unproven"},
		{"equal words, mismatch, rule IB verified", nil, badPower, nil, "", "", "refused"},
		{"pkc: A05 changed inside B_v", func(sp *world.Spec) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPost, hexAddr(sp.Roles.Anchor), ci.MappingSlotAt(ci.KeyBytes32(common.HexToHash(sp.Attestation.Blob[13])), 4), common.Hash{})}
		}, badPkc, nil, "state_changed_in_block", "A05", "unproven"},
		{"pkc: equal words, the owner was active in B_v", nil, badPkc, ownerActive, "owner_active_in_block", "", "unproven"},
		{"pkc: equal words, rule IB verified", nil, badPkc, nil, "", "", "refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureFn(t, 11155111, world.VariantH0, c.muts)
			r, _ := f.must2c(c.tweak, c.hook)
			p := part(t, r, ci.JudgedRegistryLink)
			if string(p.Status) != c.status {
				t.Fatalf("registry_link %s (%v), want %s", p.Status, p.State, c.status)
			}
			switch {
			case c.status == "refused":
				if r.Headline.Kind != ci.HeadlineRefused || (p.State.Code != ci.Prefix+"registry_mismatch" && p.State.Code != ci.Prefix+"pkc_mismatch") {
					t.Fatalf("headline %s state %v", r.Headline.Kind, p.State)
				}
				return
			case p.State.Fields["reason"] != c.reason || r.Headline.Kind != ci.HeadlineUnproven:
				t.Fatalf("state %v headline %s, want reason %s", p.State, r.Headline.Kind, c.reason)
			}
			if p.State.Fields["part"] != nil && p.State.Fields["part"] != ci.JudgedRegistryLink {
				t.Fatalf("the carried state names part %v", p.State.Fields["part"])
			}
			if c.reason == "state_changed_in_block" {
				fld, _ := p.State.Fields["field"].(string)
				if !strings.HasPrefix(fld, c.field) || p.State.Fields["block"] != hv(f) || p.State.Fields["pre"] == p.State.Fields["post"] {
					t.Fatalf("state %v", p.State.Fields)
				}
			}
		})
	}
}

// Step 23: every outcome prints rules_not_judged and the residuals, also the outcomes in which step 23 does not run (SKELETON-FIX of runner.go:
// buildReport and earlyReport): a prelude refusal, the no-container outcome and a framework halt in steps 0-2.
func TestC2RulesNotJudgedInEveryOutcome(t *testing.T) {
	f := newFixtureFn(t, 11155111, world.VariantH0, nil)
	check := func(name string, r ci.Report, kind string) {
		t.Helper()
		if r.Headline.Kind != kind {
			t.Fatalf("%s: headline %s, want %s", name, r.Headline.Kind, kind)
		}
		if fmt.Sprint(r.RulesNotJudged) != fmt.Sprint(ci.FixedRulesNotJudged()) || fmt.Sprint(r.Residuals) != fmt.Sprint(ci.FixedResiduals()) {
			t.Fatalf("%s: rules_not_judged %v residuals %v", name, r.RulesNotJudged, r.Residuals)
		}
		m, err := r.Map()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rn, _ := m["rules_not_judged"].([]any); len(rn) != 4 {
			t.Fatalf("%s: the printed rules_not_judged has %d rows", name, len(rn))
		}
	}
	ver := f.build2c(nil)
	ctx := f.built.Inputs.Ctx
	// prelude refusal (step 1b): a mandatory member is missing
	bad := ctx
	bad.S7 = nil
	r, err := ver.Verify(bad, f.built.Inputs.Container, f.m)
	if err != nil {
		t.Fatal(err)
	}
	check("context_incomplete", r, ci.HeadlineRefused)
	// no container (step 1c(a))
	r, err = ver.Verify(ctx, nil, f.m)
	if err != nil {
		t.Fatal(err)
	}
	check("no container", r, ci.HeadlineUnproven)
	// a framework refusal of step 2 halts the run before steps 24 and 23
	ff := newFixtureFn(t, 11155111, world.VariantH0, func(sp *world.Spec) []ci.Mutation {
		return []ci.Mutation{{Op: "set_field", Target: "container", Path: "leg.number", Value: []byte(fmt.Sprintf("%q", fmt.Sprint(f.built.World.Container.Leg.Number+1)))}}
	})
	r, tr := ff.must2c(nil, nil)
	if tr.Halt == nil || !tr.Halt.Framework {
		t.Fatalf("no framework halt: %+v", tr.Halt)
	}
	check("framework halt", r, ci.HeadlineRefused)
}
