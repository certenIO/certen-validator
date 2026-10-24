// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// Package 2b-2 (steps 18, 18b, 19, 22) is tested on the synthetic worlds with the REAL steps of packages 2a, 2b-1 and 2b-2 and stand-ins only
// for the three steps of package 2c (21, 23, 24), which report their parts as verified. The stand-in of step 23 hands the facts and the
// visited nodes of the run back to the test.

type b2fx struct{ *b1fx }

func b2New(t *testing.T, chain uint64, variant string, muts ...ci.Mutation) *b2fx {
	t.Helper()
	return &b2fx{b1New(t, chain, variant, muts...)}
}

func (f *b2fx) verifier() *ci.StepVerifier { return f.verifierWith("") }

// verifierWith is the verifier with one step of package 2b-2 replaced by a stand-in that reports its parts verified (the mutation gate).
func (f *b2fx) verifierWith(disabled ci.StepID) *ci.StepVerifier {
	f.t.Helper()
	reg := ci.NewStepRegistry()
	for _, r := range []ci.Registrar{ci.RegisterSteps2a, ci.RegisterSteps2b1} {
		if err := r(reg); err != nil {
			f.t.Fatal(err)
		}
	}
	real := ci.Steps2b2()
	for _, id := range ci.OwnedBy(ci.Owner2b2) {
		fn := real[id]
		if id == disabled {
			sp, _ := ci.Spec(id)
			fn = func(env *ci.Env) (ci.StepOutput, error) {
				var out ci.StepOutput
				for _, p := range sp.Parts {
					out.Parts = append(out.Parts, env.Verified(p))
				}
				return out, nil
			}
		}
		if err := reg.Register(id, fn); err != nil {
			f.t.Fatal(err)
		}
	}
	for _, id := range ci.OwnedBy(ci.Owner2c) {
		id := id
		sp, _ := ci.Spec(id)
		fn := func(env *ci.Env) (ci.StepOutput, error) {
			var out ci.StepOutput
			for _, p := range sp.Parts {
				out.Parts = append(out.Parts, env.Verified(p))
			}
			switch id {
			case ci.Step21:
				env.Facts.C.RegistryLink = "via S9"
			case ci.Step23:
				env.Facts.C.RulesNotJudged = ci.FixedRulesNotJudged()
				f.facts = *env.Facts
				f.visited = env.Nodes.VisitedNodes()
			case ci.Step24:
				env.Facts.C.Level = ci.LevelBinding{Authenticated: true, JudgedAtLevel: "finalized"}
			}
			return out, nil
		}
		if err := reg.Register(id, fn); err != nil {
			f.t.Fatal(err)
		}
	}
	v, err := ci.NewVerifier(reg)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *b2fx) verify() (ci.Report, ci.Trace) {
	f.t.Helper()
	in := f.built.Inputs
	rep, tr, err := f.verifier().VerifyTrace(in.Ctx, in.Container, f.m)
	if err != nil {
		f.t.Fatalf("the verifier returned an error: %v", err)
	}
	return rep, tr
}

func (f *b2fx) slot(station string, a common.Address, s common.Hash, v common.Hash) ci.Mutation {
	return world.SetStorage(station, a, s, v)
}

// ---- H0 ----

func TestB2H0VerifiesOnEveryChainAndLink(t *testing.T) {
	for _, chain := range []uint64{11155111, 84532, 421614, 2017} {
		for _, variant := range []string{world.VariantH0, world.VariantS6Silent, world.VariantHops} {
			t.Run(fmt.Sprintf("%d/%s", chain, variant), func(t *testing.T) {
				f := b2New(t, chain, variant)
				r, tr := f.verify()
				for _, part := range []string{ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow, ci.JudgedCodeIdentity} {
					b1Want(t, r, part, "verified", "")
				}
				if r.Headline.Kind != ci.HeadlineVerified {
					t.Fatalf("headline %s (first %v)", r.Headline.Kind, r.Headline.First)
				}
				if !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
					t.Fatalf("node accounting: %+v", tr.NodesCheck)
				}
				b := f.facts.B2
				if !b.IB.Evaluated || !b.IB.Verified || len(b.IB.Owners) != 1 || b.CodeFailure != nil || len(b.Changed) != 0 || b.RecordCreatedInBlock {
					t.Fatalf("facts after H0: %+v", b)
				}
				// the words step 13 compares are all there, with the documented spelling (D4 of S8_FREEZE.md and D-B2-9)
				for _, st := range []ci.AuthStation{b.Pre, b.Post} {
					for _, k := range []string{"A05", "A07", "A10", "A11", "A14", "A18", "A01", "A08", "A12", "A13", "A15", "A16", "A17", "A19", "A20", "A21", "V01", "V02", "V03", "A02:0", "A02:12"} {
						if _, ok := st.Words[k]; !ok {
							t.Fatalf("no word %s at %x", k, st.StateRoot)
						}
					}
					for _, v := range b.Validators {
						for _, sfx := range []string{":0", ":1", ":3", ":key"} {
							if _, ok := st.Words["A09:"+lower(v.Address)+sfx]; !ok {
								t.Fatalf("no validator word A09:%s%s", lower(v.Address), sfx)
							}
						}
					}
				}
			})
		}
	}
}

func lower(a common.Address) string {
	s := a.Hex()
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// ---- mutations ----

type b2case struct {
	name string
	muts func(f *b2fx) []ci.Mutation
	// want are `part status code k v ...` rows
	want []b2want
	head string
}

type b2want struct {
	part, status, code string
	kv                 []string
}

func TestB2Mutations(t *testing.T) {
	h0 := b2New(t, 11155111, world.VariantH0)
	h0.verify()
	words := h0.facts.B2.Pre.Words
	A, V, O := h0.addr(h0.spec.Roles.Anchor), h0.addr(h0.spec.Roles.Verifier), h0.addr(h0.spec.Roles.Owner)
	anchorID := common.HexToHash(h0.spec.Settlement.AnchorID)
	opID := common.Hash(h0.built.Inputs.Ctx.Batch.OperationID)
	rec10 := ci.MemberSlot(ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1), 10)
	used := ci.MappingSlotAt(ci.KeyBytes32(opID), 18)
	bv := fmt.Sprint(h0.spec.Blocks.Attest.Number)
	auth, win := ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow
	both := func(slot, v common.Hash) func(*b2fx) []ci.Mutation {
		return func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPre, A, slot, v), world.SetStorage(world.StationPost, A, slot, v)}
		}
	}
	cases := []b2case{
		{"binding off at both stations", both(ci.SlotIndex(6), common.Hash{}), []b2want{{auth, "refused", "authorization_mismatch", []string{"field", "binding", "at", "attest_pre"}}, {win, "verified", "", nil}}, ci.HeadlineRefused},
		{"binding off only after the attestation", func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPost, A, ci.SlotIndex(6), common.Hash{})}
		}, []b2want{{auth, "unproven", "state_changed_in_block", []string{"field", "A08", "block", bv}}}, ci.HeadlineUnproven},
		{"binding off at both and the owner active", func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPre, A, ci.SlotIndex(6), common.Hash{}), world.SetStorage(world.StationPost, A, ci.SlotIndex(6), common.Hash{}), world.SetNonce(world.StationPost, O, 99)}
		}, []b2want{{auth, "unproven", "owner_active_in_block", []string{"part", auth}}, {win, "unproven", "owner_active_in_block", []string{"part", win}}}, ci.HeadlineUnproven},
		{"used commitment already 1 at pre", func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPre, A, used, ci.SlotIndex(1))}
		}, []b2want{{auth, "refused", "attest_mismatch", []string{"field", "flip"}}}, ci.HeadlineRefused},
		{"owner has code at pre", func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetCode(world.StationPre, O, world.CodeSpec{Hex: "0x6000"})}
		}, []b2want{{win, "unproven", "owner_not_eoa", []string{"part", win}}, {auth, "verified", "", nil}}, ci.HeadlineUnproven},
		{"record created in B_v", func(*b2fx) []ci.Mutation {
			w := words["A02:10"]
			w[11] = 0
			return []ci.Mutation{world.SetStorage(world.StationPre, A, rec10, w)}
		}, []b2want{{auth, "unproven", "record_created_in_block", []string{"block", bv}}}, ci.HeadlineUnproven},
		{"verifier threshold changed at both", func(*b2fx) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationPre, V, ci.SlotIndex(0), ci.SlotIndex(1)), world.SetStorage(world.StationPost, V, ci.SlotIndex(0), ci.SlotIndex(1))}
		}, []b2want{{auth, "refused", "authorization_mismatch", []string{"field", "verifier_threshold"}}}, ci.HeadlineRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := b2New(t, 11155111, world.VariantH0, c.muts(h0)...)
			r, _ := f.verify()
			if r.Headline.Kind != c.head {
				t.Fatalf("headline %s (first %v), want %s", r.Headline.Kind, r.Headline.First, c.head)
			}
			for _, w := range c.want {
				b1Want(t, r, w.part, w.status, w.code, w.kv...)
			}
		})
	}
}

// A block that the settlement header does not authenticate (the spine is broken) decides nothing from its own state: the authorization part
// keeps the refusal of step 16, and code_identity and intra_block_window are unproven (attest_absent), even when the state of that block
// is plainly wrong. The reads are still made, so the node accounting of step 22b stays exact (D-B2-1).
func TestB2UnlinkedBlockDecidesNothingFromItsState(t *testing.T) {
	h0 := b2New(t, 11155111, world.VariantH0)
	A := h0.addr(h0.spec.Roles.Anchor)
	for name, muts := range map[string][]ci.Mutation{
		"honest state": nil,
		"wrong code and binding off": {world.SetCode(world.StationPost, A, world.CodeSpec{Hex: "0x00"}),
			world.SetStorage(world.StationPre, A, ci.SlotIndex(6), common.Hash{}), world.SetStorage(world.StationPost, A, ci.SlotIndex(6), common.Hash{})},
	} {
		t.Run(name, func(t *testing.T) {
			f := b2New(t, 11155111, world.VariantH0, muts...)
			raw := f.edit(func(c *ci.Container) {
				s := c.Attest.Attest.Spine[1]
				s[len(s)-1] ^= 1
			})
			rep, tr, err := f.verifier().VerifyTrace(f.built.Inputs.Ctx, raw, f.m)
			if err != nil {
				t.Fatalf("the verifier returned an error: %v", err)
			}
			b1Want(t, rep, ci.JudgedAuthorizationAttest, "refused", "header_unlinked")
			b1Want(t, rep, ci.JudgedCodeIdentity, "unproven", "attest_absent", "part", ci.JudgedCodeIdentity)
			b1Want(t, rep, ci.JudgedIntraBlockWindow, "unproven", "attest_absent", "part", ci.JudgedIntraBlockWindow)
			if !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
				t.Fatalf("node accounting: %+v", tr.NodesCheck)
			}
			if f.facts.B2.IB.Evaluated || f.facts.B2.CodeFailure != nil {
				t.Fatalf("nothing may be judged from an unlinked block: %+v", f.facts.B2)
			}
		})
	}
}
