// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// Package 2a is tested on the synthetic worlds of the world package with the real steps 1c-14 and recording stand-ins for the 11 steps of
// the other packages. The stand-ins read what steps 16-18 read (the attestation leaves and the AUTH slot set at both attestation stations)
// so that step 22b can prove that the settle reads of package 2a are EXACTLY the reads of the world's read plan (no unreferenced node, no
// missing node), and step 18's stand-in fills Facts.B2 so that the drift entries of step 13 can be exercised.

func hexAddr(s string) common.Address { return common.HexToAddress(s) }

type fixture struct {
	t     *testing.T
	m     *ci.Manifest
	spec  *world.Spec
	built *world.Built
}

func newFixture(t *testing.T, chain uint64, variant string, muts ...ci.Mutation) *fixture {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := world.Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	b, err := world.Apply(m, spec, muts, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t, m, spec, b}
}

func (f *fixture) addr(s string) common.Address { return hexAddr(s) }

// authWords reads the AUTH slot set of the plan at one attestation station (exactly the reads of world.planner.authSet) and returns the
// words the drift check of step 13 compares.
func (f *fixture) authWords(env *ci.Env, root common.Hash, flip bool) (map[string]common.Hash, error) {
	sp := f.spec
	A, V, G, O := f.addr(sp.Roles.Anchor), f.addr(sp.Roles.Verifier), f.addr(sp.Roles.Groth16), f.addr(sp.Roles.Owner)
	acct := map[common.Address]ci.AccountState{}
	for _, a := range []common.Address{A, V, G, O} {
		s, err := ci.ReadAccount(root, env.Nodes, a)
		if err != nil {
			return nil, err
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
	opID := common.Hash(env.Ctx.Batch.OperationID)
	pkc := env.Facts.B1.PKC
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	for k := uint64(0); k < 13; k++ {
		if _, err := rd("", A, ci.MemberSlot(rec, k)); err != nil {
			return nil, err
		}
	}
	for _, c := range []struct {
		id string
		s  common.Hash
	}{{"", ci.SlotIndex(0)}, {"", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2)}, {"", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3)},
		{"A05", ci.MappingSlotAt(ci.KeyBytes32(pkc), 4)}, {"A07", ci.SlotIndex(5)}, {"", ci.SlotIndex(6)}} {
		if _, err := rd(c.id, A, c.s); err != nil {
			return nil, err
		}
	}
	nw, err := rd("A10", A, ci.SlotIndex(13))
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nw.Big().Uint64(); i++ {
		el, _, _ := ci.ArrayElementSlot(13, i, 20)
		v, err := rd("", A, el)
		if err != nil {
			return nil, err
		}
		base := ci.MappingSlotAt(ci.KeyAddress(common.BytesToAddress(v[12:])), 12)
		for _, s := range []common.Hash{base, ci.MemberSlot(base, 1), ci.MemberSlot(base, 3)} {
			if _, err := rd("", A, s); err != nil {
				return nil, err
			}
		}
		if _, err := ci.ReadBytes(acct[A].StorageRoot, env.Nodes, ci.MemberSlot(base, 2), 256); err != nil {
			return nil, err
		}
	}
	for _, c := range []struct {
		id string
		n  uint64
	}{{"A11", 14}, {"", 15}, {"", 16}, {"A14", 17}, {"", 27}, {"", 29}} {
		if _, err := rd(c.id, A, ci.SlotIndex(c.n)); err != nil {
			return nil, err
		}
	}
	w30, err := rd("", A, ci.SlotIndex(30))
	if err != nil {
		return nil, err
	}
	words["A18"] = common.BytesToHash(w30[12:])
	if flip {
		if _, err := rd("", A, ci.MappingSlotAt(ci.KeyBytes32(opID), 18)); err != nil {
			return nil, err
		}
	}
	for n := uint64(0); n < 3; n++ {
		if _, err := rd("", V, ci.SlotIndex(n)); err != nil {
			return nil, err
		}
	}
	return words, nil
}

func (f *fixture) fake(id ci.StepID, skip bool) ci.StepFunc {
	sp, _ := ci.Spec(id)
	return func(env *ci.Env) (ci.StepOutput, error) {
		var out ci.StepOutput
		for _, p := range sp.Parts {
			out.Parts = append(out.Parts, env.Verified(p))
		}
		att := env.Container.Attest
		switch id {
		case ci.Step15:
			env.Facts.B1.AttestCaptured = att.Tag == ci.TagCaptured
		case ci.Step16:
			if att.Tag == ci.TagCaptured {
				hv, err := env.Header(att.Attest.HeaderV)
				if err != nil {
					return out, err
				}
				hp, err := env.Header(att.Attest.HeaderVParent)
				if err != nil {
					return out, err
				}
				env.Facts.B1.StateRootPre, env.Facts.B1.StateRootPost = hp.StateRoot, hv.StateRoot
			}
			if f.spec.Link == "hops" {
				out.ReadPlanIncomplete = "test: hop reads not made"
			}
		case ci.Step17:
			if att.Tag == ci.TagCaptured {
				hv, _ := env.Header(att.Attest.HeaderV)
				for _, root := range [][32]byte{hv.TransactionRoot, hv.ReceiptsRoot} {
					if _, err := ci.ReadIndexedLeaf(common.Hash(root), env.Nodes, uint64(att.Attest.TxIndex), env.Limits.MaxNodeBytes); err != nil {
						return out, err
					}
				}
				env.Facts.B1.PKC = common.HexToHash(f.spec.Attestation.Blob[13])
			}
		case ci.Step18:
			if att.Tag == ci.TagCaptured {
				pre, err := f.authWords(env, common.Hash(env.Facts.B1.StateRootPre), true)
				if err != nil {
					return out, err
				}
				post, err := f.authWords(env, common.Hash(env.Facts.B1.StateRootPost), true)
				if err != nil {
					return out, err
				}
				env.Facts.B2.Pre.Words, env.Facts.B2.Post.Words = pre, post
			}
		case ci.Step21:
			env.Facts.C.RegistryLink = "via S9"
		case ci.Step24:
			env.Facts.C.Level = ci.LevelBinding{Authenticated: true, JudgedAtLevel: "finalized"}
		}
		if skip && id == ci.Step15 {
			out.ReadPlanIncomplete = "test: attest side not judged"
		}
		return out, nil
	}
}

func (f *fixture) run(tweak func(*ci.LegContext), container []byte, skip bool) (ci.Report, ci.Trace) {
	f.t.Helper()
	reg := ci.NewStepRegistry()
	if err := ci.RegisterSteps2a(reg); err != nil {
		f.t.Fatal(err)
	}
	mine := map[ci.StepID]bool{}
	for _, id := range ci.OwnedBy(ci.Owner2a) {
		mine[id] = true
	}
	for _, id := range ci.RegistrableSteps() {
		if !mine[id] {
			if err := reg.Register(id, f.fake(id, skip)); err != nil {
				f.t.Fatal(err)
			}
		}
	}
	v, err := ci.NewVerifier(reg)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx := f.built.Inputs.Ctx
	if tweak != nil {
		tweak(&ctx)
	}
	if container == nil {
		container = f.built.Inputs.Container
	}
	rep, tr, err := v.VerifyTrace(ctx, container, f.m)
	if err != nil {
		f.t.Fatalf("the verifier returned an error: %v", err)
	}
	return rep, tr
}

func part(t *testing.T, r ci.Report, name string) ci.PartResult {
	t.Helper()
	for _, p := range r.Parts {
		if p.Part == name {
			return p
		}
	}
	t.Fatalf("no part %s in the report (headline %s, first %v)", name, r.Headline.Kind, r.Headline.First)
	return ci.PartResult{}
}

type want struct {
	part, status, code string
	key, val           string // one field of the state
}

func (f *fixture) expect(r ci.Report, w want) {
	f.t.Helper()
	p := part(f.t, r, w.part)
	if string(p.Status) != w.status {
		f.t.Fatalf("part %s: status %s (state %v), want %s", w.part, p.Status, p.State, w.status)
	}
	if w.code == "" {
		return
	}
	if p.State == nil || p.State.Code != ci.Prefix+w.code {
		f.t.Fatalf("part %s: state %v, want code %s", w.part, p.State, w.code)
	}
	if w.key != "" && fmt.Sprint(p.State.Fields[w.key]) != w.val {
		f.t.Fatalf("part %s: %s = %v, want %s (state %v)", w.part, w.key, p.State.Fields[w.key], w.val, p.State)
	}
}

func (f *fixture) openCodes(r ci.Report, partName string) []string {
	var out []string
	for _, o := range part(f.t, r, partName).Open {
		out = append(out, fmt.Sprintf("%s:%v", o.State.Code[len(ci.Prefix):], o.State.Fields["field"]))
	}
	return out
}

var myParts = []string{ci.JudgedSettlementPath, ci.JudgedCodeIdentity, ci.JudgedAccountProvenance, ci.JudgedPointer, ci.JudgedAuthorityLevel, ci.JudgedRecord}

// H0 on every chain: the parts of package 2a are verified, step 13 reports nothing, step 22b finds no unreferenced and no missing node
// (the reads of 2a equal the reads of the world's plan).
func TestH0SettlePathVerifiesOnEveryChain(t *testing.T) {
	for _, chain := range []uint64{11155111, 84532, 421614, 2017} {
		for _, variant := range []string{world.VariantH0, world.VariantS6Silent} {
			t.Run(fmt.Sprintf("%d/%s", chain, variant), func(t *testing.T) {
				f := newFixture(t, chain, variant)
				r, tr := f.run(nil, nil, false)
				for _, p := range myParts {
					f.expect(r, want{part: p, status: "verified"})
				}
				if variant == world.VariantH0 {
					f.expect(r, want{part: ci.JudgedS6Link, status: "verified"})
				} else {
					f.expect(r, want{part: ci.JudgedS6Link, status: "not_applicable"})
				}
				if open := f.openCodes(r, ci.JudgedStateAtSettlement); len(open) != 0 {
					t.Fatalf("state_at_settlement reports %v on H0", open)
				}
				if !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
					t.Fatalf("node accounting: %+v (first unreferenced %d): the settle reads of package 2a differ from the read plan", tr.NodesCheck, tr.NodesCheck.FirstUnreferenced)
				}
				if r.Authority == nil || r.Authority.Level != r.Authority.LoggedLevel {
					t.Fatalf("authority %+v", r.Authority)
				}
				if r.Headline.Kind != ci.HeadlineVerified {
					t.Fatalf("headline %s (first %v)", r.Headline.Kind, r.Headline.First)
				}
			})
		}
	}
}

func (f *fixture) rec() common.Hash {
	return ci.MappingSlotAt(ci.KeyBytes32(common.HexToHash(f.spec.Settlement.AnchorID)), 1)
}

func word(a common.Address) common.Hash { return common.BytesToHash(a[:]) }

func TestSettleMutations(t *testing.T) {
	decoy := hexAddr("0x1111111111111111111111111111111111111111")
	type tc struct {
		name  string
		muts  func(f *fixture) []ci.Mutation
		tweak func(f *fixture, c *ci.LegContext)
		want  []want
		open  string // expected Open entries of state_at_settlement ("" none)
	}
	acctOf := func(f *fixture) common.Address { return f.addr(f.spec.Roles.Account) }
	anchorOf := func(f *fixture) common.Address { return f.addr(f.spec.Roles.Anchor) }
	book := func(f *fixture) common.Hash { return common.HexToHash(f.spec.Settlement.AuthorityBook) }
	cases := []tc{
		{name: "pointer to a decoy anchor", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, acctOf(f), ci.SlotIndex(2), word(decoy))}
		}, want: []want{{"pointer", "refused", "pointer_mismatch", "got", decoy.Hex()}}},
		{name: "record not executed", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.MemberSlot(f.rec(), 10), common.Hash{})}
		}, want: []want{{"record", "refused", "record_not_executed", "", ""}}},
		{name: "bundle id broken by the batch root", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.MemberSlot(f.rec(), 1), common.HexToHash("0xaa"))}
		}, want: []want{{"record", "refused", "record_inconsistent", "field", "bundle_id"}}},
		{name: "batch root of the proof file differs", tweak: func(f *fixture, c *ci.LegContext) { c.Batch.BatchRoot[0] ^= 1 },
			want: []want{{"record", "refused", "record_inconsistent", "field", "merkle_root"}}},
		{name: "not a batch anchor", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.MappingSlotAt(ci.KeyBytes32(common.HexToHash(f.spec.Settlement.AnchorID)), 2), common.Hash{})}
		}, want: []want{{"record", "unproven", "unproven", "reason", "anchor_not_batch"}}},
		{name: "verifier swapped in slot 30", muts: func(f *fixture) []ci.Mutation {
			w := word(decoy)
			w[11] = 1
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.SlotIndex(30), w)}
		}, want: []want{{"code_identity", "refused", "address_not_published", "role", "blsZkVerifier"}}},
		{name: "binding off at N only", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.SlotIndex(6), common.Hash{})}
		}, want: []want{{"state_at_settlement", "open", "", "", ""}}, open: "alert:binding"},
		{name: "set root rotated after the attestation", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, anchorOf(f), ci.SlotIndex(17), common.HexToHash("0x77"))}
		}, want: []want{{"state_at_settlement", "open", "", "", ""}}, open: "drift:A14"},
		{name: "factory does not know the account", muts: func(f *fixture) []ci.Mutation {
			return []ci.Mutation{world.SetStorage(world.StationSettle, f.addr(f.spec.Roles.Factory), ci.MappingSlotAt(ci.KeyAddress(acctOf(f)), 2), common.Hash{})}
		}, want: []want{{"account_provenance", "refused", "account_not_canonical", "reason", "deployed_flag"}}},
		{name: "adiURL of the context differs", tweak: func(f *fixture, c *ci.LegContext) { c.ADIURL = c.ADIURL + "x" },
			want: []want{{"account_provenance", "refused", "account_not_canonical", "reason", "adi_url"}}},
		{name: "receipt status 0", tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.PostStateOrStatus = nil
			c.Receipt = &r
		}, want: []want{{"settlement_path", "unproven", "unproven", "reason", "settlement_not_executed"}}},
		{name: "no LeafConsumed log", tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.Logs = nil
			c.Receipt = &r
		}, want: []want{{"settlement_path", "unproven", "unproven", "reason", "settlement_event_missing"}, {"code_identity", "unproven", "unproven", "reason", "settlement_event_missing"}}},
		{name: "LeafConsumed emitted by another address", tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.Logs = nil
			for _, l := range c.Receipt.Logs {
				l2 := *l
				if len(l2.Topics) == 3 && l2.Topics[0] == ci.TopicOf(ci.SigLeafConsumed) {
					l2.Address = decoy
				}
				r.Logs = append(r.Logs, &l2)
			}
			c.Receipt = &r
		}, want: []want{{"settlement_path", "unproven", "unproven", "reason", "not_direct_call"}}},
		{name: "two LeafConsumed logs of the account", tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.Logs = append([]*types.Log(nil), c.Receipt.Logs...)
			for _, l := range c.Receipt.Logs {
				if len(l.Topics) == 3 && l.Topics[0] == ci.TopicOf(ci.SigLeafConsumed) {
					r.Logs = append(r.Logs, l)
				}
			}
			c.Receipt = &r
		}, want: []want{{"settlement_path", "unproven", "unproven", "reason", "multiple_leaf_consumed"}}},
		{name: "S6 names another contract", tweak: func(f *fixture, c *ci.LegContext) {
			s := *c.S6
			s.Contract = decoy
			c.S6 = &s
		}, want: []want{{"s6_link", "refused", "s6_link_mismatch", "field", "account"}}},
		{name: "S6 settlement block differs", tweak: func(f *fixture, c *ci.LegContext) {
			s := *c.S6
			s.SettlementBlock.Number++
			c.S6 = &s
		}, want: []want{{"s6_link", "refused", "s6_link_mismatch", "field", "block"}}},
		{name: "S6 proven at the same hash under another number", tweak: func(f *fixture, c *ci.LegContext) {
			s := *c.S6
			s.ProvenAt.Number++
			c.S6 = &s
		}, want: []want{{"s6_link", "refused", "s6_link_mismatch", "field", "proven_at"}}},
		{name: "S6 proven later with a wrong code hash", tweak: func(f *fixture, c *ci.LegContext) {
			s := *c.S6
			s.ProvenAt = ci.BlockRef{Number: s.ProvenAt.Number + 5, Hash: [32]byte{9}}
			s.CodeHash[0] ^= 1
			c.S6 = &s
		}, want: []want{{"s6_link", "refused", "s6_link_mismatch", "field", "code_hash"}}},
		{name: "S6 proven later with the right code hash", tweak: func(f *fixture, c *ci.LegContext) {
			s := *c.S6
			s.ProvenAt = ci.BlockRef{Number: s.ProvenAt.Number + 5, Hash: [32]byte{9}}
			c.S6 = &s
		}, want: []want{{"s6_link", "verified", "", "", ""}}},
		{name: "stored page level 5", muts: func(f *fixture) []ci.Mutation {
			pg := f.spec.Settlement.AuthorityPage
			return []ci.Mutation{world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(10, book(f), pg), ci.SlotIndex(1)),
				world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(9, book(f), pg), ci.SlotIndex(5))}
		}, want: []want{{"authority_level", "refused", "authority_level_invalid", "got", "5"}}},
		{name: "stored page level differs from the logged one", muts: func(f *fixture) []ci.Mutation {
			pg := f.spec.Settlement.AuthorityPage
			return []ci.Mutation{world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(10, book(f), pg), ci.SlotIndex(1)),
				world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(9, book(f), pg), ci.SlotIndex(1))}
		}, want: []want{{"authority_level", "unproven", "unproven", "reason", "level_differs_from_logged"}}},
		{name: "operation requires MANAGER of an OPERATOR page", muts: func(f *fixture) []ci.Mutation {
			d := common.FromHex(f.spec.Settlement.Legs[0].Data)
			var sel [4]byte
			copy(sel[:], d)
			pg := f.spec.Settlement.AuthorityPage
			return []ci.Mutation{world.SetStorage(world.StationSettle, acctOf(f), ci.MappingSlotAt(ci.KeyBytes4(sel), 8), ci.SlotIndex(2)),
				world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(10, book(f), pg), ci.SlotIndex(1)),
				world.SetStorage(world.StationSettle, acctOf(f), ci.PageSlot(9, book(f), pg), ci.SlotIndex(1))}
		}, tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.Logs = nil
			for _, l := range c.Receipt.Logs {
				l2 := *l
				if len(l2.Topics) == 3 && l2.Topics[0] == ci.TopicOf(ci.SigGovernanceOperation) {
					l2.Data = append([]byte(nil), l.Data...)
					copy(l2.Data[64:96], ci.SlotIndex(1).Bytes())
				}
				r.Logs = append(r.Logs, &l2)
			}
			c.Receipt = &r
		}, want: []want{{"authority_level", "unproven", "unproven", "reason", "level_below_required_at_N"}}},
		{name: "no level log in the receipt", tweak: func(f *fixture, c *ci.LegContext) {
			r := *c.Receipt
			r.Logs = nil
			for _, l := range c.Receipt.Logs {
				if len(l.Topics) == 3 && l.Topics[0] == ci.TopicOf(ci.SigGovernanceOperation) {
					continue
				}
				r.Logs = append(r.Logs, l)
			}
			c.Receipt = &r
		}, want: []want{{"authority_level", "unproven", "unproven", "reason", "level_log_missing"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var f *fixture
			f = newFixture(t, 11155111, world.VariantH0)
			if c.muts != nil {
				f = newFixture(t, 11155111, world.VariantH0, c.muts(f)...)
			}
			r, _ := f.run(func(l *ci.LegContext) {
				if c.tweak != nil {
					c.tweak(f, l)
				}
			}, nil, true)
			for _, w := range c.want {
				f.expect(r, w)
			}
			if c.open != "" {
				if got := f.openCodes(r, ci.JudgedStateAtSettlement); len(got) != 1 || got[0] != c.open {
					t.Fatalf("open entries %v, want [%s]", got, c.open)
				}
			}
		})
	}
}

func (f *fixture) edit(fn func(c *ci.Container)) []byte {
	f.t.Helper()
	c, err := ci.Decode(f.built.Inputs.Container, ci.DefaultLimits())
	if err != nil {
		f.t.Fatal(err)
	}
	fn(c)
	b, err := ci.Encode(c, ci.DefaultLimits())
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func TestLegAndStatedSettle(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	first := func(r ci.Report) string { return r.Headline.First.Code }
	for name, c := range map[string]struct {
		edit func(c *ci.Container)
		code string
		key  string
		val  string
	}{
		"leg number": {func(c *ci.Container) { c.Leg.Number++ }, "block_mismatch", "field", "number"},
		"leg hash":   {func(c *ci.Container) { c.Leg.Hash[0] ^= 1 }, "block_mismatch", "field", "hash"},
		"chain":      {func(c *ci.Container) { c.Chain++ }, "block_mismatch", "field", "chain"},
		"unknown rsn": {func(c *ci.Container) {
			c.Settle = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: "made_up"}}
		}, "evidence_malformed", "reason", "unknown_stated_reason"},
		"attest rsn": {func(c *ci.Container) {
			c.Settle = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: "attest_event_not_found"}}
		}, "evidence_malformed", "reason", "unknown_stated_reason"},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := f.run(nil, f.edit(c.edit), true)
			if r.Headline.Kind != ci.HeadlineRefused || first(r) != ci.Prefix+c.code || fmt.Sprint(r.Headline.First.Fields[c.key]) != c.val {
				t.Fatalf("headline %s first %v", r.Headline.Kind, r.Headline.First)
			}
		})
	}
	for _, reason := range []string{"state_unavailable", "capture_not_attempted_in_window"} {
		t.Run("stated settle "+reason, func(t *testing.T) {
			raw := f.edit(func(c *ci.Container) {
				c.Settle = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: c.Leg.Number, JudgedHash: c.Leg.Hash,
					Failures: []ci.ProviderFailure{{Host: "rpc.example", Error: "pruned"}}}}
			})
			r, _ := f.run(nil, raw, true)
			for _, p := range []string{"settlement_path", "code_identity", "account_provenance", "pointer", "record", "authority_level", "state_at_settlement"} {
				f.expect(r, want{part: p, status: "unproven", code: "unproven", key: "reason", val: reason})
			}
			f.expect(r, want{part: "s6_link", status: "verified"}) // ProvenAt == Leg in H0: judged without a settle read
			if r.Headline.Kind != ci.HeadlineUnproven {
				t.Fatalf("headline %s: a Stated part never raises a status above unproven", r.Headline.Kind)
			}
		})
	}
}

func TestInfrastructureCallIsNotApplicableAndHalts(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantS6Silent)
	anchor := f.addr(f.spec.Roles.Anchor)
	r, _ := f.run(func(c *ci.LegContext) {
		rc := *c.Receipt
		rc.Logs = nil
		c.Receipt = &rc
		raw := types.NewTx(&types.LegacyTx{To: &anchor, Data: []byte{1, 2, 3, 4}})
		c.Tx = raw
	}, nil, true)
	if r.Headline.Kind != ci.HeadlineNotApplicable || r.Headline.NotApplicable.Fields["role"] != "anchor" {
		t.Fatalf("headline %s %v", r.Headline.Kind, r.Headline.NotApplicable)
	}
	// an unknown target, or an account event next to the anchor target, is never not_applicable
	r, _ = f.run(func(c *ci.LegContext) {
		rc := *c.Receipt
		rc.Logs = nil
		c.Receipt = &rc
		to := hexAddr("0x2222222222222222222222222222222222222222")
		c.Tx = types.NewTx(&types.LegacyTx{To: &to})
	}, nil, true)
	f.expect(r, want{part: "settlement_path", status: "unproven", code: "unproven", key: "reason", val: "settlement_event_missing"})
}
