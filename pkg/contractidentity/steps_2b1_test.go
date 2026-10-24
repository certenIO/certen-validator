// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// Package 2b-1 (steps 15, 16, 17, 20) is tested on the synthetic worlds with the real steps 1c-14 of package 2a, the real steps of 2b-1 that a
// test names, and stand-ins that report `verified` for the parts of every other step. The stand-in of step 18 hands the facts of the run back
// to the test.

type b1fx struct {
	t     *testing.T
	m     *ci.Manifest
	spec  *world.Spec
	built *world.Built
	facts ci.Facts
	// visited are the nodes the run visited, captured by the stand-in of step 23 (after every real step ran)
	visited [][]byte
	// authErr is the error of the stand-in of step 18 when its AUTH reads did not verify (a world with a refused link or leaf)
	authErr error
}

func b1New(t *testing.T, chain uint64, variant string, muts ...ci.Mutation) *b1fx {
	t.Helper()
	return b1NewSpec(t, chain, variant, nil, muts...)
}

// b1NewSpec is b1New with an edit of the world description before it is derived (the mutation paths cannot name a station such as hop.1).
func b1NewSpec(t *testing.T, chain uint64, variant string, edit func(*world.Spec), muts ...ci.Mutation) *b1fx {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := world.Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(spec)
	}
	b, err := world.Apply(m, spec, muts, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &b1fx{t: t, m: m, spec: spec, built: b}
}

func (f *b1fx) addr(s string) common.Address { return common.HexToAddress(s) }

// verifier builds the Verifier: the real steps 1c-14, the real steps `real` of package 2b-1 and stand-ins for the rest.
func (f *b1fx) verifier(real []ci.StepID) *ci.StepVerifier {
	f.t.Helper()
	reg := ci.NewStepRegistry()
	if err := ci.RegisterSteps2a(reg); err != nil {
		f.t.Fatal(err)
	}
	isReal := map[ci.StepID]bool{}
	for _, id := range real {
		isReal[id] = true
	}
	mine := map[ci.StepID]bool{}
	for _, id := range ci.OwnedBy(ci.Owner2a) {
		mine[id] = true
	}
	for _, id := range ci.RegistrableSteps() {
		if mine[id] {
			continue
		}
		var fn ci.StepFunc
		if isReal[id] {
			fn = ci.B1Step(id)
		} else {
			sp, _ := ci.Spec(id)
			id := id
			fn = func(env *ci.Env) (ci.StepOutput, error) {
				var out ci.StepOutput
				for _, p := range sp.Parts {
					out.Parts = append(out.Parts, env.Verified(p))
				}
				switch id {
				case ci.Step15:
					env.Facts.B1.AttestCaptured = env.AttestStated() == nil
				case ci.Step16:
					if a := env.Container.Attest.Attest; a != nil {
						if hv, err := env.Header(a.HeaderV); err == nil {
							env.Facts.B1.StateRootPost = hv.StateRoot
						}
						if hp, err := env.Header(a.HeaderVParent); err == nil {
							env.Facts.B1.StateRootPre = hp.StateRoot
						}
					}
				case ci.Step17:
					// the pkc is read by step 13 of package 2a at N (row A05): the stand-in hands over the same value
					env.Facts.B1.PKC = common.HexToHash(f.spec.Attestation.Blob[13])
				case ci.Step18:
					if env.Facts.B1.AttestCaptured && env.Facts.B1.StateRootPre != ([32]byte{}) {
						f.authErr = f.readAuth(env)
					}
				case ci.Step23:
					f.facts = *env.Facts
					f.visited = env.Nodes.VisitedNodes()
				case ci.Step21:
					env.Facts.C.RegistryLink = "via S9"
				case ci.Step24:
					env.Facts.C.Level = ci.LevelBinding{Authenticated: true, JudgedAtLevel: "finalized"}
				}
				return out, nil
			}
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

func (f *b1fx) run(real []ci.StepID, container []byte, tweak func(*ci.LegContext)) (ci.Report, ci.Trace) {
	f.t.Helper()
	v := f.verifier(real)
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

var b1All = []ci.StepID{ci.Step15, ci.Step16, ci.Step17, ci.Step20}

func (f *b1fx) edit(fn func(c *ci.Container)) []byte {
	f.t.Helper()
	c, err := ci.Decode(f.built.Inputs.Container, ci.DefaultLimits())
	if err != nil {
		f.t.Fatal(err)
	}
	fn(c)
	return ci.EncodeUnvalidated(c)
}

func b1Part(t *testing.T, r ci.Report, name string) ci.PartResult {
	t.Helper()
	for _, p := range r.Parts {
		if p.Part == name {
			return p
		}
	}
	t.Fatalf("no part %s in the report (headline %s)", name, r.Headline.Kind)
	return ci.PartResult{}
}

// b1Want checks a part: status, the state code (without the prefix) and `key=value` pairs of its fields.
func b1Want(t *testing.T, r ci.Report, part, status, code string, kv ...string) {
	t.Helper()
	p := b1Part(t, r, part)
	if string(p.Status) != status {
		t.Fatalf("part %s: status %s (state %v), want %s %s %v", part, p.Status, p.State, status, code, kv)
	}
	if code == "" {
		return
	}
	if status == "unproven" { // every unproven state is contract_identity_unproven; its row is the reason
		kv = append([]string{"reason", code}, kv...)
		code = "unproven"
	}
	if p.State == nil || p.State.Code != ci.Prefix+code {
		t.Fatalf("part %s: state %v, want %s %v", part, p.State, code, kv)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if got := fmt.Sprint(p.State.Fields[kv[i]]); got != kv[i+1] {
			t.Fatalf("part %s: field %s = %q, want %q (state %v)", part, kv[i], got, kv[i+1], p.State)
		}
	}
}

func b1AttestTxIndex(f *b1fx) int {
	for i, tx := range f.spec.Blocks.Attest.Txs {
		if tx.Role == "attestation" {
			return i
		}
	}
	f.t.Fatal("no attestation transaction in the world")
	return -1
}

func b1Hex(b []byte) string { return hexutil.Encode(b) }

// ---- H0 ----

func TestB1H0VerifiesOnEveryChainAndLink(t *testing.T) {
	for _, chain := range []uint64{11155111, 84532, 421614, 2017} {
		for _, variant := range []string{world.VariantH0, world.VariantS6Silent, world.VariantHops} {
			t.Run(fmt.Sprintf("%d/%s", chain, variant), func(t *testing.T) {
				f := b1New(t, chain, variant)
				r, _ := f.run(b1All, nil, nil)
				b1Want(t, r, ci.JudgedAuthorizationAttest, "verified", "")
				b := f.facts.B1
				if !b.AttestCaptured || !b.HeaderLinked || b.HopChain.Walked == 0 {
					t.Fatalf("facts after H0: %+v", b)
				}
				wantLink := ci.LinkSpine
				if variant == world.VariantHops {
					wantLink = ci.LinkHops
				}
				if b.HopChain.Link != wantLink {
					t.Fatalf("link %d, want %d", b.HopChain.Link, wantLink)
				}
				if b.AttestTx == nil || b.AttestTx.To() == nil || *b.AttestTx.To() != f.addr(f.spec.Roles.Anchor) {
					t.Fatalf("attestation tx %v", b.AttestTx)
				}
				if b.MessageHash == ([32]byte{}) || b.PKC == ([32]byte{}) || common.Hash(b.MessageRecomputed) != common.Hash(b.MessageHash) {
					t.Fatalf("message %x recomputed %x pkc %x", b.MessageHash, b.MessageRecomputed, b.PKC)
				}
				if b.StateRootPre == ([32]byte{}) || b.StateRootPost == ([32]byte{}) || b.HeaderV.Number != f.spec.Blocks.Attest.Number {
					t.Fatalf("headers: %+v", b.HeaderV)
				}
				if b.Call.OuterSigned == nil || len(b.Call.ValidatorAddresses) != len(b.Call.VotingPowers) || b.Call.BlobInnerTotal == nil {
					t.Fatalf("call %+v", b.Call)
				}
			})
		}
	}
}

// ---- step 15 ----

func TestB1Step15StatedAttest(t *testing.T) {
	f := b1New(t, 11155111, world.VariantH0)
	statedWith := func(reason, detail string) []byte {
		return f.edit(func(c *ci.Container) {
			c.Attest = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: 77, JudgedHash: [32]byte{7}, Detail: detail,
				Failures: []ci.ProviderFailure{{Host: "h", Error: "e"}}}}
		})
	}
	for _, reason := range []string{ci.StatedCaptureNotAttemptedInWindow, ci.StatedStateUnavailable, ci.StatedAttestBlockStateUnavailable} {
		r, _ := f.run(b1All, statedWith(reason, ""), nil)
		b1Want(t, r, ci.JudgedAuthorizationAttest, "unproven", reason, "reason", reason, "part", ci.JudgedAuthorizationAttest, "judgedBlock", "77")
		b1Want(t, r, ci.JudgedIntraBlockWindow, "unproven", "attest_absent", "part", ci.JudgedIntraBlockWindow)
		b1Want(t, r, ci.JudgedRegistryLink, "unproven", "attest_absent", "part", ci.JudgedRegistryLink)
	}
	r, _ := f.run(b1All, statedWith(ci.StatedAttestEventNotFound, ""), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "unproven", "attest_event_not_found", "part", ci.JudgedAuthorizationAttest)
	r, _ = f.run(b1All, statedWith(ci.StatedBlockTooLarge, "bytes=1048577;limit=1048576"), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "unproven", "block_too_large", "part", ci.JudgedAuthorizationAttest, "bytes", "1048577", "limit", "1048576")
	b1Want(t, r, ci.JudgedIntraBlockWindow, "unproven", "block_too_large", "part", ci.JudgedIntraBlockWindow, "bytes", "1048577", "limit", "1048576")
	r, _ = f.run(b1All, statedWith(ci.StatedBlockTooLarge, "txs=4097;limit=4096"), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "unproven", "block_too_large", "bytes", "4097", "limit", "4096")
	r, _ = f.run(b1All, statedWith(ci.StatedAttestBlockOutOfReach, "gap=8192;window=8191;hops_carried=0;last_hop=11950123"), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "unproven", "attest_block_out_of_reach", "gap", "8192", "window", "8191", "hops_carried", "0", "last_hop", "11950123")
	b1Want(t, r, ci.JudgedIntraBlockWindow, "unproven", "attest_absent")
	// a Stated part never raises a status: no part is verified by it and the headline is not verified
	if r.Headline.Kind == ci.HeadlineVerified || r.Headline.Kind == ci.HeadlineVerifiedCore {
		t.Fatalf("headline %s over a Stated attest part", r.Headline.Kind)
	}
	// a reason outside the six builders and an unparseable detail are framework refusals
	for _, c := range []struct{ reason, detail, wantReason string }{
		{"some_new_reason", "", "unknown_stated_reason"},
		{ci.StatedBlockTooLarge, "limit=1", "bad_stated_reason"},
		{ci.StatedBlockTooLarge, "bytes=1;limit=99999999999999999999", "bad_stated_reason"},
		{ci.StatedAttestBlockOutOfReach, "gap=1", "bad_stated_reason"},
	} {
		r, _ := f.run(b1All, statedWith(c.reason, c.detail), nil)
		if r.Headline.Kind != ci.HeadlineRefused || r.Headline.First == nil || r.Headline.First.Code != ci.CodeEvidenceMalformed ||
			fmt.Sprint(r.Headline.First.Fields["reason"]) != c.wantReason || fmt.Sprint(r.Headline.First.Fields["part"]) != "attest" {
			t.Fatalf("%s/%q: headline %s first %v", c.reason, c.detail, r.Headline.Kind, r.Headline.First)
		}
	}
}

// ---- step 16 ----

func TestB1Step16Spine(t *testing.T) {
	f := b1New(t, 11155111, world.VariantH0)
	step16 := []ci.StepID{ci.Step15, ci.Step16}
	spineCase := func(name string, fn func(c *ci.Container), code string, kv ...string) {
		t.Run(name, func(t *testing.T) {
			r, _ := f.run(step16, f.edit(fn), nil)
			b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", code, kv...)
		})
	}
	n := len(f.spec.Blocks.Between)
	if n < 2 {
		t.Fatalf("H0 spine has %d between headers", n)
	}
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-1] ^= 1; return c }
	spineCase("a spine header altered", func(c *ci.Container) { c.Attest.Attest.Spine[1] = flip(c.Attest.Attest.Spine[1]) }, "header_unlinked", "link", "spine", "index", "1", "reason", "hash_chain_broken")
	spineCase("the first spine header is altered", func(c *ci.Container) { c.Attest.Attest.Spine[0] = flip(c.Attest.Attest.Spine[0]) }, "header_unlinked", "index", "0", "reason", "hash_chain_broken")
	spineCase("spine reordered", func(c *ci.Container) {
		s := c.Attest.Attest.Spine
		s[0], s[1] = s[1], s[0]
	}, "header_unlinked", "index", "0", "reason", "hash_chain_broken")
	spineCase("a header dropped from the spine", func(c *ci.Container) {
		s := c.Attest.Attest.Spine
		c.Attest.Attest.Spine = append(s[:1:1], s[2:]...)
	}, "header_unlinked", "index", "1", "reason", "hash_chain_broken")
	spineCase("empty spine", func(c *ci.Container) { c.Attest.Attest.Spine = nil }, "header_unlinked", "link", "spine", "index", "0", "reason", "hash_chain_broken")
	spineCase("the spine does not end at headerV", func(c *ci.Container) { c.Attest.Attest.HeaderV = flip(c.Attest.Attest.HeaderV) }, "header_unlinked", "reason", "hash_chain_broken")
	spineCase("headerVParent is not the parent", func(c *ci.Container) { c.Attest.Attest.HeaderVParent = flip(c.Attest.Attest.HeaderVParent) }, "header_unlinked", "index", "0", "reason", "parent_mismatch")
	spineCase("B_v is the settlement block under link 2", func(c *ci.Container) { c.Attest.Attest.HeaderV = f.built.Inputs.Ctx.Settlement.Header }, "attest_mismatch", "field", "order")
	spineCase("a spine header that is no header", func(c *ci.Container) { c.Attest.Attest.Spine[1] = []byte{0x01, 0x02} }, "header_unlinked", "index", "1", "reason", "hash_chain_broken")
}

func TestB1Step16SameBlock(t *testing.T) {
	f := b1New(t, 11155111, world.VariantH0)
	step16 := []ci.StepID{ci.Step15, ci.Step16}
	settleIdx := uint32(f.built.Inputs.Ctx.Settlement.Tx.LeafIndex)
	if settleIdx == 0 {
		t.Fatal("the settlement transaction is the first of its block: no txIndex below it")
	}
	same := func(txIndex uint32, hv func(c *ci.Container) []byte) []byte {
		return f.edit(func(c *ci.Container) {
			a := c.Attest.Attest
			a.HeaderVParent = a.Spine[0] // the header of N-1 is the parent of the settlement header
			a.Link, a.Spine, a.HopHeaders = ci.LinkSameBlock, nil, nil
			a.HeaderV = hv(c)
			a.TxIndex = txIndex
		})
	}
	settleHeader := func(*ci.Container) []byte { return f.built.Inputs.Ctx.Settlement.Header }
	// N-1 passes, N fails: the order rule is exact
	r, _ := f.run(step16, same(settleIdx-1, settleHeader), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "verified", "")
	r, _ = f.run(step16, same(settleIdx, settleHeader), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "attest_mismatch", "field", "order")
	r, _ = f.run(step16, same(settleIdx+1, settleHeader), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "attest_mismatch", "field", "order")
	// headerV is not the settlement block
	r, _ = f.run(step16, same(0, func(c *ci.Container) []byte { return c.Attest.Attest.HeaderVParent }), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "header_unlinked", "link", "same_block", "index", "0", "reason", "hash_chain_broken")
}

// readAuth is the stand-in of step 18: it makes exactly the reads of the world's plan for the AUTH slot set at both attestation stations
// (rows A01-A21, V01-V03, C01), so that step 22b judges the container against the reads of the whole algorithm. It records no word.
func (f *b1fx) readAuth(env *ci.Env) error {
	sp := f.spec
	A, V, G, O := f.addr(sp.Roles.Anchor), f.addr(sp.Roles.Verifier), f.addr(sp.Roles.Groth16), f.addr(sp.Roles.Owner)
	anchorID := common.HexToHash(sp.Settlement.AnchorID)
	opID := common.Hash(env.Ctx.Batch.OperationID)
	pkc := common.Hash(env.Facts.B1.PKC)
	for _, root := range []common.Hash{common.Hash(env.Facts.B1.StateRootPre), common.Hash(env.Facts.B1.StateRootPost)} {
		acct := map[common.Address]ci.AccountState{}
		for _, a := range []common.Address{A, V, G, O} {
			s, err := ci.ReadAccount(root, env.Nodes, a)
			if err != nil {
				return err
			}
			acct[a] = s
		}
		rd := func(a common.Address, s common.Hash) (common.Hash, error) {
			return ci.ReadSlot(acct[a].StorageRoot, env.Nodes, s)
		}
		rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
		slots := []common.Hash{ci.SlotIndex(0), ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2), ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3),
			ci.MappingSlotAt(ci.KeyBytes32(pkc), 4), ci.SlotIndex(5), ci.SlotIndex(6)}
		for k := uint64(0); k < 13; k++ {
			slots = append(slots, ci.MemberSlot(rec, k))
		}
		for _, s := range slots {
			if _, err := rd(A, s); err != nil {
				return err
			}
		}
		n, err := rd(A, ci.SlotIndex(13))
		if err != nil {
			return err
		}
		for i := uint64(0); i < n.Big().Uint64(); i++ {
			el, _, _ := ci.ArrayElementSlot(13, i, 20)
			v, err := rd(A, el)
			if err != nil {
				return err
			}
			base := ci.MappingSlotAt(ci.KeyAddress(common.BytesToAddress(v[12:])), 12)
			for _, s := range []common.Hash{base, ci.MemberSlot(base, 1), ci.MemberSlot(base, 3)} {
				if _, err := rd(A, s); err != nil {
					return err
				}
			}
			if _, err := ci.ReadBytes(acct[A].StorageRoot, env.Nodes, ci.MemberSlot(base, 2), 256); err != nil {
				return err
			}
		}
		for _, s := range []uint64{14, 15, 16, 17, 27, 29, 30} {
			if _, err := rd(A, ci.SlotIndex(s)); err != nil {
				return err
			}
		}
		if _, err := rd(A, ci.MappingSlotAt(ci.KeyBytes32(opID), 18)); err != nil {
			return err
		}
		for s := uint64(0); s < 3; s++ {
			if _, err := rd(V, ci.SlotIndex(s)); err != nil {
				return err
			}
		}
	}
	return nil
}
