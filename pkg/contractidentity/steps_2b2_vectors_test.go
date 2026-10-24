// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The vector set s8_2b2_1: the VS8 rows of steps 18, 18b, 19 and 22 (ids 120-139, 170-178; 176 is decided by step 15 but authored here), each a
// few mutation lines on H0 with an expectation DERIVED FROM THE SPECIFICATION TEXT (V2_SPEC_S8 r3.2, "Policy rules" and its verdict precedence
// D4, steps 18-22, Item 3 field lists). The expectation names the parts of this package (authorization_attest, intra_block_window,
// code_identity, record for VS8-125); the headline is the one the full verifier yields when package 2c judges its parts as verified. The set
// is written once (CERTEN_WRITE_S8_2B2=1); world.WriteSet refuses a published set.

const vectorSet2b2 = "s8_2b2_1"

// naivePrePostAccepts are the vectors a naive verifier that compares only the AUTH words of pre and post (and the rules on them) ACCEPTS: no
// word differs, every rule passes, only the owner's account (nonce, code) or the transaction list shows the problem. The integration negative
// control NaivePrePost (package 2c) must accept each of them while the real verifier does not return `verified`.
var naivePrePostAccepts = []string{"VS8-171.owner_code_pre", "VS8-171.owner_code_post", "VS8-171.owner_nonce_differs", "VS8-171.owner_sent_attestation",
	"VS8-172", "VS8-173.delegation_set_and_cleared", "VS8-178.sepolia_0x05"}

type b2author struct {
	t   *testing.T
	by  map[uint64]*b2fx
	out []ci.Vector
}

func (a *b2author) add(id string, e ci.Expected, muts ...ci.Mutation) {
	a.out = append(a.out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
}

func (a *b2author) fx(chain uint64) *b2fx {
	if f, ok := a.by[chain]; ok {
		return f
	}
	f := b2New(a.t, chain, world.VariantH0)
	f.verify()
	a.by[chain] = f
	return f
}

func lowerHex(h common.Hash) string { return strings.ToLower(h.Hex()) }

func (a *b2author) vectors() []ci.Vector {
	a.out = nil
	f := a.fx(11155111)
	w := f.facts.B2.Pre.Words
	post := f.facts.B2.Post.Words
	m := f.m
	pol := m.Policy()
	A, V, O := f.addr(f.spec.Roles.Anchor), f.addr(f.spec.Roles.Verifier), f.addr(f.spec.Roles.Owner)
	anchorID := common.HexToHash(f.spec.Settlement.AnchorID)
	opID := common.Hash(f.built.Inputs.Ctx.Batch.OperationID)
	pkc := common.Hash(f.facts.B1.PKC)
	bv := f.spec.Blocks.Attest.Number
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	rec10, used := ci.MemberSlot(rec, 10), ci.MappingSlotAt(ci.KeyBytes32(opID), 18)
	auth, win, code := ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow, ci.JudgedCodeIdentity
	pre, pst := world.StationPre, world.StationPost
	ownerNonce := f.spec.Stations[pre].Accounts[strings.ToLower(O.Hex())].Nonce
	ratio := func(n, d uint64) string { return fmt.Sprintf("%d/%d", n, d) }
	wantA, wantV := ratio(pol.BLSThreshold.Numerator, pol.BLSThreshold.Denominator), ratio(pol.VerifierThreshold.Numerator, pol.VerifierThreshold.Denominator)

	setA := func(st string, slot, v common.Hash) ci.Mutation { return world.SetStorage(st, A, slot, v) }
	bothA := func(slot, v common.Hash) []ci.Mutation { return []ci.Mutation{setA(pre, slot, v), setA(pst, slot, v)} }
	cat := func(l ...[]ci.Mutation) []ci.Mutation {
		var out []ci.Mutation
		for _, x := range l {
			out = append(out, x...)
		}
		return out
	}
	one := func(m ci.Mutation) []ci.Mutation { return []ci.Mutation{m} }
	nonce := func(st string, n uint64) []ci.Mutation { return one(world.SetNonce(st, O, n)) }
	bit := func(h common.Hash, i int, v byte) common.Hash { h[i] = v; return h }
	slot30 := func() common.Hash { // the H0 word of anchor slot 30: verifier address, enabled, min level, min level for value ops
		var x common.Hash
		copy(x[12:], V[:])
		x[11], x[10], x[9] = byte(b2n(w["A19"])), byte(b2n(w["A20"])), byte(b2n(w["A21"]))
		return x
	}()

	// expectations
	hl := func(headline string, parts map[string]string, states ...ci.ExpectedState) ci.Expected {
		return b1exp(headline, parts, states...)
	}
	changed := func(row string, p, q common.Hash) ci.Expected {
		return hl(ci.HeadlineUnproven, map[string]string{auth: "unproven"}, b1unproven(auth, map[string]any{"reason": "state_changed_in_block", "field": row, "pre": p, "post": q, "block": bv}))
	}
	refusedAuth := func(code string, fields map[string]any) ci.Expected {
		return hl(ci.HeadlineRefused, map[string]string{auth: "refused", win: "verified"}, b1est(auth, code, fields))
	}
	mismatch := func(field string, onchain, want any) ci.Expected {
		return refusedAuth("authorization_mismatch", map[string]any{"field": field, "onchain": onchain, "want": want, "at": "attest_pre"})
	}
	flip := hl(ci.HeadlineRefused, map[string]string{auth: "refused"}, b1est(auth, "attest_mismatch", map[string]any{"field": "flip"}))
	windowU := func(reason string, fields map[string]any) ci.ExpectedState {
		fields["reason"], fields["part"] = reason, win
		return b1unproven(win, fields)
	}
	ownerActive := func(n uint64) ci.ExpectedState {
		return windowU("owner_active_in_block", map[string]any{"address": O, "pre": ownerNonce, "post": n})
	}

	// ---- VS8-120: each AUTH row differs between pre and post (post altered) ----
	other := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000a7")
	type row struct {
		id   string
		slot common.Hash
		val  common.Hash
		acct common.Address
		name string
	}
	v0 := f.facts.B2.Validators[0].Address
	vbase := ci.MappingSlotAt(ci.KeyAddress(v0), 12)
	for _, r := range []row{
		{"A01", ci.SlotIndex(0), ci.SlotIndex(1), A, "A01"}, {"A02:11", ci.MemberSlot(rec, 11), other, A, "A02_word11"}, {"A03", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2), ci.SlotIndex(0), A, "A03"},
		{"A04", ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3), other, A, "A04"}, {"A05", ci.MappingSlotAt(ci.KeyBytes32(pkc), 4), ci.SlotIndex(0), A, "A05"},
		{"A07", ci.SlotIndex(5), other, A, "A07"}, {"A08", ci.SlotIndex(6), ci.SlotIndex(0), A, "A08"}, {"A09:" + b2lower(v0) + ":1", ci.MemberSlot(vbase, 1), other, A, "A09_power"},
		{"A11", ci.SlotIndex(14), other, A, "A11"}, {"A12", ci.SlotIndex(15), other, A, "A12"}, {"A13", ci.SlotIndex(16), other, A, "A13"}, {"A14", ci.SlotIndex(17), other, A, "A14"},
		{"A17", ci.SlotIndex(29), common.BytesToHash(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()), A, "A17"},
		{"V01", ci.SlotIndex(0), other, V, "V01"}, {"V02", ci.SlotIndex(1), other, V, "V02"},
	} {
		a.add("VS8-120."+r.name, changed(r.id, w[r.id], r.val), world.SetStorage(pst, r.acct, r.slot, r.val))
	}
	for _, r := range []struct {
		id string
		by int
	}{{"A19", 11}, {"A20", 10}, {"A21", 9}} {
		x := slot30
		x[r.by] ^= 1
		a.add("VS8-120."+r.id, changed(r.id, w[r.id], b2h(uint64(x[r.by]))), setA(pst, ci.SlotIndex(30), x))
	}
	post0 := f.facts.B2.Post.Accounts["A"].CodeHash
	a.add("VS8-120.C01", hl(ci.HeadlineRefused, map[string]string{auth: "unproven", code: "refused"},
		b1unproven(auth, map[string]any{"reason": "state_changed_in_block", "field": "C01:A", "pre": post0, "post": f.keccak([]byte{0}), "block": bv}),
		b1est(code, "code_unproven_bytes", map[string]any{"address": A})), world.SetCode(pst, A, world.CodeSpec{Hex: "0x00"}))

	// ---- VS8-121 / 122 / 123 / 124: the flips and the byte rule ----
	w10 := w["A02:10"]
	a.add("VS8-121.used_commitment_already_1_at_pre", flip, one(setA(pre, used, ci.SlotIndex(1)))...)
	a.add("VS8-121.proof_executed_already_1_at_pre", flip, one(setA(pre, rec10, bit(w10, 10, 1)))...)
	a.add("VS8-121.no_flip_in_the_block", flip, one(setA(pst, used, ci.SlotIndex(0)))...)
	a.add("VS8-122.governance_executed_0_to_1_passes", hl(ci.HeadlineVerified, map[string]string{auth: "verified"}), one(setA(pst, rec10, bit(post["A02:10"], 9, 1)))...)
	a.add("VS8-122.governance_executed_already_1_at_pre", flip, setA(pre, rec10, bit(w10, 9, 1)), setA(pst, rec10, bit(post["A02:10"], 9, 1)))
	a.add("VS8-122.bytes_24_31_nonzero", changed("A02:10", w10, bit(post["A02:10"], 0, 1)), one(setA(pst, rec10, bit(post["A02:10"], 0, 1)))...)
	vb31 := post["A02:10"]
	vb31[31] ^= 1
	a.add("VS8-122.validator_bytes_differ", changed("A02:10", w10, vb31), one(setA(pst, rec10, vb31))...)
	a.add("VS8-122.governance_level_not_the_decoded_one", flip, one(setA(pst, rec10, bit(post["A02:10"], 8, post["A02:10"][8]+1)))...)
	a.add("VS8-123.governance_level_pre_1", flip, one(setA(pre, rec10, bit(w10, 8, 1)))...)
	a.add("VS8-124.record_created_in_b_v", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven"}, b1unproven(auth, map[string]any{"reason": "record_created_in_block", "block": bv})), one(setA(pre, rec10, bit(w10, 11, 0)))...)
	a.add("VS8-125.recreated_record", hl(ci.HeadlineRefused, map[string]string{ci.JudgedRecord: "refused"}, b1est(ci.JudgedRecord, "record_not_executed", map[string]any{"anchorId": anchorID, "valid": true, "proofExecuted": false})),
		one(world.SetStorage(world.StationSettle, A, rec10, bit(w10, 10, 0)))...)

	// ---- VS8-125 (step 18b, lemma U): the premises of the lemma on the records of B_v ----
	a.add("VS8-125.not_a_batch_anchor", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven"}, b1unproven(auth, map[string]any{"reason": "anchor_not_batch", "anchorId": anchorID})),
		bothA(ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2), ci.SlotIndex(0))...)
	a.add("VS8-125.operation_id_not_the_key", flip, bothA(ci.MemberSlot(rec, 7), other)...)
	a.add("VS8-125.bundle_id_not_recomputed", hl(ci.HeadlineRefused, map[string]string{auth: "refused"}, b1est(auth, "record_inconsistent", map[string]any{"field": "bundle_id"})),
		bothA(ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3), other)...)

	// ---- VS8-130 .. 139: the rules (R only with equal words, a failing predicate at both stations and rule IB verified) ----
	a.add("VS8-130.binding_off", mismatch("binding", uint64(0), uint64(1)), bothA(ci.SlotIndex(6), common.Hash{})...)
	a.add("VS8-130.anchor_threshold", mismatch("threshold", ratio(3, pol.BLSThreshold.Denominator), wantA), bothA(ci.SlotIndex(15), ci.SlotIndex(3))...)
	a.add("VS8-130.verifier_threshold", mismatch("verifier_threshold", ratio(0, pol.VerifierThreshold.Denominator), wantV),
		world.SetStorage(pre, V, ci.SlotIndex(0), common.Hash{}), world.SetStorage(pst, V, ci.SlotIndex(0), common.Hash{}))
	en := slot30
	en[11] = 0
	a.add("VS8-130.enabled_off", mismatch("enabled", uint64(0), uint64(1)), bothA(ci.SlotIndex(30), en)...)
	a.add("VS8-130.commitment_not_authorized", refusedAuthCommit(pkc), bothA(ci.MappingSlotAt(ci.KeyBytes32(pkc), 4), common.Hash{})...)
	newPKC := common.HexToHash("0xabcdef")
	a.add("VS8-130.pkc_changed_in_calldata", refusedAuthCommit(newPKC), world.Set("attestation.blob.13", newPKC.Hex()))
	a.add("VS8-131.set_root_not_the_registry_root", mismatch("set_root", other, w["A14"]), bothA(ci.SlotIndex(17), other)...)
	a.add("VS8-133.paused_at_both", mismatch("paused", uint64(1), uint64(0)), bothA(ci.SlotIndex(0), ci.SlotIndex(1))...)
	gv := common.HexToAddress("0x1111111111111111111111111111111111111111")
	a.add("VS8-134.governance_verifier_set", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven"}, b1unproven(auth, map[string]any{"reason": "governance_verifier_unpinned", "address": gv, "at": "attest_pre"})),
		bothA(ci.SlotIndex(29), common.BytesToHash(gv.Bytes()))...)
	ml := slot30
	ml[10] = 0
	a.add("VS8-135.minimum_governance_level_0", mismatch("minimum_governance_level", uint64(0), uint64(pol.MinimumGovernanceLevel)), bothA(ci.SlotIndex(30), ml)...)
	a.add("VS8-136.binding_1_to_0_after_the_attestation", changed("A08", w["A08"], common.Hash{}), one(setA(pst, ci.SlotIndex(6), common.Hash{}))...)
	a.add("VS8-137.binding_0_to_1_before_the_attestation", changed("A08", common.Hash{}, post["A08"]), one(setA(pre, ci.SlotIndex(6), common.Hash{}))...)
	a.add("VS8-137.paused_1_to_0", changed("A01", ci.SlotIndex(1), post["A01"]), one(setA(pre, ci.SlotIndex(0), ci.SlotIndex(1)))...)
	a.add("VS8-138.binding_0_at_both_owner_toggled", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven", win: "unproven"},
		b1unproven(auth, map[string]any{"reason": "owner_active_in_block", "part": auth, "address": O, "pre": ownerNonce, "post": ownerNonce + 1}), ownerActive(ownerNonce+1)),
		cat(bothA(ci.SlotIndex(6), common.Hash{}), nonce(pst, ownerNonce+1))...)
	a.add("VS8-139.binding_0_owner_untouched_ib_verified", mismatch("binding", uint64(0), uint64(1)), bothA(ci.SlotIndex(6), common.Hash{})...)
	fill := a.filler(11155111)
	a.add("VS8-139.binding_0_ib_unproven_tx_type", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven", win: "unproven"},
		b1unproven(auth, map[string]any{"reason": "tx_type_unsupported", "part": auth, "type": "0x05", "index": uint64(fill)}),
		windowU("tx_type_unsupported", map[string]any{"type": "0x05", "index": uint64(fill)})),
		cat(bothA(ci.SlotIndex(6), common.Hash{}), one(world.Set(fmt.Sprintf("blocks.attest.txs.%d.wire", fill), "0x05c0")))...)

	// ---- VS8-170 .. 178: rule IB ----
	winOnly := func(headline string, s ci.ExpectedState) ci.Expected {
		return hl(headline, map[string]string{win: "unproven", auth: "verified"}, s)
	}
	a.add("VS8-170.honest_block", hl(ci.HeadlineVerified, map[string]string{win: "verified", auth: "verified", code: "verified"}))
	ownerCode := world.CodeSpec{Hex: "0x6000"}
	a.add("VS8-171.owner_code_pre", winOnly(ci.HeadlineUnproven, windowU("owner_not_eoa", map[string]any{"address": O})), one(world.SetCode(pre, O, ownerCode))...)
	a.add("VS8-171.owner_code_post", winOnly(ci.HeadlineUnproven, windowU("owner_not_eoa", map[string]any{"address": O})), one(world.SetCode(pst, O, ownerCode))...)
	a.add("VS8-171.owner_nonce_differs", winOnly(ci.HeadlineUnproven, ownerActive(ownerNonce+1)), nonce(pst, ownerNonce+1)...)
	a.add("VS8-171.owner_sent_attestation", winOnly(ci.HeadlineUnproven, ownerActive(ownerNonce+1)), nonce(pst, ownerNonce+1)...)
	a.add("VS8-172", winOnly(ci.HeadlineUnproven, ownerActive(ownerNonce+2)), nonce(pst, ownerNonce+2)...)
	a.add("VS8-173.delegation_set_and_cleared", winOnly(ci.HeadlineUnproven, ownerActive(ownerNonce+1)), nonce(pst, ownerNonce+1)...)
	a.add("VS8-173.persistent_set_threshold", hl(ci.HeadlineUnproven, map[string]string{auth: "unproven", win: "unproven"},
		b1unproven(auth, map[string]any{"reason": "state_changed_in_block", "field": "A12", "pre": w["A12"], "post": ci.SlotIndex(3), "block": bv}), ownerActive(ownerNonce+1)),
		cat(one(setA(pst, ci.SlotIndex(15), ci.SlotIndex(3))), nonce(pst, ownerNonce+1))...)
	root0 := f.built.Inputs.Container
	c0, err := ci.Decode(root0, ci.DefaultLimits())
	if err != nil {
		a.t.Fatal(err)
	}
	tx0 := c0.Attest.Attest.BlockTxs[0]
	bad := append([]byte(nil), tx0...)
	bad[len(bad)-1] ^= 1
	a.add("VS8-174.block_txs_root_mismatch", hl(ci.HeadlineRefused, map[string]string{win: "refused"}, b1est(win, "attest_mismatch", map[string]any{"field": "block_txs"})),
		b1cont("attest.attest.block_txs.0", b1hexNo(bad)))
	for _, d := range []struct{ id, detail string }{{"txs_cap", "txs=4097;limit=4096"}, {"bytes_cap", "bytes=1048577;limit=1048576"}} {
		st := ci.Stated{State: ci.StatedState, Reason: ci.StatedBlockTooLarge, JudgedBlock: 77, JudgedHash: [32]byte(bytes.Repeat([]byte{7}, 32)), Detail: d.detail}
		c := *c0
		c.Attest = ci.Part{Tag: ci.TagStated, Stated: &st}
		raw, err := ci.Encode(&c, ci.DefaultLimits())
		if err != nil {
			a.t.Fatal(err)
		}
		f.verifierRun(raw)
		nodes := make([]string, len(f.visited))
		for i, n := range f.visited {
			nodes[i] = b1hexNo(n)
		}
		n, lim := uint64(4097), uint64(4096)
		if d.id == "bytes_cap" {
			n, lim = 1048577, 1048576
		}
		a.add("VS8-176."+d.id, hl(ci.HeadlineUnproven, map[string]string{win: "unproven"}, b1unproven(win, map[string]any{"reason": "block_too_large", "part": win, "bytes": n, "limit": lim})),
			b1cont("attest", map[string]any{"tag": "2", "stated": map[string]any{"state": ci.StatedState, "reason": ci.StatedBlockTooLarge, "judged_block": "77", "judged_hash": strings.Repeat("07", 32), "failures": []string{}, "detail": d.detail}}),
			b1cont("nodes", nodes))
	}
	gate := func(id, build, cond string, muts ...ci.Mutation) {
		a.add("VS8-177."+id, winOnly(ci.HeadlineUnproven, windowU("build_without_writer_proof", map[string]any{"build": build, "condition": cond})), muts...)
	}
	ab, vb := "CertenAnchorV8_2/r5", "BLSZKVerifierV2_1/r5"
	mf := func(path string, v any) ci.Mutation {
		b, _ := json.Marshal(v)
		return ci.Mutation{Op: "set_field", Target: "manifest", Path: path, Value: b}
	}
	gate("anchor_status_missing", ab, "status_missing", ci.Mutation{Op: "unset_field", Target: "manifest", Path: "builds." + ab + ".authWriters"})
	gate("anchor_condition_c_fails", ab, "c", mf("builds."+ab+".authWriters.status", "fail"), mf("builds."+ab+".authWriters.conditions.c", "fail"))
	gate("verifier_condition_a_fails", vb, "a", mf("builds."+vb+".authWriters.status", "fail"), mf("builds."+vb+".authWriters.conditions.a", "fail"))
	gate("anchor_allowlist_wider", ab, "allowlist_not_frozen", mf("builds."+ab+".authWriterAllowList.rows.4.allowedWrites", []string{"anchors[].governanceExecuted", "anchors[].valid"}))

	// ---- VS8-178: a type that is in neither list of the chain, one vector per (chain, type) ----
	for _, c := range []struct {
		chain uint64
		name  string
		types []byte
	}{{11155111, "sepolia", []byte{0x05}}, {84532, "base", []byte{0x05, 0x01, 0x03}}, {421614, "arbitrum", []byte{0x05, 0x01, 0x78}}, {2017, "adiri", []byte{0x05, 0x01, 0x03, 0x04}}} {
		fl := a.filler(c.chain)
		for _, ty := range c.types {
			muts := one(world.Set(fmt.Sprintf("blocks.attest.txs.%d.wire", fl), fmt.Sprintf("0x%02xc0", ty)))
			if c.chain != 11155111 {
				muts = append(one(world.Set("chain", c.chain)), muts...)
			}
			a.add(fmt.Sprintf("VS8-178.%s_0x%02x", c.name, ty), winOnly(ci.HeadlineUnproven, windowU("tx_type_unsupported", map[string]any{"type": fmt.Sprintf("0x%02x", ty), "index": uint64(fl)})), muts...)
		}
	}
	return a.out
}

func refusedAuthCommit(pkc common.Hash) ci.Expected {
	return b1exp(ci.HeadlineRefused, map[string]string{ci.JudgedAuthorizationAttest: "refused"}, b1est(ci.JudgedAuthorizationAttest, "commitment_not_authorized", map[string]any{"pkc": pkc, "at": "attest_pre"}))
}

func b2n(h common.Hash) uint64        { return new(big.Int).SetBytes(h[:]).Uint64() }
func b2h(n uint64) common.Hash        { return common.BigToHash(new(big.Int).SetUint64(n)) }
func b2lower(a common.Address) string { return lower(a) }

// filler is the index of a transaction of the attestation block that is neither the attestation nor needed by anything else: the "one more
// type-2 transaction" of the world.
func (a *b2author) filler(chain uint64) int {
	f := a.fx(chain)
	for i, tx := range f.spec.Blocks.Attest.Txs {
		if tx.Role != "attestation" && tx.Role == "" && tx.Type == 2 {
			return i
		}
	}
	a.t.Fatalf("no filler transaction on chain %d", chain)
	return -1
}

func (f *b2fx) keccak(b []byte) common.Hash { return crypto.Keccak256Hash(b) }

// verifierRun runs the verifier on a replacement container (the facts and visited nodes are captured by the stand-in of step 23).
func (f *b2fx) verifierRun(container []byte) {
	f.t.Helper()
	if _, _, err := f.verifier().VerifyTrace(f.built.Inputs.Ctx, container, f.m); err != nil {
		f.t.Fatalf("the verifier returned an error: %v", err)
	}
}

func b2Author(t *testing.T) *b2author { return &b2author{t: t, by: map[uint64]*b2fx{}} }

func (a *b2author) verifier() ci.Verifier {
	v := a.fx(11155111).verifier()
	return ci.VerifierFunc(func(ctx ci.LegContext, container []byte, m *ci.Manifest) (ci.Report, error) {
		return v.Verify(ctx, container, m)
	})
}

func TestB2VectorsAgainstTheVerifier(t *testing.T) {
	a := b2Author(t)
	base := a.fx(11155111)
	wj, err := base.spec.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	wj = append(wj, '\n')
	ver := a.verifier()
	ids := map[string]bool{}
	for _, v := range a.vectors() {
		ids[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			in, err := world.Builder{Manifest: base.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("the world cannot build the vector: %v", err)
			}
			m, st, err := in.ResolveManifest()
			if err != nil || st != nil {
				t.Fatalf("manifest: %v %v", err, st)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, m)
			if err != nil {
				t.Fatalf("verifier error: %v", err)
			}
			if err := ci.MatchExpected(v.Expected, rep); err != nil {
				t.Fatalf("%v (headline first %v)", err, rep.Headline.First)
			}
		})
	}
	for _, id := range naivePrePostAccepts {
		if !ids[id] {
			t.Errorf("the NaivePrePost list names %s, which is not a vector of the set", id)
		}
	}
}

// The published set: loaded from disk (every file hash-checked), run WITHOUT the world builder on the materialised inputs and regenerated into a
// temporary directory, which must be byte-identical.
func TestVectorSet2b2IsPublishedRunsAndIsReproducible(t *testing.T) {
	a := b2Author(t)
	vectors := a.vectors()
	dir := filepath.Join("testdata", "contractidentity", "vectors", vectorSet2b2)
	if _, err := os.Stat(dir); err != nil && os.Getenv("CERTEN_WRITE_S8_2B2") == "1" {
		if err := world.WriteSet(dir, a.fx(11155111).spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSet2b2, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	for _, r := range ci.RunSet(set, nil, a.verifier()) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	tmp := filepath.Join(t.TempDir(), "again")
	if err := world.WriteSet(tmp, a.fx(11155111).spec, vectors); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(tmp)
	published, _ := os.ReadDir(dir)
	if len(entries) != len(published) {
		t.Fatalf("regenerated %d files, published %d", len(entries), len(published))
	}
	for _, e := range entries {
		x, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
		y, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if !bytes.Equal(x, y) {
			t.Errorf("file %s differs from the published one", e.Name())
		}
	}
}

// The mutation gate of the specification: each step of package 2b-2 is replaced in turn by a stand-in that reports its parts verified, and at
// least one vector of the set must fail.
func TestEveryStepOfPackage2b2IsKilledByAVector(t *testing.T) {
	a := b2Author(t)
	base := a.fx(11155111)
	wj, err := base.spec.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	wj = append(wj, '\n')
	vectors := a.vectors()
	for _, id := range ci.OwnedBy(ci.Owner2b2) {
		ver := base.verifierWith(id)
		failed := 0
		for _, v := range vectors {
			in, err := world.Builder{Manifest: base.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			m, st, err := in.ResolveManifest()
			if err != nil || st != nil {
				t.Fatalf("manifest: %v %v", err, st)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, m)
			if err != nil || ci.MatchExpected(v.Expected, rep) != nil {
				failed++
			}
		}
		if failed == 0 {
			t.Errorf("step %s disabled and no vector failed", id)
		}
		t.Logf("step %s disabled: %d of %d vectors fail", id, failed, len(vectors))
	}
}
