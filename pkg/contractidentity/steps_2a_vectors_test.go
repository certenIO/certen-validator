// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The vector set s8_2a_1: the VS8 rows of steps 1c-14 (V2_SPEC_S8 r3.2 FINAL, F15 lift). Each vector is a few mutation lines on H0 (Sepolia, h0)
// and an expectation DERIVED FROM THE SPECIFICATION TEXT (the row of Freeze item 5 and the step it names), written before the verifier is
// run; the expectation names the parts of this package only (the headline is the one the full verifier yields when the other packages judge
// their parts of H0 as verified, which they do on every vector below: no vector touches the attestation side).

const (
	vectorSet2a  = "s8_2a_1"
	vectorSet2a2 = "s8_2a_2"
)

func cf(m map[string]any) json.RawMessage {
	b, err := ci.Canonical(m)
	if err != nil {
		panic(err)
	}
	return b
}

func est(part, code string, fields map[string]any) ci.ExpectedState {
	return ci.ExpectedState{Part: part, Code: ci.Prefix + code, Fields: cf(fields)}
}

func exp(headline string, parts map[string]string, states ...ci.ExpectedState) ci.Expected {
	return ci.Expected{Headline: headline, Parts: parts, States: states}
}

func ctxSet(path string, v any) ci.Mutation {
	b, _ := json.Marshal(v)
	return ci.Mutation{Op: "set_field", Target: "context", Path: path, Value: b}
}

func contSet(path string, v any) ci.Mutation {
	b, _ := json.Marshal(v)
	return ci.Mutation{Op: "set_field", Target: "container", Path: path, Value: b}
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

// maskClamp is the mask of the maskRule written independently of the verifier: zero every reference range, ranges clamped to the code.
func maskClamp(code []byte, refs []ci.Ref) []byte {
	out := append([]byte(nil), code...)
	for _, r := range refs {
		for i := r.Start; i < r.Start+r.Length && i < len(out); i++ {
			if i >= 0 {
				out[i] = 0
			}
		}
	}
	return out
}

type author struct {
	t *testing.T
	f *fixture
}

func (a *author) addr(s string) common.Address { return common.HexToAddress(s) }

func (a *author) roles() (acct, anchor, verifier, g16, factory common.Address) {
	r := a.f.spec.Roles
	return a.addr(r.Account), a.addr(r.Anchor), a.addr(r.Verifier), a.addr(r.Groth16), a.addr(r.Factory)
}

// storedWord is the value the H0 world stores in a settle-station slot.
func (a *author) storedWord(who common.Address, slot common.Hash) common.Hash {
	acct := a.f.spec.Stations[world.StationSettle].Accounts[strings.ToLower(who.Hex())]
	return common.HexToHash(acct.Storage[strings.ToLower(slot.Hex())])
}

func (a *author) code(who common.Address) []byte {
	for _, c := range a.f.built.World.Container.Codes {
		if c.Address == [20]byte(who) {
			return append([]byte(nil), c.Runtime...)
		}
	}
	a.t.Fatalf("H0 carries no code for %s", who.Hex())
	return nil
}

func (a *author) build(key string) ci.Build {
	b, ok := a.f.m.Build(key)
	if !ok {
		a.t.Fatalf("no build %s", key)
	}
	return b
}

func refsOf(b ci.Build, name string) []ci.Ref {
	for _, im := range b.Immutables {
		if im.Name == name {
			return im.References
		}
	}
	return nil
}

func allRefs(b ci.Build) []ci.Ref {
	var out []ci.Ref
	for _, im := range b.Immutables {
		out = append(out, im.References...)
	}
	return out
}

func (a *author) setCode(who common.Address, code []byte) ci.Mutation {
	return world.SetCode(world.StationSettle, who, world.CodeSpec{Hex: hx(code)})
}

// notPublished is the expected code_not_published state of `code` against the pinned build.
func (a *author) notPublished(role string, who common.Address, code []byte, b ci.Build) map[string]any {
	return map[string]any{"role": role, "address": who, "code_hash": crypto.Keccak256Hash(code),
		"masked_keccak": crypto.Keccak256Hash(maskClamp(code, allRefs(b))), "want": common.HexToHash(b.Runtime.MaskedKeccak)}
}

// freeByte is an index of code outside every reference range, near the middle.
func freeByte(code []byte, b ci.Build) int {
	refs := allRefs(b)
	for i := len(code) / 2; i < len(code); i++ {
		in := false
		for _, r := range refs {
			in = in || (i >= r.Start && i < r.Start+r.Length)
		}
		if !in {
			return i
		}
	}
	return 0
}

// longWord is the first data word of a long-form (32 byte) string.
func longWord(s string) common.Hash {
	if len(s) != 32 {
		panic("longWord wants exactly 32 bytes")
	}
	return common.BytesToHash([]byte(s))
}

func (a *author) logs() []world.LogSpec {
	return append([]world.LogSpec(nil), a.f.spec.Settlement.Logs...)
}

func (a *author) wire(to common.Address, data []byte) string {
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(a.f.spec.Chain), Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: 21000, To: &to, Data: data})
	b, err := tx.MarshalBinary()
	if err != nil {
		a.t.Fatal(err)
	}
	return hx(b)
}

const settleTxPath = "blocks.settle.txs.2"

var mine = []string{ci.JudgedSettlementPath, ci.JudgedCodeIdentity, ci.JudgedAccountProvenance, ci.JudgedPointer, ci.JudgedAuthorityLevel, ci.JudgedRecord}

func allMine(status string, except ...string) map[string]string {
	m := map[string]string{}
	for _, p := range mine {
		m[p] = status
	}
	for _, e := range except {
		delete(m, e)
	}
	return m
}

func only(part, status string) map[string]string { return map[string]string{part: status} }

func unp(reason string, extra map[string]any) map[string]any {
	m := map[string]any{"reason": reason}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func bytes32(b byte) [32]byte {
	var o [32]byte
	for i := range o {
		o[i] = b
	}
	return o
}

func merge(a, b map[string]string) map[string]string {
	o := map[string]string{}
	for k, v := range a {
		o[k] = v
	}
	for k, v := range b {
		o[k] = v
	}
	return o
}

func withoutAddr(l []string, a common.Address) []string {
	out := []string{}
	for _, c := range l {
		if !strings.EqualFold(c, a.Hex()) {
			out = append(out, c)
		}
	}
	return out
}

func flipByte(c []byte, i int) []byte {
	d := append([]byte(nil), c...)
	d[i] ^= 0xff
	return d
}

func (a *author) vectors() []ci.Vector {
	acct, anchor, verifier, g16, factory := a.roles()
	spec := a.f.spec
	decoy := a.addr("0x1111111111111111111111111111111111111111")
	leg := a.f.built.World.Container.Leg
	anchorID := common.HexToHash(spec.Settlement.AnchorID)
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	to32 := func(c common.Address) common.Hash { return common.BytesToHash(c[:]) }
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		if muts == nil {
			muts = []ci.Mutation{}
		}
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	selSettle := ci.Selector4(ci.SigExecuteGovernanceDirect)
	leaf := func(addr common.Address, key common.Hash) world.LogSpec {
		return world.LogSpec{Address: strings.ToLower(addr.Hex()), Topics: []string{hx(ci.TopicOf(ci.SigLeafConsumed).Bytes()), hx(anchorID.Bytes()), hx(key.Bytes())}, Data: hx(common.HexToHash(spec.Context.Batch.OperationID).Bytes())}
	}
	opLog, leafLog := a.logs()[0], a.logs()[1]
	leafKey := common.HexToHash(leafLog.Topics[2])
	silent := world.Set("variant", world.VariantS6Silent)
	zero := 0

	// ---- 1c ----
	add("VS8-019", exp(ci.HeadlineUnproven, allMine("unproven"), est(ci.JudgedSettlementPath, "unproven", map[string]any{"part": "all", "reason": "no_evidence_in_file"})),
		ci.Mutation{Op: "truncate", Target: "container", Length: &zero})
	stated := func(reason string) []ci.Mutation {
		muts := []ci.Mutation{contSet("settle", map[string]any{"tag": "2", "stated": map[string]any{"state": ci.StatedState, "reason": reason,
			"judged_block": fmt.Sprint(leg.Number), "judged_hash": hex.EncodeToString(leg.Hash[:]), "failures": []map[string]string{{"host": "rpc.example", "error": "pruned"}}, "detail": ""}})}
		for _, i := range a.attestOnlyDrops() {
			ix := i
			muts = append(muts, ci.Mutation{Op: "drop_node", Target: "container", Index: &ix})
		}
		return muts
	}
	carried := func(reason, part string) ci.ExpectedState {
		return est(part, "unproven", map[string]any{"reason": reason, "part": part, "judgedBlock": leg.Number, "judgedHash": leg.Hash,
			"failures": []any{map[string]any{"host": "rpc.example", "error": "pruned"}}})
	}
	for _, r := range []string{"state_unavailable", "capture_not_attempted_in_window"} {
		var st []ci.ExpectedState
		for _, p := range []string{ci.JudgedSettlementPath, ci.JudgedCodeIdentity, ci.JudgedAccountProvenance, ci.JudgedPointer, ci.JudgedRecord, ci.JudgedAuthorityLevel, ci.JudgedStateAtSettlement} {
			st = append(st, carried(r, p))
		}
		parts := allMine("unproven")
		parts[ci.JudgedStateAtSettlement] = "unproven"
		add("VS8-022."+r, exp(ci.HeadlineUnproven, parts, st...), stated(r)...)
	}
	add("VS8-023.same_block", exp(ci.HeadlineUnproven, only(ci.JudgedS6Link, "verified")), stated("state_unavailable")...)
	later := append(stated("state_unavailable"), ctxSet("s6.proven_at.number", fmt.Sprint(leg.Number+5)), ctxSet("s6.proven_at.hash", hx(func() []byte { b := bytes32(9); return b[:] }())))
	add("VS8-023.later_proven_at", exp(ci.HeadlineUnproven, only(ci.JudgedS6Link, "unproven"), carried("state_unavailable", ci.JudgedS6Link)), later...)
	for _, r := range []string{"made_up_reason", "attest_event_not_found"} {
		add("VS8-024.settle_"+r, exp(ci.HeadlineRefused, nil, ci.ExpectedState{Part: "first", Code: ci.Prefix + "evidence_malformed",
			Fields: cf(map[string]any{"part": "settle", "index": uint64(0), "reason": "unknown_stated_reason", "got_len": uint64(0), "want_len": uint64(0)})}),
			contSet("settle", map[string]any{"tag": "2", "stated": map[string]any{"state": ci.StatedState, "reason": r, "judged_block": "1", "judged_hash": strings.Repeat("00", 32), "failures": []string{}, "detail": ""}}))
	}

	// ---- 2 ----
	first := func(code string, f map[string]any) ci.ExpectedState {
		return ci.ExpectedState{Part: "first", Code: ci.Prefix + code, Fields: cf(f)}
	}
	add("VS8-030.number", exp(ci.HeadlineRefused, nil, first("block_mismatch", map[string]any{"field": "number", "want": leg.Number, "got": leg.Number + 1})), contSet("leg.number", fmt.Sprint(leg.Number+1)))
	flipped := leg.Hash
	flipped[0] ^= 1
	add("VS8-030.hash", exp(ci.HeadlineRefused, nil, first("block_mismatch", map[string]any{"field": "hash", "want": leg.Hash, "got": flipped})), contSet("leg.hash", hex.EncodeToString(flipped[:])))
	add("VS8-030.chain", exp(ci.HeadlineRefused, nil, first("block_mismatch", map[string]any{"field": "chain", "want": spec.Chain, "got": spec.Chain + 1})), contSet("chain", fmt.Sprint(spec.Chain+1)))

	// ---- 3 ----
	rcpt, err := (&types.Receipt{Type: 2, Status: types.ReceiptStatusFailed, CumulativeGasUsed: 21000}).MarshalBinary()
	if err != nil {
		a.t.Fatal(err)
	}
	add("VS8-040", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), est(ci.JudgedSettlementPath, "unproven", unp("settlement_not_executed", map[string]any{"status": []byte{}}))),
		world.Set(settleTxPath+".receipt", hx(rcpt)))
	add("VS8-041", exp(ci.HeadlineVerified, allMine("verified")))
	notDirect := est(ci.JudgedSettlementPath, "unproven", map[string]any{"to": acct, "selector": selSettle, "reason": "not_direct_call"})
	foreign := leaf(decoy, leafKey)
	add("VS8-042", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), notDirect), world.Set("settlement.logs", []world.LogSpec{opLog, foreign}))
	missing := est(ci.JudgedSettlementPath, "unproven", unp("settlement_event_missing", map[string]any{"count": uint64(0)}))
	add("VS8-043", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), missing), world.Set("settlement.logs", []world.LogSpec{opLog}))
	multiple := est(ci.JudgedSettlementPath, "unproven", map[string]any{"to": acct, "selector": selSettle, "reason": "multiple_leaf_consumed"})
	add("VS8-044", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), multiple), world.Set("settlement.logs", []world.LogSpec{opLog, leafLog, leafLog}))
	add("VS8-045.foreign_next_to_candidate", exp(ci.HeadlineVerified, allMine("verified")), world.Set("settlement.logs", []world.LogSpec{opLog, foreign, leafLog}))
	other := leaf(acct, common.HexToHash("0xbeef"))
	add("VS8-045.two_keys_same_emitter", exp(ci.HeadlineVerified, allMine("verified")), world.Set("settlement.logs", []world.LogSpec{opLog, other, leafLog}))
	pinned := a.build("CertenAccountV7_3/r5")
	acctCode := a.code(acct)
	odd := []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x60, 0x0f, 0x57}
	add("VS8-048", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "code_not_published", a.notPublished("account", acct, odd, pinned))), silent, a.setCode(acct, odd))
	add("VS8-049.silent", exp(ci.HeadlineVerified, merge(allMine("verified"), only(ci.JudgedS6Link, "not_applicable"))), silent)
	notProven := []ci.Mutation{silent, ctxSet("s6_status", "s6_not_proven"), ctxSet("s6_state", "replay_slot_unproven")}
	vcore := exp(ci.HeadlineVerifiedCore, merge(allMine("verified"), only(ci.JudgedS6Link, "not_applicable")))
	vcore.Open = []ci.ExpectedOpen{{Part: ci.JudgedS6Link, Kind: ci.OpenNotChecked, Code: ci.Prefix + "not_checked", Fields: cf(map[string]any{"part": "s6_link", "reason": "s6_not_proven", "state": "replay_slot_unproven"})}}
	add("VS8-049.not_proven", vcore, notProven...)
	add("VS8-057.one_candidate_not_proven", vcore, notProven...)
	infra := func(to common.Address, logs []world.LogSpec) []ci.Mutation {
		return []ci.Mutation{silent, world.Set("settlement.logs", logs), world.Set(settleTxPath, world.TxSpec{Role: "settlement", Type: 2, Wire: a.wire(to, []byte{1, 2, 3, 4})})}
	}
	add("VS8-050", exp(ci.HeadlineNotApplicable, nil, est(ci.JudgedSettlementPath, "not_applicable", map[string]any{"reason": "certen_infrastructure_call", "to": anchor, "role": "anchor"})), infra(anchor, []world.LogSpec{})...)
	evMissing := exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), missing)
	add("VS8-051", evMissing, infra(decoy, []world.LogSpec{})...)
	add("VS8-052", evMissing, infra(anchor, []world.LogSpec{opLog})...)
	add("VS8-053.two_candidates", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), multiple), silent, world.Set("settlement.logs", []world.LogSpec{opLog, leafLog, leafLog}))
	add("VS8-053.foreign_only", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), notDirect), silent, world.Set("settlement.logs", []world.LogSpec{opLog, foreign}))
	orig := a.f.built.Inputs.Ctx.Tx.Data()
	add("VS8-054", exp(ci.HeadlineUnproven, only(ci.JudgedSettlementPath, "unproven"), est(ci.JudgedSettlementPath, "unproven", map[string]any{"to": acct, "selector": [4]byte{0xde, 0xad, 0xbe, 0xef}, "reason": "selector_not_pinned"})),
		world.Set(settleTxPath, world.TxSpec{Role: "settlement", Type: 2, Wire: a.wire(acct, append([]byte{0xde, 0xad, 0xbe, 0xef}, orig[4:]...))}))

	// ---- 4 ----
	link := func(field string) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedS6Link, "refused"), est(ci.JudgedS6Link, "s6_link_mismatch", map[string]any{"field": field}))
	}
	add("VS8-055.account", link("account"), ctxSet("s6.contract", strings.ToLower(decoy.Hex())))
	add("VS8-055.block", link("block"), ctxSet("s6.settlement_block.number", fmt.Sprint(leg.Number+1)))
	add("VS8-056.proven_at", link("proven_at"), ctxSet("s6.proven_at.number", fmt.Sprint(leg.Number+1)))
	h9 := bytes32(9)
	laterProof := []ci.Mutation{ctxSet("s6.proven_at.number", fmt.Sprint(leg.Number+5)), ctxSet("s6.proven_at.hash", hx(h9[:]))}
	h7 := bytes32(7)
	add("VS8-056.code_hash", link("code_hash"), append(append([]ci.Mutation(nil), laterProof...), ctxSet("s6.code_hash", hx(h7[:])))...)
	add("VS8-056.later_right_code_hash", exp(ci.HeadlineVerified, allMine("verified")), laterProof...)

	// ---- 5 ----
	proxy := common.FromHex("0x363d3d373d3d3d363d73" + strings.TrimPrefix(strings.ToLower(decoy.Hex()), "0x") + "5af43d82803e903d91602b57fd5bf3")
	for name, c := range map[string][]byte{"proxy": proxy, "wrong_body": flipByte(acctCode, freeByte(acctCode, pinned)), "truncated": acctCode[:len(acctCode)-1],
		"padded": append(append([]byte(nil), acctCode...), 0), "cbor_trailer": flipByte(acctCode, len(acctCode)-1)} {
		add("VS8-060."+name, exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "code_not_published", a.notPublished("account", acct, c, pinned))), a.setCode(acct, c))
	}
	add("VS8-061", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "code_unproven_bytes", map[string]any{"address": acct})),
		world.SetCode(world.StationSettle, acct, world.CodeSpec{CodeHash: crypto.Keccak256Hash(acctCode).Hex()}))
	add("VS8-062.absent", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "account_absent", map[string]any{"role": "account", "address": acct, "root": "settle"})),
		silent, world.Unset(world.AcctPath(world.StationSettle, acct)), world.Set("carry", withoutAddr(spec.Carry, acct)))
	add("VS8-063.account_leaf", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "proof_invalid", map[string]any{"root": "settle", "address": acct, "slot": common.Hash{}})),
		a.dropOnPath(func(ns *ci.NodeSet, root common.Hash) { _, _ = ci.ReadAccount(root, ns, acct) })...)
	add("VS8-063.string_slot", exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "proof_invalid", map[string]any{"root": "settle", "address": acct, "slot": ci.SlotIndex(0)})),
		a.dropOnPath(func(ns *ci.NodeSet, root common.Hash) { _, _ = ci.ReadSlot(a.storageRoot(acct), ns, ci.SlotIndex(0)) })...)

	// ---- 6, 7 ----
	notCanon := func(reason string) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "account_not_canonical", map[string]any{"reason": reason}))
	}
	add("VS8-065.adi_url", notCanon("adi_url"), ctxSet("adi_url", spec.Context.ADIURL+"x"))
	add("VS8-065.governing_book", notCanon("governing_book"), world.SetStorage(world.StationSettle, acct, ci.DynDataSlot(ci.SlotIndex(11), 0), longWord(spec.Context.ADIURL+"/Book")))
	ownerRefs := refsOf(pinned, "owner")
	immWord := func(name string) common.Hash {
		return common.HexToHash(spec.Stations[world.StationSettle].Accounts[strings.ToLower(acct.Hex())].Code.Immutables[name])
	}
	wrong := to32(decoy)
	for _, name := range []string{"owner", "governingBookHash", "_entryPoint"} {
		imm := map[string]string{}
		for _, n := range []string{"owner", "governingBookHash", "_entryPoint"} {
			imm[n] = immWord(n).Hex()
		}
		imm[name] = wrong.Hex()
		refs := refsOf(pinned, name)
		add("VS8-066."+name, exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "immutable_mismatch",
			map[string]any{"role": "account", "name": name, "offset": uint64(refs[0].Start), "got": wrong, "want": immWord(name)})),
			world.SetCode(world.StationSettle, acct, world.CodeSpec{Build: "CertenAccountV7_3/r5", Immutables: imm}))
	}
	oneRef := append([]byte(nil), acctCode...)
	oneRef[ownerRefs[1].Start+31] ^= 1
	add("VS8-066.one_reference", exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "immutable_mismatch",
		map[string]any{"role": "account", "name": "owner", "offset": uint64(ownerRefs[1].Start), "got": common.BytesToHash(oneRef[ownerRefs[1].Start : ownerRefs[1].Start+32]), "want": immWord("owner")})), a.setCode(acct, oneRef))

	// ---- 8 ----
	impostor := a.addr("0x2222222222222222222222222222222222222222")
	swap, err := world.SwapAccount(spec, world.StationSettle, acct, impostor)
	if err != nil {
		a.t.Fatal(err)
	}
	var carry []string
	for _, c := range spec.Carry {
		if strings.EqualFold(c, acct.Hex()) {
			c = strings.ToLower(impostor.Hex())
		}
		carry = append(carry, c)
	}
	impLogs := []world.LogSpec{opLog, leafLog}
	impLogs[0].Address, impLogs[1].Address = strings.ToLower(impostor.Hex()), strings.ToLower(impostor.Hex())
	impMuts := append(swap, world.Set("roles.account", strings.ToLower(impostor.Hex())), world.Set("carry", carry), world.Set("settlement.logs", impLogs), world.Set("context.s6.contract", strings.ToLower(impostor.Hex())))
	add("VS8-067.impostor_create2", notCanon("create2"), impMuts...)
	add("VS8-067.deployed_flag", notCanon("deployed_flag"), world.SetStorage(world.StationSettle, factory, ci.MappingSlotAt(ci.KeyAddress(acct), 2), common.Hash{}))
	strT, _ := abi.NewType("string", "", nil)
	enc, err := abi.Arguments{{Type: strT}, {Type: strT}}.Pack(spec.Context.ADIURL, spec.Context.ADIURL+"/book")
	if err != nil {
		a.t.Fatal(err)
	}
	add("VS8-067.registry", notCanon("registry"), world.SetStorage(world.StationSettle, factory, ci.MappingSlotAt(ci.KeyBytes32(crypto.Keccak256Hash(enc)), 3), to32(decoy)))
	fb := a.build("CertenAccountFactoryV11/r5")
	fcode := flipByte(a.code(factory), freeByte(a.code(factory), fb))
	add("VS8-067.factory_code", exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "code_not_published", a.notPublished("accountFactory", factory, fcode, fb))), a.setCode(factory, fcode))

	// ---- 9, 10 ----
	ptr := func(got common.Address) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedPointer, "refused"), est(ci.JudgedPointer, "pointer_mismatch", map[string]any{"account": acct, "got": got, "want": anchor}))
	}
	add("VS8-070.decoy", ptr(decoy), world.SetStorage(world.StationSettle, acct, ci.SlotIndex(2), to32(decoy)))
	add("VS8-070.zero", ptr(common.Address{}), world.SetStorage(world.StationSettle, acct, ci.SlotIndex(2), common.Hash{}))
	ab := a.build("CertenAnchorV8_2/r5")
	acode := a.code(anchor)
	chainRefs := refsOf(ab, "DEPLOYMENT_CHAIN_ID")
	badRef := append([]byte(nil), acode...)
	badRef[chainRefs[3].Start+31] ^= 1
	add("VS8-071.one_of_nine", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "immutable_mismatch",
		map[string]any{"role": "anchor", "name": "DEPLOYMENT_CHAIN_ID", "offset": uint64(chainRefs[3].Start), "got": common.BytesToHash(badRef[chainRefs[3].Start : chainRefs[3].Start+32]), "want": common.BigToHash(new(big.Int).SetUint64(spec.Chain))})), a.setCode(anchor, badRef))
	acodeBad := flipByte(acode, freeByte(acode, ab))
	add("VS8-071.code", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "code_not_published", a.notPublished("anchor", anchor, acodeBad, ab))), a.setCode(anchor, acodeBad))

	// ---- 11 ----
	w10 := a.storedWord(anchor, ci.MemberSlot(rec, 10))
	clear := func(idx int) common.Hash { w := w10; w[idx] = 0; return w }
	notExec := func(valid, pe bool) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedRecord, "refused"), est(ci.JudgedRecord, "record_not_executed", map[string]any{"anchorId": anchorID, "valid": valid, "proofExecuted": pe}))
	}
	add("VS8-072.valid_0", notExec(false, true), world.SetStorage(world.StationSettle, anchor, ci.MemberSlot(rec, 10), clear(11)))
	add("VS8-072.proof_executed_0", notExec(true, false), world.SetStorage(world.StationSettle, anchor, ci.MemberSlot(rec, 10), clear(10)))
	add("VS8-073", exp(ci.HeadlineUnproven, only(ci.JudgedRecord, "unproven"), est(ci.JudgedRecord, "unproven", unp("anchor_not_batch", map[string]any{"anchorId": anchorID}))),
		world.SetStorage(world.StationSettle, anchor, ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2), common.Hash{}))
	inc := func(field string) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedRecord, "refused"), est(ci.JudgedRecord, "record_inconsistent", map[string]any{"field": field}))
	}
	add("VS8-074.leaf_count", inc("bundle_id"), world.SetStorage(world.StationSettle, anchor, ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3), common.BigToHash(big.NewInt(4))))
	add("VS8-074.batch_root_in_record", inc("bundle_id"), world.SetStorage(world.StationSettle, anchor, ci.MemberSlot(rec, 1), common.HexToHash("0xaa")))
	h5a := bytes32(0x5a)
	for _, c := range []struct{ path, field string }{{"batch.batchRoot", "merkle_root"}, {"batch.batchOperationID", "operation_id"}, {"batch.accSetRoot", "acc_set_root"}, {"batch.incarnation", "incarnation"}} {
		add("VS8-074."+c.field, inc(c.field), ctxSet(c.path, hx(h5a[:])))
	}

	// ---- 12 ----
	w30 := a.storedWord(anchor, ci.SlotIndex(30))
	add("VS8-075.verifier_not_a_row", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "address_not_published", map[string]any{"role": "blsZkVerifier", "address": decoy})),
		world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(30), func() common.Hash { w := to32(decoy); w[11] = 1; return w }()))
	vb := a.build("BLSZKVerifierV2_1/r5")
	vcode := a.code(verifier)
	vrefs := refsOf(vb, "groth16Verifier")
	vbad := append([]byte(nil), vcode...)
	vbad[vrefs[1].Start+31] ^= 1
	add("VS8-075.references_differ", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "immutable_mismatch",
		map[string]any{"role": "blsZkVerifier", "name": "groth16Verifier", "offset": uint64(vrefs[1].Start), "got": common.BytesToHash(vbad[vrefs[1].Start : vrefs[1].Start+32]), "want": to32(g16)})), a.setCode(verifier, vbad))
	gb := a.build("BLSZKVerifierV2Generated/r7")
	gcode := flipByte(a.code(g16), len(a.code(g16))/2)
	add("VS8-075.generated_code", exp(ci.HeadlineRefused, only(ci.JudgedCodeIdentity, "refused"), est(ci.JudgedCodeIdentity, "code_not_published", a.notPublished("groth16Verifier", g16, gcode, gb))), a.setCode(g16, gcode))

	// ---- 13 ----
	alert := func(field string, onchain, want any) ci.Expected {
		e := exp(ci.HeadlineVerifiedCore, allMine("verified", ci.JudgedS6Link))
		e.Open = []ci.ExpectedOpen{{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenAlert, Code: ci.Prefix + "alert", Fields: cf(map[string]any{"field": field, "at": "settle", "onchain": onchain, "want": want})}}
		return e
	}
	with30 := func(idx int, v byte) common.Hash { w := w30; w[idx] = v; return w }
	add("VS8-076.binding_off", alert("binding", uint64(0), uint64(1)), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(6), common.Hash{}))
	add("VS8-076.paused", alert("paused", uint64(1), uint64(0)), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(0), common.BigToHash(big.NewInt(1))))
	add("VS8-076.enabled_off", alert("enabled", uint64(0), uint64(1)), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(30), with30(11, 0)))
	add("VS8-076.min_gov_0", alert("minimum_governance_level", uint64(0), uint64(1)), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(30), with30(10, 0)))
	add("VS8-076.governance_verifier", alert("governance_verifier", decoy, common.Address{}), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(29), to32(decoy)))
	add("VS8-076.owner", alert("owner", decoy, a.addr(spec.Roles.Owner)), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(27), to32(decoy)))
	pol := a.f.m.Policy()
	// the validator-set root commits to num and den: a changed numerator at N is ALSO a set_root alert (F15), recomputed independently here
	var vals []ci.RegistryMember
	vals = append(vals, ci.RegistryMember{})
	vals = vals[:0]
	for _, m := range spec.Context.Registry9.Members {
		vals = append(vals, ci.RegistryMember{Address: a.addr(m.Address), Power: m.Power})
	}
	sort.Slice(vals, func(i, j int) bool { return bytes.Compare(vals[i].Address[:], vals[j].Address[:]) < 0 })
	addrs, powers := []common.Address{}, []*big.Int{}
	for _, v := range vals {
		addrs, powers = append(addrs, v.Address), append(powers, new(big.Int).SetUint64(v.Power))
	}
	addrsT, _ := abi.NewType("address[]", "", nil)
	powT, _ := abi.NewType("uint256[]", "", nil)
	u256, _ := abi.NewType("uint256", "", nil)
	newNum := pol.BLSThreshold.Numerator + 1
	rootEnc, err := abi.Arguments{{Type: addrsT}, {Type: powT}, {Type: u256}, {Type: u256}}.Pack(addrs, powers, new(big.Int).SetUint64(newNum), new(big.Int).SetUint64(pol.BLSThreshold.Denominator))
	if err != nil {
		a.t.Fatal(err)
	}
	thr := alert("threshold", fmt.Sprintf("%d/%d", newNum, pol.BLSThreshold.Denominator), fmt.Sprintf("%d/%d", pol.BLSThreshold.Numerator, pol.BLSThreshold.Denominator))
	storedRoot := a.storedWord(anchor, ci.SlotIndex(17))
	thr.Open = append([]ci.ExpectedOpen{{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenAlert, Code: ci.Prefix + "alert", Fields: cf(map[string]any{"field": "set_root", "at": "settle", "onchain": storedRoot, "want": crypto.Keccak256Hash(rootEnc)})}}, thr.Open...)
	add("VS8-076.threshold_and_set_root", thr, world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(15), common.BigToHash(new(big.Int).SetUint64(newNum))))
	add("VS8-076.verifier_threshold", alert("verifier_threshold", fmt.Sprintf("%d/%d", pol.VerifierThreshold.Numerator+1, pol.VerifierThreshold.Denominator), fmt.Sprintf("%d/%d", pol.VerifierThreshold.Numerator, pol.VerifierThreshold.Denominator)),
		world.SetStorage(world.StationSettle, verifier, ci.SlotIndex(0), common.BigToHash(new(big.Int).SetUint64(pol.VerifierThreshold.Numerator+1))))
	val := spec.Context.Registry9.Members[0]
	vbase := ci.MappingSlotAt(ci.KeyAddress(a.addr(val.Address)), 12)
	rootEx := alert("set_root", storedRoot, func() common.Hash {
		vv := append([]ci.RegistryMember(nil), vals...)
		for i := range vv {
			if vv[i].Address == a.addr(val.Address) {
				vv[i].Power = 123456
			}
		}
		ad, po := []common.Address{}, []*big.Int{}
		for _, v := range vv {
			ad, po = append(ad, v.Address), append(po, new(big.Int).SetUint64(v.Power))
		}
		enc, _ := abi.Arguments{{Type: addrsT}, {Type: powT}, {Type: u256}, {Type: u256}}.Pack(ad, po, new(big.Int).SetUint64(pol.BLSThreshold.Numerator), new(big.Int).SetUint64(pol.BLSThreshold.Denominator))
		return crypto.Keccak256Hash(enc)
	}())
	// [r3.3:S2] step 13: "differences from the attest state are drift": the power of the listed validator is 123456 at N, whatever it was at
	// the attestation, so the record word A09:<addr>:1 drifts beside the set_root alert (r3.2 expectation: the alert alone)
	var oldPower uint64
	for _, v := range vals {
		if v.Address == a.addr(val.Address) {
			oldPower = v.Power
		}
	}
	rootEx.Open = append(rootEx.Open, ci.ExpectedOpen{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenDrift, Code: ci.Prefix + "drift", Fields: cf(map[string]any{
		"field": "A09:" + strings.ToLower(a.addr(val.Address).Hex()) + ":1", "attest": common.BigToHash(new(big.Int).SetUint64(oldPower)), "settle": common.BigToHash(big.NewInt(123456))})})
	add("VS8-076.set_root_inconsistent", rootEx, world.SetStorage(world.StationSettle, anchor, ci.MemberSlot(vbase, 1), common.BigToHash(big.NewInt(123456))))
	// ---- unpinned generations (real live code, world/testdata/code) ----
	unpinned := func(row, gen, kind string, code []byte) map[string]any {
		return map[string]any{"reason": row, "generation": gen, "code_hash": crypto.Keccak256Hash(code), "kind": kind}
	}
	for _, g := range []struct{ id, file, kind string }{{"VS8-046", world.GenV7Catalogued, "catalogued"}, {"VS8-047", world.GenV7Observed, "observed"}} {
		code, err := world.GenerationRuntime(g.file)
		if err != nil {
			a.t.Fatal(err)
		}
		st := unpinned("account_generation_unpinned", "CertenAccountV7", g.kind, code)
		add(g.id+"."+g.kind, exp(ci.HeadlineUnproven, merge(only(ci.JudgedSettlementPath, "unproven"), only(ci.JudgedCodeIdentity, "unproven")),
			est(ci.JudgedSettlementPath, "unproven", st), est(ci.JudgedCodeIdentity, "unproven", st)), silent, a.setCode(acct, code))
	}
	v81 := a.addr("0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0")
	v81Code, err := world.GenerationRuntime(world.GenAnchorV8_1)
	if err != nil {
		a.t.Fatal(err)
	}
	add("VS8-070.anchor_v8_1", exp(ci.HeadlineUnproven, only(ci.JudgedPointer, "unproven"), est(ci.JudgedPointer, "unproven", unpinned("anchor_generation_unpinned", "CertenAnchorV8_1", "catalogued", v81Code))),
		world.SetStorage(world.StationSettle, acct, ci.SlotIndex(2), to32(v81)),
		world.Set(world.AcctPath(world.StationSettle, v81), world.AcctSpec{Nonce: 1, Code: &world.CodeSpec{Hex: hx(v81Code)}}),
		world.Set("carry", append(append([]string{}, spec.Carry...), strings.ToLower(v81.Hex()))))

	// ---- VS8-057: the four s6_silent-or-s6_not_proven rows give identical results; s6_not_proven adds the Open entry ----
	s6Open := []ci.ExpectedOpen{{Part: ci.JudgedS6Link, Kind: ci.OpenNotChecked, Code: ci.Prefix + "not_checked", Fields: cf(map[string]any{"part": "s6_link", "reason": "s6_not_proven", "state": "replay_slot_unproven"})}}
	withOpen := func(e ci.Expected) ci.Expected { e.Open = s6Open; return e }
	add("VS8-057.foreign_only_not_proven", withOpen(exp(ci.HeadlineUnproven, merge(only(ci.JudgedSettlementPath, "unproven"), only(ci.JudgedS6Link, "not_applicable")), notDirect)),
		append(append([]ci.Mutation(nil), notProven...), world.Set("settlement.logs", []world.LogSpec{opLog, foreign}))...)
	add("VS8-057.two_candidates_not_proven", withOpen(exp(ci.HeadlineUnproven, merge(only(ci.JudgedSettlementPath, "unproven"), only(ci.JudgedS6Link, "not_applicable")), multiple)),
		append(append([]ci.Mutation(nil), notProven...), world.Set("settlement.logs", []world.LogSpec{opLog, leafLog, leafLog}))...)
	add("VS8-057.no_log_unknown_target_not_proven", withOpen(exp(ci.HeadlineUnproven, merge(only(ci.JudgedSettlementPath, "unproven"), only(ci.JudgedS6Link, "not_applicable")), missing)),
		append(append([]ci.Mutation(nil), notProven...), world.Set("settlement.logs", []world.LogSpec{}), world.Set(settleTxPath, world.TxSpec{Role: "settlement", Type: 2, Wire: a.wire(decoy, []byte{1, 2, 3, 4})}))...)
	// ---- VS8-064: both string forms verify in H0 (adiURL 27 bytes short, governingBook 32 bytes long); a missing data word is proof_invalid ----
	bookData := ci.DynDataSlot(ci.SlotIndex(11), 0)
	add("VS8-064.missing_data_word", exp(ci.HeadlineRefused, only(ci.JudgedAccountProvenance, "refused"), est(ci.JudgedAccountProvenance, "proof_invalid", map[string]any{"root": "settle", "address": acct, "slot": bookData})),
		a.dropOnPath(func(ns *ci.NodeSet, root common.Hash) { _, _ = ci.ReadSlot(a.storageRoot(acct), ns, bookData) })...)

	// ---- 14 ----
	otherBook := common.HexToHash("0xdead")
	leg0 := spec.Settlement.Legs[0]
	sel0 := common.FromHex(leg0.Data)[:4]
	var selKey [4]byte
	copy(selKey[:], sel0)
	withLvl := func(l world.LogSpec, level int) world.LogSpec {
		d := common.FromHex(l.Data)
		copy(d[64:96], common.BigToHash(big.NewInt(int64(level))).Bytes())
		l.Data = hx(d)
		return l
	}
	single := func(level int) []world.LogSpec { return []world.LogSpec{withLvl(opLog, level), leafLog} }
	opFor := func(target string, level int) world.LogSpec {
		l := withLvl(opLog, level)
		l.Topics = []string{opLog.Topics[0], opLog.Topics[1], hx(to32(a.addr(target)).Bytes())}
		return l
	}
	batchLog := func(callCount, level int) world.LogSpec {
		return world.LogSpec{Address: opLog.Address, Topics: []string{hx(ci.TopicOf(ci.SigGovernanceBatch).Bytes()), opLog.Topics[1], hx(anchorID.Bytes())},
			Data: hx(append(common.BigToHash(big.NewInt(int64(callCount))).Bytes(), common.BigToHash(big.NewInt(int64(level))).Bytes()...))}
	}
	batchOf := func(legs []world.LegSpec, logs []world.LogSpec) []ci.Mutation {
		return []ci.Mutation{world.Set("settlement.batch", true), world.Set("settlement.legs", legs), world.Set("settlement.logs", append(logs, leafLog))}
	}
	twoLegs := []world.LegSpec{leg0, leg0}
	page := func(p uint64) ci.Mutation { return world.Set("settlement.authority_page", p) }
	stored := func(b common.Hash, p uint64, level int) []ci.Mutation {
		return []ci.Mutation{world.SetStorage(world.StationSettle, acct, ci.PageSlot(10, b, p), ci.SlotIndex(1)), world.SetStorage(world.StationSettle, acct, ci.PageSlot(9, b, p), common.BigToHash(big.NewInt(int64(level))))}
	}
	lvlOK := exp(ci.HeadlineVerified, allMine("verified"))
	authU := func(f map[string]any) ci.Expected {
		return exp(ci.HeadlineUnproven, only(ci.JudgedAuthorityLevel, "unproven"), est(ci.JudgedAuthorityLevel, "unproven", f))
	}
	add("VS8-080.page2_admin", lvlOK, page(2), world.Set("settlement.logs", single(3)))
	add("VS8-080.page3_operator", lvlOK, page(3), world.Set("settlement.logs", single(1)))
	add("VS8-081", lvlOK, append([]ci.Mutation{page(3), world.Set("settlement.logs", single(3))}, stored(common.HexToHash(spec.Settlement.AuthorityBook), 3, 3)...)...)
	below := func(leg int, level, required string) ci.Expected {
		return authU(map[string]any{"reason": "level_below_required_at_N", "leg": uint64(leg), "level": level, "required": required})
	}
	add("VS8-082", below(0, "NONE", "OPERATOR"), world.Set("settlement.authority_book", otherBook.Hex()), world.Set("settlement.logs", single(0)))
	add("VS8-083", lvlOK, append([]ci.Mutation{world.Set("settlement.authority_book", otherBook.Hex()), world.Set("settlement.logs", single(1))}, stored(otherBook, 1, 1)...)...)
	add("VS8-084.requirement", below(0, "OPERATOR", "MANAGER"), page(3), world.Set("settlement.logs", single(1)),
		world.SetStorage(world.StationSettle, acct, ci.MappingSlotAt(ci.KeyBytes4(selKey), 8), common.BigToHash(big.NewInt(2))))
	tenEther := "10000000000000000000"
	bigLeg := leg0
	bigLeg.Value = tenEther
	add("VS8-084.value", below(0, "OPERATOR", "ROOT"), page(3), world.Set("settlement.legs", []world.LegSpec{bigLeg}), world.Set("settlement.logs", single(1)))
	selfLeg := leg0
	selfLeg.Target = strings.ToLower(acct.Hex())
	add("VS8-085.self_call", authU(map[string]any{"reason": "self_call_leg", "leg": uint64(0)}), world.Set("settlement.legs", []world.LegSpec{selfLeg}))
	add("VS8-085.batch_second_leg_fails", below(1, "OPERATOR", "ROOT"), append([]ci.Mutation{page(3)}, batchOf([]world.LegSpec{leg0, bigLeg},
		[]world.LogSpec{opFor(leg0.Target, 1), opFor(leg0.Target, 1), batchLog(2, 1)})...)...)
	sixtyFive := make([]world.LegSpec, 65)
	for i := range sixtyFive {
		sixtyFive[i] = leg0
	}
	add("VS8-086.too_many_legs", authU(map[string]any{"reason": "too_many_legs", "count": uint64(65), "limit": uint64(64)}), world.Set("settlement.batch", true), world.Set("settlement.legs", sixtyFive))
	badCalldata := append([]byte(nil), orig...)
	copy(badCalldata[4+64:4+96], bytes.Repeat([]byte{0xff}, 32))
	add("VS8-086.undecodable", authU(map[string]any{"reason": "calldata_undecodable", "field": "data"}), world.Set(settleTxPath, world.TxSpec{Role: "settlement", Type: 2, Wire: a.wire(acct, badCalldata)}))
	add("VS8-087.stored_level_5", exp(ci.HeadlineRefused, only(ci.JudgedAuthorityLevel, "refused"), est(ci.JudgedAuthorityLevel, "authority_level_invalid", map[string]any{"field": "page_level", "got": big.NewInt(5)})),
		stored(common.HexToHash(spec.Settlement.AuthorityBook), spec.Settlement.AuthorityPage, 5)...)
	add("VS8-088.stored_differs_from_logged", authU(map[string]any{"reason": "level_differs_from_logged", "logged": "ROOT", "computed": "OPERATOR"}),
		stored(common.HexToHash(spec.Settlement.AuthorityBook), spec.Settlement.AuthorityPage, 1)...)
	missingLog := authU(map[string]any{"reason": "level_log_missing"})
	add("VS8-089.no_operation_log", missingLog, world.Set("settlement.logs", []world.LogSpec{leafLog}))
	add("VS8-089.level_above_4", missingLog, world.Set("settlement.logs", single(5)))
	add("VS8-089.batch_ok", lvlOK, batchOf(twoLegs, []world.LogSpec{opFor(leg0.Target, 4), opFor(leg0.Target, 4), batchLog(2, 4)})...)
	add("VS8-089.batch_one_log_short", missingLog, batchOf(twoLegs, []world.LogSpec{opFor(leg0.Target, 4), batchLog(2, 4)})...)
	add("VS8-089.batch_call_count", missingLog, batchOf(twoLegs, []world.LogSpec{opFor(leg0.Target, 4), opFor(leg0.Target, 4), batchLog(3, 4)})...)
	add("VS8-089.batch_two_levels", missingLog, batchOf(twoLegs, []world.LogSpec{opFor(leg0.Target, 4), opFor(leg0.Target, 3), batchLog(2, 4)})...)
	return out
}

// storageRoot is the proven storage root of an H0 settle-station account (read through a throwaway node set so that no walk is recorded).
func (a *author) storageRoot(who common.Address) common.Hash {
	c := a.f.built.World.Container
	ns, err := ci.NewNodeSet(c.Nodes)
	if err != nil {
		a.t.Fatal(err)
	}
	st, err := ci.ReadAccount(a.f.built.World.StateRoots[world.StationSettle], ns, who)
	if err != nil {
		a.t.Fatal(err)
	}
	return st.StorageRoot
}

// vectorsSet2 are the vectors added after the first hand-mutant run of the published set s8_2a_1 found three conditions no vector pinned (the
// bundleId word of the record, a non-boolean _pageLevelSet word, an out-of-enum _operationRequirements word). A published set is never edited:
// they are a second set.
func (a *author) vectorsSet2() []ci.Vector {
	acct, anchor, _, _, _ := a.roles()
	spec := a.f.spec
	anchorID := common.HexToHash(spec.Settlement.AnchorID)
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	book := common.HexToHash(spec.Settlement.AuthorityBook)
	var selKey [4]byte
	copy(selKey[:], common.FromHex(spec.Settlement.Legs[0].Data)[:4])
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	add("VS8-074.bundle_id_word", exp(ci.HeadlineRefused, only(ci.JudgedRecord, "refused"), est(ci.JudgedRecord, "record_inconsistent", map[string]any{"field": "bundle_id"})),
		world.SetStorage(world.StationSettle, anchor, ci.MemberSlot(rec, 0), common.HexToHash("0xbb")))
	setSlot := ci.PageSlot(10, book, spec.Settlement.AuthorityPage)
	add("VS8-087.page_level_set_not_bool", exp(ci.HeadlineRefused, only(ci.JudgedAuthorityLevel, "refused"), est(ci.JudgedAuthorityLevel, "proof_invalid", map[string]any{"root": "settle", "address": acct, "slot": setSlot})),
		world.SetStorage(world.StationSettle, acct, setSlot, common.BigToHash(big.NewInt(2))))
	reqSlot := ci.MappingSlotAt(ci.KeyBytes4(selKey), 8)
	add("VS8-087.requirement_above_4", exp(ci.HeadlineRefused, only(ci.JudgedAuthorityLevel, "refused"), est(ci.JudgedAuthorityLevel, "proof_invalid", map[string]any{"root": "settle", "address": acct, "slot": reqSlot})),
		world.SetStorage(world.StationSettle, acct, reqSlot, common.BigToHash(big.NewInt(5))))
	return out
}

// dropOnPath returns the drop_node mutation of the last node (in container order) a walk visits; dropping any node of the path breaks the read.
func (a *author) dropOnPath(walk func(ns *ci.NodeSet, root common.Hash)) []ci.Mutation {
	c := a.f.built.World.Container
	ns, err := ci.NewNodeSet(c.Nodes)
	if err != nil {
		a.t.Fatal(err)
	}
	walk(ns, a.f.built.World.StateRoots[world.StationSettle])
	vis := ns.VisitedNodes()
	last := vis[len(vis)-1]
	for i, n := range c.Nodes {
		if bytes.Equal(n, last) {
			ix := i
			return []ci.Mutation{{Op: "drop_node", Target: "container", Index: &ix}}
		}
	}
	a.t.Fatal("visited node not in the container")
	return nil
}

// attestOnlyDrops is the list of node indexes (descending) that no attestation-side read visits: the nodes a builder prunes when the settle
// part is Stated. It is derived by the faithful attestation-side readers of the fixture (the AUTH slot set at both stations and the two
// leaves of the attestation block), not by the verifier under test.
func (a *author) attestOnlyDrops() []int {
	in := a.f.built.Inputs
	env, st, err := ci.Prelude(in.Ctx, in.Container, a.f.m)
	if err != nil || st != nil {
		a.t.Fatalf("prelude: %v %v", err, st)
	}
	att := env.Container.Attest.Attest
	hv, _ := env.Header(att.HeaderV)
	hp, _ := env.Header(att.HeaderVParent)
	env.Facts.B1.PKC = common.HexToHash(a.f.spec.Attestation.Blob[13])
	env.Facts.A.AnchorID = common.HexToHash(a.f.spec.Settlement.AnchorID)
	for _, root := range [][32]byte{hv.TransactionRoot, hv.ReceiptsRoot} {
		if _, err := ci.ReadIndexedLeaf(common.Hash(root), env.Nodes, uint64(att.TxIndex), env.Limits.MaxNodeBytes); err != nil {
			a.t.Fatal(err)
		}
	}
	for _, r := range [][32]byte{hp.StateRoot, hv.StateRoot} {
		if _, err := a.f.authWords(env, common.Hash(r), true); err != nil {
			a.t.Fatal(err)
		}
	}
	un := env.Nodes.Unvisited()
	sort.Sort(sort.Reverse(sort.IntSlice(un)))
	return un
}

// ---- the tests ----

func (f *fixture) verifier() ci.Verifier {
	return ci.VerifierFunc(func(ctx ci.LegContext, container []byte, m *ci.Manifest) (ci.Report, error) {
		reg := ci.NewStepRegistry()
		if err := ci.RegisterSteps2a(reg); err != nil {
			return ci.Report{}, err
		}
		own := map[ci.StepID]bool{}
		for _, id := range ci.OwnedBy(ci.Owner2a) {
			own[id] = true
		}
		for _, id := range ci.RegistrableSteps() {
			if !own[id] {
				if err := reg.Register(id, f.fake(id, false)); err != nil {
					return ci.Report{}, err
				}
			}
		}
		v, err := ci.NewVerifier(reg)
		if err != nil {
			return ci.Report{}, err
		}
		return v.Verify(ctx, container, m)
	})
}

func worldJSON(t *testing.T, f *fixture) []byte {
	b, err := f.spec.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// Every vector against the verifier through the world builder (fast loop, one failure per vector).
func TestVectors2aAgainstTheVerifier(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author{t, f}
	wj := worldJSON(t, f)
	ver := f.verifier()
	for _, v := range append(a.vectors(), a.vectorsSet2()...) {
		t.Run(v.ID, func(t *testing.T) {
			in, err := world.Builder{Manifest: f.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("the world cannot build the vector: %v", err)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, f.m)
			if err != nil {
				t.Fatalf("verifier error: %v", err)
			}
			if err := ci.MatchExpected(v.Expected, rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func setDir(name string) string {
	return filepath.Join("testdata", "contractidentity", "vectors", name)
}

// The published set: loaded from disk (every file hash-checked by the loader), run WITHOUT the world builder on the materialised inputs, and
// regenerated into a temporary directory, which must be byte-identical (the world builder and the author did not drift). The set is written
// once, by CERTEN_WRITE_S8_2A=1; world.WriteSet refuses to write into a published set.
func TestVectorSet2aIsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author{t, f}
	for name, vectors := range map[string][]ci.Vector{vectorSet2a: a.vectors(), vectorSet2a2: a.vectorsSet2()} {
		t.Run(name, func(t *testing.T) { checkPublished(t, f, name, vectors) })
	}
}

func checkPublished(t *testing.T, f *fixture, name string, vectors []ci.Vector) {
	dir := setDir(name)
	if _, err := os.Stat(dir); err != nil && os.Getenv("CERTEN_WRITE_S8_2A") == "1" {
		if err := world.WriteSet(dir, f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatalf("the set %s is not published: %v", name, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	for _, r := range ci.RunSet(set, nil, f.verifier()) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	tmp := filepath.Join(t.TempDir(), "again")
	if err := world.WriteSet(tmp, f.spec, vectors); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	published, _ := os.ReadDir(dir)
	if len(entries) != len(published) {
		t.Fatalf("regenerated %d files, published %d", len(entries), len(published))
	}
	for _, e := range entries {
		a, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if !bytes.Equal(a, b) {
			t.Errorf("file %s differs from the published one", e.Name())
		}
	}
}

// The mutation gate of the specification ("each step of the algorithm is disabled in turn and at least one vector must fail"): a disabled
// step still computes its facts but judges nothing (it reports its declared parts verified and marks the read plan incomplete), and the
// set must catch it. Also: the gate bites on the step, not on a side effect: the set is run with the real steps first.
func TestEveryStepOfPackage2aIsKilledByAVector(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	wj := worldJSON(t, f)
	vectors := append((&author{t, f}).vectors(), (&author{t, f}).vectorsSet2()...)
	inputs := make([]ci.Inputs, len(vectors))
	for i, v := range vectors {
		in, err := world.Builder{Manifest: f.m}.Build(wj, v, nil)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		inputs[i] = in
	}
	run := func(disabled ci.StepID) (failed []string) {
		reg := ci.NewStepRegistry()
		for id, fn := range ci.Steps2a() {
			if id == disabled {
				inner, spec := fn, mustSpec(id)
				fn = func(env *ci.Env) (ci.StepOutput, error) {
					if _, err := inner(env); err != nil {
						return ci.StepOutput{}, err
					}
					// the refusal facts are the step's own judgement: a disabled step does not hand them to the dependent steps either
					switch disabled {
					case ci.Step3:
						env.Facts.A.PathFailure, env.Facts.A.GenerationState = nil, nil
					case ci.Step5:
						env.Facts.A.AccountRefusal = nil
					case ci.Step10:
						env.Facts.A.AnchorRefusal = nil
					}
					out := ci.StepOutput{ReadPlanIncomplete: "gate: step disabled"}
					for _, p := range spec.Parts {
						out.Parts = append(out.Parts, env.Verified(p))
					}
					return out, nil
				}
			}
			if err := reg.Register(id, fn); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range ci.RegistrableSteps() {
			if mustSpec(id).Owner != ci.Owner2a {
				if err := reg.Register(id, f.fake(id, false)); err != nil {
					t.Fatal(err)
				}
			}
		}
		v, err := ci.NewVerifier(reg)
		if err != nil {
			t.Fatal(err)
		}
		for i, vec := range vectors {
			rep, err := v.Verify(inputs[i].Ctx, inputs[i].Container, f.m)
			if err != nil || ci.MatchExpected(vec.Expected, rep) != nil {
				failed = append(failed, vec.ID)
			}
		}
		return failed
	}
	if bad := run(""); len(bad) != 0 {
		t.Fatalf("the intact verifier fails %v", bad)
	}
	for _, id := range ci.OwnedBy(ci.Owner2a) {
		if failed := run(id); len(failed) == 0 {
			t.Errorf("disabling step %s fails no vector: the set does not cover it", id)
		} else {
			t.Logf("step %s disabled: %d vectors fail (first %s)", id, len(failed), failed[0])
		}
	}
}
