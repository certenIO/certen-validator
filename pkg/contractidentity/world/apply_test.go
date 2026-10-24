// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/finality"
)

func h0(t *testing.T, chain uint64, variant string) (*ci.Manifest, *Spec, *World) {
	t.Helper()
	m := manifest(t)
	sp, err := Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Derive(m, sp)
	if err != nil {
		t.Fatal(err)
	}
	if w.PlanErr != nil || w.CheckErr != nil {
		t.Fatalf("H0 is not clean: %v / %v", w.PlanErr, w.CheckErr)
	}
	return m, sp, w
}

func apply(t *testing.T, m *ci.Manifest, sp *Spec, container []byte, muts ...ci.Mutation) *Built {
	t.Helper()
	b, err := Apply(m, sp, muts, container)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSemanticSetStorageRederivesEverythingAbove(t *testing.T) {
	m, sp, base := h0(t, sepolia, VariantH0)
	A := addrOf(t, sp.Roles.Anchor)
	// binding switched off at the attestation block, both stations: slot 6 := 0
	b := apply(t, m, sp, nil, SetStorage(StationPre, A, ci.SlotIndex(6), common.Hash{}), SetStorage(StationPost, A, ci.SlotIndex(6), common.Hash{}))
	w := b.World
	if w.PlanErr != nil || w.CheckErr != nil {
		t.Fatalf("a semantic mutation must leave the evidence consistent: %v / %v", w.PlanErr, w.CheckErr)
	}
	for _, st := range []string{StationPre, StationPost} {
		if w.StateRoots[st] == base.StateRoots[st] {
			t.Fatalf("%s: the state root did not change", st)
		}
	}
	if w.StateRoots[StationSettle] != base.StateRoots[StationSettle] {
		t.Fatal("an attestation-block mutation changed the settlement state")
	}
	rd := newReads(t, w)
	if rd.slot(StationPre, A, ci.SlotIndex(6)) != (common.Hash{}) || rd.slot(StationPost, A, ci.SlotIndex(6)) != (common.Hash{}) || rd.slot(StationSettle, A, ci.SlotIndex(6)) != wordU(1) {
		t.Fatal("slot 6 after the mutation")
	}
	// the headers above the changed states are re-derived and still linked
	if w.BlockHashes[BlockAttestParent] == base.BlockHashes[BlockAttestParent] || w.BlockHashes[BlockAttest] == base.BlockHashes[BlockAttest] || w.BlockHashes[BlockSettle] == base.BlockHashes[BlockSettle] {
		t.Fatal("header hashes did not follow the state roots")
	}
	c := w.Container
	att := c.Attest.Attest
	if crypto.Keccak256Hash(att.HeaderVParent) != parentOf(t, att.HeaderV) || crypto.Keccak256Hash(att.Spine[0]) != parentOf(t, w.HeaderRLP[BlockSettle]) || c.Leg.Hash != [32]byte(w.BlockHashes[BlockSettle]) {
		t.Fatal("the links were not re-derived")
	}
	if _, _, err := w.Ctx.Settlement.Verify(); err != nil {
		t.Fatalf("the re-derived settlement does not verify: %v", err)
	}
	if b.Inputs.Ctx.S7.FinalizedBlock.Hash != c.Leg.Hash || b.Inputs.Ctx.S6.SettlementBlock.Hash != c.Leg.Hash {
		t.Fatal("S6 / S7 do not follow the settlement block")
	}
	if !bytes.Equal(b.Inputs.Container, w.ContainerBytes) || bytes.Equal(w.ContainerBytes, base.ContainerBytes) {
		t.Fatal("container bytes")
	}
}

func TestSemanticNonceCodeAndHeaderFields(t *testing.T) {
	m, sp, base := h0(t, sepolia, VariantH0)
	O, A := addrOf(t, sp.Roles.Owner), addrOf(t, sp.Roles.Anchor)
	b := apply(t, m, sp, nil, SetNonce(StationPost, O, 46))
	rd := newReads(t, b.World)
	if rd.acct(StationPre, O).Nonce != 45 || rd.acct(StationPost, O).Nonce != 46 || b.World.CheckErr != nil {
		t.Fatalf("owner nonce: %d/%d %v", rd.acct(StationPre, O).Nonce, rd.acct(StationPost, O).Nonce, b.World.CheckErr)
	}
	// code replaced at the settlement station: the code hash of the account leaf follows, the carried code of the anchor is the new one
	b = apply(t, m, sp, nil, SetCode(StationSettle, A, CodeSpec{Hex: "0x6000"}))
	if rd := newReads(t, b.World); rd.acct(StationSettle, A).CodeHash != crypto.Keccak256Hash([]byte{0x60, 0x00}) {
		t.Fatal("code hash")
	}
	for _, c := range b.World.Container.Codes {
		if c.Address == A && !bytes.Equal(c.Runtime, []byte{0x60, 0x00}) {
			t.Fatal("carried code")
		}
	}
	// a header field that is derived from nothing else: the hash changes and the link above follows
	b = apply(t, m, sp, nil, SetHeaderField(BlockAttest, "timestamp", "123456"))
	if b.World.BlockHashes[BlockAttest] == base.BlockHashes[BlockAttest] || b.World.CheckErr != nil || b.World.PlanErr != nil {
		t.Fatal("timestamp")
	}
	att := b.World.Container.Attest.Attest
	if crypto.Keccak256Hash(att.Spine[len(att.Spine)-1]) != b.World.BlockHashes[BlockAttest] || parentOf(t, b.World.HeaderRLP["between.0"]) != b.World.BlockHashes[BlockAttest] {
		t.Fatal("the spine does not follow the re-derived attestation header")
	}
	// a FORGED state root in the header is not re-derived: the strict reads under the header root fail with a missing node
	b = apply(t, m, sp, nil, SetHeaderField(BlockAttest, "stateRoot", hh(crypto.Keccak256Hash([]byte("forged")))))
	if b.World.CheckErr == nil || !strings.Contains(b.World.CheckErr.Error(), "missing_node") {
		t.Fatalf("forged header root: %v", b.World.CheckErr)
	}
	if b.World.PlanErr != nil {
		t.Fatalf("the capture reads the tries it holds: %v", b.World.PlanErr)
	}
	// a forged transactions root breaks the settlement-style leaf walk of the attestation transaction
	b = apply(t, m, sp, nil, SetHeaderField(BlockAttest, "transactionsRoot", hh(crypto.Keccak256Hash([]byte("forged")))))
	if b.World.CheckErr == nil {
		t.Fatal("forged transactions root")
	}
}

func TestSwapAccountMovesTheEntry(t *testing.T) {
	m, sp, _ := h0(t, sepolia, VariantH0)
	acct := addrOf(t, sp.Roles.Account)
	decoy := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	muts, err := SwapAccount(sp, StationSettle, acct, decoy)
	if err != nil {
		t.Fatal(err)
	}
	b := apply(t, m, sp, nil, muts...)
	st := b.World.d.states[StationSettle]
	if st.accts[decoy] == nil || st.accts[acct] != nil || st.accts[decoy].root != b.World.d.states[StationSettle].accts[decoy].root {
		t.Fatal("the account was not moved")
	}
	// the plan reads the role address: the account is now proven ABSENT there; the carried container lacks its code, and the missing carry is named
	if b.World.PlanErr == nil || !strings.Contains(b.World.PlanErr.Error(), "no materialised code") {
		t.Fatalf("plan error: %v", b.World.PlanErr)
	}
	rd := newReads(t, b.World)
	if rd.acct(StationSettle, acct).Exists {
		t.Fatal("the role address still proves an account")
	}
}

func TestRawContainerMutations(t *testing.T) {
	m, sp, base := h0(t, sepolia, VariantH0)
	n := len(base.ContainerBytes)
	// set_byte: one byte differs, the world and the context are untouched
	off := 30
	b := apply(t, m, sp, nil, ci.Mutation{Op: "set_byte", Target: "container", Offset: &off, Value: json.RawMessage(`"ff"`)})
	diff := 0
	for i := range b.Inputs.Container {
		if b.Inputs.Container[i] != base.ContainerBytes[i] {
			diff++
		}
	}
	if len(b.Inputs.Container) != n || diff != 1 || b.Inputs.Container[off] != 0xff || b.World.StateRoots[StationPost] != base.StateRoots[StationPost] {
		t.Fatalf("set_byte: %d bytes differ", diff)
	}
	// truncate / append_hex / replace_hex
	l := n - 1
	b = apply(t, m, sp, nil, ci.Mutation{Op: "truncate", Target: "container", Length: &l})
	if len(b.Inputs.Container) != n-1 {
		t.Fatal("truncate")
	}
	b = apply(t, m, sp, nil, ci.Mutation{Op: "append_hex", Target: "container", Value: json.RawMessage(`"00"`)})
	if len(b.Inputs.Container) != n+1 {
		t.Fatal("append_hex")
	}
	o4 := 4
	b = apply(t, m, sp, nil, ci.Mutation{Op: "replace_hex", Target: "container", Offset: &o4, Old: "00000014", New: "00000015"})
	if b.Inputs.Container[7] != 0x15 {
		t.Fatal("replace_hex")
	}
	if _, err := Apply(m, sp, []ci.Mutation{{Op: "replace_hex", Target: "container", Offset: &o4, Old: "ffffffff", New: "00"}}, nil); err == nil {
		t.Fatal("replace_hex accepted a wrong old value")
	}
	// drop_node: one node fewer, the container decodes, and the strict reads miss a node
	i0 := 3
	b = apply(t, m, sp, nil, ci.Mutation{Op: "drop_node", Target: "container", Index: &i0})
	dc, err := ci.Decode(b.Inputs.Container, ci.DefaultLimits())
	if err != nil || len(dc.Nodes) != len(base.Container.Nodes)-1 {
		t.Fatalf("drop_node: %v", err)
	}
	if err := base.Recheck(b.Inputs.Container); err == nil || !strings.Contains(err.Error(), "missing_node") {
		t.Fatalf("a dropped node must be a missing node: %v", err)
	}
	// add_node: a byte string no read visits is nodes_unreferenced (step 22b)
	hexNode, _ := json.Marshal(strings.Repeat("ab", 40))
	b = apply(t, m, sp, nil, ci.Mutation{Op: "add_node", Target: "container", Value: hexNode})
	if err := base.Recheck(b.Inputs.Container); err == nil || !strings.Contains(err.Error(), "nodes_unreferenced") {
		t.Fatalf("an unreferenced node: %v", err)
	}
	// reorder nodes: re-encoded without validation, so the container no longer decodes
	b = apply(t, m, sp, nil, ci.Mutation{Op: "reorder", Target: "container", List: "nodes"})
	if _, err := ci.Decode(b.Inputs.Container, ci.DefaultLimits()); err == nil {
		t.Fatal("a reversed node list decoded")
	}
	// structured set_field on the container: the tx index, re-encoded without validation
	b = apply(t, m, sp, nil, ci.Mutation{Op: "set_field", Target: "container", Path: "attest.attest.tx_index", Value: json.RawMessage(`"9"`)})
	dc, err = ci.Decode(b.Inputs.Container, ci.DefaultLimits())
	if err != nil || dc.Attest.Attest.TxIndex != 9 {
		t.Fatalf("set_field tx_index: %v", err)
	}
	// a Stated settle part
	b = apply(t, m, sp, nil,
		ci.Mutation{Op: "set_field", Target: "container", Path: "settle", Value: json.RawMessage(`{"tag":"2","stated":{"state":"contract_identity_unproven","reason":"state_unavailable","judged_block":"1","judged_hash":"` + strings.Repeat("11", 32) + `","failures":[],"detail":"x"}}`)})
	dc, err = ci.Decode(b.Inputs.Container, ci.DefaultLimits())
	if err != nil || dc.Settle.Tag != ci.TagStated || dc.Settle.Stated.Reason != "state_unavailable" {
		t.Fatalf("stated settle: %v", err)
	}
	// structured edits need a container that decodes
	if _, err := Apply(m, sp, []ci.Mutation{{Op: "reorder", Target: "container", List: "nodes"}, {Op: "drop_node", Target: "container", Index: &i0}}, nil); err == nil {
		t.Fatal("drop_node on an undecodable container")
	}
	// a vector's own container file replaces the derived one before the mutations
	own := base.ContainerBytes[:len(base.ContainerBytes)-1]
	b = apply(t, m, sp, own, ci.Mutation{Op: "append_hex", Target: "container", Value: json.RawMessage(`"aa"`)})
	if len(b.Inputs.Container) != n || b.Inputs.Container[n-1] != 0xaa {
		t.Fatal("container file")
	}
}

func TestContextMutations(t *testing.T) {
	m, sp, base := h0(t, sepolia, VariantH0)
	set := func(path, v string) ci.Mutation {
		return ci.Mutation{Op: "set_field", Target: "context", Path: path, Value: json.RawMessage(v)}
	}
	unset := func(path string) ci.Mutation { return ci.Mutation{Op: "unset_field", Target: "context", Path: path} }
	for _, tok := range []string{"settlement", "tx", "receipt", "adi_url", "s6", "batch.batchRoot", "batch.batchOperationID", "batch.accSetRoot", "batch.incarnation", "s7"} {
		b := apply(t, m, sp, nil, unset(tok))
		err := b.Inputs.Ctx.ValidateContext()
		if err == nil || !strings.Contains(err.Error(), mapMissing(tok)) {
			t.Fatalf("unset %s: %v", tok, err)
		}
	}
	// s6_proven with S6 nil is the same refusal; an unset registry9 is optional
	b := apply(t, m, sp, nil, unset("registry9"))
	if b.Inputs.Ctx.Registry9 != nil || b.Inputs.Ctx.ValidateContext() != nil {
		t.Fatal("registry9 is optional")
	}
	b = apply(t, m, sp, nil, set("adi_url", `"acc://other.acme"`), set("s6_status", `"s6_not_proven"`), set("s6_state", `"replay_slot_not_found"`))
	if b.Inputs.Ctx.ADIURL != "acc://other.acme" || b.Inputs.Ctx.S6Status != ci.S6NotProven || b.Inputs.Ctx.S6State != "replay_slot_not_found" || b.Inputs.Ctx.ValidateContext() != nil {
		t.Fatalf("scalar context members: %v", b.Inputs.Ctx.ValidateContext())
	}
	b = apply(t, m, sp, nil, set("s6.code_hash", `"`+hh(crypto.Keccak256Hash([]byte("other")))+`"`), set("s6.proven_at.number", `"7"`), set("registry9.members.0.power", `11`), set("registry9.signer_commitment", `"`+hh(common.Hash{})+`"`))
	if b.Inputs.Ctx.S6.CodeHash == base.Ctx.S6.CodeHash || b.Inputs.Ctx.S6.ProvenAt.Number != 7 || b.Inputs.Ctx.Registry9.Members[0].Power != 11 || b.Inputs.Ctx.Registry9.SignerCommitment != [32]byte{} {
		t.Fatalf("s6 / registry9 edits: %+v", b.Inputs.Ctx.S6)
	}
	b = apply(t, m, sp, nil, set("batch.accSetRoot", `"`+hh(common.Hash{})+`"`))
	if err := b.Inputs.Ctx.ValidateContext(); err == nil || !strings.Contains(err.Error(), "batch.accSetRoot") {
		t.Fatalf("zero accSetRoot: %v", err)
	}
	if _, err := Apply(m, sp, []ci.Mutation{set("settlement", `"x"`)}, nil); err == nil {
		t.Fatal("a derived member was set")
	}
}

func mapMissing(tok string) string { return tok }

func TestProfileSelectorsAndTheBuilder(t *testing.T) {
	m := manifest(t)
	sp, err := Generate(m, sepolia, VariantH0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sp.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	// the vector selects Base and the hop variant; later world mutations apply on top
	v := ci.Vector{ID: "VS8-102.hops_base", Base: "H0", Mutations: []ci.Mutation{
		Set("chain", 84532), Set("variant", "hops"), SetNonce(StationPost, common.HexToAddress("0x91C798AA0Ad11d2670029b3B0572d154bd42c059"), 46)}}
	in, err := Builder{}.Build(raw, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ci.Decode(in.Container, ci.DefaultLimits())
	if err != nil || c.Chain != 84532 || c.Attest.Attest.Link != ci.LinkHops || len(c.Attest.Attest.HopHeaders) != 2 {
		t.Fatalf("selected profile: %v", err)
	}
	if in.Ctx.Chain != 84532 || in.Manifest == nil {
		t.Fatal("inputs")
	}
	// an unknown member is not silently ignored
	_, err = Builder{}.Build(raw, ci.Vector{ID: "VS8-001", Base: "H0", Mutations: []ci.Mutation{Set("stations.settle.nope", 1)}}, nil)
	if err == nil {
		t.Fatal("an unknown world member was accepted")
	}
	_, err = Builder{}.Build(raw, ci.Vector{ID: "VS8-001", Base: "H0", Mutations: []ci.Mutation{Set("variant", "nonsense")}}, nil)
	if err == nil {
		t.Fatal("an unknown variant was accepted")
	}
}

func TestWriteSetIsALoadablePublishedSet(t *testing.T) {
	m := manifest(t)
	sp, _ := Generate(m, sepolia, VariantH0)
	dir := filepath.Join(t.TempDir(), "worldtest1")
	A := addrOf(t, sp.Roles.Anchor)
	vecs := []ci.Vector{
		{ID: "VS8-070", Base: "H0", Mutations: []ci.Mutation{SetStorage(StationPre, A, ci.SlotIndex(6), common.Hash{})}, Expected: ci.Expected{Headline: "unproven"}},
		{ID: "VS8-070.second", Base: "H0", Mutations: nil, Expected: ci.Expected{Headline: "verified"}},
	}
	if err := WriteSet(dir, sp, vecs); err != nil {
		t.Fatal(err)
	}
	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != 2 || len(set.World) == 0 {
		t.Fatalf("loaded %d vectors", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		in, err := Builder{}.Build(set.World, v, set.Containers[v.ID])
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if _, err := ci.Decode(in.Container, ci.DefaultLimits()); err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
	}
	// a published set is never edited
	if err := WriteSet(dir, sp, vecs); err == nil {
		t.Fatal("WriteSet overwrote a published set")
	}
	// the runner never passes without a verifier
	for _, r := range ci.RunSet(set, Builder{}, nil) {
		if r.Outcome != ci.OutcomeNotRun {
			t.Fatalf("%s: %s", r.ID, r.Outcome)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST")); err != nil {
		t.Fatal(err)
	}
}

func TestSpineAndHopVariantsDifferOnlyWhereTheyShould(t *testing.T) {
	_, _, a := h0(t, sepolia, VariantH0)
	_, _, s := h0(t, sepolia, VariantS6Silent)
	_, _, h := h0(t, sepolia, VariantHops)
	if !bytes.Equal(a.ContainerBytes, s.ContainerBytes) || s.Ctx.S6Status != ci.S6Silent || s.Ctx.S6 != nil || s.Ctx.S6Reason != "unsupported_generation" {
		t.Fatal("s6silent must differ from H0 in the context only")
	}
	if a.Ctx.S6Status != ci.S6Proven || a.Ctx.S6 == nil || a.Ctx.Registry9 == nil {
		t.Fatal("H0 carries S6 and Registry9")
	}
	ha := h.Container.Attest.Attest
	if ha.Link != ci.LinkHops || len(ha.HopHeaders) != 2 || len(ha.Spine) != 0 {
		t.Fatalf("hops variant: link %d, %d hops", ha.Link, len(ha.HopHeaders))
	}
	// the three gaps of the hop variant are W, W/2 and 7 (a gap of exactly W is the boundary that passes)
	m := manifest(t)
	e, _ := m.EIP2935(sepolia)
	fv, _ := finality.ReadHeader(ha.HeaderV)
	f1, _ := finality.ReadHeader(ha.HopHeaders[0])
	f2, _ := finality.ReadHeader(ha.HopHeaders[1])
	fn, _ := finality.ReadHeader(h.HeaderRLP[BlockSettle])
	if f1.Number-fv.Number != e.Window || f2.Number-f1.Number != e.Window/2 || fn.Number-f2.Number != 7 {
		t.Fatalf("gaps %d %d %d", f1.Number-fv.Number, f2.Number-f1.Number, fn.Number-f2.Number)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(ha.TxLeaf); err != nil || tx.Type() != 2 {
		t.Fatal("attestation transaction")
	}
}
