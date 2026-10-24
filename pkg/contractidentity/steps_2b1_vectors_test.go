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
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The vector set s8_2b1_1: the VS8 rows of steps 15, 16, 17 and 20 (V2_SPEC_S8 r3.2 FINAL, F15 lift), each a few mutation lines on H0 (Sepolia
// h0, or its hops variant) with an expectation DERIVED FROM THE SPECIFICATION TEXT. The expectation names the parts of this package only
// (authorization_attest, and for step 15 also intra_block_window and registry_link); the headline is the one the full verifier yields when the
// other packages judge their parts as verified. The set is written once (CERTEN_WRITE_S8_2B1=1); world.WriteSet refuses a published set.

const vectorSet2b1 = "s8_2b1_1"

func b1cf(m map[string]any) json.RawMessage {
	b, err := ci.Canonical(m)
	if err != nil {
		panic(err)
	}
	return b
}

func b1est(part, code string, fields map[string]any) ci.ExpectedState {
	return ci.ExpectedState{Part: part, Code: ci.Prefix + code, Fields: b1cf(fields)}
}

func b1unproven(part string, fields map[string]any) ci.ExpectedState {
	return b1est(part, "unproven", fields)
}

func b1exp(headline string, parts map[string]string, states ...ci.ExpectedState) ci.Expected {
	return ci.Expected{Headline: headline, Parts: parts, States: states}
}

func b1cont(path string, v any) ci.Mutation {
	b, _ := json.Marshal(v)
	return ci.Mutation{Op: "set_field", Target: "container", Path: path, Value: b}
}

type b1author struct {
	t    *testing.T
	base *b1fx // Sepolia h0
	hops *b1fx // Sepolia hops
	out  []ci.Vector
}

func (a *b1author) add(id string, e ci.Expected, muts ...ci.Mutation) {
	a.out = append(a.out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
}

func b1hexNo(b []byte) string { return hex.EncodeToString(b) }

func (a *b1author) vectors() []ci.Vector {
	a.out = nil
	f, h := a.base, a.hops
	c0, err := ci.Decode(f.built.Inputs.Container, ci.DefaultLimits())
	if err != nil {
		a.t.Fatal(err)
	}
	ch, err := ci.Decode(h.built.Inputs.Container, ci.DefaultLimits())
	if err != nil {
		a.t.Fatal(err)
	}
	att, atth := c0.Attest.Attest, ch.Attest.Attest
	settleHeader := f.built.Inputs.Ctx.Settlement.Header
	settleIdx := f.built.Inputs.Ctx.Settlement.Tx.LeafIndex
	auth := ci.JudgedAuthorizationAttest
	ref := func(code string, fields map[string]any) ci.Expected {
		return b1exp(ci.HeadlineRefused, map[string]string{auth: "refused"}, b1est(auth, code, fields))
	}
	unp := func(fields map[string]any) ci.Expected {
		return b1exp(ci.HeadlineUnproven, map[string]string{auth: "unproven"}, b1unproven(auth, fields))
	}
	flip := func(b []byte) string { c := append([]byte(nil), b...); c[len(c)-1] ^= 1; return b1hexNo(c) }
	toHops := world.Set("variant", "hops")

	// ---- VS8-100: the attest part is Stated, each reason (step 15) ----
	stated := func(reason, detail string) ci.Mutation {
		return b1cont("attest", map[string]any{"tag": "2", "stated": map[string]any{"state": ci.StatedState, "reason": reason, "judged_block": "77",
			"judged_hash": strings.Repeat("07", 32), "failures": []string{}, "detail": detail}})
	}
	// a Stated attest part carries no attest nodes: the container keeps exactly the nodes the verifier visits (step 22b)
	trimmed := func(reason, detail string) []ci.Mutation {
		m := stated(reason, detail)
		raw, err := ci.Encode(func() *ci.Container {
			c := *c0
			c.Attest = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: 77, JudgedHash: [32]byte(bytes.Repeat([]byte{7}, 32)), Detail: detail}}
			return &c
		}(), ci.DefaultLimits())
		if err != nil {
			a.t.Fatal(err)
		}
		f.run(b1All, raw, nil)
		nodes := make([]string, len(f.visited))
		for i, n := range f.visited {
			nodes[i] = b1hexNo(n)
		}
		return []ci.Mutation{m, b1cont("nodes", nodes)}
	}
	absent := func(part string) ci.ExpectedState {
		return b1unproven(part, map[string]any{"reason": "attest_absent", "part": part})
	}
	all3 := map[string]string{auth: "unproven", ci.JudgedIntraBlockWindow: "unproven", ci.JudgedRegistryLink: "unproven"}
	judged := func(reason string) map[string]any {
		return map[string]any{"reason": reason, "part": auth, "judgedBlock": uint64(77), "judgedHash": [32]byte(bytes.Repeat([]byte{7}, 32)), "failures": []any{}}
	}
	for _, r := range []string{ci.StatedCaptureNotAttemptedInWindow, ci.StatedStateUnavailable, ci.StatedAttestBlockStateUnavailable} {
		a.add("VS8-100."+r, b1exp(ci.HeadlineUnproven, all3, b1unproven(auth, judged(r)), absent(ci.JudgedIntraBlockWindow), absent(ci.JudgedRegistryLink)), trimmed(r, "")...)
	}
	a.add("VS8-100.attest_event_not_found", b1exp(ci.HeadlineUnproven, all3, b1unproven(auth, map[string]any{"reason": "attest_event_not_found", "part": auth}),
		absent(ci.JudgedIntraBlockWindow), absent(ci.JudgedRegistryLink)), trimmed(ci.StatedAttestEventNotFound, "")...)
	a.add("VS8-100.attest_block_out_of_reach", b1exp(ci.HeadlineUnproven, all3, b1unproven(auth, map[string]any{"reason": "attest_block_out_of_reach", "gap": uint64(8192),
		"window": uint64(8191), "hops_carried": uint64(0), "last_hop": f.spec.Blocks.Attest.Number}), absent(ci.JudgedIntraBlockWindow), absent(ci.JudgedRegistryLink)),
		trimmed(ci.StatedAttestBlockOutOfReach, fmt.Sprintf("gap=8192;window=8191;hops_carried=0;last_hop=%d", f.spec.Blocks.Attest.Number))...)
	a.add("VS8-100.block_too_large", b1exp(ci.HeadlineUnproven, all3, b1unproven(auth, map[string]any{"reason": "block_too_large", "part": auth, "bytes": uint64(1048577), "limit": uint64(1048576)}),
		b1unproven(ci.JudgedIntraBlockWindow, map[string]any{"reason": "block_too_large", "part": ci.JudgedIntraBlockWindow, "bytes": uint64(1048577), "limit": uint64(1048576)}),
		absent(ci.JudgedRegistryLink)), trimmed(ci.StatedBlockTooLarge, "bytes=1048577;limit=1048576")...)
	a.add("VS8-100.unknown_reason", b1exp(ci.HeadlineRefused, nil), stated("some_new_reason", ""))

	// ---- VS8-101: order (step 16a) ----
	order := map[string]any{"field": "order"}
	a.add("VS8-101.spine_bv_not_below_n", ref("attest_mismatch", order), b1cont("attest.attest.header_v", b1hexNo(settleHeader)))
	a.add("VS8-101.same_block_txindex_equals_settlement", ref("attest_mismatch", order),
		b1cont("attest.attest.link", "0"), b1cont("attest.attest.spine", []string{}), b1cont("attest.attest.header_v", b1hexNo(settleHeader)),
		b1cont("attest.attest.header_v_parent", b1hexNo(att.Spine[0])), b1cont("attest.attest.tx_index", fmt.Sprint(settleIdx)))
	a.add("VS8-101.hops_bv_not_below_n", ref("attest_mismatch", order), toHops, b1cont("attest.attest.header_v", b1hexNo(settleHeader)))

	// ---- VS8-102: the window is exact; a hop across a gap wider than W verifies; W+1 without a hop is the named limit ----
	e, _ := f.m.EIP2935(11155111)
	W := e.Window
	bv := h.spec.Blocks.Attest.Number
	a.add("VS8-102.hops_gap_W_passes", b1exp(ci.HeadlineVerified, map[string]string{auth: "verified"}), toHops)
	// with no hop carried the nodes of the two hop stations are no longer visited: the container keeps exactly the nodes the verifier visits
	noHops := h.edit(func(c *ci.Container) { c.Attest.Attest.HopHeaders = nil })
	h.run(b1All, noHops, nil)
	kept := make([]string, len(h.visited))
	for i, n := range h.visited {
		kept[i] = b1hexNo(n)
	}
	a.add("VS8-102.no_hop_gap_beyond_window", unp(map[string]any{"reason": "attest_block_out_of_reach", "gap": W + W/2 + 7, "window": W, "hops_carried": uint64(0), "last_hop": bv}),
		toHops, b1cont("attest.attest.hop_headers", []string{}), b1cont("nodes", kept))

	// ---- VS8-103: hop chain refusals ----
	hopsRef := func(idx uint64, reason string) ci.Expected {
		return ref("header_unlinked", map[string]any{"link": "hops", "index": idx, "reason": reason})
	}
	a.add("VS8-103.hops_swapped", hopsRef(0, "gap_out_of_range"), toHops, b1cont("attest.attest.hop_headers", []string{b1hexNo(atth.HopHeaders[1]), b1hexNo(atth.HopHeaders[0])}))
	a.add("VS8-103.hop_duplicated", hopsRef(1, "numbers_not_consecutive"), toHops, b1cont("attest.attest.hop_headers", []string{b1hexNo(atth.HopHeaders[0]), b1hexNo(atth.HopHeaders[0])}))
	a.add("VS8-103.first_hop_dropped", hopsRef(0, "gap_out_of_range"), toHops, b1cont("attest.attest.hop_headers", []string{b1hexNo(atth.HopHeaders[1])}))
	hist := strings.ToLower(h.spec.Roles.History)
	stations := func(edit func(st map[string]*world.Station)) ci.Mutation {
		raw, _ := json.Marshal(h.spec.Stations)
		var st map[string]*world.Station
		_ = json.Unmarshal(raw, &st)
		edit(st)
		return world.Set("stations", st)
	}
	acct := func(st map[string]*world.Station, i int) *world.AcctSpec {
		s := st[world.HopStation(i)]
		if s.Accounts[hist] == nil {
			s.Accounts[hist] = &world.AcctSpec{}
		}
		if s.Accounts[hist].Storage == nil {
			s.Accounts[hist].Storage = map[string]string{}
		}
		return s.Accounts[hist]
	}
	h1 := h.spec.Blocks.Between[0].Number
	a.add("VS8-103.hop_slot_other_hash", hopsRef(0, "slot_mismatch"), toHops, stations(func(st map[string]*world.Station) {
		acct(st, 1).Storage[strings.ToLower(ci.SlotIndex(bv%W).Hex())] = strings.ToLower(common.HexToHash("0x5555").Hex())
	}))
	a.add("VS8-103.hop_slot_empty", hopsRef(1, "slot_mismatch"), toHops, stations(func(st map[string]*world.Station) {
		acct(st, 2).Storage[strings.ToLower(ci.SlotIndex(h1%W).Hex())] = strings.ToLower(common.Hash{}.Hex())
	}))
	a.add("VS8-103.history_code_not_pin", hopsRef(1, "history_code_mismatch"), toHops, stations(func(st map[string]*world.Station) {
		acct(st, 2).Code = &world.CodeSpec{Hex: "0x00"}
	}))

	// ---- VS8-104: spine refusals and the parent of B_v ----
	sp := func(idx uint64, reason string) ci.Expected {
		return ref("header_unlinked", map[string]any{"link": "spine", "index": idx, "reason": reason})
	}
	hx := func(l [][]byte) []string {
		out := make([]string, len(l))
		for i, b := range l {
			out[i] = b1hexNo(b)
		}
		return out
	}
	spine := hx(att.Spine)
	swap := append([]string(nil), spine...)
	swap[0], swap[1] = swap[1], swap[0]
	a.add("VS8-104.spine_header_altered", sp(1, "hash_chain_broken"), b1cont("attest.attest.spine.1", flip(att.Spine[1])))
	a.add("VS8-104.spine_first_altered", sp(0, "hash_chain_broken"), b1cont("attest.attest.spine.0", flip(att.Spine[0])))
	a.add("VS8-104.spine_reordered", sp(0, "hash_chain_broken"), b1cont("attest.attest.spine", swap))
	a.add("VS8-104.spine_header_dropped", sp(1, "hash_chain_broken"), b1cont("attest.attest.spine", []string{spine[0], spine[2]}))
	a.add("VS8-104.spine_empty", sp(0, "hash_chain_broken"), b1cont("attest.attest.spine", []string{}))
	a.add("VS8-104.spine_does_not_end_at_header_v", sp(2, "hash_chain_broken"), b1cont("attest.attest.header_v", flip(att.HeaderV)))
	a.add("VS8-104.header_v_parent_not_the_parent", sp(0, "parent_mismatch"), b1cont("attest.attest.header_v_parent", flip(att.HeaderVParent)))

	// ---- VS8-110/111/112/113/140: the attestation transaction, the blob, the binding ----
	i := b1AttestTxIndex(f)
	txp := func(m string) string { return "blocks.attest.txs." + big.NewInt(int64(i)).String() + "." + m }
	failedReceipt, _ := (&types.Receipt{Type: 2, Status: 0, CumulativeGasUsed: 100000}).MarshalBinary()
	wrapper := func(data []byte) string {
		to := common.HexToAddress("0x2222222222222222222222222222222222222222")
		raw, _ := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: 21000, To: &to, Data: data}).MarshalBinary()
		return b1Hex(raw)
	}
	mm := func(field string) ci.Expected { return ref("attest_mismatch", map[string]any{"field": field}) }
	other := common.HexToHash("0x7777").Hex()
	a.add("VS8-110.tx_of_another_transaction", mm("tx_to"), world.Set(txp("role"), ""), world.Set(txp("seed"), 4242))
	a.add("VS8-110.receipt_without_proof_executed", mm("log"), world.Set("attestation.logs", []world.LogSpec{}))
	a.add("VS8-110.status_zero", mm("status"), world.Set(txp("receipt"), b1Hex(failedReceipt)))
	// [r3.2:F16] the transaction and receipt proofs are proof_invalid{root:attest_tx|attest_receipt, address:A, slot:rlp(txIndex) as 0x hex}
	proofInvalid := func(root string) ci.Expected {
		return ref("proof_invalid", map[string]any{"root": root, "address": f.addr(f.spec.Roles.Anchor), "slot": b1RlpIndexOf(uint64(att.TxIndex))})
	}
	a.add("VS8-110.tx_leaf_not_under_the_root", proofInvalid("attest_tx"), b1cont("attest.attest.tx_leaf", b1hexNo(att.TxLeaf)+"00"))
	a.add("VS8-110.receipt_leaf_not_under_the_root", proofInvalid("attest_receipt"), b1cont("attest.attest.receipt_leaf", b1hexNo(att.ReceiptLeaf)+"00"))
	a.add("VS8-111.wrapper_with_the_log", unp(map[string]any{"reason": "attest_indirect_call", "to": common.HexToAddress("0x2222222222222222222222222222222222222222"), "selector": [4]byte{1, 2, 3, 4}}),
		world.Set(txp("wire"), wrapper([]byte{1, 2, 3, 4})))
	a.add("VS8-111.type_3_transaction", unp(map[string]any{"reason": "attest_tx_type_unsupported", "type": "0x03"}), world.Set(txp("wire"), "0x03c0"))
	a.add("VS8-112.blob_word_12_not_M", mm("blob_layout"), world.Set("attestation.blob.12", other))
	a.add("VS8-112.pkc_zero", mm("blob_layout"), world.Set("attestation.blob.13", common.Hash{}.Hex()))
	a.add("VS8-113.anchor_id_in_calldata", mm("anchor_id"), world.Set("attestation.anchor_id", other))
	a.add("VS8-113.operation_commitment", mm("operation_commitment"), world.Set("attestation.operation_commitment", other))
	// [r3.2:F16] a proven, successful direct call whose calldata the strict decoder refuses is U attest_calldata_undecodable, never R and never a pass
	a.add("VS8-113.calldata_undecodable", unp(map[string]any{"reason": "truncated", "field": "anchorId"}), world.Set(txp("wire"), b1Direct(a.t, f.addr(f.spec.Roles.Anchor), append(b1ExecSel(a.t), make([]byte, 31)...))))
	a.add("VS8-140.message_hash", mm("message_hash"), world.Set("attestation.blob.12", other), world.Set("attestation.message_hash", other))
	return a.out
}

func b1Author(t *testing.T) *b1author {
	return &b1author{t: t, base: b1New(t, 11155111, world.VariantH0), hops: b1New(t, 11155111, world.VariantHops)}
}

// stepVerifier is the Verifier of the vector tests: the real steps 1c-14 and 15-20, stand-ins for the rest.
func (a *b1author) verifier() ci.Verifier {
	v := a.base.verifier(b1All)
	return ci.VerifierFunc(func(ctx ci.LegContext, container []byte, m *ci.Manifest) (ci.Report, error) {
		return v.Verify(ctx, container, m)
	})
}

func TestB1VectorsAgainstTheVerifier(t *testing.T) {
	a := b1Author(t)
	wj, err := a.base.spec.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	wj = append(wj, '\n')
	ver := a.verifier()
	for _, v := range a.vectors() {
		t.Run(v.ID, func(t *testing.T) {
			in, err := world.Builder{Manifest: a.base.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("the world cannot build the vector: %v", err)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, a.base.m)
			if err != nil {
				t.Fatalf("verifier error: %v", err)
			}
			if err := ci.MatchExpected(v.Expected, rep); err != nil {
				t.Fatalf("%v (headline first %v)", err, rep.Headline.First)
			}
		})
	}
}

// The published set: loaded from disk (every file hash-checked), run WITHOUT the world builder on the materialised inputs and regenerated into a
// temporary directory, which must be byte-identical.
func TestVectorSet2b1IsPublishedRunsAndIsReproducible(t *testing.T) {
	a := b1Author(t)
	vectors := a.vectors()
	dir := filepath.Join("testdata", "contractidentity", "vectors", vectorSet2b1)
	if _, err := os.Stat(dir); err != nil && os.Getenv("CERTEN_WRITE_S8_2B1") == "1" {
		if err := world.WriteSet(dir, a.base.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSet2b1, err)
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
	if err := world.WriteSet(tmp, a.base.spec, vectors); err != nil {
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
