// Copyright 2026 Certen Protocol

// Command vectorgen writes the finality_chain1 vector set (V2_SPEC_S7 sections 2.2, 2.3, 2.6, 3.1, 7, 8.2) into
// pkg/finality/testdata/finality_chain1: goldens.json, chains.json, containers.json, table.json and MANIFEST.json (the sha256
// of every file) with MANIFEST.json.sha256 (the sha256 of the manifest). The TypeScript verifier consumes byte-identical copies.
//
// Every tamper vector states its expected verdict as a literal canonical string written HERE, not computed from the code under
// test; the valid vectors are built with the package's own hash functions, whose bytes the goldens G0 and G1 (computed
// independently with Python hashlib and node crypto, V2_SPEC_S7 2.2) pin. A set is specification: new evidence gets a new set
// (finality_chain2), never a re-baseline of this one.
//
//	go run ./pkg/finality/vectorgen -out pkg/finality/testdata/finality_chain1
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/certen/independant-validator/pkg/finality"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func fill(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

type leg struct {
	Chain       uint64 `json:"chain"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`
}

type vector struct {
	Name    string            `json:"name"`
	Note    string            `json:"note"`
	Leg     leg               `json:"leg"`
	Carried leg               `json:"carried"`
	Addenda []json.RawMessage `json:"addenda"`
	Expect  string            `json:"expect"` // "ok" or the canonical state text
}

func ref(chain, number uint64, h [32]byte) finality.BlockRef {
	return finality.BlockRef{Chain: chain, Number: number, Hash: h}
}

func legOf(b finality.BlockRef) leg { return leg{b.Chain, b.Number, hx(b.Hash[:])} }

func container(kind string, b finality.BlockRef, level finality.Level, body string) []byte {
	c := finality.Container{Header: finality.ContainerHeader{Kind: kind, Chain: b.Chain, Level: level, BlockNumber: b.Number, BlockHash: b.Hash}, Body: []byte(body)}
	enc, err := c.Encode()
	if err != nil {
		panic(err)
	}
	return enc
}

type step struct {
	level finality.Level
	kind  string
	body  string
}

var proofID = [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4d, 0xef, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}

// chainOf builds a chain for leg b under d0, hashing every addendum exactly as the spec says (no validation).
func chainOf(d0 [32]byte, b finality.BlockRef, steps []step) []finality.Addendum {
	var out []finality.Addendum
	var prev [32]byte
	for i, s := range steps {
		a := finality.Addendum{ProofID: proofID, Seq: uint64(i + 1), Level: s.level, Chain: b.Chain, Kind: s.kind,
			Evidence: container(s.kind, b, s.level, s.body), PrevHash: prev}
		a.OwnHash = finality.OwnHash(d0, a)
		prev = a.OwnHash
		out = append(out, a)
	}
	return out
}

func rehash(d0 [32]byte, chain []finality.Addendum) []finality.Addendum {
	var prev [32]byte
	for i := range chain {
		chain[i].PrevHash = prev
		chain[i].OwnHash = finality.OwnHash(d0, chain[i])
		prev = chain[i].OwnHash
	}
	return chain
}

func main() {
	out := flag.String("out", "pkg/finality/testdata/finality_chain1", "output directory")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// generate writes the whole set into dir. A failure is returned, never swallowed.
func generate(dir string) (err error) {
	out := &dir
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("vectorgen: %v", r)
		}
	}()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(*out, 0o755))

	const (
		sep  = finality.ChainSepolia
		base = finality.ChainBaseSepolia
	)
	lSep := ref(sep, 11845679, fill(0x22))
	lBase := ref(base, 47368146, fill(0x33))
	d0Sep, d0Base := finality.LegBindingOf(lSep), finality.LegBindingOf(lBase)
	const (
		kSepFin  = "eth-sepolia/finalized/v1"
		kBaseL1  = "base-sepolia/l1_posted/v1"
		kBaseFin = "base-sepolia/finalized/v1"
	)
	L1, FIN := finality.LevelL1Posted, finality.LevelFinalized
	flip := func(b [32]byte) [32]byte { b[7] ^= 1; return b }

	// ---- goldens ----
	g0Add := finality.Addendum{Seq: 1, Level: FIN, Chain: sep, Kind: kSepFin, Evidence: []byte("CFE1-test-vector")}
	g0d0 := fill(0x11)
	g0Own := finality.OwnHash(g0d0, g0Add)
	g1Own := finality.OwnHash(d0Sep, g0Add)
	evSum := sha256.Sum256(g0Add.Evidence)
	goldens := map[string]any{
		"g0": map[string]any{
			"d0": hx(g0d0[:]), "prevHash": hx(make([]byte, 32)), "seq": "1", "level": "3", "chain": "11155111", "kind": kSepFin,
			"evidenceAscii": "CFE1-test-vector", "evidenceSha256": hx(evSum[:]),
			"preimageHex": hx(finality.OwnHashPreimage(g0d0, g0Add)), "preimageLen": len(finality.OwnHashPreimage(g0d0, g0Add)), "ownHash": hx(g0Own[:]),
		},
		"g1": map[string]any{
			"leg":        map[string]any{"chain": "11155111", "blockNumber": "11845679", "blockHash": hx(lSep.Hash[:])},
			"d0Preimage": hx(finality.LegBindingPreimage(sep, lSep.Number, lSep.Hash)), "d0PreimageLen": len(finality.LegBindingPreimage(sep, lSep.Number, lSep.Hash)),
			"d0": hx(d0Sep[:]), "prevHash": hx(make([]byte, 32)), "seq": "1", "level": "3", "chain": "11155111", "kind": kSepFin,
			"evidenceAscii": "CFE1-test-vector", "ownHash": hx(g1Own[:]),
		},
	}
	writeJSON(*out, "goldens.json", goldens, must)

	// ---- chain vectors ----
	carriedOK := func(b finality.BlockRef) leg { return legOf(b) }
	var vs []vector
	add := func(v vector) { vs = append(vs, v) }

	add(vector{Name: "valid_empty", Note: "no addenda: nothing is claimed beyond the proof itself", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: nil, Expect: "ok"})
	add(vector{Name: "valid_sepolia_finalized", Note: "one addendum", Leg: legOf(lSep), Carried: carriedOK(lSep),
		Addenda: raw(chainOf(d0Sep, lSep, []step{{FIN, kSepFin, "lc"}})), Expect: "ok"})
	add(vector{Name: "valid_base_l1_posted_then_finalized", Note: "levels in ascending order", Leg: legOf(lBase), Carried: carriedOK(lBase),
		Addenda: raw(chainOf(d0Base, lBase, []step{{L1, kBaseL1, "a"}, {FIN, kBaseFin, "b"}})), Expect: "ok"})
	add(vector{Name: "valid_base_finalized_then_l1_posted", Note: "any level order is valid: seq orders the chain, not the levels (R1)", Leg: legOf(lBase), Carried: carriedOK(lBase),
		Addenda: raw(chainOf(d0Base, lBase, []step{{FIN, kBaseFin, "b"}, {L1, kBaseL1, "a"}})), Expect: "ok"})

	two := func() []finality.Addendum {
		return chainOf(d0Base, lBase, []step{{L1, kBaseL1, "a"}, {FIN, kBaseFin, "b"}})
	}
	c := two()
	c[1].Seq = 3
	add(vector{Name: "tamper_seq_gap", Note: "second addendum states seq 3", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"seq_gap","seq":"3","want":"2"}}`})
	c = two()
	c[1].PrevHash = flip(c[1].PrevHash)
	add(vector{Name: "tamper_prev_hash", Note: "second addendum's prevHash is not the first's ownHash", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"prev_hash","seq":"2"}}`})
	c = two()
	c[0].PrevHash[0] = 1
	add(vector{Name: "tamper_first_prev_hash_not_zero", Note: "the first addendum's prevHash is not 32 zero bytes", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"prev_hash","seq":"1"}}`})
	c = two()
	c[0].OwnHash = flip(c[0].OwnHash)
	add(vector{Name: "tamper_own_hash", Note: "stored ownHash flipped", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"own_hash","seq":"1"}}`})
	c = two()
	c[0].Evidence = append(append([]byte(nil), c[0].Evidence...), 0)
	add(vector{Name: "tamper_evidence_byte", Note: "evidence changed after hashing", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"own_hash","seq":"1"}}`})
	c = chainOf(d0Base, lBase, []step{{FIN, kBaseFin, "b"}, {FIN, kBaseFin, "b2"}})
	add(vector{Name: "tamper_level_duplicate", Note: "two finalized addenda, correctly chained", Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(c),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"level_duplicate","level":"finalized","seq":"2"}}`})
	add(vector{Name: "tamper_kind_unregistered_version", Note: "kind v2 is not a table row, correctly hashed", Leg: legOf(lBase), Carried: carriedOK(lBase),
		Addenda: raw(chainOf(d0Base, lBase, []step{{FIN, "base-sepolia/finalized/v2", "b"}})),
		Expect:  `{"code":"finality_chain_broken","fields":{"chain":"84532","check":"kind","kind":"base-sepolia/finalized/v2","level":"finalized","seq":"1"}}`})
	add(vector{Name: "kind_level1_refused", Note: "level 1 (included) is derived and never stored; correctly hashed", Leg: legOf(lBase), Carried: carriedOK(lBase),
		Addenda: raw(rehash(d0Base, []finality.Addendum{{ProofID: proofID, Seq: 1, Level: finality.LevelIncluded, Chain: base, Kind: "included.eth-mpt/v1", Evidence: []byte("x")}})),
		Expect:  `{"code":"finality_addendum_malformed","fields":{"field":"level","reason":"level \"included\" is derived and never stored (stored levels: l1_posted, finalized)"}}`})
	add(vector{Name: "kind_wrong_level_for_kind", Note: "the l1_posted kind at level finalized", Leg: legOf(lBase), Carried: carriedOK(lBase),
		Addenda: raw(rehash(d0Base, []finality.Addendum{{ProofID: proofID, Seq: 1, Level: FIN, Chain: base, Kind: kBaseL1, Evidence: []byte("x")}})),
		Expect:  `{"code":"finality_chain_broken","fields":{"chain":"84532","check":"kind","kind":"base-sepolia/l1_posted/v1","level":"finalized","seq":"1"}}`})
	add(vector{Name: "kind_l1_posted_on_sepolia", Note: "Sepolia is the L1: it has no l1_posted row, so the file cannot supply one", Leg: legOf(lSep), Carried: carriedOK(lSep),
		Addenda: raw(rehash(d0Sep, []finality.Addendum{{ProofID: proofID, Seq: 1, Level: L1, Chain: sep, Kind: kBaseL1, Evidence: []byte("x")}})),
		Expect:  `{"code":"finality_chain_broken","fields":{"chain":"11155111","check":"kind","kind":"base-sepolia/l1_posted/v1","level":"l1_posted","seq":"1"}}`})

	// leg binding
	carriedAltered := legOf(lBase)
	carriedAltered.BlockNumber++
	add(vector{Name: "leg_binding_altered_leg_member", Note: "the carried leg's blockNumber differs from the verified Settlement's: nothing else is judged",
		Leg: legOf(lBase), Carried: carriedAltered, Addenda: raw(two()),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"leg_binding","got":{"blockHash":"` + hx(lBase.Hash[:]) + `","blockNumber":"47368147","chain":"84532"},"seq":"0","want":{"blockHash":"` + hx(lBase.Hash[:]) + `","blockNumber":"47368146","chain":"84532"}}}`})
	other := ref(base, 47368147, fill(0x33))
	add(vector{Name: "wrong_d0_with_matching_leg", Note: "addenda chained under the D0 of another block, leg member untouched: fails own_hash at seq 1",
		Leg: legOf(lBase), Carried: carriedOK(lBase), Addenda: raw(chainOf(finality.LegBindingOf(other), lBase, []step{{L1, kBaseL1, "a"}, {FIN, kBaseFin, "b"}})),
		Expect: `{"code":"finality_chain_broken","fields":{"check":"own_hash","seq":"1"}}`})
	add(vector{Name: "chain_unsupported", Note: "a chain id that is not a row of the table has no S7 statement at all",
		Leg: legOf(ref(1, 100, fill(0x44))), Carried: carriedOK(ref(1, 100, fill(0x44))), Addenda: nil,
		Expect: `{"code":"finality_chain_unsupported","fields":{"chain":"1"}}`})
	writeJSON(*out, "chains.json", map[string]any{"format": "certen-finality-vectors/1", "set": "finality_chain1", "kind": "chain", "vectors": vs}, must)

	// ---- container vectors ----
	type cvec struct {
		Name   string            `json:"name"`
		Note   string            `json:"note"`
		Hex    string            `json:"hex"`
		Limits map[string]uint64 `json:"limits,omitempty"`
		Expect string            `json:"expect"`
	}
	var cs []cvec
	good := container(kBaseFin, lBase, FIN, "BODY")
	goodL1 := container(kBaseL1, lBase, L1, "")
	hdr := func(b []byte) string { return hx(b) }
	cs = append(cs,
		cvec{Name: "header_l3", Note: "valid finalized header with a 4-byte body", Hex: hdr(good),
			Expect: `{"blockHash":"` + hx(lBase.Hash[:]) + `","blockNumber":"47368146","body":"424f4459","chain":"84532","kind":"base-sepolia/finalized/v1","level":"3"}`},
		cvec{Name: "header_l2_empty_body", Note: "valid l1_posted header, empty body", Hex: hdr(goodL1),
			Expect: `{"blockHash":"` + hx(lBase.Hash[:]) + `","blockNumber":"47368146","body":"","chain":"84532","kind":"base-sepolia/l1_posted/v1","level":"2"}`},
	)
	badMagic := append([]byte(nil), good...)
	badMagic[3] = '2'
	cs = append(cs, cvec{Name: "header_bad_magic", Note: "CFE2", Hex: hdr(badMagic), Expect: `{"code":"finality_evidence_unrecognised","fields":{"kind":"","version":"magic:43464532"}}`})
	for _, lv := range []byte{0, 1, 4} {
		b := append([]byte(nil), good...)
		b[4+4+len(kBaseFin)+8] = lv
		cs = append(cs, cvec{Name: fmt.Sprintf("header_level_%d", lv), Note: "levels other than 2 and 3 are never carried", Hex: hdr(b),
			Expect: fmt.Sprintf(`{"code":"finality_evidence_malformed","fields":{"got_len":"%d","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`, lv)})
	}
	cs = append(cs,
		cvec{Name: "header_truncated_in_blockhash", Note: "cut inside the block hash", Hex: hdr(good[:4+4+len(kBaseFin)+8+1+8+10]),
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"10","part":"header.blockHash","reason":"truncated","want_len":"32"}}`},
		cvec{Name: "header_truncated_in_magic", Note: "three bytes", Hex: hdr(good[:3]),
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"3","part":"header.magic","reason":"truncated","want_len":"4"}}`},
	)
	nul := append([]byte(nil), good...)
	nul[4+4+2] = 0
	cs = append(cs, cvec{Name: "header_kind_has_nul", Note: "a STR holds no NUL", Hex: hdr(nul),
		Expect: fmt.Sprintf(`{"code":"finality_evidence_malformed","fields":{"got_len":"%d","index":"2","part":"header.kind","reason":"a STR is ASCII with no NUL","want_len":"%d"}}`, len(kBaseFin), len(kBaseFin))})
	cs = append(cs, cvec{Name: "evidence_too_large", Note: "the container exceeds max_evidence_bytes (overridden to 64 for the vector)", Hex: hdr(good), Limits: map[string]uint64{"max_evidence_bytes": 64},
		Expect: fmt.Sprintf(`{"code":"finality_evidence_too_large","fields":{"count":"%d","limit":"64","part":"evidence"}}`, len(good))})
	cs = append(cs, cvec{Name: "header_kind_str_too_long", Note: "kind STR over max_string_bytes (overridden to 8)", Hex: hdr(good), Limits: map[string]uint64{"max_string_bytes": 8},
		Expect: fmt.Sprintf(`{"code":"finality_evidence_too_large","fields":{"count":"%d","limit":"8","part":"header.kind"}}`, len(kBaseFin))})
	writeJSON(*out, "containers.json", map[string]any{"format": "certen-finality-vectors/1", "set": "finality_chain1", "kind": "container", "vectors": cs}, must)

	// ---- codec probe vectors: body = LIST<LP> (part probe.list, <= 4 items of <= 16 bytes) || NODES (part probe.nodes, nodes <= 8
	// bytes, count <= max_nodes) || u64 (probe.n) || end (probe.end) ----
	nodes := finality.EncodeNodes([][]byte{[]byte("n1"), []byte("n2"), []byte("n3")})
	probe := func(items [][]byte, nds [][]byte, n uint64, tail []byte) string {
		var w finality.Writer
		w.LPList(items)
		w.Nodes(nds)
		w.U64(n)
		w.Fixed(tail)
		return hx(w.Bytes())
	}
	type pvec struct {
		Name   string            `json:"name"`
		Note   string            `json:"note"`
		Hex    string            `json:"hex"`
		Limits map[string]uint64 `json:"limits,omitempty"`
		Expect string            `json:"expect"`
	}
	items := [][]byte{[]byte("ab"), nil, []byte("c")}
	var ps []pvec
	ps = append(ps,
		pvec{Name: "probe_valid", Note: "decode then re-encode is the identity", Hex: probe(items, nodes, 7, nil), Expect: "ok"},
		pvec{Name: "probe_trailing_byte", Hex: probe(items, nodes, 7, []byte{0}),
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"probe.end","reason":"trailing bytes","want_len":"0"}}`},
		pvec{Name: "probe_list_over_limit", Hex: probe([][]byte{{1}, {2}, {3}, {4}, {5}}, nodes, 7, nil),
			Expect: `{"code":"finality_evidence_too_large","fields":{"count":"5","limit":"4","part":"probe.list"}}`},
		pvec{Name: "probe_element_over_limit", Hex: probe([][]byte{make([]byte, 17)}, nodes, 7, nil),
			Expect: `{"code":"finality_evidence_too_large","fields":{"count":"17","index":"0","limit":"16","part":"probe.list"}}`},
		pvec{Name: "probe_nodes_over_max_nodes", Note: "max_nodes overridden to 2", Hex: probe(items, nodes, 7, nil), Limits: map[string]uint64{"max_nodes": 2},
			Expect: `{"code":"finality_evidence_too_large","fields":{"count":"3","limit":"2","part":"probe.nodes"}}`},
		pvec{Name: "probe_node_over_max_node_bytes", Hex: probe(items, [][]byte{make([]byte, 9)}, 7, nil),
			Expect: `{"code":"finality_evidence_too_large","fields":{"count":"9","index":"0","limit":"8","part":"probe.nodes"}}`},
		pvec{Name: "probe_nodes_descending", Hex: probe(items, [][]byte{nodes[1], nodes[0]}, 7, nil),
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes are not strictly ascending by keccak256 and unique","want_len":"0"}}`},
		pvec{Name: "probe_nodes_duplicate", Hex: probe(items, [][]byte{nodes[0], nodes[0]}, 7, nil),
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes are not strictly ascending by keccak256 and unique","want_len":"0"}}`},
		pvec{Name: "probe_truncated_u64", Hex: probe(items, nodes, 7, nil)[:len(probe(items, nodes, 7, nil))-8],
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.n","reason":"truncated","want_len":"8"}}`},
		pvec{Name: "probe_count_exceeds_remaining", Note: "a hostile count never allocates", Hex: "00000004" + "00000000",
			Expect: `{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.list","reason":"count exceeds the remaining bytes","want_len":"16"}}`},
	)
	writeJSON(*out, "codec_probe.json", map[string]any{
		"format": "certen-finality-vectors/1", "set": "finality_chain1", "kind": "codec_probe",
		"grammar": "LPList(part probe.list, limit 4, element max 16) || Nodes(part probe.nodes, max_nodes from limits (default 8192), node max 8) || U64(probe.n) || End(probe.end)",
		"vectors": ps}, must)

	// ---- table ----
	type tq struct {
		Chain  uint64 `json:"chain"`
		Level  uint8  `json:"level"`
		Expect string `json:"expect"`
	}
	tqs := []tq{
		{sep, 3, "kind:eth-sepolia/finalized/v1"},
		{sep, 2, `{"code":"level_not_applicable","fields":{"chain":"11155111","level":"l1_posted","reason":"this chain is the L1"}}`},
		{base, 2, "kind:base-sepolia/l1_posted/v1"}, {base, 3, "kind:base-sepolia/finalized/v1"},
		{finality.ChainArbitrumSepolia, 2, "kind:arb-sepolia/l1_posted/v1"}, {finality.ChainArbitrumSepolia, 3, "kind:arb-sepolia/finalized/v1"},
		{finality.ChainAdiri, 3, "kind:adiri/finalized/v1"},
		{finality.ChainAdiri, 2, `{"code":"level_not_applicable","fields":{"chain":"2017","level":"l1_posted","reason":"no L1 settlement exists"}}`},
		{1, 3, `{"code":"finality_chain_unsupported","fields":{"chain":"1"}}`},
		{0, 3, `{"code":"finality_chain_unsupported","fields":{"chain":"0"}}`},
		{base, 1, `{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"level","reason":"included (1) is derived and never stored; only l1_posted (2) and finalized (3) have kinds","want_len":"2"}}`},
	}
	writeJSON(*out, "table.json", map[string]any{"format": "certen-finality-vectors/1", "set": "finality_chain1", "kind": "table", "queries": tqs}, must)

	// ---- manifest ----
	files := []string{"goldens.json", "chains.json", "containers.json", "codec_probe.json", "table.json"}
	sums := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(*out, f))
		must(err)
		s := sha256.Sum256(b)
		sums[f] = hx(s[:])
	}
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	writeJSON(*out, "MANIFEST.json", map[string]any{"format": "certen-finality-manifest/1", "set": "finality_chain1", "files": sums}, must)
	mb, err := os.ReadFile(filepath.Join(*out, "MANIFEST.json"))
	must(err)
	ms := sha256.Sum256(mb)
	must(os.WriteFile(filepath.Join(*out, "MANIFEST.json.sha256"), []byte(hx(ms[:])+"\n"), 0o644))
	fmt.Printf("wrote %d files to %s; manifest sha256 %s\n", len(files)+2, *out, hx(ms[:]))
	return nil
}

func writeJSON(dir, name string, v any, must func(error)) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644))
}

// raw renders a chain as the JSON elements of the portable `finality.addenda` member.
func raw(chain []finality.Addendum) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(chain))
	for _, a := range chain {
		b, err := json.Marshal(a)
		if err != nil {
			panic(err)
		}
		out = append(out, b)
	}
	return out
}
