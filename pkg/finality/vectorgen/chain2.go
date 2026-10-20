// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
)

// finality_chain2 (RB11-B2B1) supersedes finality_chain1 for every expectation that carried a Go sentence, and adds the cases
// the independent review V-B2A found untested (D1 block hash / chain binding, D2 header slots, D3 strict JSON, D6 pins unknown
// key, D8 conditional fields) plus the pins invariants and the canonical form of a mixed-type fields map. finality_chain1 is NOT
// touched: chain2's containers.json, codec_probe.json, table.json and the chain vectors are chain1's files read back with the
// ten superseded expectations replaced by the literals below (the enum token instead of the sentence) and nothing else.
//
//	go run ./pkg/finality/vectorgen -set chain2 -chain1 pkg/finality/testdata/finality_chain1 -out pkg/finality/testdata/finality_chain2
//
// Every expectation here is a literal written in this file, never computed from the code under test.

// superseded2 maps a chain1 expectation (canonical state text or ordinary text) to its chain2 replacement.
var superseded2 = [][2]string{
	{`{"code":"finality_addendum_malformed","fields":{"field":"level","reason":"level \"included\" is derived and never stored (stored levels: l1_posted, finalized)"}}`,
		`{"code":"finality_addendum_malformed","fields":{"field":"level","reason":"level_not_stored"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.level","reason":"level_not_stored","want_len":"2"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"header.level","reason":"level_not_stored","want_len":"2"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"header.level","reason":"level_not_stored","want_len":"2"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"25","index":"2","part":"header.kind","reason":"a STR is ASCII with no NUL","want_len":"25"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"25","index":"2","part":"header.kind","reason":"str_not_ascii_or_nul","want_len":"25"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"probe.end","reason":"trailing bytes","want_len":"0"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"probe.end","reason":"trailing_bytes","want_len":"0"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes are not strictly ascending by keccak256 and unique","want_len":"0"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes_not_ascending_unique","want_len":"0"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.list","reason":"count exceeds the remaining bytes","want_len":"16"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.list","reason":"count_exceeds_remaining","want_len":"16"}}`},
	{`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"level","reason":"included (1) is derived and never stored; only l1_posted (2) and finalized (3) have kinds","want_len":"2"}}`,
		`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"level","reason":"level_not_stored","want_len":"2"}}`},
}

func supersede(expect string) string {
	for _, p := range superseded2 {
		if expect == p[0] {
			return p[1]
		}
	}
	return expect
}

// reissue reads a chain1 vector file and returns it with every `expect` passed through supersede, vector order and all other
// members unchanged. The number of replaced expectations is returned.
func reissue(chain1Dir, name, set string, must func(error)) (map[string]any, int) {
	b, err := os.ReadFile(filepath.Join(chain1Dir, name))
	must(err)
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	must(dec.Decode(&doc))
	doc["set"] = set
	changed := 0
	for _, key := range []string{"vectors", "queries"} {
		list, ok := doc[key].([]any)
		if !ok {
			continue
		}
		for _, e := range list {
			m := e.(map[string]any)
			old, _ := m["expect"].(string)
			if nw := supersede(old); nw != old {
				m["expect"] = nw
				changed++
			}
		}
	}
	return doc, changed
}

func hdrRLP(items [][]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	if len(payload) <= 55 {
		return append([]byte{0xc0 + byte(len(payload))}, payload...)
	}
	n := []byte{}
	for l := len(payload); l > 0; l >>= 8 {
		n = append([]byte{byte(l & 0xff)}, n...)
	}
	return append(append([]byte{0xf7 + byte(len(n))}, n...), payload...)
}

func rlpStr(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return b
	case len(b) <= 55:
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	panic("rlpStr: item too long for the vector builder")
}

// headerItems is the 17-item header the vectors vary: slots 0,3,4,5,16 are 32-byte strings, 8 the number 258 (0x0102), 11 the
// timestamp 1700000000 (0x6553f100), the others a single byte.
func headerItems(n int) [][]byte {
	var items [][]byte
	for i := 0; i < n; i++ {
		switch i {
		case 0, 3, 4, 5, 16:
			h := fill(byte(0x10 + i))
			items = append(items, rlpStr(h[:]))
		case 8:
			items = append(items, rlpStr([]byte{0x01, 0x02}))
		case 11:
			items = append(items, rlpStr([]byte{0x65, 0x53, 0xf1, 0x00}))
		default:
			items = append(items, rlpStr([]byte{byte(i + 1)}))
		}
	}
	return items
}

// pinsMap parses the embedded pins into generic maps (numbers kept exact), lets edit change them and renders them with sorted
// keys and two-space indentation, LF only, as the pins file is.
func pinsText(edit func(top, sep map[string]any)) string {
	var top map[string]any
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		panic(err)
	}
	if edit != nil {
		edit(top, top["eth_sepolia"].(map[string]any))
	}
	b, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

func anchorMap(period int, wsp int) map[string]any {
	return map[string]any{
		"committee_root": "0x" + strings.Repeat("ab", 32), "derived_by": []any{"lighthouse", "lodestar"},
		"link_sha256": strings.Repeat("cd", 32), "period": json.Number(fmt.Sprint(period)), "wsp_epochs": json.Number(fmt.Sprint(wsp)),
	}
}

func generate2(dir, chain1Dir, registryPath string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("vectorgen chain2: %v", r)
		}
	}()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(dir, 0o755))
	const set = "finality_chain2"
	const (
		sep  = finality.ChainSepolia
		base = finality.ChainBaseSepolia
		arb  = finality.ChainArbitrumSepolia
	)
	const (
		kSepFin  = "eth-sepolia/finalized/v1"
		kBaseL1  = "base-sepolia/l1_posted/v1"
		kBaseFin = "base-sepolia/finalized/v1"
		kArbFin  = "arb-sepolia/finalized/v1"
	)
	L1, FIN := finality.LevelL1Posted, finality.LevelFinalized
	lSep := ref(sep, 11845679, fill(0x22))
	lBase := ref(base, 47368146, fill(0x33))
	lSec := ref(base, 47368146, fill(0xab)) // the section vectors carry a hash with letters so an upper-case edit differs
	d0Sep, d0Base := finality.LegBindingOf(lSep), finality.LegBindingOf(lBase)
	replaced := 0

	// ---- chains.json: chain1's chain vectors (kind_level1_refused re-issued with its token) + the real-kind Sepolia vector ----
	chains, n := reissue(chain1Dir, "chains.json", set, must)
	replaced += n
	vs := chains["vectors"].([]any)
	vecToMap := func(v vector) map[string]any {
		b, e := json.Marshal(v)
		must(e)
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		must(d.Decode(&m))
		return m
	}
	vs = append(vs,
		vecToMap(vector{Name: "kind_l1_posted_on_sepolia_real_kind", Note: "Sepolia is the L1: it has no l1_posted row; the kind string is the real one the table would carry (eth-sepolia/l1_posted/v1), not another chain's",
			Leg: legOf(lSep), Carried: legOf(lSep),
			Addenda: raw(rehash(d0Sep, []finality.Addendum{{ProofID: proofID, Seq: 1, Level: L1, Chain: sep, Kind: "eth-sepolia/l1_posted/v1", Evidence: []byte("x")}})),
			Expect:  `{"code":"finality_chain_broken","fields":{"chain":"11155111","check":"kind","kind":"eth-sepolia/l1_posted/v1","level":"l1_posted","seq":"1"}}`}),
		vecToMap(vector{Name: "kind_adiri_l1_posted_real_kind", Note: "Adiri has no L1 settlement: no l1_posted row",
			Leg: legOf(ref(finality.ChainAdiri, 498759, fill(0x55))), Carried: legOf(ref(finality.ChainAdiri, 498759, fill(0x55))),
			Addenda: raw(rehash(finality.LegBindingOf(ref(finality.ChainAdiri, 498759, fill(0x55))), []finality.Addendum{{ProofID: proofID, Seq: 1, Level: L1, Chain: finality.ChainAdiri, Kind: "adiri/l1_posted/v1", Evidence: []byte("x")}})),
			Expect:  `{"code":"finality_chain_broken","fields":{"chain":"2017","check":"kind","kind":"adiri/l1_posted/v1","level":"l1_posted","seq":"1"}}`}),
	)
	chains["vectors"] = vs
	writeJSON(dir, "chains.json", chains, must)

	// ---- containers.json, codec_probe.json, table.json: chain1's, re-issued ----
	for _, f := range []string{"containers.json", "codec_probe.json", "table.json"} {
		doc, n := reissue(chain1Dir, f, set, must)
		replaced += n
		writeJSON(dir, f, doc, must)
	}
	if replaced != len(superseded2) {
		return fmt.Errorf("vectorgen chain2: %d expectations were replaced, the supersession list has %d", replaced, len(superseded2))
	}

	// ---- json.json: strict JSON of an addendum, a section and a proof id (D3) ----
	type jvec struct {
		Name   string `json:"name"`
		Note   string `json:"note,omitempty"`
		Target string `json:"target"` // addendum | section | proofId
		Input  string `json:"input"`
		Expect string `json:"expect"`
	}
	var js []jvec
	jadd := func(name, target, input, expect string) {
		js = append(js, jvec{Name: name, Target: target, Input: input, Expect: expect})
	}
	am := func(field, reason string) string {
		return `{"code":"finality_addendum_malformed","fields":{"field":"` + field + `","reason":"` + reason + `"}}`
	}
	amk := func(field, reason, key string) string {
		return `{"code":"finality_addendum_malformed","fields":{"field":"` + field + `","key":"` + key + `","reason":"` + reason + `"}}`
	}
	good := chainOf(d0Base, lBase, []step{{FIN, kBaseFin, "b"}})
	gb, e := json.Marshal(good[0])
	must(e)
	V := string(gb)
	sw := func(old, nw string) string {
		if !strings.Contains(V, old) {
			panic("json vector base lacks " + old)
		}
		return strings.Replace(V, old, nw, 1)
	}
	zero64 := strings.Repeat("0", 64)
	idText := `"proofId":"` + finality.ProofIDString(proofID) + `"`
	jadd("addendum_valid", "addendum", V, "ok")
	jadd("addendum_key_case_Seq", "addendum", sw(`"seq"`, `"Seq"`), amk("addendum", "unknown_key", "Seq"))
	jadd("addendum_key_case_proofid", "addendum", sw(`"proofId"`, `"proofid"`), amk("addendum", "unknown_key", "proofid"))
	jadd("addendum_extra_key", "addendum", strings.Replace(V, `{`, `{"extra":1,`, 1), amk("addendum", "unknown_key", "extra"))
	jadd("addendum_duplicate_seq", "addendum", strings.Replace(V, `{`, `{"seq":1,`, 1), amk("addendum", "duplicate_key", "seq"))
	jadd("addendum_key_spelled_with_unicode_escape_is_the_key", "addendum", sw(`"seq"`, `"seq"`), "ok")
	jadd("addendum_unicode_escape_key_duplicates_seq", "addendum", strings.Replace(V, `{`, `{"seq":1,`, 1), amk("addendum", "duplicate_key", "seq"))
	jadd("addendum_missing_kind", "addendum", sw(`"kind":"`+kBaseFin+`",`, ``), amk("addendum", "missing_key", "kind"))
	jadd("addendum_missing_ownHash", "addendum", sw(`,"ownHash":"`+hx(good[0].OwnHash[:])+`"`, ``), amk("addendum", "missing_key", "ownHash"))
	jadd("addendum_prevHash_uppercase", "addendum", sw(`"prevHash":"`+zero64+`"`, `"prevHash":"`+strings.Repeat("A", 64)+`"`), am("prevHash", "not_lowercase_hex"))
	jadd("addendum_ownHash_uppercase", "addendum", sw(hx(good[0].OwnHash[:]), strings.ToUpper(hx(good[0].OwnHash[:]))), am("ownHash", "not_lowercase_hex"))
	jadd("addendum_ownHash_short", "addendum", sw(hx(good[0].OwnHash[:]), hx(good[0].OwnHash[:])[:62]), am("ownHash", "not_32_bytes"))
	jadd("addendum_ownHash_odd_length", "addendum", sw(hx(good[0].OwnHash[:]), hx(good[0].OwnHash[:])[:63]), am("ownHash", "not_lowercase_hex"))
	jadd("addendum_ownHash_0x_prefix", "addendum", sw(`"ownHash":"`, `"ownHash":"0x`), am("ownHash", "not_lowercase_hex"))
	jadd("addendum_evidence_not_hex", "addendum", sw(`"evidence":"`, `"evidence":"zz`), am("evidence", "not_lowercase_hex"))
	jadd("addendum_evidence_uppercase", "addendum", sw(`"evidence":"43464531`, `"evidence":"43464531`+"AB"), am("evidence", "not_lowercase_hex"))
	jadd("addendum_level_included", "addendum", sw(`"level":"finalized"`, `"level":"included"`), am("level", "level_not_stored"))
	jadd("addendum_level_unknown", "addendum", sw(`"level":"finalized"`, `"level":"L1_POSTED"`), am("level", "unknown_level"))
	jadd("addendum_seq_null", "addendum", sw(`"seq":1`, `"seq":null`), am("seq", "bad_value"))
	jadd("addendum_seq_string", "addendum", sw(`"seq":1`, `"seq":"1"`), am("seq", "bad_value"))
	jadd("addendum_seq_float", "addendum", sw(`"seq":1`, `"seq":1.0`), am("seq", "bad_value"))
	jadd("addendum_seq_exponent", "addendum", sw(`"seq":1`, `"seq":1e0`), am("seq", "bad_value"))
	jadd("addendum_seq_negative", "addendum", sw(`"seq":1`, `"seq":-1`), am("seq", "bad_value"))
	jadd("addendum_seq_overflow_u64", "addendum", sw(`"seq":1`, `"seq":18446744073709551616`), am("seq", "bad_value"))
	jadd("addendum_chain_boolean", "addendum", sw(`"chain":84532`, `"chain":true`), am("chain", "bad_value"))
	jadd("addendum_kind_number", "addendum", sw(`"kind":"`+kBaseFin+`"`, `"kind":7`), am("kind", "bad_value"))
	jadd("addendum_proofId_upper", "addendum", sw(idText, `"proofId":"`+strings.ToUpper(finality.ProofIDString(proofID))+`"`), am("proofId", "not_canonical_uuid"))
	jadd("addendum_proofId_no_dashes", "addendum", sw(idText, `"proofId":"`+strings.ReplaceAll(finality.ProofIDString(proofID), "-", "")+`"`), am("proofId", "not_canonical_uuid"))
	jadd("addendum_trailing_data", "addendum", V+" x", am("addendum", "not_json"))
	jadd("addendum_second_document", "addendum", V+V, am("addendum", "not_json"))
	jadd("addendum_not_an_object", "addendum", `[]`, am("addendum", "not_json"))
	jadd("addendum_null_document", "addendum", `null`, am("addendum", "not_json"))
	jadd("addendum_syntax_error_after_an_unknown_key", "addendum", `{"extra":1,`, am("addendum", "not_json"))

	sect := finality.NewSection(lSec, good)
	sb, e := json.Marshal(sect)
	must(e)
	S := string(sb)
	legText := `"leg":{"chain":84532,"blockNumber":47368146,"blockHash":"` + hx(lSec.Hash[:]) + `"}`
	if !strings.Contains(S, legText) {
		panic("section vector base lacks the leg text")
	}
	ss := func(old, nw string) string { return strings.Replace(S, old, nw, 1) }
	jadd("section_valid", "section", S, "ok")
	jadd("section_wrong_format", "section", ss(finality.SectionFormat, "certen-finality-addenda/2"), am("format", "wrong_format"))
	jadd("section_key_case_Format", "section", ss(`"format"`, `"Format"`), amk("finality", "unknown_key", "Format"))
	jadd("section_old_digest_member", "section", ss(`{`, `{"originalProofDigest":"00",`), amk("finality", "unknown_key", "originalProofDigest"))
	jadd("section_duplicate_leg", "section", ss(`{`, `{`+legText+`,`), amk("finality", "duplicate_key", "leg"))
	jadd("section_missing_addenda", "section", strings.Replace(S, `,"addenda":`+string(mustMarshal(sect.Addenda, must)), ``, 1), amk("finality", "missing_key", "addenda"))
	jadd("section_leg_missing_blockHash", "section", ss(`,"blockHash":"`+hx(lSec.Hash[:])+`"`, ``), amk("leg", "missing_key", "blockHash"))
	jadd("section_leg_extra_key", "section", ss(legText[:len(legText)-1], legText[:len(legText)-1]+`,"x":1`), amk("leg", "unknown_key", "x"))
	jadd("section_leg_blockHash_uppercase", "section", ss(hx(lSec.Hash[:]), strings.ToUpper(hx(lSec.Hash[:]))), am("leg.blockHash", "not_lowercase_hex"))
	jadd("section_leg_blockHash_short", "section", ss(`"blockHash":"`+hx(lSec.Hash[:]), `"blockHash":"`+hx(lSec.Hash[:])[:62]), am("leg.blockHash", "not_32_bytes"))
	jadd("section_leg_blockNumber_string", "section", ss(`"blockNumber":47368146`, `"blockNumber":"47368146"`), am("leg.blockNumber", "bad_value"))
	jadd("section_addenda_null", "section", strings.Replace(S, `"addenda":`+string(mustMarshal(sect.Addenda, must)), `"addenda":null`, 1), am("addenda", "bad_value"))
	jadd("section_addenda_element_error_carries_index", "section", strings.Replace(S, `"seq":1`, `"seq":null`, 1),
		`{"code":"finality_addendum_malformed","fields":{"field":"seq","index":"0","reason":"bad_value"}}`)
	jadd("section_trailing_data", "section", S+" x", am("finality", "not_json"))
	for _, p := range []struct{ name, in, ex string }{
		{"proofId_valid", finality.ProofIDString(proofID), "ok"},
		{"proofId_upper", strings.ToUpper(finality.ProofIDString(proofID)), "bad"},
		{"proofId_no_dashes", strings.ReplaceAll(finality.ProofIDString(proofID), "-", ""), "bad"},
		{"proofId_braces", "{" + finality.ProofIDString(proofID) + "}", "bad"},
		{"proofId_urn", "urn:uuid:" + finality.ProofIDString(proofID), "bad"},
		{"proofId_dash_misplaced", "01234567-89a-b4def-8012-3456789abcde0", "bad"},
		{"proofId_35_chars", finality.ProofIDString(proofID)[1:], "bad"},
		{"proofId_37_chars", finality.ProofIDString(proofID) + "0", "bad"},
		{"proofId_non_hex", "0123456g-89ab-4def-8012-3456789abcde", "bad"},
		{"proofId_empty", "", "bad"},
	} {
		ex := p.ex
		if ex == "bad" {
			ex = am("proofId", "not_canonical_uuid")
		}
		jadd(p.name, "proofId", p.in, ex)
	}
	writeJSON(dir, "json.json", map[string]any{"format": "certen-finality-vectors/1", "set": set, "kind": "json",
		"runner":  "addendum: Addendum.UnmarshalJSON(input); section: ParseSection(input); proofId: ParseProofID(input); expect is ok or the canonical state",
		"vectors": js}, must)

	// ---- header.json: positional header reading (D2) ----
	type hvec struct {
		Name   string `json:"name"`
		Note   string `json:"note,omitempty"`
		Hex    string `json:"hex"`
		Expect string `json:"expect"`
	}
	var hs []hvec
	hadd := func(name, note string, raw []byte, expect string) { hs = append(hs, hvec{name, note, hx(raw), expect}) }
	hm := func(index, reason string, got, want int) string {
		idx := ""
		if index != "" {
			idx = `"index":"` + index + `",`
		}
		return fmt.Sprintf(`{"code":"finality_evidence_malformed","fields":{"got_len":"%d",%s"part":"header","reason":"%s","want_len":"%d"}}`, got, idx, reason, want)
	}
	okHeader := func(items int, wd string) string {
		return fmt.Sprintf(`{"items":"%d","number":"258","timestamp":"1700000000","withdrawalsRoot":%s}`, items, wd)
	}
	wdHex := fill(0x10 + 16)
	hadd("header_17_items", "number 0x0102, timestamp 0x6553f100, withdrawalsRoot present", hdrRLP(headerItems(17)), okHeader(17, `"`+hx(wdHex[:])+`"`))
	hadd("header_12_items_no_withdrawals", "", hdrRLP(headerItems(12)), okHeader(12, `null`))
	hadd("header_23_items", "a future header with trailing items is read positionally", hdrRLP(headerItems(23)), okHeader(23, `"`+hx(wdHex[:])+`"`))
	withItem := func(i int, enc []byte, n int) []byte {
		items := headerItems(n)
		items[i] = enc
		return hdrRLP(items)
	}
	listEnc := []byte{0xc2, 0x01, 0x02} // an RLP list of the two items 0x01 0x02
	for _, i := range []int{0, 3, 4, 5, 16} {
		hadd(fmt.Sprintf("header_list_in_item_%d", i), "an RLP list in a 32-byte slot", withItem(i, listEnc, 17), hm(fmt.Sprint(i), "header_item_is_list", 2, 32))
	}
	for _, i := range []int{8, 11} {
		hadd(fmt.Sprintf("header_list_in_item_%d", i), "an RLP list in an integer slot was read as the number 0 before RB11-B2B1", withItem(i, listEnc, 17), hm(fmt.Sprint(i), "header_item_is_list", 2, 8))
	}
	hadd("header_empty_list_in_item_8", "", withItem(8, []byte{0xc0}, 17), hm("8", "header_item_is_list", 0, 8))
	two := headerItems(17)
	two[3], two[8] = listEnc, listEnc
	hadd("header_list_in_items_3_and_8_reports_the_lowest_slot", "slots are judged in ascending order", hdrRLP(two), hm("3", "header_item_is_list", 2, 32))
	hadd("header_list_in_unread_item_13_is_accepted", "only the positional slots are read", withItem(13, listEnc, 17), okHeader(17, `"`+hx(wdHex[:])+`"`))
	hadd("header_number_leading_zero", "item 8 = 00 01", withItem(8, rlpStr([]byte{0x00, 0x01}), 17), hm("8", "header_item_not_canonical_uint", 2, 8))
	hadd("header_number_single_zero_byte", "item 8 = 00 (zero is the empty string)", withItem(8, rlpStr([]byte{0x00}), 17), hm("8", "header_item_not_canonical_uint", 1, 8))
	hadd("header_number_nine_bytes", "", withItem(8, rlpStr([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0}), 17), hm("8", "header_item_not_canonical_uint", 9, 8))
	hadd("header_timestamp_leading_zero", "", withItem(11, rlpStr([]byte{0x00, 0x65}), 17), hm("11", "header_item_not_canonical_uint", 2, 8))
	hadd("header_number_empty_is_zero", "the canonical zero", withItem(8, rlpStr(nil), 17), fmt.Sprintf(`{"items":"17","number":"0","timestamp":"1700000000","withdrawalsRoot":"%s"}`, hx(wdHex[:])))
	hadd("header_stateRoot_31_bytes", "", withItem(3, rlpStr(make([]byte, 31)), 17), hm("3", "header_item_not_32_bytes", 31, 32))
	hadd("header_too_few_items", "", hdrRLP(headerItems(11)), hm("", "header_too_few_items", 11, 12))
	hadd("header_not_a_list", "", []byte{0x01}, hm("", "header_not_rlp_list", 1, 0))
	hadd("header_trailing_byte", "", append(hdrRLP(headerItems(12)), 0), hm("", "header_trailing_bytes", 1, 0))
	hadd("header_item_truncated", "an item claims 3 bytes and has 1", []byte{0xc2, 0x83, 0x01}, hm("0", "header_bad_item", 2, 0))
	writeJSON(dir, "header.json", map[string]any{"format": "certen-finality-vectors/1", "set": set, "kind": "header",
		"runner": "ReadHeader(hex); ok -> {items, number, timestamp, withdrawalsRoot} as decimal strings / lower hex / null", "vectors": hs}, must)

	// ---- judge.json: the per-addendum judgement with NO kind registered (D1) ----
	type gvec struct {
		Name     string          `json:"name"`
		Note     string          `json:"note,omitempty"`
		Leg      leg             `json:"leg"`
		Addendum json.RawMessage `json:"addendum"`
		Expect   string          `json:"expect"`
	}
	var gs []gvec
	gadd := func(name, note string, a finality.Addendum, expect string) {
		b, e := json.Marshal(a)
		must(e)
		gs = append(gs, gvec{name, note, legOf(lBase), b, expect})
	}
	mk := func(kind string, b finality.BlockRef, level finality.Level, chain uint64, evidence []byte) finality.Addendum {
		if evidence == nil {
			evidence = container(kind, b, level, "body")
		}
		a := finality.Addendum{ProofID: proofID, Seq: 1, Level: level, Chain: chain, Kind: kind, Evidence: evidence}
		a.OwnHash = finality.OwnHash(finality.LegBindingOf(lBase), a)
		return a
	}
	otherHash := ref(base, lBase.Number, fill(0x99))
	otherNumber := ref(base, lBase.Number+1, lBase.Hash)
	arbBlock := ref(arb, lBase.Number, lBase.Hash)
	gadd("judge_container_about_the_leg_but_no_kind_registered", "everything binds; only the kind is missing", mk(kBaseFin, lBase, FIN, base, nil),
		`{"code":"finality_evidence_unrecognised","fields":{"kind":"`+kBaseFin+`","version":"v1"}}`)
	gadd("judge_same_chain_and_number_other_block_hash", "the container is about another block of the same height", mk(kBaseFin, otherHash, FIN, base, nil),
		`{"code":"finality_block_mismatch","fields":{"field":"blockHash","got":"`+hx(otherHash.Hash[:])+`","want":"`+hx(lBase.Hash[:])+`"}}`)
	gadd("judge_other_block_number", "", mk(kBaseFin, otherNumber, FIN, base, nil),
		`{"code":"finality_block_mismatch","fields":{"field":"blockNumber","got":"47368147","want":"47368146"}}`)
	gadd("judge_container_and_addendum_both_carry_another_chain", "the hash chain and the row are consistent for chain 421614, but the leg settled on 84532", mk(kArbFin, arbBlock, FIN, arb, nil),
		`{"code":"finality_block_mismatch","fields":{"field":"chain","got":"421614","want":"84532"}}`)
	gadd("judge_header_kind_differs_from_the_addendum", "", mk(kBaseFin, lBase, FIN, base, container(kBaseL1, lBase, FIN, "body")),
		`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.kind","reason":"differs_from_addendum","want_len":"0"}}`)
	gadd("judge_header_chain_differs_from_the_addendum", "", mk(kBaseFin, lBase, FIN, base, container(kBaseFin, arbBlock, FIN, "body")),
		`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.chain","reason":"differs_from_addendum","want_len":"0"}}`)
	gadd("judge_header_level_differs_from_the_addendum", "", mk(kBaseFin, lBase, FIN, base, container(kBaseFin, lBase, L1, "body")),
		`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.level","reason":"differs_from_addendum","want_len":"0"}}`)
	gadd("judge_evidence_is_not_a_container", "", mk(kBaseFin, lBase, FIN, base, []byte("x")),
		`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"header.magic","reason":"truncated","want_len":"4"}}`)
	writeJSON(dir, "judge.json", map[string]any{"format": "certen-finality-vectors/1", "set": set, "kind": "judge",
		"runner": "NewRegistry() with no kind registered; JudgeAddendum(leg, addendum, nil) -> canonical state", "vectors": gs}, must)

	// ---- pins.json: strictness and the invariants the Sepolia verifier relies on (D3, D6) ----
	type pvec struct {
		Name   string `json:"name"`
		Note   string `json:"note,omitempty"`
		Text   string `json:"text"`
		Expect string `json:"expect"`
	}
	var ps []pvec
	padd := func(name, note, text, expect string) { ps = append(ps, pvec{name, note, text, expect}) }
	pc := func(reason string, kv ...string) string {
		fields := `"reason":"` + reason + `"`
		// kv are alternating key, rendered-json-value pairs; render sorted with reason
		m := map[string]string{"reason": `"` + reason + `"`}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = `"` + k + `":` + m[k]
		}
		_ = fields
		return `{"code":"finality_pins_corrupt","fields":{` + strings.Join(parts, ",") + `}}`
	}
	idxOf := func(i int) []string { return []string{"index", `"` + fmt.Sprint(i) + `"`} }
	padd("pins_embedded", "the embedded file itself", pinsText(nil), "ok")
	padd("pins_two_anchors_valid", "periods ascend, wsp_epochs 279 and 256", pinsText(func(_, s map[string]any) {
		s["anchors"] = []any{anchorMap(1000, 279), anchorMap(1001, 256)}
	}), "ok")
	padd("pins_unknown_key_sorted_after_published_utc", "zzz sorts last: order is fine, the key is not in the schema (D6)", strings.Replace(pinsText(nil), "\n}\n", ",\n  \"zzz\": 1\n}\n", 1), pc("unknown_key", "key", `"zzz"`))
	padd("pins_unknown_key_in_eth_sepolia", "", pinsText(func(_, s map[string]any) { s["zzz"] = json.Number("1") }), pc("unknown_key", "key", `"zzz"`))
	padd("pins_unknown_key_in_a_fork", "", pinsText(func(_, s map[string]any) { s["forks"].([]any)[2].(map[string]any)["zzz"] = json.Number("1") }), pc("unknown_key", "key", `"zzz"`))
	padd("pins_unknown_key_in_an_anchor", "", pinsText(func(_, s map[string]any) {
		a := anchorMap(1000, 279)
		a["zzz"] = json.Number("1")
		s["anchors"] = []any{a}
	}), pc("unknown_key", "key", `"zzz"`))
	padd("pins_key_case_Format", "exact-case keys: Go's decoder would accept this", pinsText(func(top, _ map[string]any) {
		top["Format"] = top["format"]
		delete(top, "format")
	}), pc("unknown_key", "key", `"Format"`))
	padd("pins_key_case_in_eth_sepolia", "", pinsText(func(_, s map[string]any) {
		s["Max_links"] = s["max_links"]
		delete(s, "max_links")
	}), pc("unknown_key", "key", `"Max_links"`))
	padd("pins_keys_unsorted", "", strings.Replace(pinsText(nil), `"format": "certen-finality-pins/1",`, `"format": "certen-finality-pins/1", "aaa": 0,`, 1), pc("keys_unsorted", "key", `"aaa"`))
	padd("pins_duplicate_key", "", strings.Replace(pinsText(nil), `"format": "certen-finality-pins/1",`, `"format": "certen-finality-pins/1", "format": "certen-finality-pins/1",`, 1), pc("duplicate_key", "key", `"format"`))
	padd("pins_crlf", "", strings.ReplaceAll(pinsText(nil), "\n", "\r\n"), pc("contains_cr"))
	padd("pins_byte_order_mark", "", "\xef\xbb\xbf"+pinsText(nil), pc("byte_order_mark"))
	padd("pins_trailing_document", "", pinsText(nil)+"{}", pc("not_json"))
	padd("pins_wrong_format", "", strings.Replace(pinsText(nil), "certen-finality-pins/1", "certen-finality-pins/2", 1), pc("wrong_format"))
	padd("pins_published_utc_empty", "", pinsText(func(top, _ map[string]any) { top["published_utc"] = "" }), pc("published_utc_empty"))
	padd("pins_wrong_chain_id", "", pinsText(func(_, s map[string]any) { s["chain_id"] = json.Number("1") }), pc("chain_id_mismatch"))
	padd("pins_genesis_root_uppercase", "", strings.Replace(pinsText(nil), "0xd8ea17", "0xD8ea17", 1), pc("genesis_validators_root_malformed"))
	padd("pins_bound_max_links_zero", "bounds must be present and positive", pinsText(func(_, s map[string]any) { s["max_links"] = json.Number("0") }), pc("bound_missing", "key", `"max_links"`))
	padd("pins_bound_max_spine_headers_absent", "", pinsText(func(_, s map[string]any) { delete(s, "max_spine_headers") }), pc("bound_missing", "key", `"max_spine_headers"`))
	padd("pins_bound_epochs_per_period_absent", "", pinsText(func(_, s map[string]any) { delete(s, "epochs_per_period") }), pc("bound_missing", "key", `"epochs_per_period"`))
	padd("pins_bound_sync_committee_size_absent", "", pinsText(func(_, s map[string]any) { delete(s, "sync_committee_size") }), pc("bound_missing", "key", `"sync_committee_size"`))
	padd("pins_participation_below_two_thirds", "min_participants 300 of 512", pinsText(func(_, s map[string]any) { s["min_participants"] = json.Number("300") }), pc("participation_floor_invalid"))
	padd("pins_forks_empty", "", pinsText(func(_, s map[string]any) { s["forks"] = []any{} }), pc("forks_empty"))
	padd("pins_first_fork_not_at_epoch_zero", "", pinsText(func(_, s map[string]any) { s["forks"].([]any)[0].(map[string]any)["epoch"] = json.Number("1") }), pc("first_fork_not_epoch_zero"))
	padd("pins_fork_epoch_equal_to_previous", "forks must ascend strictly", pinsText(func(_, s map[string]any) { s["forks"].([]any)[2].(map[string]any)["epoch"] = json.Number("50") }), pc("fork_epoch_not_ascending", idxOf(2)...))
	padd("pins_fork_epoch_descending", "", pinsText(func(_, s map[string]any) { s["forks"].([]any)[4].(map[string]any)["epoch"] = json.Number("99") }), pc("fork_epoch_not_ascending", idxOf(4)...))
	padd("pins_fork_version_malformed", "", pinsText(func(_, s map[string]any) { s["forks"].([]any)[1].(map[string]any)["version"] = "0x9000" }), pc("fork_malformed", idxOf(1)...))
	padd("pins_fork_layout_unknown", "", pinsText(func(_, s map[string]any) { s["forks"].([]any)[6].(map[string]any)["layout"] = "fulu" }), pc("fork_layout_unknown", idxOf(6)...))
	padd("pins_anchor_wsp_epochs_255", "wsp_epochs < 256 is invalid (V2_SPEC_S7 5.2 step 3)", pinsText(func(_, s map[string]any) {
		s["anchors"] = []any{anchorMap(1000, 279), anchorMap(1001, 255)}
	}), pc("anchor_wsp_epochs_below_256", idxOf(1)...))
	padd("pins_anchor_wsp_epochs_zero", "", pinsText(func(_, s map[string]any) { s["anchors"] = []any{anchorMap(1000, 0)} }), pc("anchor_wsp_epochs_below_256", idxOf(0)...))
	padd("pins_anchor_period_duplicate", "anchors are unique by period", pinsText(func(_, s map[string]any) {
		s["anchors"] = []any{anchorMap(1000, 279), anchorMap(1000, 279)}
	}), pc("anchor_period_duplicate", idxOf(1)...))
	padd("pins_anchor_period_descending", "anchors ascend by period", pinsText(func(_, s map[string]any) {
		s["anchors"] = []any{anchorMap(1001, 279), anchorMap(1000, 279)}
	}), pc("anchor_period_not_ascending", idxOf(1)...))
	padd("pins_anchor_committee_root_uppercase", "", pinsText(func(_, s map[string]any) {
		a := anchorMap(1000, 279)
		a["committee_root"] = "0x" + strings.Repeat("AB", 32)
		s["anchors"] = []any{a}
	}), pc("anchor_malformed", idxOf(0)...))
	padd("pins_anchor_derived_by_empty", "", pinsText(func(_, s map[string]any) {
		a := anchorMap(1000, 279)
		a["derived_by"] = []any{}
		s["anchors"] = []any{a}
	}), pc("anchor_derived_by_empty", idxOf(0)...))
	writeJSON(dir, "pins.json", map[string]any{"format": "certen-finality-vectors/1", "set": set, "kind": "pins",
		"runner": "ParsePinsOverride(text) (no expected hash); ok or the canonical state", "vectors": ps}, must)

	// ---- canonical.json: the canonical form of a mixed-type fields map ----
	type cfield struct {
		Key   string `json:"key"`
		Type  string `json:"type"`
		Value any    `json:"value,omitempty"`
	}
	type cvec struct {
		Name   string   `json:"name"`
		Note   string   `json:"note,omitempty"`
		Code   string   `json:"code"`
		Fields []cfield `json:"fields"`
		Expect string   `json:"expect"`
	}
	mixed := cvec{
		Name: "canonical_mixed_types", Note: "sorted keys, no whitespace, every integer width as a decimal string, bytes as lower hex, a Level by name",
		Code: "finality_chain_broken",
		Fields: []cfield{
			{"seq", "u64", "18446744073709551615"}, {"n_int", "int", "-5"}, {"n_u8", "u8", "255"}, {"n_i64", "i64", "-9223372036854775808"},
			{"level", "level", "finalized"}, {"h", "bytes32", strings.Repeat("ab", 32)}, {"b", "bytes", "0102"}, {"ok", "bool", "true"}, {"none", "null", nil},
			{"s", "string", `a"b`}, {"t", "time", "1970-01-01T00:00:00Z"}, {"l", "u64list", []string{"1", "2"}},
			{"nested", "map", []cfield{{"z", "u32", "1"}, {"a", "bytes", "0102"}}},
		},
		Expect: `{"code":"finality_chain_broken","fields":{"b":"0102","h":"` + strings.Repeat("ab", 32) + `","l":["1","2"],"level":"finalized","n_i64":"-9223372036854775808","n_int":"-5","n_u8":"255","nested":{"a":"0102","z":"1"},"none":null,"ok":true,"s":"a\"b","seq":"18446744073709551615","t":"1970-01-01T00:00:00Z"}}`,
	}
	writeJSON(dir, "canonical.json", map[string]any{"format": "certen-finality-vectors/1", "set": set, "kind": "canonical",
		"runner": "NewState(code, fields...) with each typed field converted to the language's value; Canonical() is compared", "vectors": []cvec{mixed}}, must)

	// ---- manifest ----
	files := []string{"chains.json", "containers.json", "codec_probe.json", "table.json", "json.json", "header.json", "judge.json", "pins.json", "canonical.json"}
	sums := map[string]string{}
	for _, f := range files {
		b, e := os.ReadFile(filepath.Join(dir, f))
		must(e)
		s := sha256.Sum256(b)
		sums[f] = hx(s[:])
	}
	reg, e := os.ReadFile(registryPath)
	must(e)
	rs := sha256.Sum256(reg)
	c1m, e := os.ReadFile(filepath.Join(chain1Dir, "MANIFEST.json"))
	must(e)
	c1s := sha256.Sum256(c1m)
	writeJSON(dir, "MANIFEST.json", map[string]any{"format": "certen-finality-manifest/1", "set": set, "files": sums,
		"supersedes": map[string]any{"set": "finality_chain1", "manifest_sha256": hx(c1s[:]), "goldens": "finality_chain1/goldens.json is unchanged and still the golden of G0 and G1", "replaced_expectations": len(superseded2)},
		"registry":   map[string]any{"path": "testdata/finality/states.json", "sha256": hx(rs[:])}}, must)
	mb, e := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	must(e)
	ms := sha256.Sum256(mb)
	must(os.WriteFile(filepath.Join(dir, "MANIFEST.json.sha256"), []byte(hx(ms[:])+"\n"), 0o644))
	fmt.Printf("wrote %d files to %s; manifest sha256 %s\n", len(files)+2, dir, hx(ms[:]))
	return nil
}

func mustMarshal(v any, must func(error)) []byte {
	b, err := json.Marshal(v)
	must(err)
	return b
}

var _ = hex.EncodeToString
