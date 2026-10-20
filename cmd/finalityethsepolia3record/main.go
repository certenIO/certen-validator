// Copyright 2026 Certen Protocol

// Command finalityethsepolia3record writes the vector set finality_eth_sepolia3 (review V-C2-A1 defects D1-D3) OFFLINE from the bytes
// of finality_eth_sepolia1 (the 14-entry vector ledger, its link files and extension files) and the pins embedded in this build.
// Every case is a hand-written description (a patch of a named file) with a hand-written expected verdict (code, reason, inner);
// this program applies the patch with its own code, runs the production verifier, REFUSES to write a case whose production verdict
// differs from the hand-written one, and records the verdict's canonical form. It never edits set 1 or set 2.
//
//	finalityethsepolia3record -set1 pkg/finality/ethsepolia/testdata/finality_eth_sepolia1 -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia3
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/certen/independant-validator/pkg/finality"
)

const setName = "finality_eth_sepolia3"

// Offsets inside the electra-layout bootstrap of period 1378 (the root pin): offset(4) | committee 24,624 | committee branch 6*32 |
// header (beacon 112 | exec offset 4 | exec branch 4*32) | exec header.
const (
	committeeBranchAt = 4 + 24624
	headerAt          = 4 + 24624 + 6*32
	parentRootAt      = headerAt + 16
	execBranchAt      = headerAt + 112 + 4
)

type anchorPatch struct {
	Period uint64 `json:"period"`
	Field  string `json:"field"` // block_root | period
	Value  string `json:"value"`
}

type linkPatch struct {
	Period uint64 `json:"period"`
	Offset int    `json:"offset"`
	Xor    uint8  `json:"xor"`
	Relink bool   `json:"relink"` // set the anchor's link_sha256 to the patched file's hash
}

type linkMove struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

type ledgerCase struct {
	Format      string        `json:"format"`
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Op          string        `json:"op"` // verify_ledger | extend
	Pins        string        `json:"pins"`
	Extension   string        `json:"extension,omitempty"`
	LinksDir    string        `json:"links_dir"`
	LinksOnly   []uint64      `json:"links_only,omitempty"`
	AnchorPatch []anchorPatch `json:"anchor_patch,omitempty"`
	LinkPatch   []linkPatch   `json:"link_patch,omitempty"`
	LinkMove    []linkMove    `json:"link_move,omitempty"`
	Expect      string        `json:"expect_canonical"`

	want want
}

// want is the hand-written verdict.
type want struct {
	ok     bool
	period uint64
	reason string
	inner  string
}

type lcsszCase struct {
	Format      string `json:"format"`
	ID          string `json:"id"`
	Description string `json:"description"`
	Len         int    `json:"len"`
	AttOff      int    `json:"att_off"`
	FinOff      int    `json:"fin_off"`
	ExecHash    string `json:"exec_hash"`
	ExecNumber  uint64 `json:"exec_number"`
	Expect      string `json:"expect"` // ok | finalized_header_too_short | invalid
}

func main() {
	set1 := flag.String("set1", "", "finality_eth_sepolia1 directory")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *set1 == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: finalityethsepolia3record -set1 <dir> -out <dir>")
		os.Exit(2)
	}
	if err := run(*set1, *out); err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
}

func rd(dir, rel string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
	return b
}

func run(set1, out string) error {
	files := map[string][]byte{}
	files["pins/embedded.json"] = finality.EmbeddedPinsBytes()
	files["pins/vector_main.json"] = rd(set1, "pins/main.json")
	files["pins/base_1386.json"] = rd(set1, "extend/base_1386.json")
	files["pins/extend_valid.pins.json"] = rd(set1, "extend/extend_valid.pins.json")
	for p := uint64(1378); p <= 1391; p++ {
		files["raw/links/"+strconv.FormatUint(p, 10)+".ssz"] = rd(set1, "raw/links/"+strconv.FormatUint(p, 10)+".ssz")
	}
	boot := files["raw/links/1378.ssz"]
	if sum := sha256.Sum256(boot); hex.EncodeToString(sum[:]) != "e55bc5ef6ede9cf7b1f09ba302d1723001bd03268672f2dd4875c8c38889c81d" {
		return fmt.Errorf("set 1 root bootstrap is not the embedded root pin's file")
	}

	const bogus = "0x00000000000000000000000000000000000000000000000000000000000000ab"
	root1378 := "0x5f71d7f650f9252b48749b5f062c0c234e01afd69f364ab600e2b6051494b20d"
	bogusRoot := root1378[:len(root1378)-1] + "e"
	rp := "root_pin_unverifiable"
	bi, pm := "finality_bootstrap_invalid", "finality_pin_mismatch"
	one := []uint64{1378}
	cases := []*ledgerCase{
		{ID: "ledger1_embedded_valid", Description: "control: the embedded single-entry ledger re-derives from its root bootstrap, judged as the kind-2 anchor", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one, want: want{ok: true}},
		{ID: "ledger1_bogus_block_root", Description: "the root pin's block_root differs from the bootstrap header's root (D1: accepted before)", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			AnchorPatch: []anchorPatch{{1378, "block_root", bogusRoot}}, want: want{period: 1378, reason: rp, inner: pm}},
		{ID: "ledger1_committee_branch_flipped", Description: "one byte of the bootstrap's current-committee branch flipped, link_sha256 recomputed (D1)", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			LinkPatch: []linkPatch{{1378, committeeBranchAt + 5, 1, true}}, want: want{period: 1378, reason: rp, inner: bi}},
		{ID: "ledger1_header_parent_root_flipped", Description: "one byte of the bootstrap header's parent_root flipped, link_sha256 recomputed: the header no longer hashes to the pinned block_root (D1)", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			LinkPatch: []linkPatch{{1378, parentRootAt + 3, 1, true}}, want: want{period: 1378, reason: rp, inner: pm}},
		{ID: "ledger1_header_exec_branch_flipped", Description: "one byte of the bootstrap header's execution branch flipped, link_sha256 recomputed (D1)", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			LinkPatch: []linkPatch{{1378, execBranchAt + 10, 1, true}}, want: want{period: 1378, reason: rp, inner: bi}},
		{ID: "ledger1_header_period_is_not_the_entrys", Description: "the entry is relabelled period 1377 (its bootstrap file moved to 1377.ssz) although the header's slot is in period 1378 (D1)", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			AnchorPatch: []anchorPatch{{1378, "period", "1377"}}, LinkMove: []linkMove{{1378, 1377}}, want: want{period: 1377, reason: rp, inner: bi}},
		{ID: "ledger1_bootstrap_byte_flipped_not_relinked", Description: "one bootstrap byte flipped without recomputing link_sha256: the file is not the one the pin names", Op: "verify_ledger", Pins: "pins/embedded.json", LinksOnly: one,
			LinkPatch: []linkPatch{{1378, committeeBranchAt + 5, 1, false}}, want: want{period: 1378, reason: rp}},
		{ID: "ledger14_valid", Description: "control: the 14-entry vector ledger re-derives from its root pin", Op: "verify_ledger", Pins: "pins/vector_main.json", want: want{ok: true}},
		{ID: "ledger14_bogus_first_block_root", Description: "the root pin of the 14-entry ledger is bogus: named at the root pin (was link_refused at 1379)", Op: "verify_ledger", Pins: "pins/vector_main.json",
			AnchorPatch: []anchorPatch{{1378, "block_root", bogusRoot}}, want: want{period: 1378, reason: rp, inner: pm}},
		{ID: "ledger14_block_root_on_1379", Description: "a block_root on the first appended entry (D2)", Op: "verify_ledger", Pins: "pins/vector_main.json",
			AnchorPatch: []anchorPatch{{1379, "block_root", bogus}}, want: want{period: 1379, reason: "block_root_on_appended_entry"}},
		{ID: "ledger14_block_root_on_1385", Description: "a block_root on a middle appended entry (D2)", Op: "verify_ledger", Pins: "pins/vector_main.json",
			AnchorPatch: []anchorPatch{{1385, "block_root", bogus}}, want: want{period: 1385, reason: "block_root_on_appended_entry"}},
		{ID: "ledger14_block_root_on_last_1391", Description: "a block_root on the last appended entry: never derived or compared before (D2)", Op: "verify_ledger", Pins: "pins/vector_main.json",
			AnchorPatch: []anchorPatch{{1391, "block_root", bogus}}, want: want{period: 1391, reason: "block_root_on_appended_entry"}},
		{ID: "extend_valid", Description: "control: five appended entries 1387..1391 without a block_root extend the base", Op: "extend", Pins: "pins/base_1386.json", Extension: "pins/extend_valid.pins.json", want: want{ok: true}},
		{ID: "extend_block_root_on_1387", Description: "an extension whose first appended entry carries a block_root (D2)", Op: "extend", Pins: "pins/base_1386.json", Extension: "pins/extend_valid.pins.json",
			AnchorPatch: []anchorPatch{{1387, "block_root", bogus}}, want: want{period: 1387, reason: "block_root_on_appended_entry"}},
		{ID: "extend_block_root_on_1389", Description: "an extension whose middle appended entry carries a block_root (D2)", Op: "extend", Pins: "pins/base_1386.json", Extension: "pins/extend_valid.pins.json",
			AnchorPatch: []anchorPatch{{1389, "block_root", bogus}}, want: want{period: 1389, reason: "block_root_on_appended_entry"}},
		{ID: "extend_block_root_on_last_1391", Description: "an extension whose LAST appended entry carries a block_root: returned a Pins before (D2)", Op: "extend", Pins: "pins/base_1386.json", Extension: "pins/extend_valid.pins.json",
			AnchorPatch: []anchorPatch{{1391, "block_root", bogus}}, want: want{period: 1391, reason: "block_root_on_appended_entry"}},
	}
	var ids []string
	for _, c := range cases {
		c.Format, c.LinksDir = "certen-finality-ethsepolia-ledger-case/1", "raw/links"
		got, err := judge(c, files)
		if err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
		c.Expect = got
		j, _ := json.MarshalIndent(c, "", " ")
		files["ledger/"+c.ID+".json"] = append(j, '\n')
		ids = append(ids, c.ID)
	}

	hash := "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	lc := []lcsszCase{
		{ID: "lcssz_exact_fit", Description: "finalized header exactly holds the execution payload header's fixed part: accepted, hash and number read", Len: 2056, AttOff: 400, FinOff: 1228, ExecHash: hash, ExecNumber: 11950125, Expect: "ok"},
		{ID: "lcssz_fin_off_2048_len_2056", Description: "the reviewer's shape (D3): FinalityUpdateSlots accepts it, FinalizedExec sliced fu[2292:2056] and panicked", Len: 2056, AttOff: 400, FinOff: 2048, Expect: "finalized_header_too_short"},
		{ID: "lcssz_one_byte_short", Description: "finalized header one byte short of the fixed part", Len: 2056, AttOff: 400, FinOff: 1229, Expect: "finalized_header_too_short"},
		{ID: "lcssz_below_minimum_length", Description: "one byte below the minimum Electra finality update: refused before any slice", Len: 2055, AttOff: 400, FinOff: 1228, Expect: "invalid"},
		{ID: "lcssz_finalized_offset_not_after_attested", Description: "finalized offset equal to the attested offset", Len: 2056, AttOff: 400, FinOff: 400, Expect: "invalid"},
	}
	for _, c := range lc {
		c.Format = "certen-finality-lcssz-case/1"
		j, _ := json.MarshalIndent(c, "", " ")
		files["lcssz/"+c.ID+".json"] = append(j, '\n')
		ids = append(ids, c.ID)
	}

	sums := map[string]string{}
	for rel, d := range files {
		s := sha256.Sum256(d)
		sums[rel] = hex.EncodeToString(s[:])
	}
	m, _ := json.MarshalIndent(map[string]any{"format": "certen-finality-manifest/1", "set": setName, "cases": ids, "files": sums}, "", " ")
	m = append(m, '\n')
	files["MANIFEST.json"] = m
	ms := sha256.Sum256(m)
	files["MANIFEST.json.sha256"] = []byte(hex.EncodeToString(ms[:]) + "\n")
	var names []string
	for rel := range files {
		names = append(names, rel)
	}
	sort.Strings(names)
	for _, rel := range names {
		p := filepath.Join(out, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[rel], 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("%s: %d ledger cases, %d lcssz cases, MANIFEST sha256 %x\n", setName, len(cases), len(lc), ms)
	return nil
}

// judge applies the case's patches with this program's own code, runs the production verifier and returns the canonical verdict,
// or an error when the verdict differs from the hand-written one.
func judge(c *ledgerCase, files map[string][]byte) (string, error) {
	links := map[uint64][]byte{}
	for p := uint64(1378); p <= 1391; p++ {
		if len(c.LinksOnly) > 0 && !contains(c.LinksOnly, p) {
			continue
		}
		links[p] = append([]byte(nil), files["raw/links/"+strconv.FormatUint(p, 10)+".ssz"]...)
	}
	target := c.Pins
	if c.Op == "extend" {
		target = c.Extension
	}
	var m map[string]any
	if err := json.Unmarshal(files[target], &m); err != nil {
		return "", err
	}
	anchors := m["eth_sepolia"].(map[string]any)["anchors"].([]any)
	find := func(period uint64) map[string]any {
		for _, a := range anchors {
			if am := a.(map[string]any); uint64(am["period"].(float64)) == period {
				return am
			}
		}
		panic("no anchor for the period")
	}
	for _, lp := range c.LinkPatch {
		links[lp.Period][lp.Offset] ^= lp.Xor
		if lp.Relink {
			sum := sha256.Sum256(links[lp.Period])
			find(lp.Period)["link_sha256"] = hex.EncodeToString(sum[:])
		}
	}
	for _, ap := range c.AnchorPatch {
		switch ap.Field {
		case "block_root":
			find(ap.Period)["block_root"] = ap.Value
		case "period":
			v, _ := strconv.ParseUint(ap.Value, 10, 64)
			find(ap.Period)["period"] = float64(v)
		default:
			panic("unknown anchor patch field")
		}
	}
	for _, mv := range c.LinkMove {
		links[mv.To] = links[mv.From]
		delete(links, mv.From)
	}
	raw := files[c.Pins]
	patched := files[target]
	if len(c.AnchorPatch)+len(c.LinkPatch) > 0 {
		patched, _ = json.MarshalIndent(m, "", "  ")
		patched = append(patched, '\n')
	}
	var verdict error
	var canon string
	switch c.Op {
	case "verify_ledger":
		p, err := finality.ParsePinsOverride(patched)
		if err != nil {
			return "", err
		}
		if verdict = p.VerifyLedger(links); verdict == nil {
			e, _ := p.Sepolia()
			canon = string((&finality.StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors))}}).Canonical())
		}
	case "extend":
		base, err := finality.ParsePinsOverride(raw)
		if err != nil {
			return "", err
		}
		got, err := base.Extend(patched, links)
		if verdict = err; err == nil {
			e, _ := got.Sepolia()
			_, src := got.Identity()
			canon = string((&finality.StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors)), "pins_source": src}}).Canonical())
		}
	}
	if verdict != nil {
		s, ok := finality.AsNamed(verdict)
		if !ok {
			return "", fmt.Errorf("unnamed verdict %v", verdict)
		}
		canon = string(s.Canonical())
		if c.want.ok || s.Code != finality.CodeLedgerExtensionBad || s.Fields["period"] != c.want.period || s.Fields["reason"] != c.want.reason ||
			(c.want.inner != "" && s.Fields["inner"] != c.want.inner) || (c.want.inner == "" && s.Fields["inner"] != nil) {
			return "", fmt.Errorf("production verdict %s differs from the hand-written one %+v", canon, c.want)
		}
	} else if !c.want.ok {
		return "", fmt.Errorf("production accepted a case hand-written to be refused as %+v", c.want)
	}
	return canon, nil
}

func contains(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
