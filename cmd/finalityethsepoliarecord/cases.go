// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const readme = `# finality_eth_sepolia1 - published conformance vectors for eth-sepolia/finalized/v1

Spec: V2_SPEC_S7 r2 sections 3.3, 4.3 and 5.3 (Pins.Extend). The Go verifier is pkg/finality/ethsepolia (Verifier.Verify) over
pkg/finality/ethl1; the TypeScript verifier consumes a byte-identical copy of this directory and must return the same canonical
verdict bytes on every case. Same layout as finality_arb_posted1; where it differs it is stated here.

| path | content |
|---|---|
| raw/<leg>/evidence.bin | the REAL CFE1 container built by the production Prover and accepted by the verifier: gloas_latest (block 11,950,125, post-Gloas, served by the latest finality update), gloas_period (block 11,862,203, post-Gloas, served by the best update of its period), legacy (block 11,845,679, pre-Gloas, electra layout, long spine) |
| raw/<leg>/leg.json | the Sepolia block it is about: hash, number, raw RLP header (Settlement.Header) |
| raw/<leg>/capture.json | when, from where and how long the build took |
| raw/links/<period>.ssz | the ledger link files: the root-pin bootstrap (1378) and the update that derived each later entry |
| raw/pending/ | the recorded answers (finality update, head slot, headers by hash) that the offline builder test replays for a leg newer than the finalized head |
| pins/main.json | the pins the cases are judged under: the embedded pins' network section and a 14-entry ledger (periods 1378..1391) derived by VERIFIED LIGHT-CLIENT LINKS from the root pin. IT IS A VECTOR PIN: its entries 1379..1390 were not cross-checked on two beacon clients (no public endpoint serves those historical states, see the check-in); the published ledger in pkg/finality/pins holds the root pin only |
| pins/<name>.json | variants that alter exactly one thing: ledger_ends_1385, ledger_empty, gvr_other |
| cases/<id>.json | one verification case |
| extend/ | Pins.Extend cases: base and extension pins files, link overrides |

## A verification case

{format, id, description, pins, leg{chain, number, hash, header_rlp}, evidence_base, evidence_patches[{at, del, ins}], expect_canonical}.
The evidence is evidence_base with every patch applied; offsets refer to the BASE, patches are applied from the highest at to the
lowest (they never overlap); ins is 0x hex. The call is Kind.Verify(pins, leg, evidence) with the pins parsed as an override file.
expect_canonical is the canonical text of the verdict: {"code":"verified","fields":{...}} (fields: finalized_slot, finalized_exec_number,
participants, periods_crossed, headers_walked, anchor_period, kind, level) or {"code":<state>,"fields":{...}}; keys sorted at every
level, no whitespace, EVERY integer a decimal string, every byte string 0x lower-case hex. The literals are written in
cmd/finalityethsepoliarecord, computed there from the recorded bytes by small independent readers (RLP, SSZ offsets), not by the
verifier; build refuses a case whose verdict differs from its literal.

## An extend case

{format, id, description, base (pins file), extension (pins file), links_dir, links_replace{period: file}, links_drop[period], expect_canonical}.
The call is ParsePinsOverride(base).Extend(extension bytes, links) with links = every <period>.ssz of links_dir, replaced and dropped
as stated. expect_canonical is {"code":"verified","fields":{"anchors":N,"pins_source":"extension:<sha256 of the extension>"}} or the
finality_ledger_extension_invalid state.

## Check order (the first failing check names the state)

container header (magic, kind, chain, level, block number, block hash against the leg); body decode (bounded, strict: lc.links
count, spine count, trailing bytes); every spine header readable; the L1 finalized head from the LC part (profile, anchor kind and
period, ledger, layouts, forks, every link and the final update); the spine (top = finalized execution head, parent chain);
the leg's number on the spine; hash and byte identity; the spine ends at the leg.

## Regenerating

    finalitypins derive-sepolia -min-clients 0 -api-timeout 4s -out-pins <dir>/pins.json -links-dir <dir>/links     # vector pins
    finalityethsepoliarecord record -vecpins <dir> -raw <raw dir>                                                   # network
    finalityethsepoliarecord build  -raw <raw dir> -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia1      # offline
`

type extendCase struct {
	Format       string            `json:"format"`
	ID           string            `json:"id"`
	Description  string            `json:"description"`
	Base         string            `json:"base"`
	Extension    string            `json:"extension"`
	LinksDir     string            `json:"links_dir"`
	LinksReplace map[string]string `json:"links_replace,omitempty"`
	LinksDrop    []uint64          `json:"links_drop,omitempty"`
	Expect       string            `json:"expect_canonical"`
}

func lcLeg(l *rawLeg) legJSON { return legOf(l.ref) }

// verifyCases builds every verification case.
func (b *builder) verifyCases(legs map[string]*rawLeg) error {
	G := legs["gloas_latest"]
	n := len(G.body.Spine)
	if n < 6 {
		return fmt.Errorf("the recorded spine has %d headers; the adversarial cases need at least 6", n)
	}
	hi := make([]hdrInfo, n)
	for i, h := range G.body.Spine {
		hi[i] = readHdr(h)
	}
	m := n / 2
	top := hi[0]
	ref := G.ref
	anchor := func(pins string) (string, [32]byte) {
		a, _ := b.pins(pins).EthSepolia.AnchorFor(G.body.LC.AnchorPeriod)
		var r [32]byte
		x, _ := hex.DecodeString(a.CommitteeRoot[2:])
		copy(r[:], x)
		return a.CommitteeRoot, r
	}
	wantRoot, _ := anchor("main")
	fu := G.body.LC.FinalUpdate.SSZ
	lay := lcssz.LayoutOfFinalityUpdate(fu)
	_, finSlot, sigSlot, _ := lcssz.FinalityUpdateSlots(lay, fu)
	part, _ := lcssz.FinalityUpdateParticipants(lay, fu)
	_ = finSlot
	hdrPatch := func(at int, v []byte) patch { return replaceAt(at, v) }
	numberPatch := func(v uint64) patch { var x [8]byte; putU64(x[:], v); return hdrPatch(41, x[:]) }
	hashPatch := func(h [32]byte) patch { return hdrPatch(49, h[:]) }
	flip := func(h [32]byte) [32]byte { h[0] ^= 0xff; return h }
	legWith := func(number uint64, hash [32]byte, hdr []byte) legJSON {
		return legJSON{Chain: strconv.FormatUint(chain, 10), Number: strconv.FormatUint(number, 10), Hash: hx(hash[:]), HeaderRLP: hx(hdr)}
	}
	count := func(v int) patch { return patch{At: G.spineAt, Del: 4, Ins: u32(v)} }
	elem := func(i int) patch { return patch{At: G.elemAt[i], Del: 4 + len(G.body.Spine[i]), Ins: "0x"} }
	sigFail := func(extra ...any) string {
		return canonState("finality_signature_invalid", append([]any{"index", uint64(len(G.body.LC.Links)), "signature_slot", sigSlot,
			"fork_version", "0x90000076", "participants", uint64(part)}, extra...)...)
	}
	add := func(id, desc, pins string, leg legJSON, patches []patch, expect string) error {
		return b.add(vecCase{ID: id, Description: desc, Pins: "pins/" + pins + ".json", Leg: leg, Patches: patches, Expect: expect}, G, verifyWith)
	}
	main := "main"
	L := lcLeg(G)

	if err := add("valid_gloas_latest", "post-Gloas block 11,950,125 against the latest finality update at record time", main, L, nil, validExpect(G)); err != nil {
		return err
	}
	for _, c := range []struct {
		id, desc string
		patches  []patch
		expect   string
	}{
		{"adv_spine_header_forged", "one byte of the middle spine header's stateRoot flipped: its hash no longer is its child's parentHash", func() []patch {
			at := G.elemAt[m] + 4 + bytes.Index(G.body.Spine[m], hi[m].stateRoot[:]) + 3
			return []patch{replaceAt(at, []byte{G.ev[at] ^ 0xff})}
		}(), func() string {
			mut := append([]byte(nil), G.body.Spine[m]...)
			mut[bytes.Index(mut, hi[m].stateRoot[:])+3] ^= 0xff
			return canonState("finality_header_chain_broken", "spine", "l1", "at_number", hi[m-1].number-1, "want_hash", hx(hi[m-1].parent[:]),
				"got_hash", hx(crypto.Keccak256(mut)), "reason", "parent_hash_mismatch")
		}()},
		{"adv_spine_gap_header_missing", "the middle spine header removed (count adjusted): the chain has a gap", []patch{count(n - 1), elem(m)},
			canonState("finality_header_chain_broken", "spine", "l1", "at_number", hi[m-1].number-1, "want_hash", hx(hi[m-1].parent[:]),
				"got_hash", hx(hi[m+1].hash[:]), "reason", "parent_hash_mismatch")},
		{"adv_spine_top_not_finalized_head", "the first spine header removed: h_0 is no longer the finalized execution head", []patch{count(n - 1), elem(0)},
			canonState("finality_header_chain_broken", "spine", "l1", "at_number", hi[1].number, "want_hash", hx(top.hash[:]),
				"got_hash", hx(hi[1].hash[:]), "reason", "parent_hash_mismatch")},
		{"adv_spine_count_over_bound", "the spine count is 16385, one over max_spine_headers", []patch{count(16385)},
			canonState("finality_evidence_too_large", "part", "spine", "count", uint64(16385), "limit", uint64(16384))},
		{"adv_spine_empty", "an empty spine", []patch{count(0), {At: G.elemAt[0], Del: len(G.ev) - G.elemAt[0], Ins: "0x"}},
			canonState("finality_evidence_malformed", "part", "spine", "reason", "spine_empty", "got_len", uint64(0), "want_len", uint64(1))},
		{"adv_spine_ends_above_leg", "the leg's own header (h_k) removed: the spine stops one block above the leg", []patch{count(n - 1), elem(n - 1)},
			canonState("finality_block_not_covered", "block_number", ref.Number, "finalized_exec_number", top.number)},
		{"adv_container_number_differs", "the container header names block number+1", []patch{numberPatch(ref.Number + 1)},
			canonState("finality_block_mismatch", "field", "blockNumber", "want", ref.Number, "got", ref.Number+1)},
		{"adv_container_hash_differs", "the container header names another block hash", []patch{hashPatch(flip(ref.Hash))},
			canonState("finality_block_mismatch", "field", "blockHash", "want", hx(ref.Hash[:]), "got", hx(func() []byte { h := flip(ref.Hash); return h[:] }()))},
		{"adv_container_chain_wrong", "the container header names chain 1", []patch{replaceAt(32, []byte{0, 0, 0, 0, 0, 0, 0, 1})},
			canonState("finality_block_mismatch", "field", "chain", "want", uint64(chain), "got", uint64(1))},
		{"adv_container_kind_other_version", "the container header kind is eth-sepolia/finalized/v2", []patch{replaceAt(8+23, []byte{'2'})},
			canonState("finality_evidence_malformed", "part", "header.kind", "reason", "differs_from_addendum", "got_len", uint64(0), "want_len", uint64(0))},
		{"adv_container_level_l1_posted", "the container header level byte is 2", []patch{replaceAt(40, []byte{2})},
			canonState("finality_evidence_malformed", "part", "header.level", "reason", "level_not_finalized", "got_len", uint64(2), "want_len", uint64(3))},
		{"adv_container_level_zero", "the container header level byte is 0", []patch{replaceAt(40, []byte{0})},
			canonState("finality_evidence_malformed", "part", "header.level", "reason", "level_not_stored", "got_len", uint64(0), "want_len", uint64(2))},
		{"adv_container_magic_wrong", "the container magic is CFE2", []patch{replaceAt(3, []byte{'2'})},
			canonState("finality_evidence_unrecognised", "kind", "", "version", "magic:43464532")},
		{"adv_body_trailing_byte", "one byte after the spine", []patch{{At: len(G.ev), Del: 0, Ins: "0x00"}},
			canonState("finality_evidence_malformed", "part", "body", "reason", "trailing_bytes", "got_len", uint64(1), "want_len", uint64(0))},
		{"adv_spine_truncated_tail", "the last ten bytes of the last spine header cut off", []patch{{At: len(G.ev) - 10, Del: 10, Ins: "0x"}},
			canonState("finality_evidence_malformed", "part", "spine", "reason", "length_exceeds_remaining", "got_len", uint64(len(G.body.Spine[n-1])-10),
				"want_len", uint64(len(G.body.Spine[n-1])), "index", uint64(n-1))},
		{"adv_lc_final_signature_flipped", "one byte of the final update's aggregate signature flipped", []patch{replaceAt(G.finalAt+5+1344+48, []byte{G.ev[G.finalAt+5+1344+48] ^ 0x01})}, sigFail()},
		{"adv_lc_participation_341", "the final update's sync bits cleared to 341 participants", []patch{replaceAt(G.finalAt+5+1280, func() []byte {
			bits := make([]byte, 64)
			for i := 0; i < 341; i++ {
				bits[i/8] |= 1 << (i % 8)
			}
			return bits
		}())}, canonState("finality_participation_insufficient", "index", uint64(len(G.body.LC.Links)), "participants", uint64(341), "required", uint64(342), "committee", uint64(512))},
		{"adv_lc_anchor_root_altered", "the container's anchorRoot differs from the ledger's committee root", []patch{replaceAt(102, []byte{G.ev[102] ^ 0xff})},
			canonState("finality_pin_mismatch", "period", G.body.LC.AnchorPeriod, "want_root", wantRoot, "got_root", func() string {
				r := G.body.LC.AnchorRoot
				r[0] ^= 0xff
				return hx(r[:])
			}())},
		{"adv_lc_anchor_body_flipped", "one byte of the carried committee flipped: it no longer hashes to the ledger's root", []patch{replaceAt(G.anchorAt+5+100, []byte{G.ev[G.anchorAt+5+100] ^ 0x01})},
			canonState("finality_pin_mismatch", "period", G.body.LC.AnchorPeriod, "want_root", wantRoot, "got_root", func() string {
				body := append([]byte(nil), G.body.LC.AnchorBody.SSZ...)
				body[100] ^= 0x01
				r, _ := ethl1.HashTreeRootSyncCommittee(body)
				return hx(r[:])
			}())},
		{"adv_lc_anchor_period_unknown", "the anchor period is 1300, below the ledger's first entry", []patch{replaceAt(94, []byte{0, 0, 0, 0, 0, 0, 0x05, 0x14})},
			canonState("finality_pin_unknown", "kind", 1, "period", uint64(1300), "root", hx(G.body.LC.AnchorRoot[:]))},
		{"adv_lc_links_over_bound", "the link count is 65, one over max_links", []patch{{At: G.linksAt, Del: 4, Ins: u32(65)}},
			canonState("finality_evidence_too_large", "part", "lc.links", "count", uint64(65), "limit", uint64(64))},
		{"adv_lc_profile_unknown", "the LC profile is eth-lc/2", []patch{replaceAt(81+4+7, []byte{'2'})},
			canonState("finality_evidence_malformed", "part", "profile", "index", 0, "reason", "unsupported_profile", "got_len", 8, "want_len", 8)},
		{"adv_lc_anchor_kind_unknown", "the anchor kind byte is 3", []patch{replaceAt(93, []byte{3})},
			canonState("finality_evidence_malformed", "part", "anchor_kind", "index", 0, "reason", "unknown_kind", "got_len", 3, "want_len", 2)},
		{"adv_lc_final_layout_electra_byte", "the final update carries layout byte 1 (electra) over a 1,448-byte Gloas blob", []patch{replaceAt(G.finalAt, []byte{1})},
			canonState("finality_evidence_malformed", "part", "final_update", "index", 0, "reason", "length", "got_len", len(fu), "want_len", 2056)},
		{"adv_lc_final_layout_unknown", "the final update carries layout byte 9", []patch{replaceAt(G.finalAt, []byte{9})},
			canonState("finality_evidence_malformed", "part", "final_update", "index", 0, "reason", "layout_byte_unknown", "got_len", 9, "want_len", 2)},
	} {
		if err := add(c.id, c.desc, main, L, c.patches, c.expect); err != nil {
			return err
		}
	}
	// leg / spine relations: the container header follows the stated leg
	h2 := hi[n-2]
	if err := add("adv_spine_extends_below_leg", "the leg is the second-last spine block, so the spine runs one header below it", main, legWith(h2.number, h2.hash, G.body.Spine[n-2]),
		[]patch{numberPatch(h2.number), hashPatch(h2.hash)},
		canonState("finality_evidence_malformed", "part", "spine", "reason", "spine_not_ending_at_block", "got_len", uint64(n), "want_len", uint64(n-1))); err != nil {
		return err
	}
	var fake [32]byte
	for i := range fake {
		fake[i] = 0x77
	}
	if err := add("adv_leg_above_finalized_head", "the leg is the block above the finalized execution head", main, legWith(top.number+1, fake, nil),
		[]patch{numberPatch(top.number + 1), hashPatch(fake)},
		canonState("finality_block_not_covered", "block_number", top.number+1, "finalized_exec_number", top.number)); err != nil {
		return err
	}
	altered := flip(ref.Hash)
	if err := add("adv_leg_hash_not_on_spine", "the leg has the number of a spine block but another hash", main, legWith(ref.Number, altered, ref.HeaderRLP),
		[]patch{hashPatch(altered)},
		canonState("finality_block_mismatch", "field", "hash", "want", hx(altered[:]), "got", hx(ref.Hash[:]))); err != nil {
		return err
	}
	badHdr := append([]byte(nil), ref.HeaderRLP...)
	badHdr[len(badHdr)-5] ^= 0xff
	if err := add("adv_leg_header_bytes_differ", "Settlement.Header differs from the spine's last header in one byte (same stated hash)", main, legWith(ref.Number, ref.Hash, badHdr), nil,
		canonState("finality_block_mismatch", "field", "header", "want", hx(func() []byte { h := crypto.Keccak256(badHdr); return h }()), "got", hx(ref.Hash[:]))); err != nil {
		return err
	}
	// pins variants
	if err := add("adv_pins_ledger_ends_before_anchor", "a verifier whose ledger ends at period 1385 judges a proof anchored at the latest period", "ledger_ends_1385", L, nil,
		canonState("finality_ledger_behind", "needed_period", G.body.LC.AnchorPeriod, "ledger_head_period", uint64(1385))); err != nil {
		return err
	}
	if err := add("adv_pins_ledger_empty", "a verifier with an empty ledger", "ledger_empty", L, nil,
		canonState("finality_pin_unknown", "kind", 1, "period", G.body.LC.AnchorPeriod, "root", hx(G.body.LC.AnchorRoot[:]))); err != nil {
		return err
	}
	if err := add("adv_pins_gvr_other", "the pins carry another genesis_validators_root: the sync-committee domain differs", "gvr_other", L, nil, sigFail()); err != nil {
		return err
	}

	// the other real legs
	for _, id := range []string{"gloas_period", "legacy"} {
		l, ok := legs[id]
		if !ok {
			continue
		}
		if err := b.add(vecCase{ID: "valid_" + id, Description: "real leg, block " + strconv.FormatUint(l.ref.Number, 10), Pins: "pins/main.json", Leg: lcLeg(l), Expect: validExpect(l)}, l, verifyWith); err != nil {
			return err
		}
	}
	Lg := legs["legacy"]
	if Lg != nil {
		ln := len(Lg.body.Spine)
		lm := ln / 2
		lh := readHdr(Lg.body.Spine[lm])
		lprev := readHdr(Lg.body.Spine[lm-1])
		at := Lg.elemAt[lm] + 4 + bytes.Index(Lg.body.Spine[lm], lh.stateRoot[:]) + 3
		mut := append([]byte(nil), Lg.body.Spine[lm]...)
		mut[bytes.Index(mut, lh.stateRoot[:])+3] ^= 0xff
		if err := b.add(vecCase{ID: "adv_legacy_spine_header_forged", Description: "legacy leg: one byte of the middle spine header flipped", Pins: "pins/main.json", Leg: lcLeg(Lg),
			Patches: []patch{replaceAt(at, []byte{Lg.ev[at] ^ 0xff})},
			Expect:  canonState("finality_header_chain_broken", "spine", "l1", "at_number", lprev.number-1, "want_hash", hx(lprev.parent[:]), "got_hash", hx(crypto.Keccak256(mut)), "reason", "parent_hash_mismatch")}, Lg, verifyWith); err != nil {
			return err
		}
		if err := b.add(vecCase{ID: "adv_legacy_final_layout_gloas_byte", Description: "legacy leg: the electra final update carries layout byte 2 (gloas)", Pins: "pins/main.json", Leg: lcLeg(Lg),
			Patches: []patch{replaceAt(Lg.finalAt, []byte{2})},
			Expect:  canonState("finality_evidence_malformed", "part", "final_update", "index", 0, "reason", "length", "got_len", len(Lg.body.LC.FinalUpdate.SSZ), "want_len", 1448)}, Lg, verifyWith); err != nil {
			return err
		}
	}
	return nil
}

func putU64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// ---- extend cases ----

func (b *builder) extendCases(pinsRaw []byte, links map[uint64][]byte) error {
	mut := func(f func(as []map[string]any) []map[string]any) []byte {
		dec := json.NewDecoder(bytes.NewReader(pinsRaw))
		dec.UseNumber()
		var m map[string]any
		_ = dec.Decode(&m)
		es := m["eth_sepolia"].(map[string]any)
		var as []map[string]any
		for _, a := range es["anchors"].([]any) {
			as = append(as, a.(map[string]any))
		}
		out := f(as)
		l := make([]any, len(out))
		for i, a := range out {
			l[i] = a
		}
		es["anchors"] = l
		return render(m)
	}
	period := func(a map[string]any) uint64 { v, _ := a["period"].(json.Number).Int64(); return uint64(v) }
	base := mut(func(as []map[string]any) []map[string]any {
		var keep []map[string]any
		for _, a := range as {
			if period(a) <= 1386 {
				keep = append(keep, a)
			}
		}
		return keep
	})
	b.addFile("extend/base_1386.json", base)
	basePins, err := finality.ParsePinsOverride(base)
	if err != nil {
		return err
	}
	find := func(as []map[string]any, p uint64) map[string]any {
		for _, a := range as {
			if period(a) == p {
				return a
			}
		}
		return nil
	}
	sum := func(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
	type spec struct {
		id, desc string
		ext      []byte
		replace  map[uint64][]byte
		drop     []uint64
		expect   string
	}
	flipLink := func(p uint64, at int) []byte {
		l := append([]byte(nil), links[p]...)
		l[at] ^= 0x01
		return l
	}
	refusedLink := flipLink(1388, 26340)
	var specs []spec
	specs = append(specs, spec{"extend_valid", "five appended entries (1387..1391), each derived from its predecessor by the link named by its link_sha256", pinsRaw, nil, nil,
		string((&finality.StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(14), "pins_source": "extension:" + sum(pinsRaw)}}).Canonical())})
	specs = append(specs, spec{"extend_link_missing", "no link bytes for the appended period 1388", pinsRaw, nil, []uint64{1388},
		canonState("finality_ledger_extension_invalid", "period", uint64(1388), "reason", "link_missing")})
	specs = append(specs, spec{"extend_link_other_period", "the bytes supplied for 1388 are the link of 1389", pinsRaw, map[uint64][]byte{1388: links[1389]}, nil,
		canonState("finality_ledger_extension_invalid", "period", uint64(1388), "reason", "link_sha256_mismatch",
			"want_sha256", "0x"+find(allAnchors(pinsRaw), 1388)["link_sha256"].(string), "got_sha256", "0x"+sum(links[1389]))})
	specs = append(specs, spec{"extend_committee_root_altered", "the appended entry 1388 names another committee root (its link_sha256 is right)", mut(func(as []map[string]any) []map[string]any {
		r := find(as, 1388)["committee_root"].(string)
		find(as, 1388)["committee_root"] = "0x00" + r[4:]
		return as
	}), nil, nil, canonState("finality_ledger_extension_invalid", "period", uint64(1388), "reason", "committee_root_mismatch")})
	specs = append(specs, spec{"extend_wsp_widened", "the appended entry 1388 widens wsp_epochs to 300", mut(func(as []map[string]any) []map[string]any {
		find(as, 1388)["wsp_epochs"] = json.Number("300")
		return as
	}), nil, nil, canonState("finality_ledger_extension_invalid", "period", uint64(1388), "reason", "wsp_widened", "wsp_epochs", uint64(300), "limit", uint64(279))})
	specs = append(specs, spec{"extend_base_not_prefix", "the extension changes derived_by of the base entry 1380", mut(func(as []map[string]any) []map[string]any {
		a := find(as, 1380)
		a["derived_by"] = append(a["derived_by"].([]any), "x")
		return as
	}), nil, nil, canonState("finality_ledger_extension_invalid", "period", uint64(1380), "reason", "base_not_prefix", "index", uint64(2))})
	specs = append(specs, spec{"extend_non_ledger_content_differs", "the extension changes published_utc", bytes.Replace(pinsRaw, []byte(`"published_utc": "`), []byte(`"published_utc": "2099-`), 1), nil, nil,
		canonState("finality_ledger_extension_invalid", "period", uint64(0), "reason", "non_ledger_content_differs")})
	specs = append(specs, spec{"extend_period_not_next", "the entry 1388 is missing, so 1389 does not follow 1387", mut(func(as []map[string]any) []map[string]any {
		var out []map[string]any
		for _, a := range as {
			if period(a) != 1388 {
				out = append(out, a)
			}
		}
		return out
	}), nil, nil, canonState("finality_ledger_extension_invalid", "period", uint64(1389), "reason", "period_not_next", "predecessor_period", uint64(1387))})
	specs = append(specs, spec{"extend_link_refused", "the link of 1388 has one signature bit flipped and its entry names the new hash: the verifier refuses the link", mut(func(as []map[string]any) []map[string]any {
		find(as, 1388)["link_sha256"] = sum(refusedLink)
		return as
	}), map[uint64][]byte{1388: refusedLink}, nil, canonState("finality_ledger_extension_invalid", "period", uint64(1388), "reason", "link_refused", "inner", "finality_signature_invalid")})

	for _, s := range specs {
		ext := "extend/" + s.id + ".pins.json"
		b.addFile(ext, s.ext)
		c := extendCase{Format: "certen-finality-ethsepolia-extend-case/1", ID: s.id, Description: s.desc, Base: "extend/base_1386.json", Extension: ext, LinksDir: "raw/links", Expect: s.expect}
		if len(s.replace) > 0 {
			c.LinksReplace = map[string]string{}
			for p, d := range s.replace {
				rel := fmt.Sprintf("extend/%s.link%d.ssz", s.id, p)
				b.addFile(rel, d)
				c.LinksReplace[strconv.FormatUint(p, 10)] = rel
			}
		}
		c.LinksDrop = s.drop
		l := map[uint64][]byte{}
		for p, d := range links {
			l[p] = d
		}
		for p, d := range s.replace {
			l[p] = d
		}
		for _, p := range s.drop {
			delete(l, p)
		}
		v, err := basePins.Extend(s.ext, l)
		var got string
		if err != nil {
			if st, ok := finality.AsNamed(err); ok {
				got = string(st.Canonical())
			} else {
				got = "unnamed: " + err.Error()
			}
		} else {
			e, _ := v.Sepolia()
			_, src := v.Identity()
			got = string((&finality.StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors)), "pins_source": src}}).Canonical())
		}
		if got != s.expect {
			return fmt.Errorf("extend case %s: Extend says\n  %s\nthe literal is\n  %s", s.id, got, s.expect)
		}
		b.extend = append(b.extend, c)
		j, _ := json.MarshalIndent(c, "", " ")
		b.addFile("extend/"+s.id+".json", append(j, '\n'))
	}
	return nil
}

func allAnchors(raw []byte) []map[string]any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	_ = dec.Decode(&m)
	var out []map[string]any
	for _, a := range m["eth_sepolia"].(map[string]any)["anchors"].([]any) {
		out = append(out, a.(map[string]any))
	}
	return out
}

func render(m map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(m)
	return buf.Bytes()
}

var _ = ethsepolia.Name
