// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// build2 writes the published set finality_ethl1_v2: every case of v1 (regenerated from the same captured bytes under the v2
// domain tag), the electra-layout cases of the real Fulu objects, the legacy-leg final update and its 2.6 MB spine, and the
// synthetic cases for the defects V-C1A listed. v1 is frozen; this generator never writes into it.
func build2(rawDir, raw2Dir, out string) error {
	setName, labelPrefix = "finality_ethl1_v2", "finality_ethl1_v2/"
	dst := filepath.Join(out, "raw")
	for _, src := range []string{rawDir, raw2Dir} {
		if err := copyTree(src, dst); err != nil {
			return err
		}
	}
	return buildSet(dst, dst, out, true)
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		o, err := os.Create(to)
		if err != nil {
			return err
		}
		if _, err := io.Copy(o, in); err != nil {
			o.Close()
			return err
		}
		return o.Close()
	})
}

func ethlRootOf(b []byte) [32]byte { return sszCommitteeRoot(b) }

type v2in struct {
	raw2Dir   string
	comm, upd map[uint64][]byte
	fu, boot  []byte
	P         uint64
	bootRoot  string
	mk        func(kind uint8, period uint64, aroot [32]byte, body ethl1.LB, links []ethl1.LB, final []byte) ethl1.LC
	gl        func([]byte) ethl1.LB
	k1        func(period uint64, links []ethl1.LB, final []byte) ethl1.LC
	k2        func(bootstrap, final []byte) ethl1.LC
	linkRange func(from, to uint64) []ethl1.LB
	okFields  func(participants, crossed int) map[string]string
	nParts    int
}

// addPinsFrom is addPins with a base other than "main".
func (g *gen) addPinsFrom(baseName, name, desc string, mod func(*pinsFile)) {
	base := g.pins[baseName]
	pf := base
	pf.Forks = append([]forkFile(nil), base.Forks...)
	pf.Anchors = append([]anchorFile(nil), base.Anchors...)
	pf.Description = desc
	if mod != nil {
		mod(&pf)
	}
	g.pins[name] = pf
	g.put("pins/"+name+".json", canonJSON(pf))
}

// headShared records a head case whose LC file is shared with other cases (only the pins differ).
func (g *gen) headShared(id, desc, pinsName, lcID string, lc ethl1.LC, want string, fields map[string]string) {
	path := "lc/" + lcID + ".bin"
	saved, had := g.files[path]
	g.head(id, desc, pinsName, lc, want, fields)
	// g.head wrote lc/<id>.bin; move it to the shared name and point the case at it
	own := "lc/" + id + ".bin"
	if id != lcID {
		b := g.files[own]
		delete(g.files, own)
		if had && !bytes.Equal(saved, b) {
			panic("shared LC " + lcID + " differs between cases")
		}
		g.files[path] = b
		cf := "cases/" + id + ".json"
		g.files[cf] = bytes.Replace(g.files[cf], []byte(own), []byte(path), 1)
	}
}

func put32(b []byte, off int, v uint32) []byte {
	c := cp(b)
	binary.LittleEndian.PutUint32(c[off:], v)
	return c
}

func popcount(b []byte) int {
	n := 0
	for _, x := range b {
		for ; x != 0; x &= x - 1 {
			n++
		}
	}
	return n
}

// readSpineFile parses the framed legacy spine: u32be count, then per header u32be length and the raw RLP.
func readSpineFile(b []byte) [][]byte {
	n := int(binary.BigEndian.Uint32(b))
	pos := 4
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		l := int(binary.BigEndian.Uint32(b[pos:]))
		pos += 4
		out = append(out, b[pos:pos+l])
		pos += l
	}
	if pos != len(b) {
		panic("legacy spine file has trailing bytes")
	}
	return out
}

// coversFile records a Covers case whose headers live in a framed file of the set (spec 5.3 legacy leg).
func (g *gen) coversFile(id, desc string, execHash [32]byte, file string, spine [][]byte, max int, blockNumber uint64, want string, fields map[string]string) {
	head := ethl1.FinalizedHead{ExecHash: execHash}
	bl, err := head.Covers(spine, max)
	var blk ethl1.L1Block
	if err == nil {
		blk, err = ethl1.BlockAt(bl, blockNumber)
	}
	var expect json.RawMessage
	if want == "" {
		if err != nil {
			panic(fmt.Sprintf("covers %s: want success, got %v", id, err))
		}
		b, _ := json.Marshal(map[string]any{"result": "ok", "headers_walked": strconv.Itoa(len(bl)), "block": blocksJSON([]ethl1.L1Block{blk})[0]})
		expect = b
	} else {
		f, isFault := err.(*ethl1.Fault)
		if err == nil || !isFault || f.Code != want {
			panic(fmt.Sprintf("covers %s: want %s, got %v", id, want, err))
		}
		var body struct {
			Fields map[string]any `json:"fields"`
		}
		_ = json.Unmarshal(f.CanonicalJSON(), &body)
		for k, v := range fields {
			if fmt.Sprint(body.Fields[k]) != v {
				panic(fmt.Sprintf("covers %s: field %s = %v, want %s", id, k, body.Fields[k], v))
			}
		}
		expect = faultExpect(f)
	}
	g.writeCase(caseFile{Format: formatCase, ID: id, Kind: "covers", Description: desc, ExecHash: hx(execHash[:]), SpineFile: file, Max: max, BlockNumber: strconv.FormatUint(blockNumber, 10), Expect: expect})
}

func (g *gen) v2extras(c v2in) error {
	boot2 := readFile(c.raw2Dir, "bootstrap_fulu.ssz")
	u1377 := readFile(c.raw2Dir, "update_1377.ssz")
	u1378 := readFile(c.raw2Dir, "update_1378.ssz")
	spineBin := readFile(c.raw2Dir, "spine_legacy.bin")
	const (
		bootHdr   = 4 + committeeLen + 32*6 // 24,820
		updFixed  = 25216
		hdrExec   = 244
		execNum   = 404
		execGas   = 420
		execExtra = 436
		execFee   = 32
		execHash  = 472
		finUpdFix = 400
	)
	if int(binary.LittleEndian.Uint32(boot2)) != bootHdr {
		return fmt.Errorf("fulu bootstrap: first offset %d", binary.LittleEndian.Uint32(boot2))
	}
	c1378 := boot2[4 : 4+committeeLen]
	if !bytes.Equal(u1377[4:4+committeeLen], c1378) {
		return fmt.Errorf("the committee the period-1377 update learns differs from the Fulu bootstrap committee")
	}
	finOff := int(binary.LittleEndian.Uint32(u1378[24820:24824]))
	att, fin := u1378[updFixed:finOff], u1378[finOff:]
	if !bytes.Equal(u1378[4:4+committeeLen], c.comm[1379]) {
		return fmt.Errorf("the Fulu update learns a committee other than the ledger's period 1379")
	}
	// the period-1378 update converted to a finality update: the legacy-leg final update (spec 5.3)
	fu1378 := binary.LittleEndian.AppendUint32(nil, finUpdFix)
	fu1378 = binary.LittleEndian.AppendUint32(fu1378, uint32(finUpdFix+len(att)))
	fu1378 = append(fu1378, u1378[24824:24824+224]...)
	fu1378 = append(fu1378, u1378[24824+224:25208]...)
	fu1378 = append(fu1378, u1378[25208:25216]...)
	fu1378 = append(fu1378, att...)
	fu1378 = append(fu1378, fin...)
	fu1378AttOff, fu1378FinOff := finUpdFix, finUpdFix+len(att)
	n1378 := popcount(u1378[24824+224 : 24824+224+64])
	finSlot1378 := get64(fin, 0)
	execHash1378 := [32]byte{}
	copy(execHash1378[:], fin[hdrExec+execHash:hdrExec+execHash+32])
	execNum1378 := get64(fin, hdrExec+execNum)
	finExtra := len(fin) - 828
	u64s := func(v uint64) string { return strconv.FormatUint(v, 10) }
	el := func(b []byte) ethl1.LB { return ethl1.LB{Layout: ethl1.LayoutElectra, SSZ: b} }
	checkpoint := h32(fuluCheckpoint)
	k2e := func(bootstrap []byte, links []ethl1.LB, final ethl1.LB) ethl1.LC {
		lc := c.mk(2, 1378, checkpoint, el(bootstrap), links, nil)
		lc.FinalUpdate = final
		return lc
	}
	k1e := func(links []ethl1.LB, final ethl1.LB) ethl1.LC {
		lc := c.mk(1, 1378, ethlRootOf(c1378), ethl1.LB{Layout: ethl1.LayoutNone, SSZ: c1378}, links, nil)
		lc.FinalUpdate = final
		return lc
	}
	okE := func(parts, crossed int) map[string]string {
		return map[string]string{"participants": strconv.Itoa(parts), "periods_crossed": strconv.Itoa(crossed), "slot": u64s(finSlot1378), "exec_hash": hx(execHash1378[:])}
	}

	g.addPinsFrom("main", "electra_version_at_fulu", "the electra fork version in the fulu fork entry: the signing domain of a Fulu slot uses 0x90000074", func(pf *pinsFile) {
		for i := range pf.Forks {
			if pf.Forks[i].Name == "fulu" {
				pf.Forks[i].Version = "0x90000074"
			}
		}
	})
	g.addPinsFrom("main", "ledger_1378_committee_wrong", "ledger committee_root of period 1378 replaced, block_root kept", func(pf *pinsFile) {
		pf.Anchors[0].CommitteeRoot = func() string { r := sum("c1378"); return hx(r[:]) }()
	})
	g.addPinsFrom("main", "ledger_1379_learned_wrong", "ledger root of period 1379 replaced: the committee the Fulu link learns no longer matches", func(pf *pinsFile) {
		for i := range pf.Anchors {
			if pf.Anchors[i].Period == "1379" {
				pf.Anchors[i].CommitteeRoot = func() string { r := sum("c1379"); return hx(r[:]) }()
			}
		}
	})
	g.addPinsFrom("main", "network_mismatch", "pins of another chain (chain_id 1)", func(pf *pinsFile) { pf.ChainID = "1" })

	// ---- valid: the real Fulu objects
	g.head("valid_k2_fulu_k0", "legacy-leg final update: the period-1378 Fulu update converted to a finality update (electra layout), kind-2 anchor of the Fulu period-start bootstrap",
		"main", k2e(boot2, nil, el(fu1378)), "", okE(n1378, 0))
	g.head("valid_k1_fulu_k0", "the same final update under a kind-1 committee anchor (committee of period 1378)", "main", k1e(nil, el(fu1378)), "", okE(n1378, 0))
	chain := append([]ethl1.LB{el(u1378)}, c.linkRange(1379, c.P-1)...)
	g.head("valid_k2_fulu_chain_to_gloas", "mixed forks: Fulu bootstrap anchor (period 1378), the Fulu update as link 0, eleven Gloas links, the live Gloas finality update",
		"main", func() ethl1.LC { lc := k2e(boot2, chain, ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: c.fu}); return lc }(), "", c.okFields(c.nParts, int(c.P-1378)))
	g.head("valid_k1_fulu_chain_to_gloas", "mixed forks under a kind-1 anchor of period 1378", "main", k1e(chain, ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: c.fu}), "", c.okFields(c.nParts, int(c.P-1378)))

	// ---- the legacy leg: 4,057 Fulu headers from the finalized head of the period-1378 update down to block 11,845,679
	spine := readSpineFile(spineBin)
	g.coversFile("spine_legacy_leg", "legacy leg of spec 5.3: all headers from the finalized execution head of the period-1378 update (block "+u64s(execNum1378)+") to block 11,845,679",
		execHash1378, "raw/spine_legacy.bin", spine, 16384, 11845679, "", nil)
	g.coversFile("adv_spine_legacy_leg_over_bound", "the same spine against max_spine_headers 4056", execHash1378, "raw/spine_legacy.bin", spine, len(spine)-1, 11845679,
		ethl1.CodeEvidenceTooLarge, map[string]string{"part": "spine", "count": strconv.Itoa(len(spine)), "limit": strconv.Itoa(len(spine) - 1)})
	g.coversFile("spine_legacy_block_above_head", "a block above the finalized head of the period-1378 update is not covered", execHash1378, "raw/spine_legacy.bin", spine, 16384, execNum1378+1,
		ethl1.CodeBlockNotCovered, map[string]string{"block_number": u64s(execNum1378 + 1), "finalized_exec_number": u64s(execNum1378)})

	// ---- adversarial mutations of the electra bytes (kind-2 Fulu anchor, final update)
	baseFinal := func(b []byte) ethl1.LC { return k2e(boot2, nil, el(b)) }
	malformed := func(part, reason string) map[string]string { return map[string]string{"part": part, "reason": reason} }
	li := func(check string) map[string]string { return map[string]string{"check": check, "index": "0"} }
	g.head("adv_electra_forged_attested_exec_field", "attested execution.fee_recipient byte flipped: the header root no longer reaches the body root", "main",
		baseFinal(flip(fu1378, fu1378AttOff+hdrExec+execFee+3)), ethl1.CodeLinkInvalid, li("attested_header_exec_branch"))
	g.head("adv_electra_forged_finalized_exec_field", "finalized execution.gas_used byte flipped", "main",
		baseFinal(flip(fu1378, fu1378FinOff+hdrExec+execGas)), ethl1.CodeLinkInvalid, li("finalized_header_exec_branch"))
	g.head("adv_electra_forged_attested_exec_branch_node", "one node of the attested header's 4-node execution_branch flipped", "main",
		baseFinal(flip(fu1378, fu1378AttOff+116+2*32+1)), ethl1.CodeLinkInvalid, li("attested_header_exec_branch"))
	g.head("adv_electra_forged_finalized_exec_branch_node", "one node of the finalized header's execution_branch flipped", "main",
		baseFinal(flip(fu1378, fu1378FinOff+116+32+5)), ethl1.CodeLinkInvalid, li("finalized_header_exec_branch"))
	g.head("adv_electra_forged_finality_branch_node", "one node of the 7-node finality_branch flipped", "main",
		baseFinal(flip(fu1378, 8+3*32+2)), ethl1.CodeLinkInvalid, li("finality_branch"))
	{
		gloasSlot := uint64(353024 * 32)
		g.head("adv_electra_attested_slot_in_gloas_era", "electra-shaped update whose attested slot lies in the Gloas era: the wrong gindex family for the fork of its own slot", "main",
			baseFinal(put64(fu1378, fu1378AttOff, gloasSlot+10)), ethl1.CodeForkUnsupported,
			map[string]string{"slot": u64s(gloasSlot + 10), "epoch": u64s(353024), "layout": "electra"})
	}
	g.head("adv_electra_extra_data_offset_lie", "execution.extra_data offset 588 instead of 584", "main", baseFinal(put32(fu1378, fu1378AttOff+hdrExec+execExtra, 588)),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "extra_data_offset"))
	g.head("adv_electra_execution_offset_lie", "header execution offset 245 instead of 244", "main", baseFinal(put32(fu1378, fu1378AttOff+112, 245)),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "execution_offset"))
	g.head("adv_electra_attested_offset_lie", "first container offset 399 instead of 400", "main", baseFinal(put32(fu1378, 0, 399)),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "attested_offset"))
	g.head("adv_electra_finalized_offset_out_of_range", "finalized offset beyond the blob", "main", baseFinal(put32(fu1378, 4, uint32(len(fu1378)+10))),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "finalized_offset"))
	g.head("adv_electra_finalized_offset_descending", "finalized offset not past the attested header", "main", baseFinal(put32(fu1378, 4, 400)),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "finalized_offset"))
	g.head("adv_electra_overlong_tail", "40 bytes appended: the finalized header would carry more than 32 bytes of extra_data", "main", baseFinal(append(cp(fu1378), bytes.Repeat([]byte{0xab}, 40)...)),
		ethl1.CodeEvidenceMalformed, malformed("final_update", "header_length"))
	if finExtra < 32 {
		g.head("adv_electra_extra_data_grown_by_one", "one byte appended: extra_data one byte longer, so the finalized header root changes", "main", baseFinal(append(cp(fu1378), 0xab)),
			ethl1.CodeLinkInvalid, li("finalized_header_exec_branch"))
	} else {
		g.head("adv_electra_extra_data_grown_by_one", "one byte appended to a header whose extra_data is already 32 bytes", "main", baseFinal(append(cp(fu1378), 0xab)),
			ethl1.CodeEvidenceMalformed, malformed("final_update", "header_length"))
	}
	{
		cut := fu1378[:len(fu1378)-100]
		reason := "header_length"
		if len(cut) < 2056 {
			reason = "length"
		}
		g.head("adv_electra_truncated", "100 bytes cut from the end", "main", baseFinal(cut), ethl1.CodeEvidenceMalformed, malformed("final_update", reason))
	}
	{
		lc := baseFinal(fu1378)
		lc.FinalUpdate.Layout = ethl1.LayoutGloas
		g.head("adv_electra_layout_byte_gloas_on_electra_bytes", "layout byte 2 on electra bytes: not a 1,448-byte object", "main", lc, ethl1.CodeEvidenceMalformed,
			map[string]string{"part": "final_update", "reason": "length", "got_len": strconv.Itoa(len(fu1378)), "want_len": "1448"})
		lc2 := k2e(boot2, nil, ethl1.LB{Layout: ethl1.LayoutElectra, SSZ: c.fu})
		g.head("adv_gloas_layout_byte_electra_on_gloas_bytes", "layout byte 1 on the live 1,448-byte Gloas finality update: shorter than the electra minimum", "main", lc2, ethl1.CodeEvidenceMalformed,
			map[string]string{"part": "final_update", "reason": "length", "got_len": "1448", "want_len": "2056"})
		lc3 := k2e(boot2, nil, el(fu1378))
		lc3.AnchorBody.Layout = ethl1.LayoutGloas
		g.head("adv_electra_bootstrap_layout_byte_gloas", "layout byte 2 on the electra bootstrap", "main", lc3, ethl1.CodeEvidenceMalformed,
			map[string]string{"part": "anchor_body", "reason": "length", "got_len": strconv.Itoa(len(boot2)), "want_len": "25472"})
	}
	g.head("adv_electra_fork_version_wrong", "pins carry the electra version for the fulu fork: the domain of the Fulu-era signature is wrong", "electra_version_at_fulu", baseFinal(fu1378),
		ethl1.CodeSignatureInvalid, map[string]string{"fork_version": "0x90000074", "participants": strconv.Itoa(n1378)})
	bootSlot := get64(boot2, bootHdr)
	g.head("adv_electra_bootstrap_forged_exec_field", "bootstrap execution.fee_recipient byte flipped", "main", k2e(flip(boot2, bootHdr+hdrExec+execFee+1), nil, el(fu1378)),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "header_exec_branch", "slot": u64s(bootSlot)})
	g.head("adv_electra_bootstrap_committee_branch_forged", "one node of the bootstrap's 6-node current_sync_committee_branch flipped", "main", k2e(flip(boot2, 4+committeeLen+3*32), nil, el(fu1378)),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "committee_branch", "slot": u64s(bootSlot)})
	g.head("adv_electra_bootstrap_committee_swapped", "one public-key bit of the bootstrap committee flipped", "main", k2e(flip(boot2, 4+9), nil, el(fu1378)),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "committee_branch"})
	g.head("adv_electra_ledger_1378_committee_wrong", "the genuine Fulu bootstrap against a ledger committee_root for period 1378 that differs", "ledger_1378_committee_wrong", k2e(boot2, nil, el(fu1378)),
		ethl1.CodePinMismatch, map[string]string{"period": "1378"})
	g.head("adv_electra_chain_learned_not_ledger", "the Fulu link learns the committee of period 1379 but the ledger holds another root", "ledger_1379_learned_wrong",
		k2e(boot2, chain, ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: c.fu}), ethl1.CodePinMismatch, map[string]string{"period": "1379"})
	chainWith := func(mut func([]byte) []byte) ethl1.LC {
		l := append([]ethl1.LB{el(mut(cp(u1378)))}, c.linkRange(1379, c.P-1)...)
		return k2e(boot2, l, ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: c.fu})
	}
	g.head("adv_electra_link_signature_flipped", "signature bit of the Fulu link flipped", "main", chainWith(func(b []byte) []byte { return flip(b, 25112+95) }),
		ethl1.CodeSignatureInvalid, map[string]string{"index": "0"})
	g.head("adv_electra_link_next_committee_branch_forged", "one node of the Fulu link's 6-node next_sync_committee_branch flipped", "main", chainWith(func(b []byte) []byte { return flip(b, 4+committeeLen+2*32) }),
		ethl1.CodeLinkInvalid, li("next_committee_branch"))
	g.head("adv_electra_link_next_committee_forged", "one public-key bit of the Fulu link's next committee flipped", "main", chainWith(func(b []byte) []byte { return flip(b, 4+11) }),
		ethl1.CodeLinkInvalid, li("next_committee_branch"))
	g.head("adv_electra_link_participation_341", "Fulu link with 341 bits", "main", chainWith(func(b []byte) []byte { return splice(b, 25048, clearBitsKeep(b[25048:25112], 341)) }),
		ethl1.CodeParticipationInsuff, map[string]string{"index": "0", "participants": "341"})
	g.head("adv_electra_link_finality_branch_forged", "one node of the Fulu link's 7-node finality_branch flipped", "main", chainWith(func(b []byte) []byte { return flip(b, 24824+4*32) }),
		ethl1.CodeLinkInvalid, li("finality_branch"))

	// ---- the ledger rule on every learned period of the 11-link Gloas chain (V-C1A gap P): shared LC, one altered entry each
	chainLC := c.k1(1379, c.linkRange(1379, c.P-1), c.fu)
	for q := uint64(1380); q <= c.P; q++ {
		q := q
		name := "ledger_period_" + u64s(q) + "_altered"
		g.addPinsFrom("main", name, "ledger committee_root of period "+u64s(q)+" replaced", func(pf *pinsFile) {
			for i := range pf.Anchors {
				if pf.Anchors[i].Period == u64s(q) {
					pf.Anchors[i].CommitteeRoot = func() string { r := sum("altered/" + u64s(q)); return hx(r[:]) }()
				}
			}
		})
		g.headShared("adv_ledger_period_"+u64s(q)+"_altered", "valid_k1_chain with the ledger entry of period "+u64s(q)+" replaced: the committee learned for it is refused", name, "valid_k1_chain_v2", chainLC,
			ethl1.CodePinMismatch, map[string]string{"period": u64s(q)})
	}
	g.head("adv_pins_network_mismatch", "pins of chain 1 judged as Sepolia", "network_mismatch", c.k1(c.P, nil, c.fu), ethl1.CodeNetworkMismatch, map[string]string{"chain_id": "11155111", "want_chain_id": "1"})

	g.synthetic2()
	return nil
}
