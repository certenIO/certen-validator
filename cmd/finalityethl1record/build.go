// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Offsets in the Gloas objects (annex Q6).
const (
	offFUAttested   = 0
	offFUFinalized  = 496
	offFUFinBranch  = 992
	offFUBits       = 1280
	offFUSig        = 1344
	offFUSigSlot    = 1440
	offUNext        = 496
	offUNextBranch  = 25120
	offUFinalized   = 25472
	offUFinBranch   = 25968
	offUBits        = 26256
	offUSig         = 26320
	offUSigSlot     = 26416
	offHdrSlot      = 0
	offHdrParent    = 16
	offHdrState     = 48
	offHdrBody      = 80
	offHdrExec      = 112
	offHdrBranch    = 144
	offBootCommit   = 496
	offBootBranch   = 25120
	committeeLen    = 24624
	genesisValRoot  = "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
	wspEpochs       = 279
	formatPins      = "certen-finality-ethl1-test-pins/1"
	formatCase      = "certen-finality-ethl1-case/1"
	formatManifest  = "certen-finality-ethl1-vectors/1"
	maxLinksPins    = 64
	maxSpinePins    = 16384
	minParticipants = 342
)

type pinsFile struct {
	Format          string       `json:"format"`
	Description     string       `json:"description"`
	ChainID         string       `json:"chain_id"`
	GVR             string       `json:"genesis_validators_root"`
	Forks           []forkFile   `json:"forks"`
	Anchors         []anchorFile `json:"anchors"`
	MinParticipants int          `json:"min_participants"`
	MaxLinks        int          `json:"max_links"`
	MaxSpine        int          `json:"max_spine_headers"`
}
type forkFile struct {
	Name    string `json:"name"`
	Epoch   string `json:"epoch"`
	Version string `json:"version"`
	Layout  int    `json:"layout"` // 0 none, 1 electra, 2 gloas
}
type anchorFile struct {
	Period        string  `json:"period"`
	CommitteeRoot string  `json:"committee_root"`
	BlockRoot     *string `json:"block_root"`
	WSPEpochs     string  `json:"wsp_epochs"`
}

type caseFile struct {
	Format      string          `json:"format"`
	ID          string          `json:"id"`
	Kind        string          `json:"kind"` // "head" or "covers"
	Description string          `json:"description"`
	Pins        string          `json:"pins,omitempty"`
	LC          string          `json:"lc,omitempty"`
	ExecHash    string          `json:"exec_hash,omitempty"`
	Spine       []string        `json:"spine,omitempty"`
	SpineFile   string          `json:"spine_file,omitempty"`
	Max         int             `json:"max,omitempty"`
	BlockNumber string          `json:"block_number,omitempty"`
	Expect      json.RawMessage `json:"expect"`
}

type gen struct {
	out    string
	files  map[string][]byte
	cases  []string
	pins   map[string]pinsFile
	baseLC map[string]ethl1.LC
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }
func h32(s string) [32]byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		panic("bad hash " + s)
	}
	var a [32]byte
	copy(a[:], b)
	return a
}
func cp(b []byte) []byte          { return append([]byte(nil), b...) }
func flip(b []byte, i int) []byte { c := cp(b); c[i] ^= 0x01; return c }
func sum(label string) [32]byte   { return sha256.Sum256([]byte(labelPrefix + label)) }

// setName and labelPrefix name the set being generated: finality_ethl1_v1 is frozen (SUPERSEDED.md); the generator now writes v2.
var (
	setName     = "finality_ethl1_v1"
	labelPrefix = "finality_ethl1_v1/"
)

func (g *gen) put(path string, b []byte) { g.files[path] = b }

func canonJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func pinsToTypes(pf pinsFile) ethl1.Pins {
	var p ethl1.Pins
	p.Network.ChainID, _ = strconv.ParseUint(pf.ChainID, 10, 64)
	p.Network.GenesisValidatorsRoot = h32(pf.GVR)
	for _, f := range pf.Forks {
		var fk ethl1.Fork
		fk.Name = f.Name
		fk.Epoch, _ = strconv.ParseUint(f.Epoch, 10, 64)
		v, _ := hex.DecodeString(strings.TrimPrefix(f.Version, "0x"))
		copy(fk.Version[:], v)
		fk.Layout = ethl1.Layout(f.Layout)
		p.Network.Forks = append(p.Network.Forks, fk)
	}
	for _, a := range pf.Anchors {
		var an ethl1.Anchor
		an.Period, _ = strconv.ParseUint(a.Period, 10, 64)
		an.CommitteeRoot = h32(a.CommitteeRoot)
		if a.BlockRoot != nil {
			br := h32(*a.BlockRoot)
			an.BlockRoot = &br
		}
		an.WSPEpochs, _ = strconv.ParseUint(a.WSPEpochs, 10, 64)
		p.Anchors = append(p.Anchors, an)
	}
	p.MinParticipants, p.MaxLinks, p.MaxSpineHeaders = pf.MinParticipants, pf.MaxLinks, pf.MaxSpine
	return p
}

func (g *gen) addPins(name, desc string, mod func(*pinsFile)) {
	base := g.pins["main"]
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

func headOK(h ethl1.FinalizedHead) json.RawMessage {
	m := map[string]string{
		"slot": strconv.FormatUint(h.Slot, 10), "epoch": strconv.FormatUint(h.Epoch, 10), "beacon_root": hx(h.BeaconRoot[:]),
		"exec_hash": hx(h.ExecHash[:]), "participants": strconv.Itoa(h.Participants), "periods_crossed": strconv.FormatUint(h.PeriodsCrossed, 10),
	}
	b, _ := json.Marshal(map[string]any{"result": "ok", "finalized_head": m})
	return b
}

func faultExpect(f *ethl1.Fault) json.RawMessage {
	var body map[string]any
	_ = json.Unmarshal(f.CanonicalJSON(), &body)
	b, _ := json.Marshal(map[string]any{"result": "fault", "code": body["code"], "fields": body["fields"]})
	return b
}

// head runs the verifier on lc and records the case. want is the hand-written expected code ("" for success); fields are
// hand-written expectations of selected canonical field values, so a verifier bug cannot silently write its own golden.
func (g *gen) head(id, desc, pinsName string, lc ethl1.LC, want string, fields map[string]string) {
	pf, ok := g.pins[pinsName]
	if !ok {
		panic("no pins " + pinsName)
	}
	h, err := ethl1.VerifyFinalizedHead(pinsToTypes(pf), lc)
	var expect json.RawMessage
	if want == "" {
		if err != nil {
			panic(fmt.Sprintf("case %s: want success, got %v", id, err))
		}
		expect = headOK(h)
		for k, v := range fields {
			var m map[string]map[string]string
			_ = json.Unmarshal(expect, &m)
			if m["finalized_head"][k] != v {
				panic(fmt.Sprintf("case %s: ok field %s = %s, want %s", id, k, m["finalized_head"][k], v))
			}
		}
	} else {
		f, isFault := err.(*ethl1.Fault)
		if err == nil || !isFault || f.Code != want {
			panic(fmt.Sprintf("case %s: want %s, got %v", id, want, err))
		}
		var body struct {
			Fields map[string]any `json:"fields"`
		}
		_ = json.Unmarshal(f.CanonicalJSON(), &body)
		for k, v := range fields {
			if fmt.Sprint(body.Fields[k]) != v {
				panic(fmt.Sprintf("case %s: field %s = %v, want %s (%s)", id, k, body.Fields[k], v, f.CanonicalJSON()))
			}
		}
		expect = faultExpect(f)
	}
	g.put("lc/"+id+".bin", ethl1.EncodeLC(lc))
	g.writeCase(caseFile{Format: formatCase, ID: id, Kind: "head", Description: desc, Pins: "pins/" + pinsName + ".json", LC: "lc/" + id + ".bin", Expect: expect})
}

func (g *gen) writeCase(c caseFile) {
	g.put("cases/"+c.ID+".json", canonJSON(c))
	g.cases = append(g.cases, c.ID)
}

func hexList(l [][]byte) []string {
	out := make([]string, len(l))
	for i, b := range l {
		out[i] = hx(b)
	}
	return out
}

func blocksJSON(bl []ethl1.L1Block) []map[string]string {
	out := []map[string]string{}
	for _, b := range bl {
		out = append(out, map[string]string{"hash": hx(b.Hash[:]), "number": strconv.FormatUint(b.Number, 10), "state_root": hx(b.StateRoot[:]), "timestamp": strconv.FormatUint(b.Timestamp, 10)})
	}
	return out
}

// covers records a Covers case (and optionally a BlockAt lookup).
func (g *gen) covers(id, desc string, execHash [32]byte, spine [][]byte, max int, blockNumber *uint64, want string, fields map[string]string) {
	head := ethl1.FinalizedHead{ExecHash: execHash}
	bl, err := head.Covers(spine, max)
	if err == nil && blockNumber != nil {
		_, err = ethl1.BlockAt(bl, *blockNumber)
	}
	var expect json.RawMessage
	if want == "" {
		if err != nil {
			panic(fmt.Sprintf("covers %s: want success, got %v", id, err))
		}
		b, _ := json.Marshal(map[string]any{"result": "ok", "blocks": blocksJSON(bl)})
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
				panic(fmt.Sprintf("covers %s: field %s = %v, want %s (%s)", id, k, body.Fields[k], v, f.CanonicalJSON()))
			}
		}
		expect = faultExpect(f)
	}
	c := caseFile{Format: formatCase, ID: id, Kind: "covers", Description: desc, ExecHash: hx(execHash[:]), Spine: hexList(spine), Max: max, Expect: expect}
	if blockNumber != nil {
		c.BlockNumber = strconv.FormatUint(*blockNumber, 10)
	}
	g.writeCase(c)
}

func readFile(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	return b
}

func clearBitsKeep(bits []byte, keep int) []byte {
	c := cp(bits)
	n := 0
	for i := 0; i < len(c)*8; i++ {
		if c[i/8]>>(uint(i)%8)&1 == 1 {
			n++
			if n > keep {
				c[i/8] &^= 1 << (uint(i) % 8)
			}
		}
	}
	return c
}

func put64(b []byte, off int, v uint64) []byte {
	c := cp(b)
	binary.LittleEndian.PutUint64(c[off:], v)
	return c
}

func get64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func splice(b []byte, off int, repl []byte) []byte {
	c := cp(b)
	copy(c[off:], repl)
	return c
}

// build refuses to rewrite the frozen v1 set: its electra-layout stand-in verdict no longer exists in the verifier.
func build(rawDir, out string) error {
	return fmt.Errorf("finality_ethl1_v1 is frozen and superseded by finality_ethl1_v2 (see its SUPERSEDED.md): use build2")
}

func buildSet(rawDir, raw2Dir, out string, v2 bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	var capt struct {
		SigPeriod uint64   `json:"final_signature_period"`
		BootRoot  string   `json:"bootstrap_block_root"`
		Links     []uint64 `json:"link_periods"`
		Exec      string   `json:"final_finalized_exec_hash"`
	}
	if err := json.Unmarshal(readFile(rawDir, "capture.json"), &capt); err != nil {
		return err
	}
	P := capt.SigPeriod
	fu := readFile(rawDir, "finality_update.ssz")
	boot := readFile(rawDir, "bootstrap.ssz")
	fulu := readFile(rawDir, "updates/1378.ssz")
	upd := map[uint64][]byte{}
	for _, p := range capt.Links {
		upd[p] = readFile(rawDir, fmt.Sprintf("updates/%d.ssz", p))
	}
	var spineFile struct {
		Headers []string `json:"headers_rlp"`
	}
	if err := json.Unmarshal(readFile(rawDir, "spine.json"), &spineFile); err != nil {
		return err
	}
	var spine [][]byte
	for _, h := range spineFile.Headers {
		b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		spine = append(spine, b)
	}
	if binary.LittleEndian.Uint32(fulu[0:4]) != 25216 {
		return fmt.Errorf("unexpected Fulu update layout: first offset %d", binary.LittleEndian.Uint32(fulu[0:4]))
	}

	// committees of every period: C_1379 from the Fulu update, C_{p+1} from link p.
	comm := map[uint64][]byte{1379: fulu[4 : 4+committeeLen]}
	for p := uint64(1379); p < P; p++ {
		comm[p+1] = upd[p][offUNext : offUNext+committeeLen]
	}
	g := &gen{out: out, files: map[string][]byte{}, pins: map[string]pinsFile{}}
	root := func(period uint64) [32]byte { return sszCommitteeRoot(comm[period]) }

	// the bootstrap is an independent served object: its committee must be the one the link chain derived for period P.
	if !bytes.Equal(boot[offBootCommit:offBootCommit+committeeLen], comm[P]) {
		return fmt.Errorf("bootstrap committee differs from the committee derived by link %d", P-1)
	}

	// pins: main
	bootRoot := capt.BootRoot
	forks := []forkFile{
		{"genesis", "0", "0x90000069", 0}, {"altair", "50", "0x90000070", 0}, {"bellatrix", "100", "0x90000071", 0},
		{"capella", "56832", "0x90000072", 0}, {"deneb", "132608", "0x90000073", 0}, {"electra", "222464", "0x90000074", 1},
		{"fulu", "272640", "0x90000075", 1}, {"gloas", "353024", "0x90000076", 2},
	}
	mainPins := pinsFile{Format: formatPins, Description: "ledger of every period 1379.." + strconv.FormatUint(P, 10) + " derived from the captured link chain; the block_root of the last period is the captured bootstrap checkpoint",
		ChainID: "11155111", GVR: "0x" + genesisValRoot, Forks: forks, MinParticipants: minParticipants, MaxLinks: maxLinksPins, MaxSpine: maxSpinePins}
	if v2 {
		// the ledger of the v2 set starts at the Fulu period 1378 (kind-2 anchor of the Fulu bootstrap)
		r := ethlRootOf(readFile(raw2Dir, "bootstrap_fulu.ssz")[4 : 4+committeeLen])
		fb := fuluCheckpoint
		mainPins.Anchors = append(mainPins.Anchors, anchorFile{Period: "1378", CommitteeRoot: hx(r[:]), BlockRoot: &fb, WSPEpochs: strconv.Itoa(wspEpochs)})
	}
	for p := uint64(1379); p <= P; p++ {
		r := root(p)
		a := anchorFile{Period: strconv.FormatUint(p, 10), CommitteeRoot: hx(r[:]), WSPEpochs: strconv.Itoa(wspEpochs)}
		if p == P {
			a.BlockRoot = &bootRoot
		}
		mainPins.Anchors = append(mainPins.Anchors, a)
	}
	g.pins["main"] = mainPins
	g.put("pins/main.json", canonJSON(mainPins))
	setAnchor := func(pf *pinsFile, period uint64, f func(*anchorFile)) {
		for i := range pf.Anchors {
			if pf.Anchors[i].Period == strconv.FormatUint(period, 10) {
				f(&pf.Anchors[i])
				return
			}
		}
		panic("no anchor")
	}
	bad := func(label string) string { r := sum(label); return hx(r[:]) }
	g.addPins("wrong_gvr", "genesis_validators_root altered: every signing domain changes", func(pf *pinsFile) { pf.GVR = bad("gvr") })
	g.addPins("fulu_version_at_gloas", "the Fulu fork version in the gloas fork entry: the signing domain of a Gloas slot uses 0x90000075", func(pf *pinsFile) {
		pf.Forks[7].Version = "0x90000075"
	})
	g.addPins("wsp_1", "weak-subjectivity window of 1 epoch on every anchor", func(pf *pinsFile) {
		for i := range pf.Anchors {
			pf.Anchors[i].WSPEpochs = "1"
		}
	})
	g.addPins("ledger_learned_wrong", "ledger root of period P-1 replaced: the committee a link learns for it no longer matches", func(pf *pinsFile) {
		setAnchor(pf, P-1, func(a *anchorFile) { a.CommitteeRoot = bad("learned") })
	})
	g.addPins("ledger_committee_wrong", "ledger committee_root of period P replaced, block_root kept", func(pf *pinsFile) {
		setAnchor(pf, P, func(a *anchorFile) { a.CommitteeRoot = bad("committee") })
	})
	g.addPins("ledger_no_anchor_period", "period P has no entry although the ledger continues past it (a dummy P+1 entry)", func(pf *pinsFile) {
		var keep []anchorFile
		for _, a := range pf.Anchors {
			if a.Period != strconv.FormatUint(P, 10) {
				keep = append(keep, a)
			}
		}
		keep = append(keep, anchorFile{Period: strconv.FormatUint(P+1, 10), CommitteeRoot: bad("dummy"), WSPEpochs: strconv.Itoa(wspEpochs)})
		pf.Anchors = keep
	})
	g.addPins("ledger_behind", "the ledger ends at period P-1: the verifier is older than the proof", func(pf *pinsFile) {
		pf.Anchors = pf.Anchors[:len(pf.Anchors)-1]
	})
	g.addPins("ledger_no_block_root", "the entry of period P carries no block_root", func(pf *pinsFile) {
		setAnchor(pf, P, func(a *anchorFile) { a.BlockRoot = nil })
	})
	g.addPins("max_links_1", "max_links 1", func(pf *pinsFile) { pf.MaxLinks = 1 })

	// LC builders
	mk := func(kind uint8, period uint64, aroot [32]byte, body ethl1.LB, links []ethl1.LB, final []byte) ethl1.LC {
		return ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: kind, AnchorPeriod: period, AnchorRoot: aroot, AnchorBody: body, Links: links, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: final}}
	}
	gl := func(b []byte) ethl1.LB { return ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: b} }
	k1 := func(period uint64, links []ethl1.LB, final []byte) ethl1.LC {
		r := root(period)
		return mk(1, period, r, ethl1.LB{Layout: ethl1.LayoutNone, SSZ: comm[period]}, links, final)
	}
	k2 := func(bootstrap, final []byte) ethl1.LC {
		return mk(2, P, h32(bootRoot), gl(bootstrap), nil, final)
	}
	linkRange := func(from, to uint64) []ethl1.LB {
		var l []ethl1.LB
		for p := from; p <= to; p++ {
			l = append(l, gl(upd[p]))
		}
		return l
	}
	nParts := 506
	attSlot := get64(fu, offFUAttested+offHdrSlot)
	sigSlot := get64(fu, offFUSigSlot)
	bitsCount := func(b []byte) int {
		n := 0
		for _, x := range b {
			for ; x != 0; x &= x - 1 {
				n++
			}
		}
		return n
	}
	nParts = bitsCount(fu[offFUBits : offFUBits+64])
	finSlot := get64(fu, offFUFinalized+offHdrSlot)
	finHash := h32(capt.Exec)
	okFields := func(participants, crossed int) map[string]string {
		return map[string]string{"participants": strconv.Itoa(participants), "periods_crossed": strconv.Itoa(crossed), "slot": strconv.FormatUint(finSlot, 10), "exec_hash": hx(finHash[:])}
	}
	u64s := func(v uint64) string { return strconv.FormatUint(v, 10) }
	fuSigMut := func(f func(b []byte) []byte) []byte { return f(cp(fu)) }

	// ---- valid cases
	g.head("valid_k1_k0", "kind-1 committee anchor of the signing period, no links, live finality update", "main", k1(P, nil, fu), "", okFields(nParts, 0))
	g.head("valid_k2_k0", "kind-2 bootstrap anchor of a head-epoch checkpoint, no links, live finality update", "main", k2(boot, fu), "", okFields(nParts, 0))
	g.head("valid_k1_short", "kind-1 anchor two periods back, two Gloas links, live finality update", "main", k1(P-2, linkRange(P-2, P-1), fu), "", okFields(nParts, 2))
	g.head("valid_k1_chain", "kind-1 anchor at period 1379 (committee from the Fulu update), eleven Gloas links to the signing period", "main", k1(1379, linkRange(1379, P-1), fu), "", okFields(nParts, int(P-1379)))

	// ---- final update adversaries (kind 1, k = 0)
	bits := fu[offFUBits : offFUBits+64]
	g.head("adv_zero_participation", "all sync-committee bits cleared", "main", k1(P, nil, fuSigMut(func(b []byte) []byte { return splice(b, offFUBits, make([]byte, 64)) })),
		ethl1.CodeParticipationInsuff, map[string]string{"participants": "0", "required": "342", "committee": "512", "index": "0"})
	g.head("adv_participation_341", "341 of 512 bits set, the original 506-key signature", "main", k1(P, nil, splice(fu, offFUBits, clearBitsKeep(bits, 341))),
		ethl1.CodeParticipationInsuff, map[string]string{"participants": "341"})
	g.head("adv_342_bits_506_signature", "342 bits set but the signature of the 506-key aggregate", "main", k1(P, nil, splice(fu, offFUBits, clearBitsKeep(bits, 342))),
		ethl1.CodeSignatureInvalid, map[string]string{"participants": "342", "index": "0", "signature_slot": u64s(sigSlot), "fork_version": "0x90000076"})
	g.head("adv_flipped_signature_bit", "one bit of the signature flipped", "main", k1(P, nil, flip(fu, offFUSig+95)), ethl1.CodeSignatureInvalid, map[string]string{"participants": strconv.Itoa(nParts)})
	g.head("adv_attested_slot_plus_one", "attested slot + 1 (signature slot is attested + 1, so the order check fails)", "main", k1(P, nil, put64(fu, offFUAttested+offHdrSlot, attSlot+1)),
		ethl1.CodeLinkInvalid, map[string]string{"check": "slot_order", "index": "0", "attested_slot": u64s(attSlot + 1), "signature_slot": u64s(sigSlot)})
	g.head("adv_attested_state_root_altered", "attested state_root flipped: the finality branch no longer reaches it", "main", k1(P, nil, flip(fu, offFUAttested+offHdrState)),
		ethl1.CodeLinkInvalid, map[string]string{"check": "finality_branch"})
	g.head("adv_attested_slot_minus_one_signature_over_original", "attested slot - 1: the signed object changed, the signature is for the original", "main", k1(P, nil, put64(fu, offFUAttested+offHdrSlot, attSlot-1)),
		ethl1.CodeSignatureInvalid, nil)
	g.head("adv_fulu_version_at_gloas_slot", "pins carry the Fulu version for the Gloas fork: the domain is wrong", "fulu_version_at_gloas", k1(P, nil, fu), ethl1.CodeSignatureInvalid, map[string]string{"fork_version": "0x90000075"})
	g.head("adv_wrong_genesis_validators_root", "pins carry another genesis_validators_root", "wrong_gvr", k1(P, nil, fu), ethl1.CodeSignatureInvalid, nil)
	g.head("adv_forged_finality_branch_node", "one node of the finality branch flipped", "main", k1(P, nil, flip(fu, offFUFinBranch+5*32+3)), ethl1.CodeLinkInvalid, map[string]string{"check": "finality_branch"})
	g.head("adv_forged_finalized_exec_hash", "finalized execution_block_hash flipped", "main", k1(P, nil, flip(fu, offFUFinalized+offHdrExec)), ethl1.CodeLinkInvalid, map[string]string{"check": "finalized_header_exec_branch"})
	g.head("adv_forged_finalized_exec_branch_node", "one node of the finalized execution branch flipped", "main", k1(P, nil, flip(fu, offFUFinalized+offHdrBranch+4*32)), ethl1.CodeLinkInvalid, map[string]string{"check": "finalized_header_exec_branch"})
	g.head("adv_forged_attested_exec_hash", "attested execution_block_hash flipped", "main", k1(P, nil, flip(fu, offFUAttested+offHdrExec)), ethl1.CodeLinkInvalid, map[string]string{"check": "attested_header_exec_branch"})
	g.head("adv_finalized_slot_after_attested", "finalized header slot = attested slot + 1", "main", k1(P, nil, put64(fu, offFUFinalized+offHdrSlot, attSlot+1)), ethl1.CodeLinkInvalid, map[string]string{"check": "slot_order"})
	g.head("adv_signature_slot_equals_attested", "signature_slot = attested slot", "main", k1(P, nil, put64(fu, offFUSigSlot, attSlot)), ethl1.CodeLinkInvalid, map[string]string{"check": "slot_order"})
	g.head("adv_attested_slot_in_fulu_era", "gloas layout whose attested slot lies in the Fulu epochs", "main", k1(P, nil, put64(fu, offFUAttested+offHdrSlot, 11290000)),
		ethl1.CodeForkUnsupported, map[string]string{"slot": "11290000", "epoch": "352812", "layout": "gloas"})
	g.head("adv_final_update_truncated", "finality update one byte short", "main", mk(1, P, root(P), ethl1.LB{Layout: ethl1.LayoutNone, SSZ: comm[P]}, nil, fu[:len(fu)-1]),
		ethl1.CodeEvidenceMalformed, map[string]string{"part": "final_update", "reason": "length", "got_len": "1447", "want_len": "1448"})
	{
		lc := k1(P, nil, fu)
		lc.FinalUpdate.Layout = ethl1.LayoutNone
		g.head("adv_final_update_layout_byte_zero", "layout byte 0 on a finality update", "main", lc, ethl1.CodeEvidenceMalformed, map[string]string{"part": "final_update", "reason": "layout_byte_zero"})
		lc2 := k1(P, nil, fu)
		lc2.FinalUpdate.Layout = ethl1.LayoutElectra
		g.head("adv_gloas_bytes_under_electra_layout_byte", "the Gloas bytes under the electra layout byte cannot select another parse", "main", lc2, ethl1.CodeEvidenceMalformed, map[string]string{"part": "final_update", "reason": "length", "got_len": "1448", "want_len": "2056"})
		lc3 := k1(P, nil, fu)
		lc3.Profile = "eth-lc/2"
		g.head("adv_profile_unsupported", "profile eth-lc/2", "main", lc3, ethl1.CodeEvidenceMalformed, map[string]string{"part": "profile", "reason": "unsupported_profile"})
		lc4 := k1(P, nil, fu)
		lc4.AnchorBody.Layout = ethl1.LayoutGloas
		g.head("adv_anchor_body_layout_byte_not_zero", "kind-1 body with layout byte 2", "main", lc4, ethl1.CodeEvidenceMalformed, map[string]string{"part": "anchor_body", "reason": "layout_byte_not_zero"})
		lc5 := k1(P, nil, fu)
		lc5.AnchorBody.SSZ = comm[P][:committeeLen-1]
		g.head("adv_anchor_body_short", "kind-1 committee one byte short", "main", lc5, ethl1.CodeEvidenceMalformed, map[string]string{"part": "anchor_body", "reason": "length"})
		lc6 := k1(P, nil, fu)
		lc6.AnchorKind = 3
		g.head("adv_anchor_kind_unknown", "anchor kind 3", "main", lc6, ethl1.CodeEvidenceMalformed, map[string]string{"part": "anchor_kind"})
	}

	// ---- anchors and the ledger
	g.head("adv_anchor_root_disagrees_with_committee", "anchorRoot differs from the (correct) committee root", "main", mk(1, P, sum("anchor"), ethl1.LB{Layout: ethl1.LayoutNone, SSZ: comm[P]}, nil, fu),
		ethl1.CodePinMismatch, map[string]string{"period": u64s(P), "got_root": hx(func() []byte { r := sum("anchor"); return r[:] }())})
	g.head("adv_committee_body_not_ledger", "one public-key bit of the committee body flipped: its root is not the ledger root", "main", mk(1, P, root(P), ethl1.LB{Layout: ethl1.LayoutNone, SSZ: flip(comm[P], 7)}, nil, fu),
		ethl1.CodePinMismatch, map[string]string{"period": u64s(P)})
	g.head("adv_ledger_committee_wrong_k1", "ledger committee_root of the anchor period replaced", "ledger_committee_wrong", k1(P, nil, fu), ethl1.CodePinMismatch, map[string]string{"period": u64s(P)})
	g.head("adv_pin_unknown_period", "anchor period absent although the ledger continues past it", "ledger_no_anchor_period", k1(P, nil, fu), ethl1.CodePinUnknown, map[string]string{"kind": "1", "period": u64s(P)})
	g.head("adv_ledger_behind", "anchor period beyond the ledger's head", "ledger_behind", k1(P, nil, fu), ethl1.CodeLedgerBehind, map[string]string{"needed_period": u64s(P), "ledger_head_period": u64s(P - 1)})
	g.head("adv_too_many_links", "two links against max_links 1", "max_links_1", k1(P-2, linkRange(P-2, P-1), fu), ethl1.CodeEvidenceTooLarge, map[string]string{"part": "links", "count": "2", "limit": "1"})

	// ---- links (anchor two periods back)
	short := func(links []ethl1.LB) ethl1.LC { return k1(P-2, links, fu) }
	g.head("adv_period_skip_first_link_missing", "link of period P-2 dropped: the first link is signed in the next period", "main", short(linkRange(P-1, P-1)),
		ethl1.CodeLinkInvalid, map[string]string{"check": "period_skip", "index": "0"})
	g.head("adv_period_gap_final", "both links dropped: the final update is two periods ahead", "main", short(nil),
		ethl1.CodePeriodGap, map[string]string{"signature_period": u64s(P), "store_period": u64s(P - 2)})
	g.head("adv_links_out_of_order", "links in descending period order", "main", short([]ethl1.LB{gl(upd[P-1]), gl(upd[P-2])}),
		ethl1.CodeLinkInvalid, map[string]string{"check": "period_skip", "index": "0"})
	g.head("adv_link_repeated", "the first link repeated: the second applies nothing", "main", short([]ethl1.LB{gl(upd[P-2]), gl(upd[P-2]), gl(upd[P-1])}),
		ethl1.CodeLinkInvalid, map[string]string{"check": "not_applied", "index": "1"})
	g.head("adv_link_next_committee_branch_forged", "one node of link 0's next_sync_committee_branch flipped", "main", short([]ethl1.LB{gl(flip(upd[P-2], offUNextBranch+2*32)), gl(upd[P-1])}),
		ethl1.CodeLinkInvalid, map[string]string{"check": "next_committee_branch", "index": "0"})
	g.head("adv_link_next_committee_forged", "one public-key bit of link 0's next_sync_committee flipped", "main", short([]ethl1.LB{gl(flip(upd[P-2], offUNext+11)), gl(upd[P-1])}),
		ethl1.CodeLinkInvalid, map[string]string{"check": "next_committee_branch", "index": "0"})
	g.head("adv_link_signature_flipped", "link 0 signature bit flipped", "main", short([]ethl1.LB{gl(flip(upd[P-2], offUSig+95)), gl(upd[P-1])}),
		ethl1.CodeSignatureInvalid, map[string]string{"index": "0"})
	g.head("adv_link_participation_341", "link 0 with 341 bits", "main", short([]ethl1.LB{gl(splice(upd[P-2], offUBits, clearBitsKeep(upd[P-2][offUBits:offUBits+64], 341))), gl(upd[P-1])}),
		ethl1.CodeParticipationInsuff, map[string]string{"index": "0", "participants": "341"})
	g.head("adv_link_finality_branch_forged", "link 1 finality branch node flipped", "main", short([]ethl1.LB{gl(upd[P-2]), gl(flip(upd[P-1], offUFinBranch+32))}),
		ethl1.CodeLinkInvalid, map[string]string{"check": "finality_branch", "index": "1"})
	g.head("adv_learned_committee_not_ledger", "link 0 learns the committee of period P-1 but the ledger holds another root for it", "ledger_learned_wrong", short(linkRange(P-2, P-1)),
		ethl1.CodePinMismatch, map[string]string{"period": u64s(P - 1)})
	g.head("adv_window_exceeded", "weak-subjectivity window of 1 epoch against a link finalizing hundreds of epochs after the anchor", "wsp_1", short(linkRange(P-2, P-1)),
		ethl1.CodePinWindow, map[string]string{"wsp_epochs": "1"})

	// ---- the real Fulu update: v1 recognised the electra layout and refused it by name; v2 judges it (see the electra cases)
	if !v2 {
		fuluAtt := get64(fulu, 25216)
		lc := k1(P-2, []ethl1.LB{{Layout: ethl1.LayoutElectra, SSZ: fulu}}, fu)
		g.head("electra_link_real_fulu_update", "the real period-1378 Fulu update (electra layout) as a link", "main", lc, ethl1.CodeForkUnsupported,
			map[string]string{"slot": u64s(fuluAtt), "epoch": u64s(fuluAtt / 32), "layout": "electra"})
	}

	// ---- bootstrap (kind 2)
	bootSlot := get64(boot, offHdrSlot)
	g.head("adv_bootstrap_header_not_pin", "bootstrap parent_root flipped: the header root is not the pinned block_root (the execution branch still holds)", "main", k2(flip(boot, offHdrParent), fu),
		ethl1.CodePinMismatch, map[string]string{"period": u64s(P)})
	g.head("adv_bootstrap_committee_branch_forged", "one node of current_sync_committee_branch flipped", "main", k2(flip(boot, offBootBranch+3*32), fu),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "committee_branch", "slot": u64s(bootSlot)})
	g.head("adv_bootstrap_committee_swapped", "one public-key bit of the bootstrap committee flipped", "main", k2(flip(boot, offBootCommit+9), fu),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "committee_branch"})
	g.head("adv_bootstrap_exec_branch_forged", "one node of the bootstrap header's execution branch flipped", "main", k2(flip(boot, offHdrBranch+2*32), fu),
		ethl1.CodeBootstrapInvalid, map[string]string{"check": "header_exec_branch", "slot": u64s(bootSlot)})
	{
		lc := k2(boot, fu)
		lc.AnchorRoot = sum("bootanchor")
		g.head("adv_bootstrap_anchor_root_not_pin", "anchorRoot differs from the ledger block_root", "main", lc, ethl1.CodePinMismatch, map[string]string{"period": u64s(P)})
	}
	g.head("adv_bootstrap_committee_not_ledger", "bootstrap is genuine but the ledger's committee_root for the period differs", "ledger_committee_wrong", k2(boot, fu),
		ethl1.CodePinMismatch, map[string]string{"period": u64s(P)})
	g.head("adv_bootstrap_ledger_has_no_block_root", "kind-2 anchor against a ledger entry without a block_root", "ledger_no_block_root", k2(boot, fu), ethl1.CodePinUnknown, map[string]string{"kind": "2", "period": u64s(P)})
	{
		lc := k2(boot, fu)
		lc.AnchorBody.Layout = ethl1.LayoutNone
		g.head("adv_bootstrap_layout_byte_zero", "layout byte 0 on a bootstrap", "main", lc, ethl1.CodeEvidenceMalformed, map[string]string{"part": "anchor_body", "reason": "layout_byte_zero"})
	}
	g.head("adv_bootstrap_wrong_period_label", "kind-2 anchor labelled with the previous period (ledger entry of P-1 has no block_root)", "main",
		mk(2, P-1, h32(bootRoot), gl(boot), nil, fu), ethl1.CodePinUnknown, map[string]string{"kind": "2", "period": u64s(P - 1)})

	// ---- spine
	topHash := h32(capt.Exec)
	nTop := rlpNumber(spine[0])
	g.covers("spine_valid_20", "20 live headers from the finalized head", topHash, spine, 16384, nil, "", nil)
	nb := nTop - 5
	g.covers("spine_valid_block_lookup", "lookup of the header 5 below the head", topHash, spine, 16384, &nb, "", nil)
	{
		over := nTop + 1
		g.covers("spine_block_above_head", "block one above the finalized head is not covered", topHash, spine, 16384, &over, ethl1.CodeBlockNotCovered, map[string]string{"block_number": u64s(over), "finalized_exec_number": u64s(nTop)})
		under := nTop - uint64(len(spine))
		g.covers("spine_block_below_spine", "block below the spine's last header is not covered", topHash, spine, 16384, &under, ethl1.CodeBlockNotCovered, nil)
	}
	g.covers("spine_prefix_3", "three headers only", topHash, spine[:3], 16384, nil, "", nil)
	{
		bad := make([][]byte, len(spine))
		copy(bad, spine)
		bad[7] = flip(spine[7], len(spine[7])-1)
		g.covers("adv_spine_forged_link", "header 7 altered (last byte): header 6's parentHash no longer matches", topHash, bad, 16384, nil, ethl1.CodeHeaderChainBroken,
			map[string]string{"reason": "hash", "spine": "l1", "at_number": u64s(nTop - 7)})
		trunc := make([][]byte, len(spine))
		copy(trunc, spine)
		trunc[3] = spine[3][:len(spine[3])-1]
		g.covers("adv_spine_header_not_rlp", "header 3 truncated by one byte", topHash, trunc, 16384, nil, ethl1.CodeHeaderChainBroken, map[string]string{"reason": "rlp"})
		g.covers("adv_spine_head_hash_mismatch", "finalized exec hash flipped", func() [32]byte { h := topHash; h[0] ^= 1; return h }(), spine, 16384, nil, ethl1.CodeHeaderChainBroken,
			map[string]string{"reason": "hash", "at_number": u64s(nTop)})
		g.covers("adv_spine_too_long", "20 headers against max 19", topHash, spine, 19, nil, ethl1.CodeEvidenceTooLarge, map[string]string{"part": "spine", "count": "20", "limit": "19"})
		g.covers("adv_spine_empty", "no headers", topHash, nil, 16384, nil, ethl1.CodeEvidenceMalformed, map[string]string{"part": "spine", "reason": "empty"})
		// number mismatch: the head header gets a wrong number and its own hash becomes the head hash
		mut := rlpSetItem(spine[0], 8, rlpUintItem(nTop+5))
		mutHash := keccakB(mut)
		spine2 := append([][]byte{mut}, spine[1:]...)
		g.covers("adv_spine_number_mismatch", "head header's number raised by 5 (its hash is the stated head): header 1's number is no longer number-1", mutHash, spine2, 16384, nil, ethl1.CodeHeaderChainBroken,
			map[string]string{"reason": "number", "at_number": u64s(nTop + 4)})
		// unknown trailing items: still hash and still read
		ext := rlpAppendItems(spine[0], []byte{0x01}, bytes.Repeat([]byte{0xaa}, 32))
		extHash := keccakB(ext)
		spine3 := append([][]byte{ext}, spine[1:]...)
		g.covers("spine_head_with_unknown_trailing_items", "head header with two unknown trailing RLP items: hashed as given and read positionally", extHash, spine3, 16384, nil, "", nil)
	}

	g.synthetic()
	if v2 {
		if err := g.v2extras(v2in{raw2Dir: raw2Dir, comm: comm, upd: upd, fu: fu, boot: boot, P: P, bootRoot: bootRoot, mk: mk, gl: gl, k1: k1, k2: k2, linkRange: linkRange, okFields: okFields, nParts: nParts}); err != nil {
			return err
		}
	}
	return g.flush()
}

func (g *gen) flush() error {
	var paths []string
	for p := range g.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		full := filepath.Join(g.out, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, g.files[p], 0o644); err != nil {
			return err
		}
	}
	// manifest over every file of the set, raw capture included
	type mf struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	}
	var files []mf
	err := filepath.Walk(g.out, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(g.out, path)
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || rel == "MANIFEST.sha256" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := sha256.Sum256(b)
		files = append(files, mf{rel, hex.EncodeToString(s[:]), len(b)})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Strings(g.cases)
	m := canonJSON(map[string]any{"format": formatManifest, "set": setName, "cases": g.cases, "files": files})
	if err := os.WriteFile(filepath.Join(g.out, "manifest.json"), m, 0o644); err != nil {
		return err
	}
	ms := sha256.Sum256(m)
	return os.WriteFile(filepath.Join(g.out, "MANIFEST.sha256"), []byte(hex.EncodeToString(ms[:])+"  manifest.json\n"), 0o644)
}

// ---- small RLP and SSZ helpers (generator side)

func sszCommitteeRoot(b []byte) [32]byte {
	r, err := ethl1.HashTreeRootSyncCommittee(b)
	if err != nil {
		panic(err)
	}
	return r
}

func keccakB(b []byte) [32]byte { var out [32]byte; copy(out[:], keccak(b)); return out }

func rlpItems(raw []byte) []rlp.RawValue {
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil {
		panic(err)
	}
	return items
}

func rlpNumber(raw []byte) uint64 {
	items := rlpItems(raw)
	var s []byte
	if err := rlp.DecodeBytes(items[8], &s); err != nil {
		panic(err)
	}
	var v uint64
	for _, x := range s {
		v = v<<8 | uint64(x)
	}
	return v
}

func rlpUintItem(v uint64) rlp.RawValue {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return b
}

func rlpSetItem(raw []byte, idx int, item rlp.RawValue) []byte {
	items := rlpItems(raw)
	items[idx] = item
	b, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return b
}

func rlpAppendItems(raw []byte, extra ...[]byte) []byte {
	items := rlpItems(raw)
	for _, e := range extra {
		b, err := rlp.EncodeToBytes(e)
		if err != nil {
			panic(err)
		}
		items = append(items, b)
	}
	b, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return b
}
