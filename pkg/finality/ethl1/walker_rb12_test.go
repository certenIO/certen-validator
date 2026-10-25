// Copyright 2026 Certen Protocol

package ethl1

import (
	"crypto/sha256"
	"encoding/binary"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/bits"
	"testing"
)

func TestHeaderValidJudgesTheForkAndTheExecutionBranch(t *testing.T) {
	mk := func(layout Layout) *walker {
		p := Pins{Network: Network{Forks: []Fork{{Name: "f", Epoch: 10, Layout: layout}}}}
		return newWalker(p, specRules{}, mainnetPreset())
	}
	slotOf := func(epoch uint64) uint64 { return epoch * 32 }
	var branch [][32]byte
	for i := 0; i < 11; i++ {
		branch = append(branch, [32]byte{byte(i + 1)})
	}
	execHash := [32]byte{0xe1, 0xe2}
	gloas := lcHeader{Shape: LayoutGloas, ExecHash: execHash, Branch: branch}
	gloas.Beacon.Slot = slotOf(11)
	gloas.Beacon.BodyRoot = RootFromNormalizedBranch(execHash, branch, gindexExecHashGloas)
	deneb := lcHeader{Shape: LayoutGloas, ExecHash: execHash, Branch: branch[:9]}
	deneb.Beacon.Slot = slotOf(11)
	deneb.Beacon.BodyRoot = RootFromNormalizedBranch(execHash, branch[:9], gindexExecHashDeneb)
	exec := tExec([]byte{1, 2, 3})
	eBranch := branch[:4]
	electra := lcHeader{Shape: LayoutElectra, Exec: exec, Branch: eBranch}
	electra.Beacon.Slot = slotOf(11)
	electra.Beacon.BodyRoot = RootFromNormalizedBranch(executionHeaderRoot(exec), eBranch, gindexExecPayloadInBody)

	check := func(name string, w *walker, h lcHeader, wantOK, wantFault bool) {
		t.Helper()
		ok, f := w.headerValid(h)
		if ok != wantOK || (f != nil) != wantFault {
			t.Fatalf("%s: ok=%v fault=%v, want ok=%v fault=%v", name, ok, f, wantOK, wantFault)
		}
		if f != nil && (f.Code != CodeForkUnsupported || f.Fields["slot"] != h.Beacon.Slot) {
			t.Fatalf("%s: %s", name, f.CanonicalJSON())
		}
	}
	check("gloas header in a gloas fork", mk(LayoutGloas), gloas, true, false)
	check("deneb-era branch in an electra fork", mk(LayoutElectra), deneb, true, false)
	check("gloas gindex against the electra fork's branch", mk(LayoutElectra), gloas, false, false)
	check("electra header in an electra fork", mk(LayoutElectra), electra, true, false)
	check("electra header in a gloas fork", mk(LayoutGloas), electra, false, true)
	check("gloas shaped header in a layoutless fork", mk(LayoutNone), gloas, false, true)
	check("electra shaped header in a layoutless fork", mk(LayoutNone), electra, false, true)
	early := gloas
	early.Beacon.Slot = slotOf(9)
	check("slot before the first fork", mk(LayoutGloas), early, false, true)
	earlyE := electra
	earlyE.Beacon.Slot = slotOf(9)
	check("electra slot before the first fork", mk(LayoutElectra), earlyE, false, true)
	bad := gloas
	bad.Beacon.BodyRoot[0] ^= 1
	check("forged body root", mk(LayoutGloas), bad, false, false)
	badE := electra
	badE.Exec = append([]byte(nil), exec...)
	badE.Exec[0] ^= 1
	check("forged electra execution field", mk(LayoutElectra), badE, false, false)
}

func TestVerifyBootstrapAnchorRefusesAPeriodLabelThatIsNotTheHeadersPeriod(t *testing.T) {
	p, lc := v2Case(t, "valid_k2_k0")
	var real Anchor
	for _, a := range p.Anchors {
		if a.Period == lc.AnchorPeriod {
			real = a
		}
	}
	other := real
	other.Period = lc.AnchorPeriod + 1
	p.Anchors = append(p.Anchors, other)
	err := VerifyBootstrapAnchor(p, other.Period, lc.AnchorBody)
	f, ok := err.(*Fault)
	if !ok || f.Code != CodeBootstrapInvalid || f.Fields["check"] != "anchor_period" {
		t.Fatalf("period label one above the header's period: %v", err)
	}
	if f.Fields["slot"] == uint64(0) {
		t.Fatalf("the fault must carry the header slot: %s", f.CanonicalJSON())
	}
}

// clearBitsTo clears set bits of a 64-byte participation bitmap from the end until exactly n remain.
func clearBitsTo(b []byte, n int) {
	count := 0
	for _, x := range b {
		count += bits.OnesCount8(x)
	}
	for i := len(b)*8 - 1; i >= 0 && count > n; i-- {
		if b[i/8]>>(uint(i)%8)&1 == 1 {
			b[i/8] &^= 1 << (uint(i) % 8)
			count--
		}
	}
}

func TestParticipationFloorIsTwoThirdsAndTheMinParticipantsPin(t *testing.T) {
	p, lc := v2Case(t, "valid_k2_k0")
	head, err := VerifyFinalizedHead(p, lc)
	if err != nil {
		t.Fatal(err)
	}
	n := head.Participants
	if n < 345 || lc.FinalUpdate.Layout != LayoutGloas || len(lc.FinalUpdate.SSZ) != LightClientFinalityUpdateSize {
		t.Fatalf("the case must be a Gloas final update with at least 345 participants: n=%d layout=%v len=%d", n, lc.FinalUpdate.Layout, len(lc.FinalUpdate.SSZ))
	}
	p.MinParticipants = n
	if _, err := VerifyFinalizedHead(p, lc); err != nil {
		t.Fatalf("min_participants equal to the participation: %v", err)
	}
	p.MinParticipants = n + 1
	if _, err := VerifyFinalizedHead(p, lc); asFault(t, err).Code != CodeParticipationInsuff {
		t.Fatalf("min_participants one above the participation: %v", err)
	}
	p.MinParticipants = 1
	const bitsAt = 2*LightClientHeaderSize + 32*gloasFinalityBranchLen
	for _, c := range []struct {
		keep int
		code string
	}{{300, CodeParticipationInsuff}, {341, CodeParticipationInsuff}, {342, CodeSignatureInvalid}, {400, CodeSignatureInvalid}} {
		cut := lc
		cut.FinalUpdate.SSZ = append([]byte(nil), lc.FinalUpdate.SSZ...)
		clearBitsTo(cut.FinalUpdate.SSZ[bitsAt:bitsAt+SyncCommitteeSize/8], c.keep)
		_, err := VerifyFinalizedHead(p, cut)
		f := asFault(t, err)
		if f.Code != c.code {
			t.Fatalf("%d participants: %s, want %s", c.keep, f.CanonicalJSON(), c.code)
		}
		if c.code == CodeParticipationInsuff && (f.Fields["participants"] != c.keep || f.Fields["required"] != 342 || f.Fields["committee"] != 512) {
			t.Fatalf("%d participants: %s", c.keep, f.CanonicalJSON())
		}
	}
}

func TestLCHeaderIsEmptyIgnoresOnlyTheExtraDataOffset(t *testing.T) {
	e := make([]byte, 584)
	binary.LittleEndian.PutUint32(e[436:], 584)
	h := lcHeader{Shape: LayoutElectra, Exec: e}
	if !h.isEmpty() {
		t.Fatal("the genuine empty electra header must be empty")
	}
	for _, at := range []int{0, 435, 440, 441, 583} {
		m := append([]byte(nil), e...)
		m[at] = 1
		if (lcHeader{Shape: LayoutElectra, Exec: m}).isEmpty() {
			t.Fatalf("a non-zero byte at %d is not an empty header", at)
		}
	}
	for at := 436; at < 440; at++ {
		m := append([]byte(nil), e...)
		m[at] = 0xff
		if !(lcHeader{Shape: LayoutElectra, Exec: m}).isEmpty() {
			t.Fatalf("offset byte %d is not part of the comparison", at)
		}
	}
	if (lcHeader{Shape: LayoutElectra, Exec: e[:583]}).isEmpty() {
		t.Fatal("a short execution header is not empty")
	}
}

func TestSyncCommitteeRootIsTheSSZRootOfItsKeysAndAggregate(t *testing.T) {
	raw := make([]byte, SyncCommitteeBytes)
	for i := range raw {
		raw[i] = byte(i*7 + i/48 + 3)
	}
	keyRoot := func(pk []byte) [32]byte {
		var a, b [32]byte
		copy(a[:], pk[0:32])
		copy(b[:], pk[32:48])
		return tSha(a, b)
	}
	leaves := make([][32]byte, 512)
	for i := range leaves {
		leaves[i] = keyRoot(raw[i*48 : i*48+48])
	}
	want := tSha(tMerkle(leaves), keyRoot(raw[512*48:512*48+48]))
	got, err := HashTreeRootSyncCommittee(raw)
	if err != nil || got != want {
		t.Fatalf("sync committee root %x %v, want %x", got, err, want)
	}
	if hashTreeRootSyncCommitteeN(raw, 512) != want {
		t.Fatal("the sized variant must agree for 512 seats")
	}
	_ = sha256.Size
}

func TestKind1AnchorJudgesTheCommitteeBodyAgainstThePin(t *testing.T) {
	p, lc := v2Case(t, "valid_k1_short")
	if lc.AnchorKind != 1 {
		t.Fatalf("the case must be a kind-1 anchor, got %d", lc.AnchorKind)
	}
	body := append([]byte(nil), lc.AnchorBody.SSZ...)
	body[0] ^= 0x01 // the committee the evidence carries is not the one the root names
	lc.AnchorBody.SSZ = body
	f := asFault(t, func() error { _, err := VerifyFinalizedHead(p, lc); return err }())
	if f.Code != CodePinMismatch || f.Fields["period"] != lc.AnchorPeriod {
		t.Fatalf("a committee that does not hash to the pinned root: %s", f.CanonicalJSON())
	}
	wantRoot, err := HashTreeRootSyncCommittee(body)
	if err != nil || f.Fields["got_root"] != wantRoot {
		t.Fatalf("the fault must carry the hash of the committee that was presented: %s", f.CanonicalJSON())
	}
}

func TestLinkBlobLayoutByteAndLengthAreJudgedBeforeDecoding(t *testing.T) {
	p, lc := v2Case(t, "valid_k1_short")
	for _, layout := range []Layout{LayoutNone, Layout(7)} {
		bad := lc
		bad.Links = []LB{{Layout: layout, SSZ: lc.Links[0].SSZ}}
		f := asFault(t, func() error { _, err := VerifyFinalizedHead(p, bad); return err }())
		if f.Code != CodeEvidenceMalformed || f.Fields["part"] != "link" || f.Fields["index"] != 0 || f.Fields["reason"] == "length" {
			t.Fatalf("layout byte %d on a link: %s", layout, f.CanonicalJSON())
		}
	}
	for _, delta := range []int{-1, 1} {
		bad := lc
		ssz := append([]byte(nil), lc.Links[0].SSZ...)
		if delta < 0 {
			ssz = ssz[:len(ssz)-1]
		} else {
			ssz = append(ssz, 0)
		}
		bad.Links = []LB{{Layout: lc.Links[0].Layout, SSZ: ssz}}
		f := asFault(t, func() error { _, err := VerifyFinalizedHead(p, bad); return err }())
		if f.Code != CodeEvidenceMalformed || f.Fields["part"] != "link" || f.Fields["reason"] != "length" || f.Fields["got_len"] != len(ssz) || f.Fields["want_len"] != LightClientUpdateSize {
			t.Fatalf("a link of %d bytes: %s", len(ssz), f.CanonicalJSON())
		}
	}
}

// synthWorld is a walker whose sync committee has a key the test controls (every seat holds sk*G1 with sk = 1), so a final update
// built here carries a genuine aggregate signature and every check of walker.update can be reached and judged by its verdict.
type synthWorld struct {
	t       *testing.T
	w       *walker
	zh      [12][32]byte
	version [4]byte
	gvr     [32]byte
	period  uint64
	finSlot uint64
}

func newSynthWorld(t *testing.T) *synthWorld {
	_, _, g1, _ := bls12381.Generators()
	cmt := committeeOf(g1.Bytes())
	s := &synthWorld{t: t, version: [4]byte{1, 2, 3, 4}, gvr: [32]byte{0x77}, period: 5}
	for k := 1; k < len(s.zh); k++ {
		s.zh[k] = tSha(s.zh[k-1], s.zh[k-1])
	}
	s.finSlot = s.period * 256 * 32
	p := Pins{MinParticipants: 342, Network: Network{ChainID: SepoliaChainID, GenesisValidatorsRoot: s.gvr, Forks: []Fork{{Name: "g", Epoch: 0, Version: s.version, Layout: LayoutGloas}}},
		Anchors: []Anchor{{Period: s.period, CommitteeRoot: cmt.root, WSPEpochs: 100}}}
	s.w = newWalker(p, specRules{}, mainnetPreset())
	s.w.anchor = p.Anchors[0]
	s.w.gvr = s.gvr
	s.w.s = walkStore{finSlot: s.finSlot, cur: cmt, curPeriod: s.period}
	return s
}

func (s *synthWorld) hdr(slot uint64, state [32]byte) lcHeader {
	exec := [32]byte{0xee, byte(slot), byte(slot >> 8)}
	var branch [][32]byte
	for i := 0; i < 11; i++ {
		branch = append(branch, [32]byte{byte(i + 1), 0x5a})
	}
	h := lcHeader{Shape: LayoutGloas, ExecHash: exec, Branch: branch}
	h.Beacon.Slot, h.Beacon.StateRoot = slot, state
	h.Beacon.BodyRoot = RootFromNormalizedBranch(exec, branch, gindexExecHashGloas)
	return h
}

func (s *synthWorld) update(as, fs, ss uint64) updateObj {
	fin := lcHeader{Shape: LayoutGloas, Branch: make([][32]byte, 11)}
	var finRoot [32]byte
	if fs != 0 {
		fin = s.hdr(fs, [32]byte{0xf1})
		finRoot = hashTreeRootBeaconHeader(fin.Beacon)
	}
	fb := append([][32]byte(nil), s.zh[:9]...)
	att := s.hdr(as, RootFromNormalizedBranch(finRoot, fb, gindexFinalizedRootGloas))
	const n = 400
	bitsB := make([]byte, SyncCommitteeSize/8)
	for i := 0; i < n; i++ {
		bitsB[i/8] |= 1 << (uint(i) % 8)
	}
	msg := signingRoot(hashTreeRootBeaconHeader(att.Beacon), computeDomain(s.version, s.gvr))
	return updateObj{Shape: LayoutGloas, Attested: att, Finalized: fin, FinalityBranch: fb, NextBranch: make([][32]byte, 11),
		Aggregate: syncAggregate{Bits: bitsB, Signature: signAll(s.t, 1, msg, n)}, SignatureSlot: ss}
}

func (s *synthWorld) expect(name string, f *Fault, code, check string) {
	s.t.Helper()
	if code == "" {
		if f != nil {
			s.t.Fatalf("%s: %s", name, f.CanonicalJSON())
		}
		return
	}
	if f == nil || f.Code != code || (check != "" && f.Fields["check"] != check) {
		s.t.Fatalf("%s: got %v, want %s %s", name, f, code, check)
	}
}

func TestWalkerUpdateJudgesSlotsRelevanceLedgerWindowAndKind(t *testing.T) {
	as := uint64(5*256*32 + 100)
	{
		s := newSynthWorld(t)
		u := s.update(as, as-50, as+1)
		s.expect("a genuine final update", s.w.update(0, &u, true), "", "")
	}
	{
		s := newSynthWorld(t)
		u := s.update(as, as, as+1)
		s.expect("attested slot equal to the finalized slot", s.w.update(0, &u, true), "", "")
	}
	{
		s := newSynthWorld(t)
		u := s.update(s.finSlot, s.finSlot-5, s.finSlot+1)
		s.expect("attested slot equal to the store's finalized slot", s.w.update(0, &u, true), CodeLinkInvalid, "not_relevant")
		u = s.update(s.finSlot-1, s.finSlot-5, s.finSlot)
		s.expect("attested slot below the store's finalized slot", s.w.update(0, &u, true), CodeLinkInvalid, "not_relevant")
	}
	{
		s := newSynthWorld(t)
		s.w.p.Anchors = []Anchor{{Period: s.period, CommitteeRoot: [32]byte{0xde, 0xad}, WSPEpochs: 100}}
		u := s.update(as, as-50, as+1)
		f := s.w.update(0, &u, true)
		s.expect("a final update signed by a committee the ledger does not pin", f, CodePinMismatch, "")
		if f.Fields["period"] != s.period {
			t.Fatalf("pin_mismatch: %s", f.CanonicalJSON())
		}
	}
	for _, c := range []struct {
		name string
		dist uint64 // epochs between the signature period's start and the finalized epoch
		wsp  uint64
		code string
	}{{"window exactly the pin", 50, 50, ""}, {"one epoch beyond the pin", 51, 50, CodePinWindow}, {"inside the pin", 49, 50, ""}} {
		s := newSynthWorld(t)
		s.w.anchor.WSPEpochs = c.wsp
		fs := (s.period*256 + c.dist) * 32
		u := s.update(fs+10, fs, fs+11)
		f := s.w.update(0, &u, true)
		s.expect(c.name, f, c.code, "")
		if c.code != "" && (f.Fields["finalized_epoch"] != s.period*256+c.dist || f.Fields["anchor_epoch"] != s.period*256 || f.Fields["wsp_epochs"] != c.wsp) {
			t.Fatalf("%s: %s", c.name, f.CanonicalJSON())
		}
	}
	{
		s := newSynthWorld(t)
		s.w.p.Network.Forks = []Fork{{Name: "late", Epoch: 1 << 30, Layout: LayoutGloas}}
		u := s.update(as, as-50, as+1)
		s.expect("no fork for the attested slot", s.w.update(0, &u, true), CodeForkUnsupported, "")
	}
	{
		s := newSynthWorld(t)
		u := s.update(as, as-50, as+1)
		s.expect("a non-final update without a next committee", s.w.update(0, &u, false), CodeLinkInvalid, "not_sync_committee_update")
		u = s.update(as, 0, as+1)
		u.Finalized.ExecHash = [32]byte{1}
		s.expect("finalized slot 0 with a non-empty finalized header", s.w.update(0, &u, false), CodeLinkInvalid, "finality_branch")
	}
}
