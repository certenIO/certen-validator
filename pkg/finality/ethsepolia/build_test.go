// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const vectorDir2 = "testdata/finality_eth_sepolia2"

func readIn(t testing.TB, dir, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evidenceIn(t testing.TB, dir string, c vecCase) []byte {
	t.Helper()
	out := append([]byte(nil), readIn(t, dir, c.Base)...)
	ps := append([]vecPatch(nil), c.Patches...)
	for i := range ps { // highest offset first
		for j := i + 1; j < len(ps); j++ {
			if ps[j].At > ps[i].At {
				ps[i], ps[j] = ps[j], ps[i]
			}
		}
	}
	for _, p := range ps {
		out = append(append(append([]byte(nil), out[:p.At]...), unhexVec(t, p.Ins)...), out[p.At+p.Del:]...)
	}
	return out
}

// Every verification case of finality_eth_sepolia2 is judged under the set's pins (the embedded pins file) and must produce the
// canonical verdict the generator wrote; the valid ones also verify under the pins embedded in this very binary.
func TestPublishedVectorsFinalityEthSepolia2(t *testing.T) {
	raw := readIn(t, vectorDir2, "MANIFEST.json")
	sum := sha256.Sum256(raw)
	if got := strings.TrimSpace(string(readIn(t, vectorDir2, "MANIFEST.json.sha256"))); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json.sha256 %s, manifest hashes to %x", got, sum)
	}
	var m struct {
		Set   string            `json:"set"`
		Files map[string]string `json:"files"`
		Cases []string          `json:"cases"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Set != "finality_eth_sepolia2" {
		t.Fatalf("manifest %v set %q", err, m.Set)
	}
	for p, want := range m.Files {
		s := sha256.Sum256(readIn(t, vectorDir2, p))
		if hex.EncodeToString(s[:]) != want {
			t.Errorf("%s: sha256 %x, manifest %s", p, s, want)
		}
	}
	if len(m.Cases) != 9 {
		t.Fatalf("%d cases", len(m.Cases))
	}
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range m.Cases {
		var c vecCase
		if err := json.Unmarshal(readIn(t, vectorDir2, "cases/"+id+".json"), &c); err != nil {
			t.Fatal(err)
		}
		pins, err := finality.ParsePinsOverride(readIn(t, vectorDir2, c.Pins))
		if err != nil {
			t.Fatalf("%s: pins: %v", id, err)
		}
		ref, ev := refOf(t, c.Leg), evidenceIn(t, vectorDir2, c)
		v, verr := New().Verify(pins, ref, ev)
		if got := verdictCanon(v, verr); got != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", id, got, c.Expect)
		}
		if strings.HasPrefix(id, "valid_") {
			ve, eerr := New().Verify(embedded, ref, ev)
			if got := verdictCanon(ve, eerr); got != c.Expect {
				t.Errorf("%s under the embedded pins:\n got  %s\n want %s", id, got, c.Expect)
			}
		}
	}
}

// ---- the builder, offline ----

// replay serves the recorded answers of finality_eth_sepolia2: one finality update and the best update of every period 1378..1390.
type replay struct {
	final []byte
	links map[uint64][]byte // links[q]: the best update of period q-1 (links[1378]: the root bootstrap)
	calls []string
}

func (r *replay) Name() string { return "replay" }
func (r *replay) FinalityUpdate(context.Context) ([]byte, error) {
	r.calls = append(r.calls, "finality_update")
	return r.final, nil
}
func (r *replay) HeadSlot(context.Context) (uint64, error) { return 1, nil }
func (r *replay) Bootstrap(context.Context, [32]byte) ([]byte, error) {
	r.calls = append(r.calls, "bootstrap")
	return r.links[1378], nil
}
func (r *replay) Updates(_ context.Context, start uint64, count int) ([][]byte, error) {
	r.calls = append(r.calls, fmt.Sprintf("updates:%d:%d", start, count))
	var out [][]byte
	for i := 0; i < count; i++ {
		u, ok := r.links[start+uint64(i)+1]
		if !ok {
			return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "replay", Op: "updates", Reason: "no such period"}}}
		}
		out = append(out, u)
	}
	return out, nil
}

type headers struct {
	byHash map[[32]byte][]byte
	byNum  map[uint64][]byte
}

func (h headers) HeaderByHash(_ context.Context, x [32]byte) ([]byte, error) {
	if b, ok := h.byHash[x]; ok {
		return b, nil
	}
	return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "replay", Op: "headers", Reason: "unknown hash"}}}
}

func (h headers) HeadersByNumber(_ context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; n <= to; n++ {
		b, ok := h.byNum[n]
		if !ok {
			return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "replay", Op: "headers", Reason: "unknown number"}}}
		}
		out = append(out, b)
	}
	return out, nil
}

type recordedLeg struct {
	ref    finality.BlockRef
	ev     []byte
	body   Body
	source *replay
	hdrs   headers
}

func loadRecorded(t testing.TB, id string) recordedLeg {
	t.Helper()
	var lj vecLeg
	if err := json.Unmarshal(readIn(t, vectorDir2, "raw/"+id+"/leg.json"), &lj); err != nil {
		t.Fatal(err)
	}
	ev := readIn(t, vectorDir2, "raw/"+id+"/evidence.bin")
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384)
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64][]byte{}
	ents, err := os.ReadDir(filepath.Join(vectorDir2, "raw", "links"))
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range ents {
		p, _ := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		links[p] = readIn(t, vectorDir2, "raw/links/"+en.Name())
	}
	h := headers{byHash: map[[32]byte][]byte{}, byNum: map[uint64][]byte{}}
	for _, raw := range body.Spine {
		f, err := finality.ReadHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		h.byHash[f.Hash] = raw
		h.byNum[f.Number] = raw
	}
	return recordedLeg{ref: refOf(t, lj), ev: ev, body: body, source: &replay{final: body.LC.FinalUpdate.SSZ, links: links}, hdrs: h}
}

func embeddedPinsT(t testing.TB) *finality.Pins {
	t.Helper()
	p, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Under the root-only embedded ledger the production Prover anchors every proof at the root pin (period 1378) with the best update
// of every period up to the signature period as in-evidence links, and what it builds is byte for byte the recorded evidence, which
// the verifier accepts under the embedded pins.
func TestTheProverAnchorsAtTheRootPinWithInEvidenceLinks(t *testing.T) {
	pins := embeddedPinsT(t)
	for id, links := range map[string]int{"gloas_latest": 13, "gloas_period": 2, "legacy": 0} {
		l := loadRecorded(t, id)
		p := &Prover{Source: l.source, Exec: l.hdrs, Pins: pins, Verifier: New(), ExtraLinks: l.source.links}
		add, pend, err := p.BuildLeg(context.Background(), l.ref)
		if err != nil || add == nil || pend != nil {
			t.Fatalf("%s: add %v pend %v err %v", id, add != nil, pend, err)
		}
		if !bytes.Equal(add.Evidence, l.ev) {
			t.Fatalf("%s: the Prover's evidence is not the recorded evidence", id)
		}
		if len(l.body.LC.Links) != links || l.body.LC.AnchorPeriod != 1378 || l.body.LC.AnchorKind != 1 {
			t.Fatalf("%s: anchor kind %d period %d with %d links", id, l.body.LC.AnchorKind, l.body.LC.AnchorPeriod, len(l.body.LC.Links))
		}
		if _, err := New().Verify(pins, l.ref, add.Evidence); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}

func pinsWithMaxLinks(t testing.TB, n int) *finality.Pins {
	t.Helper()
	raw := bytes.Replace(finality.EmbeddedPinsBytes(), []byte(`"max_links": 64`), []byte(fmt.Sprintf(`"max_links": %d`, n)), 1)
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pendingFields(t testing.TB, pend *finality.PendingState) map[string]any {
	t.Helper()
	if pend == nil || pend.Reason != PendingLedgerIncomplete {
		t.Fatalf("want finality_ledger_incomplete, got %v", pend)
	}
	return pend.Judged
}

// When the links from the ledger anchor to the final update's signature period would exceed the pins' max_links the Prover builds
// nothing and answers finality_ledger_incomplete with every number it judged by and an ETA derived only from the next scheduled
// ledger publication; at exactly max_links it still builds.
func TestTheProverAnswersLedgerIncompleteBeyondMaxLinksWithAnETAFromThePublication(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	pins := embeddedPinsT(t)
	pub, err := time.Parse(time.RFC3339, pins.PublishedUTC)
	if err != nil {
		t.Fatal(err)
	}
	build := func(max int, now time.Time) (*finality.Addendum, *finality.PendingState) {
		p := &Prover{Source: l.source, Exec: l.hdrs, Pins: pinsWithMaxLinks(t, max), Verifier: New(), ExtraLinks: l.source.links, Now: func() time.Time { return now }}
		add, pend, err := p.BuildLeg(context.Background(), l.ref)
		if err != nil {
			t.Fatal(err)
		}
		return add, pend
	}
	if add, pend := build(13, pub.Add(time.Hour)); add == nil || pend != nil {
		t.Fatalf("13 links at max_links 13: add %v pend %v", add != nil, pend)
	}
	add, pend := build(12, pub.Add(time.Hour))
	if add != nil {
		t.Fatal("13 links were built at max_links 12")
	}
	j := pendingFields(t, pend)
	want := map[string]any{"needed_period": uint64(1391), "anchor_period": uint64(1378), "links_needed": uint64(13), "max_links": uint64(12),
		"missing_period": uint64(1391), "ledger_first_period": uint64(1378), "ledger_head_period": uint64(1378), "pins_published_utc": pins.PublishedUTC,
		"eta_basis": EtaNextPinsPublication}
	for k, v := range want {
		if j[k] != v {
			t.Errorf("%s = %v, want %v", k, j[k], v)
		}
	}
	if !pend.ETA.Equal(pub.Add(PinsPublicationCadence)) || pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelFinalized {
		t.Errorf("eta %v level %v next %v", pend.ETA, pend.LevelReached, pend.NextLevel)
	}
	// after the scheduled publication date the ETA is not invented
	_, late := build(12, pub.Add(PinsPublicationCadence+time.Minute))
	jl := pendingFields(t, late)
	if !late.ETA.IsZero() || jl["eta_basis"] != EtaPinsPublicationOverdue {
		t.Errorf("an overdue publication: eta %v basis %v", late.ETA, jl["eta_basis"])
	}
}

// A ledger with no entry at or below the signature period cannot anchor anything: the same named state, without an anchor.
func TestTheProverAnswersLedgerIncompleteWhenNoEntryIsAtOrBelowThePeriod(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	raw := finality.EmbeddedPinsBytes()
	i := bytes.Index(raw, []byte(`"anchors": [`))
	j := bytes.Index(raw[i:], []byte("\n    ],"))
	empty := append(append(append([]byte(nil), raw[:i]...), []byte(`"anchors": [],`)...), raw[i+j+len("\n    ],"):]...)
	pins, err := finality.ParsePinsOverride(empty)
	if err != nil {
		t.Fatal(err)
	}
	p := &Prover{Source: l.source, Exec: l.hdrs, Pins: pins, Verifier: New(), ExtraLinks: l.source.links}
	add, pend, err := p.BuildLeg(context.Background(), l.ref)
	if err != nil || add != nil {
		t.Fatalf("add %v err %v", add != nil, err)
	}
	f := pendingFields(t, pend)
	if f["missing_period"] != uint64(1391) || f["needed_period"] != uint64(1391) {
		t.Errorf("fields %v", f)
	}
	if _, has := f["anchor_period"]; has {
		t.Errorf("an anchor is named although none exists: %v", f)
	}
}

// The anchor's committee, from the link file or from the source, is hashed against the ledger entry before it goes into the evidence:
// a committee that does not hash to the entry is an unavailable source, never evidence.
func TestAnAnchorCommitteeThatDoesNotHashToTheLedgerEntryIsNeverUsed(t *testing.T) {
	l := loadRecorded(t, "legacy")
	bad := map[uint64][]byte{}
	for k, v := range l.source.links {
		bad[k] = v
	}
	boot := append([]byte(nil), bad[1378]...)
	boot[4+100] ^= 0x01 // a byte of the bootstrap's committee
	bad[1378] = boot
	for name, p := range map[string]*Prover{
		"extra link":  {Source: l.source, Exec: l.hdrs, Pins: embeddedPinsT(t), Verifier: New(), ExtraLinks: bad},
		"from source": {Source: &replay{final: l.source.final, links: bad}, Exec: l.hdrs, Pins: embeddedPinsT(t), Verifier: New()},
	} {
		add, pend, err := p.BuildLeg(context.Background(), l.ref)
		if err != nil || add != nil || pend == nil || pend.Reason != PendingLCUnavailable {
			t.Fatalf("%s: add %v pend %v err %v", name, add != nil, pend, err)
		}
		eps, _ := pend.Judged["endpoints"].([]string)
		if len(eps) != 1 || !strings.Contains(eps[0], "does not hash to the ledger entry") {
			t.Fatalf("%s: endpoints %v", name, eps)
		}
	}
}

// ---- periodCandidate ----

// synthFinal is a 1,448-byte Gloas finality update with the four fields candidateOf reads.
func synthFinal(attested, finalized, sig uint64, exec [32]byte) []byte {
	fu := make([]byte, lcssz.GloasFinalityUpdateSize)
	binary.LittleEndian.PutUint64(fu, attested)
	binary.LittleEndian.PutUint64(fu[496:], finalized)
	copy(fu[496+112:], exec[:])
	binary.LittleEndian.PutUint64(fu[len(fu)-8:], sig)
	return fu
}

// synthUpdate is a 26,424-byte Gloas update whose finality projection is synthFinal's.
func synthUpdate(attested, finalized, sig uint64, exec [32]byte) []byte {
	up := make([]byte, lcssz.GloasUpdateSize)
	binary.LittleEndian.PutUint64(up, attested)
	fin := 496 + lcssz.CommitteeBytes + 11*32
	binary.LittleEndian.PutUint64(up[fin:], finalized)
	copy(up[fin+112:], exec[:])
	binary.LittleEndian.PutUint64(up[len(up)-8:], sig)
	return up
}

// synthHeader is a readable execution header RLP with the given number and timestamp.
func synthHeader(t testing.TB, number, ts uint64) []byte {
	t.Helper()
	z32 := make([]byte, 32)
	b, err := rlp.EncodeToBytes([]any{z32, z32, make([]byte, 20), z32, z32, z32, make([]byte, 256), uint64(0), number, uint64(0), uint64(0), ts})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type probeSource struct {
	updates map[uint64][]byte
	asked   []uint64
}

func (p *probeSource) Name() string                                        { return "probe" }
func (p *probeSource) FinalityUpdate(context.Context) ([]byte, error)      { return nil, nil }
func (p *probeSource) HeadSlot(context.Context) (uint64, error)            { return 0, nil }
func (p *probeSource) Bootstrap(context.Context, [32]byte) ([]byte, error) { return nil, nil }
func (p *probeSource) Updates(_ context.Context, start uint64, count int) ([][]byte, error) {
	if count != 1 {
		return nil, fmt.Errorf("asked for %d periods at once", count)
	}
	p.asked = append(p.asked, start)
	if u, ok := p.updates[start]; ok {
		return [][]byte{u}, nil
	}
	return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "probe", Op: "updates", Reason: "no best update"}}}
}

// execOf returns a header whose number is n and the hash its finality update names.
func execOf(t testing.TB, n uint64) ([]byte, [32]byte) {
	h := synthHeader(t, n, 1)
	return h, crypto.Keccak256Hash(h)
}

func TestPeriodCandidateProbesOnePeriodAtATimeFromTheLegsOwnPeriod(t *testing.T) {
	pins := embeddedPinsT(t)
	e, _ := pins.Sepolia()
	genesis := e.GenesisTime
	legTime := genesis + (1380*8192+10)*12 // slot 1380*8192+10: period 1380
	leg := finality.BlockRef{Chain: finality.ChainSepolia, Number: 1_000_000}
	lh := finality.HeaderFields{Timestamp: legTime, Number: leg.Number}
	hd := headers{byHash: map[[32]byte][]byte{}}
	upd := map[uint64][]byte{}
	for p, n := range map[uint64]uint64{1380: leg.Number - 5, 1381: leg.Number + 7, 1382: leg.Number + 100} {
		raw, h := execOf(t, n)
		hd.byHash[h] = raw
		upd[p] = synthUpdate(p*8192+20, p*8192+10, p*8192+21, h)
	}
	src := &probeSource{updates: upd}
	pr := &Prover{Source: src, Exec: hd, Pins: pins}
	latest := candidate{sigSlot: 1383*8192 + 5, execNumber: leg.Number + 50000}
	c, err := pr.periodCandidate(context.Background(), e, leg, lh, latest)
	if err != nil {
		t.Fatal(err)
	}
	if c.execNumber != leg.Number+7 || fmt.Sprint(src.asked) != "[1380 1381]" {
		t.Fatalf("candidate %d after probes %v", c.execNumber, src.asked)
	}
}

func TestPeriodCandidateHonoursTheSpineBoundExactly(t *testing.T) {
	pins := embeddedPinsT(t)
	e, _ := pins.Sepolia()
	leg := finality.BlockRef{Chain: finality.ChainSepolia, Number: 1_000_000}
	lh := finality.HeaderFields{Timestamp: e.GenesisTime + 1380*8192*12, Number: leg.Number}
	for name, tc := range map[string]struct {
		exec uint64
		ok   bool
	}{
		"exactly the bound": {leg.Number + uint64(e.MaxSpineHeaders) - 1, true},
		"one over":          {leg.Number + uint64(e.MaxSpineHeaders), false},
		"the leg itself":    {leg.Number, true},
		"below the leg":     {leg.Number - 1, false},
	} {
		raw, h := execOf(t, tc.exec)
		src := &probeSource{updates: map[uint64][]byte{1380: synthUpdate(1380*8192+20, 1380*8192+10, 1380*8192+21, h)}}
		pr := &Prover{Source: src, Exec: headers{byHash: map[[32]byte][]byte{h: raw}}, Pins: pins}
		c, err := pr.periodCandidate(context.Background(), e, leg, lh, candidate{sigSlot: 1380*8192 + 100, execNumber: leg.Number + 99999})
		if tc.ok != (err == nil) {
			t.Errorf("%s: err %v (candidate %d)", name, err, c.execNumber)
		}
		if !tc.ok {
			pe, isPending := err.(*pendingErr)
			if !isPending || pe.p.Reason != PendingHistoryProof || pe.p.Judged["block"] != leg.Number {
				t.Errorf("%s: want history_proof_unavailable, got %v", name, err)
			}
		}
	}
}

func TestPeriodCandidateTreatsAMissingNewestPeriodAsHistoryProofUnavailableButAnEarlierGapAsAnError(t *testing.T) {
	pins := embeddedPinsT(t)
	e, _ := pins.Sepolia()
	leg := finality.BlockRef{Chain: finality.ChainSepolia, Number: 1_000_000}
	lh := finality.HeaderFields{Timestamp: e.GenesisTime + 1380*8192*12, Number: leg.Number}
	raw, h := execOf(t, leg.Number-1)
	hd := headers{byHash: map[[32]byte][]byte{h: raw}}
	// period 1380 exists and does not cover, 1381 (the newest) has no best update yet
	src := &probeSource{updates: map[uint64][]byte{1380: synthUpdate(1380*8192+20, 1380*8192+10, 1380*8192+21, h)}}
	_, err := (&Prover{Source: src, Exec: hd, Pins: pins}).periodCandidate(context.Background(), e, leg, lh, candidate{sigSlot: 1381*8192 + 3})
	if pe, ok := err.(*pendingErr); !ok || pe.p.Reason != PendingHistoryProof {
		t.Fatalf("a missing newest period: %v", err)
	}
	// the first probed period is missing: that is an unavailable source, not a verdict about the leg
	_, err = (&Prover{Source: &probeSource{updates: map[uint64][]byte{}}, Exec: hd, Pins: pins}).periodCandidate(context.Background(), e, leg, lh, candidate{sigSlot: 1381*8192 + 3})
	if _, isPending := err.(*pendingErr); err == nil || isPending {
		t.Fatalf("a missing first period: %v", err)
	}
}

func TestPeriodCandidateNeverProbesBeforeTheLedgerNorMoreThanMaxLinksPlusTwoPeriods(t *testing.T) {
	pins := embeddedPinsT(t)
	e, _ := pins.Sepolia()
	leg := finality.BlockRef{Chain: finality.ChainSepolia, Number: 1_000_000}
	hd := headers{byHash: map[[32]byte][]byte{}}
	raw, h := execOf(t, leg.Number-1)
	hd.byHash[h] = raw
	all := map[uint64][]byte{}
	for p := uint64(1300); p < 1600; p++ {
		all[p] = synthUpdate(p*8192+20, p*8192+10, p*8192+21, h)
	}
	// a block from before the beacon genesis has no slot: the probe starts at the ledger's first period, not at a wrapped number
	src := &probeSource{updates: all}
	_, err := (&Prover{Source: src, Exec: hd, Pins: pins}).periodCandidate(context.Background(), e,
		leg, finality.HeaderFields{Timestamp: e.GenesisTime - 1, Number: leg.Number}, candidate{sigSlot: 1500 * 8192})
	if _, ok := err.(*pendingErr); !ok {
		t.Fatalf("%v", err)
	}
	if len(src.asked) == 0 || src.asked[0] != e.Anchors[0].Period {
		t.Fatalf("probes %v: the first must be the ledger's first period %d", src.asked, e.Anchors[0].Period)
	}
	if len(src.asked) > e.MaxLinks+2 {
		t.Fatalf("%d probes, more than max_links+2 = %d", len(src.asked), e.MaxLinks+2)
	}
	// a leg older than the ledger starts at the ledger as well
	src2 := &probeSource{updates: all}
	_, _ = (&Prover{Source: src2, Exec: hd, Pins: pins}).periodCandidate(context.Background(), e, leg, finality.HeaderFields{Timestamp: e.GenesisTime + 5*8192*12, Number: leg.Number}, candidate{sigSlot: 1500 * 8192})
	if len(src2.asked) == 0 || src2.asked[0] != e.Anchors[0].Period {
		t.Fatalf("probes %v for a leg older than the ledger", src2.asked)
	}
}
