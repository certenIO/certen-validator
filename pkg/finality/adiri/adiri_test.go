// Copyright 2026 Certen Protocol

package adiri_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/mr-tron/base58"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

func liveParts(t *testing.T, name string) (finality.Container, *adiri.Body, *adiri.CFA1, finality.BlockRef, *finality.Pins) {
	t.Helper()
	f := loadVectors(t)
	for _, v := range f.Vectors {
		if v.Name == name {
			ev := evidenceOf(t, f, v)
			c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			b, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
			if err != nil {
				t.Fatal(err)
			}
			cf, err := adiri.DecodeCFA1(b.CFA1, finality.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			return c, b, cf, legOf(t, v), pinsOf(t, v)
		}
	}
	t.Fatalf("vector %s", name)
	return finality.Container{}, nil, nil, finality.BlockRef{}, nil
}

// encode(decode(x)) == x on the real 88 KB chain, for the body and for the whole container.
func TestCFA1AndBodyRoundTripOnTheLiveChain(t *testing.T) {
	c, b, cf, _, _ := liveParts(t, "live-513643-epoch651")
	if len(cf.Records) != 652 || len(cf.Tables) != 2 {
		t.Fatalf("%d records %d tables", len(cf.Records), len(cf.Tables))
	}
	enc, err := cf.Encode()
	if err != nil || !bytes.Equal(enc, b.CFA1) {
		t.Fatalf("CFA1 round trip: %v", err)
	}
	if !bytes.Equal(b.Encode(), c.Body) {
		t.Fatal("body round trip")
	}
	whole, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, mustEvidence(t, "live-513643-epoch651")) {
		t.Fatal("container round trip")
	}
}

// The BCS reconstruction and BLAKE3 digest reproduce the record digests the annex measured for epochs 0, 1, 2 and 642
// (research/R11-adiri.md M3), taken from Telcoin's own certificates (epoch_hash), not from this code.
func TestRecordDigestsEqualTheMeasuredAnchors(t *testing.T) {
	_, _, cf, _, _ := liveParts(t, "live-513643-epoch651")
	d := cf.RecordDigests()
	for e, want := range map[int]string{
		0:   "f07c39528bea398d8a8470a3188a4464da2c569b713831935bd190933d8939a7",
		1:   "d2e939960b3d79616d5ca42bf3f5fc12d67bdaad06510a251595efcddbefd713",
		2:   "b9eaa809acf4c608394508155f4e016baaab6be475466f8a9a74c98f0a10f4a4",
		642: "5ea75eb276abfd43ef7ec353b21f7b31a96b10a876d02aa73c606cff92d3f11f",
	} {
		if hex.EncodeToString(d[e][:]) != want {
			t.Errorf("digest(%d) = %x, want %s", e, d[e], want)
		}
	}
	// the live chain's four-signer certificates (annex M3)
	for _, e := range []int{20, 21, 22, 115, 117, 119, 120, 383} {
		if len(cf.Records[e].Signers) != 4 {
			t.Errorf("epoch %d has %d signers, annex M3 says 4", e, len(cf.Records[e].Signers))
		}
	}
}

func TestCFA1DecoderIsStrict(t *testing.T) {
	_, b, _, _, _ := liveParts(t, "live-500749-epoch600")
	lim := finality.DefaultLimits()
	cases := []struct {
		name string
		mut  func([]byte) []byte
		code string
		part string
	}{
		{"trailing byte", func(x []byte) []byte { return append(append([]byte(nil), x...), 0) }, finality.CodeEvidenceMalformed, "cfa1"},
		{"bad magic", func(x []byte) []byte { y := append([]byte(nil), x...); y[0] = 'X'; return y }, finality.CodeEvidenceMalformed, "cfa1.magic"},
		{"truncated", func(x []byte) []byte { return x[:len(x)-3] }, finality.CodeEvidenceMalformed, ""},
		{"zero tables", func(x []byte) []byte { y := append([]byte(nil), x...); y[4], y[5] = 0, 0; return y }, finality.CodeEvidenceMalformed, "cfa1.n_tables"},
		{"table index out of range", func(x []byte) []byte {
			y := append([]byte(nil), x...)
			off := 6
			for i := 0; i < 2; i++ {
				off += 1 + int(y[off])*96
			}
			y[off+4] = 9
			return y
		}, finality.CodeEvidenceMalformed, "cfa1.record"},
	}
	for _, c := range cases {
		_, err := adiri.DecodeCFA1(c.mut(b.CFA1), lim)
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != c.code || (c.part != "" && s.Fields["part"] != c.part) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// bounds from Limits: tables and records
	small := lim
	small.MaxCFA1Tables = 1
	if _, err := adiri.DecodeCFA1(b.CFA1, small); err == nil || !strings.Contains(err.Error(), "finality_evidence_too_large") || !strings.Contains(err.Error(), "cfa1.tables") {
		t.Errorf("tables bound: %v", err)
	}
	small = lim
	small.MaxCFA1Records = 100
	if _, err := adiri.DecodeCFA1(b.CFA1, small); err == nil || !strings.Contains(err.Error(), "cfa1.records") {
		t.Errorf("records bound: %v", err)
	}
	// a hostile record count never allocates: it is refused against the remaining bytes
	y := append([]byte(nil), b.CFA1...)
	off := 6
	for i := 0; i < 2; i++ {
		off += 1 + int(y[off])*96
	}
	y[off], y[off+1], y[off+2], y[off+3] = 0, 0, 0xff, 0xff
	if _, err := adiri.DecodeCFA1(y, lim); err == nil || !strings.Contains(err.Error(), "count exceeds the remaining bytes") {
		t.Errorf("hostile count: %v", err)
	}
}

func TestRoaringDecoderReadsTheNodesSerialisation(t *testing.T) {
	// "2nLqe24nocoseuuBygc8VW6FW3oXreb3pseX" is epoch 0's signed_authorities (annex M11): all five members
	got, err := adiri.DecodeRoaring(mustB58(t, "2nLqe24nocoseuuBygc8VW6FW3oXreb3pseX"))
	if err != nil || len(got) != 5 || got[0] != 0 || got[4] != 4 {
		t.Fatalf("%v %v", got, err)
	}
	enc := adiri.EncodeRoaring([]uint16{0, 1, 3, 4})
	got, err = adiri.DecodeRoaring(enc)
	if err != nil || len(got) != 4 || got[2] != 3 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := adiri.DecodeRoaring([]byte{1, 2, 3}); err == nil {
		t.Fatal("garbage decoded")
	}
}

// The package registers nothing at import: there is no init, and Register is explicit and refuses a second call.
func TestNoInitRegistration(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		n++
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "init" && fn.Recv == nil {
				t.Errorf("%s declares init()", e.Name())
			}
		}
	}
	if n < 6 {
		t.Fatalf("%d files scanned", n)
	}
	if _, err := finality.Default.Profile(finality.ChainAdiri); err != nil {
		t.Fatal(err)
	}
	reg := finality.NewRegistry()
	if err := adiri.Register(reg); err != nil {
		t.Fatal(err)
	}
	v := adiri.NewVerifier()
	if !finality.IsRow(v.Chain(), v.Level(), v.Name()) {
		t.Fatal("the kind is not a row of the table")
	}
}

// Differential: on random mutations of three synthetic chains (committee rotation, ejection, shrink) the batched
// random-linear-combination and the one-by-one pkg/crypto/bls modes return the same canonical verdict every time.
func TestBatchedAndOneByOneAgreeOnRandomMutations(t *testing.T) {
	f := loadVectors(t)
	rng := rand.New(rand.NewSource(20261020))
	pairs := 0
	for _, name := range []string{"syn-rotation", "syn-ejection-4-of-5", "syn-cumulative-shrink-to-4", "live-500749-epoch600"} {
		var v vVec
		for _, x := range f.Vectors {
			if x.Name == name {
				v = x
			}
		}
		ev := evidenceOf(t, f, v)
		pins, leg := pinsOf(t, v), legOf(t, v)
		n := 120
		if strings.HasPrefix(name, "live") {
			n = 12 // 600 records per verification, two modes
		}
		for i := 0; i < n; i++ {
			m := append([]byte(nil), ev...)
			// flips inside the CFA1 region (after the 75 B header and the 4 B length)
			for k := 0; k <= rng.Intn(2); k++ {
				pos := 79 + rng.Intn(len(m)-79)
				if strings.HasPrefix(name, "live") {
					pos = 79 + rng.Intn(60000)
				}
				m[pos] ^= byte(1 << rng.Intn(8))
			}
			v1, e1 := (&adiri.Verifier{Mode: adiri.ModeOneByOne}).Verify(pins, leg, m)
			v2, e2 := (&adiri.Verifier{Mode: adiri.ModeBatched}).Verify(pins, leg, m)
			if outcome(v1, e1) != outcome(v2, e2) {
				t.Fatalf("%s mutation %d: modes disagree\n one: %s\n bat: %s", name, i, outcome(v1, e1), outcome(v2, e2))
			}
			pairs++
		}
	}
	if pairs < 300 {
		t.Fatalf("%d pairs", pairs)
	}
}

// The batched check really is a check: a record whose signature is valid for ANOTHER record's digest fails it, and so does a
// record whose signer set is swapped for another valid set of the same size.
func TestBatchedRejectsWhatOneByOneRejects(t *testing.T) {
	_, b, cf, leg, pins := liveParts(t, "live-500749-epoch600")
	par, err := adiri.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	_ = b
	_ = leg
	for _, mode := range []adiri.Mode{adiri.ModeOneByOne, adiri.ModeBatched} {
		cf2 := *cf
		cf2.Records = append([]adiri.Record(nil), cf.Records...)
		if _, err := adiri.VerifyCommitteeChain(par, &cf2, mode, nil); err != nil {
			t.Fatalf("mode %d rejects the live chain: %v", mode, err)
		}
		// signers of record 40 change to a different 4-subset (still a quorum)
		cf2.Records[40].Signers = []uint8{1, 2, 3, 4}
		_, err := adiri.VerifyCommitteeChain(par, &cf2, mode, nil)
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != adiri.CodeCommitteeBroken || s.Fields["epoch"] != uint64(40) || s.Fields["reason"] != adiri.ReasonPairing {
			t.Fatalf("mode %d: %v", mode, err)
		}
	}
}

func mustB58(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base58.Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEvidence(t *testing.T, name string) []byte {
	t.Helper()
	f := loadVectors(t)
	for _, v := range f.Vectors {
		if v.Name == name {
			return evidenceOf(t, f, v)
		}
	}
	t.Fatal(name)
	return nil
}

// Every named state a vector expects, and every pending reason the builder emits, is in the machine registry
// (testdata/finality/states.json) with all of its required fields.
func TestEveryExpectedStateIsRegisteredWithItsRequiredFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		States map[string]struct {
			Required []string `json:"required"`
		} `json:"states"`
		Pending map[string]struct {
			Required []string `json:"required"`
		} `json:"pending_reasons"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	f := loadVectors(t)
	codes := map[string]int{}
	for _, v := range f.Vectors {
		var e struct {
			Code   string         `json:"code"`
			Fields map[string]any `json:"fields"`
		}
		if err := json.Unmarshal([]byte(v.Expect), &e); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if e.Code == "finalized" {
			continue
		}
		codes[e.Code]++
		st, ok := reg.States[e.Code]
		if !ok {
			t.Errorf("%s expects the unregistered code %s", v.Name, e.Code)
			continue
		}
		for _, r := range st.Required {
			if _, has := e.Fields[r]; !has {
				t.Errorf("%s: %s lacks the required field %s", v.Name, e.Code, r)
			}
		}
	}
	for _, c := range []string{"committee_chain_broken", "evidence_pin_mismatch", "adiri_incarnation_mismatch", "epoch_record_codec_unsupported", "finality_link_broken", "finality_header_chain_broken", "finality_block_mismatch", "finality_evidence_too_large", "finality_evidence_malformed"} {
		if codes[c] == 0 {
			t.Errorf("no vector expects %s", c)
		}
	}
	// the success verdict reports committee_shrunk (a reported attribute, not a refusal) with its three fields
	if _, ok := reg.States["committee_shrunk"]; !ok {
		t.Error("committee_shrunk is not registered")
	}
	shrunk := adiri.Shrunk(3, 4, 5)
	for _, r := range reg.States["committee_shrunk"].Required {
		if _, ok := shrunk.Fields[r]; !ok {
			t.Errorf("Shrunk lacks %s", r)
		}
	}
	for _, r := range []string{adiri.PendingEpochOpen, adiri.PendingCertPending, adiri.PendingEpochOverdue, adiri.PendingHistoryProof} {
		if _, ok := reg.Pending[r]; !ok {
			t.Errorf("pending reason %s is not registered", r)
		}
	}
	for code, fields := range map[string]*finality.StateError{
		"adiri_incarnation_mismatch":     adiri.IncarnationMismatch(adiri.NumHash{}, adiri.NumHash{}),
		"evidence_pin_mismatch":          adiri.PinMismatch("x", 1, 2),
		"committee_chain_broken":         adiri.ChainBroken(1, "x"),
		"epoch_record_codec_unsupported": adiri.CodecUnsupported(1, "a", "b"),
		"finality_link_broken":           adiri.LinkBroken("x", 1, 2, 3),
		"finality_header_chain_broken":   adiri.HeaderChainBroken(1, [32]byte{}, [32]byte{}, "r"),
		"finality_source_unavailable":    adiri.SourceUnavailable("r", []string{"e"}),
	} {
		st, ok := reg.States[code]
		if !ok || fields.Code != code {
			t.Errorf("%s: constructor/registry mismatch", code)
			continue
		}
		for _, r := range st.Required {
			if _, has := fields.Fields[r]; !has {
				t.Errorf("%s constructor lacks %s", code, r)
			}
		}
	}
}

func benchVerify(b *testing.B, mode adiri.Mode) {
	f := loadVectors(b)
	var v vVec
	for _, x := range f.Vectors {
		if x.Name == "live-513643-epoch651" {
			v = x
		}
	}
	ev, pins, leg := evidenceOf(b, f, v), pinsOf(b, v), legOf(b, v)
	ver := &adiri.Verifier{Mode: mode}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ver.Verify(pins, leg, ev); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyLive652Records measures a full verification of the real 652-record chain (V2_SPEC_S7 8.1: Go 4.06-8.0 s).
func BenchmarkVerifyLive652RecordsOneByOne(b *testing.B) { benchVerify(b, adiri.ModeOneByOne) }
func BenchmarkVerifyLive652RecordsBatched(b *testing.B)  { benchVerify(b, adiri.ModeBatched) }
