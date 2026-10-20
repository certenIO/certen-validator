// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

func goldenDigests(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/portable_unchanged_by_finality.golden")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && !strings.HasPrefix(line, "#") {
			out[f[0]] = f[1] + " " + f[2]
		}
	}
	return out
}

// The finality section is new evidence beside the document. A document without it is byte-for-byte what origin/main 979a03c
// exported (digests captured there), a document with it differs from that only by the trailing `finality` field, and neither
// the verifier nor the conformance vectors read it.
func TestPortableBytesAreUnchangedByTheFinalitySection(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Export(fx.ev, fx.ar, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ExportDocument(fx.ev, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	want := goldenDigests(t)
	for name, p := range map[string]*Portable{"export": whole, "document": doc} {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x %d", sha256.Sum256(b), len(b)); got != want[name] {
			t.Fatalf("%s: %s, the pre-finality export was %s", name, got, want[name])
		}
	}

	// with a finality section: exactly the old bytes, then the new field
	before, _ := json.Marshal(whole)
	section := []json.RawMessage{json.RawMessage(`{"proofId":"p","seq":1}`), json.RawMessage(`{"proofId":"p","seq":2}`)}
	with := *whole
	with.Finality = section
	after, err := json.Marshal(&with)
	if err != nil {
		t.Fatal(err)
	}
	suffix := `,"finality":[{"proofId":"p","seq":1},{"proofId":"p","seq":2}]}`
	if !bytes.HasSuffix(after, []byte(suffix)) || !bytes.Equal(after[:len(after)-len(suffix)], before[:len(before)-1]) {
		t.Fatal("a document with finality differs from the old bytes by more than the trailing field")
	}

	// the verifier does not read it: the same document verifies to the same report with and without
	a, err := VerifyPortable(whole)
	if err != nil {
		t.Fatal(err)
	}
	withJSON := new(Portable)
	if err := json.Unmarshal(after, withJSON); err != nil {
		t.Fatal(err)
	}
	if len(withJSON.Finality) != 2 {
		t.Fatalf("finality did not round-trip: %d", len(withJSON.Finality))
	}
	b, err := VerifyPortable(withJSON)
	if err != nil {
		t.Fatal(err)
	}
	if a.SetVerdict != b.SetVerdict || a.CertifiedBlock != b.CertifiedBlock || a.AnchorBlock != b.AnchorBlock || a.SetVerdict != proof.VerdictVerified {
		t.Fatalf("finality changed the proof's verdict: %+v vs %+v", a, b)
	}
}

// The document the proof service stores carries govRootV3Inputs; the finality section must still add only its own trailing
// member there. The test pins the placement: Finality is the last field of Portable and is omitted when empty, so no member
// that exists today can move, change or gain a neighbour.
func TestFinalitySectionIsTheLastOmittedWhenEmptyMemberOfThePortableDocument(t *testing.T) {
	typ := reflect.TypeOf(Portable{})
	last := typ.Field(typ.NumField() - 1)
	if last.Name != "Finality" || last.Tag.Get("json") != "finality,omitempty" {
		t.Fatalf("the last member of Portable is %s `%s`; the finality section must be the last, omitempty member", last.Name, last.Tag)
	}

	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ExportDocument(fx.ev, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	doc.GovRootV3Inputs = &PortableGovRootV3Inputs{G0Hash: "g0", G1Hash: "g1", G2Hash: "g2", KeyPageURL: "acc://p", KeyBookURL: "acc://b", OperationID: "op"}
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Finality = []json.RawMessage{json.RawMessage(`{"seq":1}`)}
	after, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	suffix := `,"finality":[{"seq":1}]}`
	if !bytes.HasSuffix(after, []byte(suffix)) || !bytes.Equal(after[:len(after)-len(suffix)], before[:len(before)-1]) {
		t.Fatal("with govRootV3Inputs present, a document with finality differs from the one without by more than the trailing member")
	}
	doc.Finality = []json.RawMessage{}
	empty, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, before) {
		t.Fatal("an empty finality section changed the document's bytes")
	}
}
