// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"encoding/json"
	"testing"
)

// spec25Member is the finality member of V2_SPEC_S7 section 2.5 in its canonical (compact) form: an OBJECT {format, leg,
// addenda}, not an array. proofv2 treats it as opaque; pkg/finality parses it strictly (finality.ParseSection).
const spec25Member = `{"format":"certen-finality-addenda/1","leg":{"chain":84532,"blockNumber":41234567,` +
	`"blockHash":"0x1111111111111111111111111111111111111111111111111111111111111111"},` +
	`"addenda":[{"proofId":"p","seq":1},{"proofId":"p","seq":2}]}`

// A document carrying the spec 2.5 object is read into Portable and written back byte for byte: the member keeps its type
// (an object), stays the last member, and the document before it is the pre-finality export, unchanged.
func TestADocumentCarryingTheSpec25FinalityObjectRoundTripsThroughPortableByteIdentically(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Export(fx.ev, fx.ar, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	doc := append(append([]byte(nil), plain[:len(plain)-1]...), []byte(`,"finality":`+spec25Member+`}`)...)

	var p Portable
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatalf("a document carrying the spec 2.5 object was refused: %v", err)
	}
	if kept, _ := json.Marshal(p.Finality); string(kept) != spec25Member {
		t.Fatalf("the member was not kept as the object: %s", kept)
	}
	out, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, doc) {
		t.Fatalf("the document did not round-trip byte for byte (%d bytes in, %d out)", len(doc), len(out))
	}
	// without the member the same read-and-write is the pre-finality export, byte for byte
	var q Portable
	if err := json.Unmarshal(plain, &q); err != nil {
		t.Fatal(err)
	}
	if len(q.Finality) != 0 {
		t.Fatalf("a document without the member gained one: %d bytes", len(q.Finality))
	}
	again, err := json.Marshal(&q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, plain) {
		t.Fatal("a pre-finality export did not round-trip byte for byte")
	}
	// the verifier does not read the member: the same document verifies to the same report with and without
	a, err := VerifyPortable(&q)
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyPortable(&p)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("the finality member changed what the verifier reported")
	}
}
