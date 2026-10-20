// Copyright 2026 Certen Protocol

package finality_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The member Portable carries is the spec 2.5 section object, byte for byte: a real Section, written into a portable document,
// read back and written again, is unchanged, and the framework's strict parser reads what the document carried. (An external
// test package: pkg/proof/v2 reaches pkg/finality through pkg/database, so the internal test package cannot import it.)
func TestASectionCarriedInThePortableDocumentRoundTripsAndParsesUnchanged(t *testing.T) {
	leg := finality.BlockRef{Chain: finality.ChainBaseSepolia, Number: 47368146, Hash: [32]byte{0x33, 0x33}}
	enc, err := finality.Container{Header: finality.ContainerHeader{Kind: "base-sepolia/l1_posted/v1", Chain: leg.Chain, Level: finality.LevelL1Posted, BlockNumber: leg.Number, BlockHash: leg.Hash}, Body: []byte("body")}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	add, err := finality.NewAddendum(finality.LegBindingOf(leg), [16]byte{1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16}, nil, leg.Chain, finality.LevelL1Posted, "base-sepolia/l1_posted/v1", enc)
	if err != nil {
		t.Fatal(err)
	}
	sec := finality.NewSection(leg, []finality.Addendum{add})
	raw, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(&proofv2.Portable{Format: proofv2.PortableFormat, Finality: raw})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(doc, append(append([]byte(`,"finality":`), raw...), '}')) {
		t.Fatalf("the section is not the last member of the document: %s", doc)
	}
	var back proofv2.Portable
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Finality, raw) {
		t.Fatalf("the section changed in the document:\n%s\n%s", raw, back.Finality)
	}
	again, err := json.Marshal(&back)
	if err != nil || !bytes.Equal(again, doc) {
		t.Fatalf("the document did not round-trip byte for byte: %v", err)
	}
	parsed, err := finality.ParseSection(back.Finality)
	if err != nil || parsed.Leg != sec.Leg || len(parsed.Addenda) != 1 {
		t.Fatalf("%v %+v", err, parsed)
	}
}
