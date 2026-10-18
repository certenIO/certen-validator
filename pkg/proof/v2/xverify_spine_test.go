// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// spineOf is the spine a chain holds after verifying the archive's major records from the pinned incarnation's genesis.
func spineOf(t *testing.T, r real21) *ledger.AccumulateSpineLog {
	t.Helper()
	gen, set, err := AcceptSpineGenesis(r.in, r.pin, 5)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := ExtendSpine(l, r.ar.Majors, 6)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	return l
}

// VerifyEvidence21FromSpine is the consensus-callable verifier of evidence 2.1 (RB9-I): it reaches the same verdict and report as
// Verify21FromGenesis from the spine a chain holds, and the shared 2.0 entry point still refuses the document.
func TestVerifyEvidence21FromSpineAgreesWithTheGenesisVerifier(t *testing.T) {
	r := loadReal21(t)
	l := spineOf(t, r)

	want, err := Verify21FromGenesis(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyEvidence21FromSpine(r.ev, l, r.pin)
	if err != nil {
		t.Fatalf("the real stored 2.1 document from the chain's spine: %v", err)
	}
	wj, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	gj, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(wj) != string(gj) {
		t.Fatalf("the spine verifier's report (%d bytes) differs from the genesis verifier's (%d bytes)", len(gj), len(wj))
	}
	if got.Version != Version21 || len(got.Unproven) != 0 {
		t.Fatalf("version %q, unproven %v", got.Version, got.Unproven)
	}

	// The 2.0 entry point refuses the 2.1 document; the 2.1 entry point refuses a 2.0 one and a nil document.
	if _, err := VerifyFromSpine(r.ev, l, r.pin); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("VerifyFromSpine on a 2.1 document: %v", err)
	}
	two := r.clone(t)
	two.Version = Version
	if _, err := VerifyEvidence21FromSpine(two, l, r.pin); err == nil || !strings.Contains(err.Error(), "not a v2.1") {
		t.Fatalf("VerifyEvidence21FromSpine on a 2.0 document: %v", err)
	}
	if _, err := VerifyEvidence21FromSpine(nil, l, r.pin); err == nil {
		t.Fatal("a nil document verified")
	}

	// A spine of another incarnation, or none, is refused by name before the document is read.
	if _, err := VerifyEvidence21FromSpine(r.ev, nil, r.pin); err == nil {
		t.Fatal("no spine verified")
	}
	other := r.pin
	other[0] ^= 1
	if _, err := VerifyEvidence21FromSpine(r.ev, l, other); err == nil || !strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("a spine of another incarnation: %v", err)
	}
}
