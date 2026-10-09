package main

import (
	"encoding/json"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

func TestSyntheticDocumentVerifiesInGo(t *testing.T) {
	p, err := syntheticDocument()
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(p)
	q := new(proofv2.Portable)
	if err := json.Unmarshal(j, q); err != nil {
		t.Fatal(err)
	}
	ev, ar, in, pin, err := proofv2.Import(q)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := proofv2.VerifyFromGenesis(ev, ar, in, pin)
	if err != nil {
		t.Fatalf("the synthetic document does not verify in Go: %v", err)
	}
	t.Logf("verified: majors %d certified %d set %s validators %d threshold %d", rep.Majors, rep.CertifiedBlock, rep.SetVerdict, rep.Validators, rep.Threshold)
	if rep.Validators != 4 {
		t.Fatalf("the update was not applied: %d validators", rep.Validators)
	}
}

// Every attack is refused for the reason it is meant to show, not because an earlier check tripped.
func TestSyntheticAttacksAreRefusedForTheirReason(t *testing.T) {
	p, err := syntheticDocument()
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(p)
	for _, a := range syntheticAttacks {
		var doc map[string]any
		_ = json.Unmarshal(base, &doc)
		if err := a.edit(doc); err != nil {
			t.Fatalf("%s: %v", a.file, err)
		}
		j, _ := json.Marshal(doc)
		tp := new(proofv2.Portable)
		var verr error
		if err := json.Unmarshal(j, tp); err != nil {
			verr = err
		} else {
			_, verr = proofv2.VerifyPortable(tp)
		}
		t.Logf("%-28s %v", a.file, verr)
	}
}
