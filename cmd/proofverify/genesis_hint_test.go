package main

import (
	"fmt"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The fixed text of certify_link_missing reads "an anchored item has no link" (names.json, shared with the TypeScript verifier); for the index
// genesis it means the proof v2 carries no genesis link. proofverify says so under the refusal (RB9-F6).
func TestGenesisLinkHintExplainsTheSharedWording(t *testing.T) {
	wrap := func(cs *proofv2.CertifyState) error { return fmt.Errorf("the certified proof v2: %w", cs) }
	for _, code := range []string{proofv2.StateCertifyLinkMissing, proofv2.StateCertifyLinkStart, proofv2.StateCertifyLinkEnd, proofv2.StateCertifyLinkInvalid} {
		if h := genesisLinkHint(wrap(&proofv2.CertifyState{Code: code, Fields: []string{"genesis"}})); !strings.Contains(h, "genesis link") {
			t.Errorf("%s{genesis}: hint %q", code, h)
		}
	}
	if h := genesisLinkHint(wrap(&proofv2.CertifyState{Code: proofv2.StateCertifyLinkMissing, Fields: []string{"genesis"}})); !strings.Contains(h, "anchored item") {
		t.Errorf("the missing-link hint does not explain the shared wording: %q", h)
	}
	for name, err := range map[string]error{
		"another index":  wrap(&proofv2.CertifyState{Code: proofv2.StateCertifyLinkMissing, Fields: []string{"1"}}),
		"another state":  wrap(&proofv2.CertifyState{Code: proofv2.StateCertifyUpdateReplayed, Fields: []string{"genesis"}}),
		"not a state":    fmt.Errorf("something else"),
		"no error given": nil,
	} {
		if h := genesisLinkHint(err); h != "" {
			t.Errorf("%s: hint %q, want none", name, h)
		}
	}
}
