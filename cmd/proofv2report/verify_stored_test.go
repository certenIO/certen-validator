package main

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// Evidence written since the G1 activation is version 2.1, which proofv2.Verify refuses by design: the report must judge it with the
// 2.1 verifier instead of failing every new intent with "not a v2 Accumulate proof".
func TestVerifyStoredJudgesEvidence21WithTheVersion21Verifier(t *testing.T) {
	inc := new(proof.IncarnationEvidence)
	for _, tc := range []struct{ version, want string }{
		{proofv2.Version, "incarnation evidence"},
		{proofv2.Version21, "incarnation evidence"},
		{"9.9", "not a v2 Accumulate proof"},
	} {
		_, err := verifyStored(&proofv2.Evidence{Version: tc.version}, new(proofv2.Archive), inc, [32]byte{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("version %q: got %v, want an error containing %q", tc.version, err, tc.want)
		}
	}
	if _, err := verifyStored(nil, new(proofv2.Archive), inc, [32]byte{}); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("nil evidence: got %v", err)
	}
}
