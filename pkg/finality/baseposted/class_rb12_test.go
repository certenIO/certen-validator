// Copyright 2026 Certen Protocol

package baseposted

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-GO-INT F17: the upgrader's retry table (pkg/finality, code -> failure | environment) judges the codes of this package. A leg inside a
// recorded capture gap waits for the backfill, a fact about the capture store: it is asked again at the bounded poll, not backed off. The
// states that stay verdicts keep the back-off. The table cannot name this package's constants (it cannot import it), so this test ties them.
func TestRB12F17TheCodesOfThisPackageHaveTheirRetryClass(t *testing.T) {
	for code, want := range map[string]finality.StateClass{
		CodeCaptureGap:         finality.ClassEnvironment,
		CodeCaptureNotCovering: finality.ClassFailure,
		CodeCaptureRowConflict: finality.ClassFailure,
	} {
		if got, ok := finality.ClassOfState(code); !ok || got != want {
			t.Errorf("%s: class (%q, registered=%v), want %q", code, got, ok, want)
		}
	}
}
