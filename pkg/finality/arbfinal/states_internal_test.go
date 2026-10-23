// Copyright 2026 Certen Protocol

package arbfinal

import (
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// asState passes a nil through, a named state as it is, adapts an L1 head fault to the framework's state with the same code and fields,
// and turns anything else into finality_verifier_failed carrying the cause: never a silent pass.
func TestAsStateKeepsEveryKindOfErrorWhatItIs(t *testing.T) {
	if got := asState(nil); got != nil {
		t.Fatalf("asState(nil) = %v", got)
	}
	named := PinMismatch("layout")
	if got := asState(named); got != error(named) {
		t.Errorf("a named state was rewritten: %v", got)
	}
	wrapped := fmt.Errorf("while judging: %w", named)
	if s, ok := finality.AsNamed(asState(wrapped)); !ok || s != named {
		t.Errorf("a wrapped named state was not found: %v", asState(wrapped))
	}
	fault := ethl1.BlockNotCovered(7, 5)
	s, ok := finality.AsNamed(asState(fault))
	if !ok || s.Code != fault.Code || s.Fields["block_number"] != uint64(7) || s.Fields["finalized_exec_number"] != uint64(5) {
		t.Errorf("a fault was not adapted with its code and fields: %v", asState(fault))
	}
	other := errors.New("an unexpected failure")
	s, ok = finality.AsNamed(asState(other))
	if !ok || s.Code != finality.CodeVerifierFailed || s.Fields["cause"] != other.Error() {
		t.Errorf("an unknown error did not become finality_verifier_failed: %v", asState(other))
	}
}

// innerCode is the code of the fault or named state an error carries, and "" for any other error.
func TestInnerCodeNamesTheFaultOrStateAnErrorCarries(t *testing.T) {
	fault := ethl1.BlockNotCovered(7, 5)
	if got := innerCode(fault); got == "" || got != fault.Code {
		t.Errorf("fault: %q", got)
	}
	if got := innerCode(PinMismatch("layout")); got != CodePinMismatch {
		t.Errorf("named state: %q", got)
	}
	if got := innerCode(fmt.Errorf("wrapped: %w", PinMismatch("layout"))); got != CodePinMismatch {
		t.Errorf("wrapped named state: %q", got)
	}
	if got := innerCode(errors.New("x")); got != "" {
		t.Errorf("other error: %q", got)
	}
	if got := innerCode(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
}
