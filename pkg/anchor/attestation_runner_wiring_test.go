package anchor

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/verification"
)

// consensusInstaller is a byte-for-byte copy of the anonymous interface pkg/consensus uses in
// SetAnchorScheduler to install the attestation runner. It cannot import this package's named
// types without an import cycle, so it asserts structurally — and Go matches method-set
// parameter types EXACTLY. A method declared as SetAttestationRunner(AttestationFunc) does NOT
// satisfy this, even though AttestationFunc's underlying type is identical.
//
// That is not hypothetical: it shipped. Every validator logged
//
//	"⚠️ Scheduler does not support attestation replay — on_cadence intents will NOT attest"
//
// on boot, and the whole cadence path executed intents whose proof cycle never closed. The
// assertion failed silently because a failed type assertion is just a false, not an error.
//
// If this interface and the adapter ever drift again, this fails at compile time.
type consensusInstaller interface {
	SetAttestationRunner(func(context.Context, interface{}, *verification.AnchorExecutionResult))
}

// Compile-time proof. This line alone is the regression guard.
var _ consensusInstaller = (*BFTSchedulerAdapter)(nil)

// TestAttestationRunnerIsActuallyInstalled goes one step past the compile-time check: it
// performs the same runtime assertion consensus performs, then proves the installed callback
// is the one that actually gets stored — not merely that the method exists.
func TestAttestationRunnerIsActuallyInstalled(t *testing.T) {
	a := &BFTSchedulerAdapter{}

	installer, ok := interface{}(a).(consensusInstaller)
	if !ok {
		t.Fatal("BFTSchedulerAdapter no longer satisfies the interface pkg/consensus asserts on; " +
			"on_cadence intents would execute but never attest")
	}

	called := 0
	installer.SetAttestationRunner(func(context.Context, interface{}, *verification.AnchorExecutionResult) {
		called++
	})

	a.mu.Lock()
	fn := a.attestationFn
	a.mu.Unlock()

	if fn == nil {
		t.Fatal("SetAttestationRunner did not store the callback")
	}
	fn(context.Background(), nil, nil)
	if called != 1 {
		t.Fatalf("stored callback was not the one installed (called=%d)", called)
	}
}
