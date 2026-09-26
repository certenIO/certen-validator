package execution

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// =============================================================================
// No proof cycle is ever silently skipped
// =============================================================================
//
// The adapter used to fall back to the legacy orchestrator (a one-member validator set whose
// contract loader was a TODO) and, with neither orchestrator present, returned nil - a proof cycle
// that never ran and reported nothing. Per-chain cycles dereferenced the unified orchestrator
// without a check. The adapter now requires the unified orchestrator and refuses by name.

func TestAdapterWithoutUnifiedOrchestratorRefusesByName(t *testing.T) {
	a := &UnifiedOrchestratorAdapter{}
	ctx := context.Background()
	// The adapter's one entry point (RB3-F45: the others had no caller once every cycle became one
	// chain member's).
	calls := map[string]func() error{
		"StartProofCycleWithAccumulateRef": func() error {
			return a.StartProofCycleWithAccumulateRef(ctx, "i", "u", [32]byte{}, nil, nil, "acc://a.acme/data", "tx", "")
		},
	}
	for name, call := range calls {
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked without an orchestrator: %v", name, r)
				}
			}()
			err = call()
		}()
		if !errors.Is(err, ErrProofCycleUnavailable) {
			t.Errorf("%s: a proof cycle with no orchestrator must refuse by name, got %v", name, err)
		}
	}
}

// The legacy orchestrator is not a fallback any more: the adapter holds only the unified one, and
// startup fails by name if that cannot be built.
func TestNoLegacyOrchestratorFallback(t *testing.T) {
	src, err := os.ReadFile("unified_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"legacy *ProofCycleOrchestrator", "fallbackToLegacy", "a.legacy"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("unified_adapter.go still carries a legacy fallback (%q)", forbidden)
		}
	}
}
