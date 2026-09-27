// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"os"
	"strings"
	"testing"
)

// RB3-F90: the L3 consensus time is read from the chain or left unstated - never the validator's clock.
// Production stored 10:06:03Z and 10:24:48Z for DN block 9901845, whose own time is 09:59:42Z.
func TestTheL3ConsensusTimeIsNeverTheValidatorsClock(t *testing.T) {
	if ts, err := dnBlockTime(context.Background(), "", 9901845); err == nil || ts != nil {
		t.Fatalf("no endpoint yet a time: (%v, %v)", ts, err)
	}
	if ts, err := dnBlockTime(context.Background(), "http://127.0.0.1:1/v3", 9901845); err == nil || ts != nil {
		t.Fatalf("an unreachable node yet a time: (%v, %v)", ts, err)
	}
	raw, err := os.ReadFile("proof_generator_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "time.Now()") {
		t.Fatal("the proof generator adapter still reads the validator's clock")
	}
}
