// Copyright 2026 Certen Protocol

package intent

import (
	"os"
	"strings"
	"testing"
)

// RB3 sweep: an intent is never counted as processed without consensus. Both the single- and multi-leg
// paths used to skip ValidatorBlock creation with a log line and return the intent as handled.
func TestNoIntentIsProcessedWithoutConsensus(t *testing.T) {
	raw, err := os.ReadFile("discovery.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if strings.Contains(src, "No BFT consensus configured - skipping") {
		t.Fatal("discovery still skips ValidatorBlock creation when no consensus is configured")
	}
	if n := strings.Count(src, "no BFT consensus is configured; it cannot be processed"); n != 2 {
		t.Fatalf("%d of the 2 consensus paths refuse an intent when no consensus is configured", n)
	}
}
