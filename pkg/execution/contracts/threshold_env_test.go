// Copyright 2026 Certen Protocol

package contracts

import "testing"

// RB3-F71 sweep: the threshold committed into the validator-set root is the one configured, or none.
// An unreadable value used to become 2/3 silently.
func TestTheSetRootThresholdIsReadOrRefused(t *testing.T) {
	t.Setenv(envValidatorSetThresholdNum, "")
	t.Setenv(envValidatorSetThresholdDen, "")
	if n, d, err := resolveThreshold(); err != nil || n.Int64() != 2 || d.Int64() != 3 {
		t.Fatalf("unset: (%v, %v, %v), want 2/3", n, d, err)
	}
	for _, c := range [][2]string{{"two", "3"}, {"2", "0"}, {"4", "3"}, {"-1", "3"}} {
		t.Setenv(envValidatorSetThresholdNum, c[0])
		t.Setenv(envValidatorSetThresholdDen, c[1])
		if n, d, err := resolveThreshold(); err == nil {
			t.Errorf("%s/%s committed as %v/%v", c[0], c[1], n, d)
		}
	}
}
