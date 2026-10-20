// Copyright 2026 Certen Protocol

package adiri_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-F1-FIX: the min_committee_size floor.

// ---- min_committee_size: Telcoin's own shrink floor is 4 (annex A4: when smaller, len >= 4) ----

func TestAPinBelowTelcoinsShrinkFloorOfFourIsRefused(t *testing.T) {
	for _, size := range []string{"3", "2", "1", "0", "-1"} {
		_, err := gateAdiriPins(t, func(s map[string]any) { s["min_committee_size"] = json.Number(size) })
		st := gateNamed(t, err, finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", "adiri.min_committee_size")
		_ = st
	}
	for _, size := range []string{"4", "5", "255"} {
		par, err := gateAdiriPins(t, func(s map[string]any) { s["min_committee_size"] = json.Number(size) })
		if err != nil || fmt.Sprint(par.MinCommittee) != size {
			t.Fatalf("min_committee_size %s: %v", size, err)
		}
	}
}
