package strategy

import "testing"

// SEC-H2: the MinValidators floor must reject small/empty-peer sets that would otherwise
// trivially "meet" a 2/3 threshold (total=1 → required=1 → achieved=1=self). The floor
// only ever ADDS restriction; correctly-sized fleets are governed by the 2/3 fraction.
func TestIsThresholdMet_MinValidatorsFloor(t *testing.T) {
	c := DefaultThresholdConfig() // 2/3, MinValidators=3

	cases := []struct {
		name            string
		achieved, total int64
		want            bool
	}{
		{"single-node self-attest is refused", 1, 1, false},
		{"two-node set is refused (below floor)", 2, 2, false},
		{"three-node unanimous meets floor+fraction", 3, 3, true},
		{"three-node with two signers fails fraction", 2, 3, false},
		{"seven-node with five signers (2/3) passes", 5, 7, true},
		{"seven-node with four signers fails fraction", 4, 7, false},
		{"large set but signers below floor is refused", 2, 10, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.IsThresholdMet(tc.achieved, tc.total); got != tc.want {
				t.Errorf("IsThresholdMet(achieved=%d,total=%d)=%v want %v", tc.achieved, tc.total, got, tc.want)
			}
		})
	}
}

// A config with MinValidators==0 (explicitly disabled) must not apply the floor — the
// fractional threshold governs alone. Guards against the floor silently changing behavior
// for a caller that opted out.
func TestIsThresholdMet_FloorDisabled(t *testing.T) {
	c := &ThresholdConfig{Numerator: 2, Denominator: 3, MinValidators: 0}
	if !c.IsThresholdMet(1, 1) {
		t.Error("with MinValidators=0, single-node should meet the raw 2/3 fraction (required=1)")
	}
}
