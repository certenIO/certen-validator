// Copyright 2026 Certen Protocol

package basefinal

import "testing"

// The args length a row must carry is base + per_root * n_intermediate, and that product must not wrap: a row whose
// n_intermediate is 2^59+1 would otherwise read as the one-root row (32 * (2^59+1) wraps to 32 in 64 bits).
func TestAGameRowWhoseIntermediateCountWrapsTheArgsLengthIsNotComplete(t *testing.T) {
	p := loadPins(t)
	var row ImplRow
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Complete(p.Layouts) {
			row = r
		}
	}
	l := p.Layouts[row.CWIA]
	per := l.ArgsPerRoot
	if per <= 0 || per&(per-1) != 0 {
		t.Fatalf("the test needs a power-of-two per-root length, the pinned layout has %d", per)
	}
	// per * wrapN is exactly 2^64 in unsigned arithmetic; one more root wraps to a single root's length
	wrapN := int(uint64(1) << 63 / uint64(per) * 2)
	for _, n := range []int{wrapN, wrapN + 1, wrapN + 20, wrapN/2 + 1} {
		r := row
		r.NIntermediate = n
		r.ArgsLen = int(uint64(l.ArgsBaseLen) + uint64(per)*uint64(n))
		if r.Complete(p.Layouts) {
			t.Errorf("n_intermediate %d with the wrapped args length %d reads as complete", n, r.ArgsLen)
		}
	}
	// the exact (unwrapped) sizes still decide: one and two roots are complete
	for _, n := range []int{1, 2} {
		r := row
		r.NIntermediate = n
		r.ArgsLen = l.ArgsBaseLen + per*n
		if !r.Complete(p.Layouts) {
			t.Errorf("n_intermediate %d with its exact args length is refused", n)
		}
	}
}
