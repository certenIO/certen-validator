// Copyright 2026 Certen Protocol

package main

import (
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/execution"
)

// RB12 final review D1: nothing pinned which of Earliest and Latest the adapter hands to the capture (spec E1b, r3.6 H16: the LATEST).
func TestTheCaptureFollowsTheLatestMemberDeadlineNotTheEarliest(t *testing.T) {
	t1 := time.Unix(1_700_000_000, 0)
	t2 := t1.Add(time.Hour)
	got, ok := handedToTheCapture(execution.BundleDeadline{State: execution.BundleDeadlineKnown, Earliest: t1, Latest: t2})
	if !ok || !got.Equal(t2) {
		t.Fatalf("a bundle with members due at %v and %v must hand the capture the later one: got %v %v", t1, t2, got, ok)
	}
	for _, s := range []execution.BundleDeadlineState{"not_wired", "tree_not_held", "tree_unreadable", "read_panicked", "members_finished", "no_member_deadline"} {
		if d, ok := handedToTheCapture(execution.BundleDeadline{State: s, Earliest: t1, Latest: t2}); ok || !d.IsZero() {
			t.Fatalf("state %q must hand the capture no deadline: got %v %v", s, d, ok)
		}
	}
}
