// Copyright 2026 Certen Protocol

package finality

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// RB12-P0LIVE-FIX D6 (independent verifier V-RB12-P0-LIVE, 2026-10-23).

// D6: the failure path adds `attempt` and `next_attempt_at` to the state of a failed ask (noteAttempt). Every code a failed ask can
// store - every registered code except level_not_applicable, which has its own class and is never noted - must still conform to the
// registry with them, so a stored failure row is always in the machine form of the states.
func TestRB12EveryStateAFailedAskCanStoreConformsWithItsAttemptNotes(t *testing.T) {
	reg := loadRegistry(t)
	codes := make([]string, 0, len(reg.States))
	for c := range reg.States {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	at := time.Unix(1_800_000_000, 0)
	next := at.Add(5 * time.Minute)
	checked := 0
	var bad []string
	for _, code := range codes {
		if code == CodeNotApplicable {
			continue // class N: BuilderStatusOf routes it away from the failure path
		}
		for _, st := range rb12ConformingStates(t, reg, code) {
			if msg := conforms(reg, st); msg != "" {
				t.Fatalf("the generated %s does not conform before the notes are added: %s", code, msg)
			}
			for _, refused := range []bool{false, true} {
				s := BuilderStatusOf("p", 84532, LevelL1Posted, LevelIncluded, nil, st, refused, at)
				if s.Class != BuilderUnavailable && s.Class != BuilderRefused {
					t.Fatalf("%s: a failed ask stores class U or R, got %s", code, s.Class)
				}
				s.noteAttempt(3, next)
				if s.State.Fields[FieldAttempt] != uint64(3) || s.State.Fields[FieldNextAttemptAt] != next.UTC().Format(time.RFC3339) {
					t.Fatalf("%s: the notes were not added: %v", code, s.State.Fields)
				}
				if msg := conforms(reg, s.State); msg != "" {
					bad = append(bad, fmt.Sprintf("%s (refused=%v): %s", code, refused, msg))
				}
				checked++
			}
		}
	}
	if len(bad) > 0 {
		first := bad
		if len(first) > 3 {
			first = first[:3]
		}
		t.Errorf("%d of %d stored failure rows do not conform to the registry once the attempt notes are added, e.g.\n%s", len(bad), checked, strings.Join(first, "\n"))
	}
	if checked < 2*len(codes)-2 {
		t.Fatalf("only %d states were walked", checked)
	}
}

// rb12ConformingStates builds, for one registered code, states that conform to the registry: the required fields, one variant per
// closed pending reason and one per conditional rule.
func rb12ConformingStates(t *testing.T, reg stateRegistry, code string) []*StateError {
	t.Helper()
	spec := reg.States[code]
	build := func(when map[string]string, reason string) *StateError {
		st := NewState(code)
		if code == CodePending {
			st.Fields["reason"] = reason
		}
		for k, v := range when {
			st.Fields[k] = v
		}
		fill := func(f string) {
			if _, has := st.Fields[f]; !has {
				st.Fields[f] = "x"
			}
			if set, ok := spec.Enums[f]; ok && len(set) > 0 {
				member := false
				for _, m := range set {
					member = member || fmt.Sprint(st.Fields[f]) == m
				}
				if !member {
					st.Fields[f] = set[0]
				}
			}
		}
		for changed := true; changed; {
			n := len(st.Fields)
			req := append([]string(nil), spec.Required...)
			if code == CodePending {
				req = append(req, reg.PendingReasons[reason].Required...)
			}
			for _, rule := range spec.ConditionalRequired {
				hit := true
				for k, v := range rule.When {
					if fmt.Sprint(st.Fields[k]) != v {
						hit = false
					}
				}
				if hit {
					req = append(req, rule.Required...)
				}
			}
			for _, f := range req {
				fill(f)
			}
			for f := range st.Fields {
				fill(f)
			}
			changed = len(st.Fields) != n
		}
		return st
	}
	var out []*StateError
	if code == CodePending {
		reasons := make([]string, 0, len(reg.PendingReasons))
		for r := range reg.PendingReasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			out = append(out, build(nil, r))
		}
		return out
	}
	out = append(out, build(nil, ""))
	for _, rule := range spec.ConditionalRequired {
		out = append(out, build(rule.When, ""))
	}
	return out
}
