// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

type spineRegistry struct {
	States map[string]struct {
		Group    string              `json:"group"`
		Scope    string              `json:"scope"`
		Required []string            `json:"required"`
		Optional []string            `json:"optional"`
		Enums    map[string][]string `json:"enums"`
	} `json:"states"`
	PendingReasons map[string]struct {
		Required []string `json:"required"`
	} `json:"pending_reasons"`
}

func loadSpineRegistry(t *testing.T) spineRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r spineRegistry
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// conformsTo reports a field of s that the registry does not allow, or a required field s lacks.
func conformsTo(t *testing.T, r spineRegistry, s *finality.StateError) string {
	t.Helper()
	spec, ok := r.States[s.Code]
	if !ok {
		return "code " + s.Code + " is not registered"
	}
	required := append([]string(nil), spec.Required...)
	if s.Code == finality.CodePending {
		pr, ok := r.PendingReasons[s.Fields["reason"].(string)]
		if !ok {
			return "pending reason " + s.Fields["reason"].(string) + " is not in the closed set"
		}
		required = append(required, pr.Required...)
	}
	allowed := map[string]bool{}
	for _, f := range append(required, spec.Optional...) {
		allowed[f] = true
	}
	for _, f := range required {
		if _, has := s.Fields[f]; !has {
			return s.Code + " lacks required field " + f
		}
	}
	for f := range s.Fields {
		if !allowed[f] {
			return s.Code + " carries unregistered field " + f
		}
	}
	for f, set := range spec.Enums {
		if v, has := s.Fields[f]; has {
			found := false
			for _, m := range set {
				found = found || m == v
			}
			if !found {
				return s.Code + " field " + f + " is outside its closed set"
			}
		}
	}
	return ""
}

func TestTheRegistryRecordsTheNewPendingReasonAndTheNewOperationalState(t *testing.T) {
	r := loadSpineRegistry(t)
	pr, ok := r.PendingReasons[PendingAwaitingSpine]
	if !ok || strings.Join(sorted(pr.Required), ",") != "have,need,next_attempt_at" {
		t.Fatalf("pending reason %s: %+v", PendingAwaitingSpine, pr)
	}
	spec, ok := r.States[CodeSpineRowInvalid]
	if !ok {
		t.Fatalf("%s is not registered", CodeSpineRowInvalid)
	}
	if spec.Scope != "go_operational" || strings.Join(spec.Required, ",") != "block,chain,reason" || strings.Join(spec.Optional, ",") != "at,attempt,got_hash,item,next_attempt_at,want_hash" {
		t.Fatalf("%+v", spec)
	}
	want := sorted([]string{SpineRowMalformed, SpineRowNumbers, SpineRowNotChained, SpineRowTopMismatch, SpineRowConflict})
	if got := sorted(spec.Enums["reason"]); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("enums.reason %v, constants %v", got, want)
	}
	for _, name := range []string{"required", "optional"} {
		l := spec.Required
		if name == "optional" {
			l = spec.Optional
		}
		if !sortedAlready(l) {
			t.Fatalf("%s fields must be sorted: %v", name, l)
		}
	}
	if p, ok := r.States[finality.CodePending]; !ok || !contains(p.Optional, "cause") || !sortedAlready(p.Optional) {
		t.Fatalf("finality_pending optional %v must hold cause, sorted", p.Optional)
	}
}

func sortedAlready(l []string) bool { return sort.StringsAreSorted(l) }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The states this code raises are exactly the registered shapes: every reason of the closed set, with and without the hashes, and the
// progress state as the builder produces it (a throttle, a failure and a spent budget).
func TestTheStatesTheSpineWalkRaisesConformToTheRegistry(t *testing.T) {
	r := loadSpineRegistry(t)
	for _, reason := range []string{SpineRowMalformed, SpineRowNumbers, SpineRowNotChained, SpineRowTopMismatch, SpineRowConflict} {
		for _, f := range []*spineFault{{Reason: reason}, {Reason: reason, At: 12, Hashes: true, Want: [32]byte{1}, Got: [32]byte{2}}} {
			if msg := conformsTo(t, r, spineRowInvalid(Span{Start: 1, End: 40}, f)); msg != "" {
				t.Errorf("%s: %s", reason, msg)
			}
		}
	}
	ch := newSynth(1_000_000, 300, 1)
	for name, hook := range map[string]func(call int, from, to uint64, out [][]byte) ([][]byte, error){
		"a throttle": func(int, uint64, uint64, [][]byte) ([][]byte, error) {
			return nil, &SourceError{Failures: []EndpointFailure{{Throttled: true, RetryAfter: 9e9}}}
		},
		"a failure":   func(int, uint64, uint64, [][]byte) ([][]byte, error) { return nil, errors.New("down") },
		"no failures": nil,
	} {
		clk := newClock()
		src := ch.model(clk, 0)
		src.hook = hook
		budget := DefaultSpineBudget
		if name == "no failures" {
			src.perHdr, budget = 1e9, 1 // one fetch, then the budget is spent
		}
		p := spineProver(src, nil, clk, budget)
		_, pend, err := p.spineFor(context.Background(), ch.leg(1_000_010), ch.candidate())
		if err != nil || pend == nil {
			t.Fatalf("%s: %v %v", name, pend, err)
		}
		if msg := conformsTo(t, r, pend.State()); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
}
