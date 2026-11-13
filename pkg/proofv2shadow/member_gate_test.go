// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"errors"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// DAX-1G, rules v16: the proposer attaches the initiating-signature member only from the height the chain reads it. The gate is the chain's own
// committed predicate (consensus G1InitiatorMemberInForce); an unset gate, a "no" and an error all attach nothing, so a certificate is never
// built with a member the chain would still judge with the member cleared.
func TestTheInitiatingSignatureIsAttachedOnlyWhenTheMemberIsInForce(t *testing.T) {
	hop := &proofv2.VoteHop{Page: "acc://erp.acme/book/1", Message: "ab", Signature: "cd", Block: 3}
	asm := func() *proofv2.Assembly { return &proofv2.Assembly{Initiating: hop} }
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, f) }
	for name, tc := range map[string]struct {
		gate func() (bool, error) // nil: never installed
		keep bool
	}{
		"no gate installed":          {nil, false},
		"the member is not in force": {func() (bool, error) { return false, nil }, false},
		"the member is in force":     {func() (bool, error) { return true, nil }, true},
		"the gate cannot be read":    {func() (bool, error) { return true, errors.New("ledger unavailable") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			logged = nil
			s := &Shadow{logf: logf}
			if tc.gate != nil {
				s.SetInitiatorMemberGate(tc.gate)
			}
			a := asm()
			s.gateInitiating(a)
			if (a.Initiating != nil) != tc.keep {
				t.Fatalf("the member is attached: %v, want %v", a.Initiating != nil, tc.keep)
			}
			if tc.keep && a.Initiating != hop {
				t.Fatal("the attached member is not the captured one")
			}
			if name == "the gate cannot be read" && len(logged) != 1 {
				t.Fatalf("an unreadable gate was not logged: %v", logged)
			}
		})
	}
	// A shadow with no logger and a failing gate does not panic; an assembly that is nil is left alone.
	s := &Shadow{}
	s.SetInitiatorMemberGate(func() (bool, error) { return false, errors.New("x") })
	a := asm()
	s.gateInitiating(a)
	s.gateInitiating(nil)
	if a.Initiating != nil {
		t.Fatal("an unreadable gate attached the member")
	}
}

// The gate installed on the Lazy shadow before it starts reaches the shadow when it becomes ready, and one installed after it is ready reaches it at once.
func TestLazyInstallsTheMemberGateOnTheShadow(t *testing.T) {
	yes := func() (bool, error) { return true, nil }
	l := NewLazy(nil, func(string, ...any) {})
	l.SetInitiatorMemberGate(yes)
	if l.memberGate == nil {
		t.Fatal("the gate was not kept for the shadow that is not ready yet")
	}
	s := &Shadow{}
	if s.initiatorMemberInForce() {
		t.Fatal("a shadow with no gate reports the member in force")
	}
	l.ready(s)
	if !s.initiatorMemberInForce() {
		t.Fatal("the gate installed before the shadow was ready did not reach it")
	}
	late := &Shadow{}
	later := NewLazy(nil, func(string, ...any) {})
	later.ready(late)
	if late.initiatorMemberInForce() {
		t.Fatal("a shadow made ready with no gate reports the member in force")
	}
	later.SetInitiatorMemberGate(yes)
	if !late.initiatorMemberInForce() {
		t.Fatal("the gate set after the shadow was ready did not reach it")
	}
}
