// Copyright 2026 Certen Protocol

package contractidentity

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the pure helpers of steps_2b1.go and steps_2b2.go.

func TestMutKill5B1ReadFailure(t *testing.T) {
	root := "settle"
	a := common.Address{7}
	defSlot, errSlot := common.Hash{1}, common.Hash{2}
	st, err := b1ReadFailure(fmt.Errorf("wrapped: %w", &ReadError{Kind: ReadWalkFailed, Slot: &errSlot}), root, a, defSlot)
	if err != nil || st == nil || st.Code != CodeProofInvalid || st.Fields["slot"] != errSlot || st.Fields["root"] != root || st.Fields["address"] != a {
		t.Errorf("a read error that names its slot: %v %v", st, err)
	}
	st, err = b1ReadFailure(&ReadError{Kind: ReadWalkFailed}, root, a, defSlot)
	if err != nil || st == nil || st.Fields["slot"] != defSlot {
		t.Errorf("a read error without a slot keeps the caller's slot: %v %v", st, err)
	}
	plain := errors.New("not a read error")
	if st, err := b1ReadFailure(plain, root, a, defSlot); st != nil || err != plain {
		t.Errorf("any other error is returned as it is: %v %v", st, err)
	}
}

func TestMutKill5B1StatedStatesWithoutAnUnprovenRow(t *testing.T) {
	auth, window, ok, err := b1StatedStates(&Stated{Reason: "no_such_reason"})
	if auth != nil || window != nil || ok || err == nil || !strings.Contains(err.Error(), "has no unproven row") {
		t.Errorf("a reason without a row: %v %v %v %v", auth, ok, err, window)
	}
}

func TestMutKill5B2KeyLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"A:5", "A:7", true}, {"A:7", "A:5", false}, {"A:5", "A:x", true}, {"A:x", "A:5", false}, {"A:x", "A:y", true}, {"A:y", "A:x", false},
		{"A", "A:1", true}, {"A:1", "A", false}, {"A:10", "A:9", false}, {"A:9", "A:10", true}, {"A:9", "B:1", true}, {"B:1", "A:9", false},
	} {
		if got := b2KeyLess(c.a, c.b); got != c.want {
			t.Errorf("b2KeyLess(%q,%q) = %v", c.a, c.b, got)
		}
	}
}

func TestMutKill5B2Unchanged(t *testing.T) {
	ch := func(rows ...string) []AuthDiff {
		var out []AuthDiff
		for _, r := range rows {
			out = append(out, AuthDiff{Row: r})
		}
		return out
	}
	for _, c := range []struct {
		ch   []AuthDiff
		rows []string
		want bool
	}{
		{ch("A01"), []string{"A01"}, false},
		{ch("A02"), []string{"A01"}, true},
		{ch("A01:x"), []string{"A01"}, false},
		{ch("A011"), []string{"A01"}, true},
		{ch("A02", "A01"), []string{"A03", "A01"}, false},
		{nil, []string{"A01"}, true},
		{ch("A01"), nil, true},
	} {
		if got := b2Unchanged(c.ch, c.rows); got != c.want {
			t.Errorf("b2Unchanged(%v,%v) = %v", c.ch, c.rows, got)
		}
	}
}

// TestMutKill5ABIFieldPathsStayWithinSixtyFourCharacters pins the argument for b1Step17's truncation of ae.Field to 64 characters: no field path of
// the comprehensive-proof call schema, with an array index of up to ten digits at every array on the path, is longer than 64 characters, so the
// truncation can never remove a character (the mutants field[:63] and field[:65] are equivalent).
func TestMutKill5ABIFieldPathsStayWithinSixtyFourCharacters(t *testing.T) {
	longest, at := 0, ""
	var walk func(p string, ty *abiT, extra, depth int)
	walk = func(p string, ty *abiT, extra, depth int) {
		if n := len(p) + extra; n > longest {
			longest, at = n, p
		}
		if depth > 12 {
			t.Fatalf("schema deeper than 12 at %s", p)
		}
		switch ty.k {
		case 'd', 'f':
			walk(p+"[0]", ty.elem, extra+9, depth+1)
		case 't':
			for _, f := range ty.fields {
				name := f.name
				if p != "" {
					name = p + "." + f.name
				}
				walk(name, f.t, extra, depth+1)
			}
		}
	}
	for _, f := range []abiF{fd("anchorId", tB32()), fd("proof", certenProofType(DefaultABILimits()))} {
		walk(f.name, f.t, 0, 0)
	}
	if longest > 64 {
		t.Errorf("a field path of %d characters (%s) would be truncated", longest, at)
	}
}
