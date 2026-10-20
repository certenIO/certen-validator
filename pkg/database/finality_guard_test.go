// Copyright 2026 Certen Protocol

package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/finality"
)

// A refusal of the table trigger (SQLSTATE 23001) is the registered go_operational state finality_guard_refused, not a value of
// the closed finality_chain_broken checks; a unique violation stays the append race; anything else is returned unchanged.
func TestFinalityGuardRefusalIsARegisteredStateOutsideTheClosedChainBrokenChecks(t *testing.T) {
	const id = "01234567-89ab-4def-8012-3456789abcde"
	err := appendInsertError(id, 3, &pq.Error{Code: "23001", Message: "addendum 3 of x is a second addendum at level 3"})
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != finality.CodeGuardRefused {
		t.Fatalf("the trigger refusal is %v", err)
	}
	if st.Fields["proof_id"] != id || st.Fields["seq"] != uint64(3) || !strings.Contains(st.Fields["cause"].(string), "second addendum") {
		t.Fatalf("%+v", st.Fields)
	}
	if st.Code == finality.CodeChainBroken {
		t.Fatal("the guard refusal must not be a finality_chain_broken state")
	}
	conflict := appendInsertError(id, 3, &pq.Error{Code: "23505"})
	if c, ok := finality.AsNamed(conflict); !ok || c.Code != finality.CodeAppendConflict {
		t.Fatalf("a unique violation is the append race: %v", conflict)
	}
	other := errors.New("connection reset")
	if got := appendInsertError(id, 3, other); got != other {
		t.Fatalf("an unrelated error was rewritten: %v", got)
	}
}
