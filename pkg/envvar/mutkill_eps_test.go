// Copyright 2026 Certen Protocol

package envvar

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// RB12 EPSILON stage 2 (EPS-MUTKILL-1): the readers' decisions pinned one by one. An unset variable is the stated default with no error for
// EVERY reader; a value exactly at the bound is accepted and one below it is refused; a well-formed value above the bound is read; and a
// refused value hands back the default beside its refusal.

const mkKey = "CERTEN_ENVVAR_MUTKILL"

func TestEveryReaderTreatsAnUnsetVariableAsItsDefaultWithoutError(t *testing.T) {
	t.Setenv(mkKey, "")
	if v, err := Bool(mkKey, true); !v || err != nil {
		t.Errorf("Bool: (%v, %v)", v, err)
	}
	if v, err := Bool(mkKey, false); v || err != nil {
		t.Errorf("Bool false default: (%v, %v)", v, err)
	}
	if v, err := Int(mkKey, 7, 1); v != 7 || err != nil {
		t.Errorf("Int: (%v, %v)", v, err)
	}
	if v, err := Int64(mkKey, 7, 1); v != 7 || err != nil {
		t.Errorf("Int64: (%v, %v)", v, err)
	}
	if v, err := Uint64(mkKey, 7, 1); v != 7 || err != nil {
		t.Errorf("Uint64: (%v, %v)", v, err)
	}
	if v, err := Float(mkKey, 7.5, 1); v != 7.5 || err != nil {
		t.Errorf("Float: (%v, %v)", v, err)
	}
	if v, err := Duration(mkKey, 7*time.Second, time.Second); v != 7*time.Second || err != nil {
		t.Errorf("Duration: (%v, %v)", v, err)
	}
	if v, err := Seconds(mkKey, 7*time.Second, 1); v != 7*time.Second || err != nil {
		t.Errorf("Seconds: (%v, %v)", v, err)
	}
	if v, err := OneOf(mkKey, "a", "a", "b"); v != "a" || err != nil {
		t.Errorf("OneOf: (%v, %v)", v, err)
	}
	// A variable that holds only blanks is unset too.
	t.Setenv(mkKey, "   ")
	if v, err := Int(mkKey, 9, 1); v != 9 || err != nil {
		t.Errorf("blank Int: (%v, %v)", v, err)
	}
}

func TestIntegerReadersAcceptTheBoundAndRefuseOneBelowKeepingTheDefault(t *testing.T) {
	t.Setenv(mkKey, "5")
	if n, err := Int(mkKey, 1, 5); n != 5 || err != nil {
		t.Errorf("Int at the bound: (%v, %v)", n, err)
	}
	if n, err := Int64(mkKey, 1, 5); n != 5 || err != nil {
		t.Errorf("Int64 at the bound: (%v, %v)", n, err)
	}
	if n, err := Uint64(mkKey, 1, 5); n != 5 || err != nil {
		t.Errorf("Uint64 at the bound: (%v, %v)", n, err)
	}
	t.Setenv(mkKey, "9")
	if n, err := Int(mkKey, 1, 5); n != 9 || err != nil {
		t.Errorf("Int above the bound: (%v, %v)", n, err)
	}
	if n, err := Int64(mkKey, 1, 5); n != 9 || err != nil {
		t.Errorf("Int64 above the bound: (%v, %v)", n, err)
	}
	if n, err := Uint64(mkKey, 1, 5); n != 9 || err != nil {
		t.Errorf("Uint64 above the bound: (%v, %v)", n, err)
	}
	t.Setenv(mkKey, "-3")
	if n, err := Int64(mkKey, 1, -3); n != -3 || err != nil {
		t.Errorf("Int64 negative at its negative bound: (%v, %v)", n, err)
	}
	t.Setenv(mkKey, "4")
	if n, err := Int(mkKey, 1, 5); n != 1 || err == nil {
		t.Errorf("Int below the bound: (%v, %v)", n, err)
	}
	if n, err := Int64(mkKey, 1, 5); n != 1 || err == nil {
		t.Errorf("Int64 below the bound: (%v, %v)", n, err)
	}
	if n, err := Uint64(mkKey, 1, 5); n != 1 || err == nil {
		t.Errorf("Uint64 below the bound: (%v, %v)", n, err)
	}
}

func TestFloatDecidesFiniteAtOrAboveTheBoundAndAtMostOneE300(t *testing.T) {
	for _, c := range []struct {
		value   string
		ok      bool
		wantVal float64
	}{
		{"2.5", true, 2.5},
		{"1", true, 1},      // exactly the bound
		{"0.999", false, 0}, // just below the bound
		{"1e300", true, 1e300},
		{"1.0000000000001e300", false, 0},
		{"1e301", false, 0},
		{"Inf", false, 0},
		{"+Inf", false, 0},
		{"-Inf", false, 0},
		{"NaN", false, 0},
		{"abc", false, 0},
	} {
		t.Setenv(mkKey, c.value)
		got, err := Float(mkKey, 42, 1)
		if c.ok && (err != nil || got != c.wantVal) {
			t.Errorf("Float(%q) = (%v, %v), want (%v, nil)", c.value, got, err, c.wantVal)
		}
		if !c.ok && (err == nil || got != 42 || !strings.Contains(err.Error(), "at least 1")) {
			t.Errorf("Float(%q) = (%v, %v), want the default beside a refusal", c.value, got, err)
		}
	}
}

func TestDurationAcceptsTheBoundAndWellFormedValuesAndRefusesTheRest(t *testing.T) {
	def := 3 * time.Second
	for _, c := range []struct {
		value string
		ok    bool
		want  time.Duration
	}{
		{"1s", true, time.Second}, // exactly the bound
		{"90s", true, 90 * time.Second},
		{"5m", true, 5 * time.Minute},
		{"999ms", false, 0},
		{"0s", false, 0},
		{"-5s", false, 0},
		{"soon", false, 0},
		{"10", false, 0}, // a bare number has no unit
	} {
		t.Setenv(mkKey, c.value)
		got, err := Duration(mkKey, def, time.Second)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("Duration(%q) = (%v, %v), want (%v, nil)", c.value, got, err, c.want)
		}
		if !c.ok && (err == nil || got != def) {
			t.Errorf("Duration(%q) = (%v, %v), want the default beside a refusal", c.value, got, err)
		}
	}
}

func TestSecondsDecidesEachRefusalOnItsOwnAndNamesTheBound(t *testing.T) {
	def := 3 * time.Second
	// minSeconds 0 lets a value be unparseable without being below the bound: only the parse error can refuse it.
	for _, v := range []string{"seven", "1.5", "5s", "0x10"} {
		t.Setenv(mkKey, v)
		if got, err := Seconds(mkKey, def, 0); err == nil || got != def {
			t.Errorf("Seconds(%q, min 0) = (%v, %v): an unparseable value must be refused", v, got, err)
		}
	}
	// A parseable value below the bound is refused by the bound alone.
	t.Setenv(mkKey, "0")
	if got, err := Seconds(mkKey, def, 1); err == nil || got != def || !strings.Contains(err.Error(), "at least 1") {
		t.Errorf("Seconds(0, min 1) = (%v, %v)", got, err)
	}
	t.Setenv(mkKey, "-4")
	if got, err := Seconds(mkKey, def, -3); err == nil || got != def {
		t.Errorf("Seconds(-4, min -3) = (%v, %v)", got, err)
	}
	// Exactly the bound is read.
	t.Setenv(mkKey, "1")
	if got, err := Seconds(mkKey, def, 1); err != nil || got != time.Second {
		t.Errorf("Seconds(1, min 1) = (%v, %v)", got, err)
	}
	t.Setenv(mkKey, "0")
	if got, err := Seconds(mkKey, def, 0); err != nil || got != 0 {
		t.Errorf("Seconds(0, min 0) = (%v, %v)", got, err)
	}
	// The ceiling is exact and the refusal names the number of seconds that still fits.
	maxN := int64(math.MaxInt64 / int64(time.Second))
	t.Setenv(mkKey, fmt.Sprint(maxN+1))
	_, err := Seconds(mkKey, def, 1)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("at most %d", maxN)) {
		t.Errorf("the ceiling refusal must name %d seconds: %v", maxN, err)
	}
	if maxN != 9223372036 {
		t.Errorf("the largest whole number of seconds a time.Duration holds changed: %d", maxN)
	}
}

func TestOneOfIsCaseInsensitiveReturnsTheAllowedSpellingAndKeepsTheDefaultOnRefusal(t *testing.T) {
	t.Setenv(mkKey, " B ")
	if v, err := OneOf(mkKey, "a", "a", "B"); v != "b" || err != nil {
		t.Errorf("OneOf = (%v, %v)", v, err)
	}
	t.Setenv(mkKey, "c")
	v, err := OneOf(mkKey, "a", "a", "b")
	if err == nil || v != "a" || !strings.Contains(err.Error(), "one of a|b") {
		t.Errorf("OneOf refusal = (%v, %v)", v, err)
	}
}

func TestBoolRefusalKeepsTheDefaultBothWays(t *testing.T) {
	t.Setenv(mkKey, "maybe")
	if v, err := Bool(mkKey, true); !v || err == nil {
		t.Errorf("Bool(maybe, true) = (%v, %v)", v, err)
	}
	if v, err := Bool(mkKey, false); v || err == nil {
		t.Errorf("Bool(maybe, false) = (%v, %v)", v, err)
	}
}
