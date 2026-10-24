// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"strings"
	"testing"
)

// RB12-INDEX-FIX D3: `validator finality-index-selfcheck [--sample N]` reads its arguments strictly (a sample outside 1..1024, a stray word or
// a missing value is the usage text and exit 5, before anything is opened).
func TestFinalityIndexSelfCheckArguments(t *testing.T) {
	for _, c := range []struct {
		args   []string
		sample int
		ok     bool
	}{
		{nil, 16, true},
		{[]string{"--sample", "64"}, 64, true},
		{[]string{"--sample", "1024"}, 1024, true},
		{[]string{"--sample", "0"}, 0, false},
		{[]string{"--sample", "1025"}, 0, false},
		{[]string{"--sample", "many"}, 0, false},
		{[]string{"--sample"}, 0, false},
		{[]string{"sample", "4"}, 0, false},
	} {
		got, ok := parseFinalityIndexSelfCheckArgs(c.args)
		if ok != c.ok || (ok && got != c.sample) {
			t.Errorf("%v: sample %d ok %v, want %d %v", c.args, got, ok, c.sample, c.ok)
		}
	}
	var out, errw bytes.Buffer
	if code := runFinalityIndexSelfCheck([]string{"--sample", "0"}, &out, &errw); code != 5 || !strings.Contains(errw.String(), "usage: certen-validator finality-index-selfcheck") {
		t.Fatalf("a bad argument is the usage and its own exit code 5 (1 is a mismatch): %d %q", code, errw.String())
	}
}

// RB12-INDEX-B: `validator finality-arb-index-selfcheck` has the same strict arguments and the same usage code.
func TestFinalityArbIndexSelfCheckUsageIsExitCode5(t *testing.T) {
	var out, errw bytes.Buffer
	for _, args := range [][]string{{"--sample", "0"}, {"--sample"}, {"sample", "4"}, {"--sample", "1025"}} {
		errw.Reset()
		if code := runFinalityArbIndexSelfCheck(args, &out, &errw); code != 5 || !strings.Contains(errw.String(), "usage: certen-validator finality-arb-index-selfcheck") {
			t.Fatalf("%v: want the usage and exit code 5 (1 is a mismatch), got %d %q", args, code, errw.String())
		}
	}
}
