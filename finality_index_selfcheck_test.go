// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"strings"
	"testing"
)

// RB12-INDEX-FIX D3: `validator finality-index-selfcheck [--sample N]` reads its arguments strictly (a sample outside 1..1024, a stray word or
// a missing value is the usage text and exit 1, before anything is opened).
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
	if code := runFinalityIndexSelfCheck([]string{"--sample", "0"}, &out, &errw); code != 1 || !strings.Contains(errw.String(), "usage: certen-validator finality-index-selfcheck") {
		t.Fatalf("a bad argument is the usage and exit 1: %d %q", code, errw.String())
	}
}
