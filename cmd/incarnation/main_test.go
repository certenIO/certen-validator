package main

import (
	"strings"
	"testing"
)

// The daily check (RB5 close-out §3.10): equal is 0, another incarnation is 3 naming both values, a malformed
// expectation is a usage error.
func TestCheckExpected(t *testing.T) {
	var got [32]byte
	got[0], got[31] = 0xca, 0xa0
	if code, _ := checkExpected("0xca000000000000000000000000000000000000000000000000000000000000a0", got); code != 0 {
		t.Fatalf("equal incarnation: exit %d", code)
	}
	code, msg := checkExpected("0xcb000000000000000000000000000000000000000000000000000000000000a0", got)
	if code != 3 || !strings.Contains(msg, "INCARNATION CHANGED") || !strings.Contains(msg, "0xcb") || !strings.Contains(msg, "0xca") {
		t.Fatalf("another incarnation: exit %d, %q", code, msg)
	}
	if code, _ := checkExpected("0x1234", got); code != 2 {
		t.Fatalf("a malformed expectation: exit %d", code)
	}
}
