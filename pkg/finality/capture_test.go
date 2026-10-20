// Copyright 2026 Certen Protocol

package finality

import (
	"strings"
	"testing"
)

func TestCaptureItemNamesAreTheDocumentedAlphabetAndBoundedAtTheLimit(t *testing.T) {
	ok := []string{"hdr", "inbox", "tx/3", "txnodes/12", "blob/0/1", "basefinal/game/00ff", "a_b-c", strings.Repeat("a", MaxCaptureItem)}
	for _, item := range ok {
		if err := CheckCaptureItem(item); err != nil {
			t.Errorf("%q: %v", item, err)
		}
	}
	bad := []string{"", "Hdr", "tx/", "/tx", "tx//3", "tx 3", "tx.3", "tx\n", strings.Repeat("a", MaxCaptureItem+1)}
	for _, item := range bad {
		if err := CheckCaptureItem(item); err == nil {
			t.Errorf("%q was accepted", item)
		}
	}
}

func TestCaptureKeyNamesChainBlockHashPrefixAndItem(t *testing.T) {
	k := CaptureKey{Chain: 84532, L1Block: 777, L1Hash: [32]byte{0xab, 0xcd, 0xef, 0x01}, Item: "tx/3"}
	if got, want := k.String(), "chain 84532 l1 777 abcdef01 item tx/3"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}
