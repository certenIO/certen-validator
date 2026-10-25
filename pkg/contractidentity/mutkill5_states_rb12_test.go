// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for states.go AsState and the short-string branch of reads.go ReadBytes.

func TestMutKill5AsState(t *testing.T) {
	if s, ok := AsState(errors.New("plain")); ok || s != nil {
		t.Errorf("a plain error holds no state: %v %v", s, ok)
	}
	if s, ok := AsState(nil); ok || s != nil {
		t.Errorf("nil holds no state: %v %v", s, ok)
	}
	st := stRefused()
	if s, ok := AsState(fmt.Errorf("wrapped: %w", st)); !ok || s != st {
		t.Errorf("a wrapped state is found: %v %v", s, ok)
	}
}

func TestMutKill5ReadBytesShortStrings(t *testing.T) {
	w, strs := honestWorld(t)
	sto := w.storage[w.accounts[1].addr]
	var all [][]byte
	for _, i := range []uint64{20, 21} {
		all = append(all, provePath(t, sto, SlotIndex(i).Bytes())...)
	}
	ns := mustNS(t, asContainerOrder(all))
	before := ns.VisitedCount()
	for i, k := range []string{"empty", "s31"} {
		got, err := ReadBytes(sto.Hash(), ns, SlotIndex(uint64(20+i)), 1024)
		if err != nil || !bytes.Equal(got, strs[k]) || (k == "s31" && !strings.HasPrefix(string(got), "aaaa")) {
			t.Fatalf("%s: %q %v", k, got, err)
		}
	}
	if ns.VisitedCount() == before {
		t.Error("the head slots were read")
	}
}
