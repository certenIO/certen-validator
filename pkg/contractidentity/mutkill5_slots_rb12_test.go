// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the survivors and uncovered sites of slots.go.

func mk5Word(idx int, b byte) common.Hash {
	var w common.Hash
	w[idx] = b
	return w
}

func TestMutKill5SlotErrorText(t *testing.T) {
	if got := (&SlotError{Reason: "why"}).Error(); got != "storage slot: why" {
		t.Errorf("no detail: %q", got)
	}
	if got := (&SlotError{Reason: "why", Detail: "how"}).Error(); got != "storage slot: why: how" {
		t.Errorf("detail: %q", got)
	}
}

func TestMutKill5KeyUintZeroIsAKey(t *testing.T) {
	k, err := KeyUint(big.NewInt(0))
	if err != nil || k != (SlotKey{}) {
		t.Errorf("zero: %x %v", k, err)
	}
	if _, err := KeyUint(big.NewInt(-1)); err == nil {
		t.Error("a negative number is not a uint256 key")
	}
}

func TestMutKill5PackedAndWordReaders(t *testing.T) {
	if v, err := PackedUint64(common.Hash{}, 30, 4); err == nil || v != 0 {
		t.Errorf("PackedUint64 past the word: %d %v", v, err)
	}
	if a, err := PackedAddress(common.Hash{}, 20); err == nil || a != (common.Address{}) {
		t.Errorf("PackedAddress past the word: %x %v", a, err)
	}
	if b, err := PackedBool(common.Hash{}, 32); err == nil || b {
		t.Errorf("PackedBool past the word: %v %v", b, err)
	}
	if b, err := PackedBool(mk5Word(31, 2), 0); err == nil || b {
		t.Errorf("PackedBool of a byte of 2 must refuse and return false: %v %v", b, err)
	}
	if b, err := PackedBool(mk5Word(0, 2), 31); err == nil || b {
		t.Errorf("PackedBool of a byte of 2 at offset 31 must refuse: %v %v", b, err)
	}
	if b, err := WordBool(mk5Word(30, 1)); err == nil || b {
		t.Errorf("WordBool with byte 30 set: %v %v", b, err)
	}
	if b, err := WordBool(mk5Word(0, 1)); err == nil || b {
		t.Errorf("WordBool with byte 0 set: %v %v", b, err)
	}
	if b, err := WordBool(mk5Word(31, 2)); err == nil || b {
		t.Errorf("WordBool of 2: %v %v", b, err)
	}
	if b, err := WordBool(mk5Word(31, 1)); err != nil || !b {
		t.Errorf("WordBool of 1: %v %v", b, err)
	}
	if v, err := WordUint64(mk5Word(31, 7)); err != nil || v != 7 {
		t.Errorf("WordUint64: %d %v", v, err)
	}
	if v, err := WordUint64(mk5Word(23, 1)); err == nil || v != 0 {
		t.Errorf("WordUint64 with byte 23 set: %d %v", v, err)
	}
	if a, err := WordAddress(mk5Word(11, 1)); err == nil || a != (common.Address{}) {
		t.Errorf("WordAddress with byte 11 set: %x %v", a, err)
	}
}
