// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the survivors and uncovered sites of reads.go.

func mk5RLP(t *testing.T, items ...any) []byte {
	t.Helper()
	b, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMutKill5ReadErrorText(t *testing.T) {
	h := common.HexToHash("0x01")
	miss := (&ReadError{Kind: ReadMissingNode, Missing: h}).Error()
	if !strings.HasSuffix(miss, " node="+h.Hex()) {
		t.Errorf("missing node must name the node: %q", miss)
	}
	if other := (&ReadError{Kind: ReadWalkFailed, Missing: h}).Error(); strings.Contains(other, "node=") || strings.HasSuffix(other, ": ") {
		t.Errorf("a non-missing kind names no node and an empty detail adds nothing: %q", other)
	}
	if got := (&ReadError{Kind: ReadWalkFailed, Detail: "dd"}).Error(); !strings.HasSuffix(got, ": dd") {
		t.Errorf("detail: %q", got)
	}
}

func TestMutKill5WalkReaderWithoutSetHoldsNothing(t *testing.T) {
	if ok, err := (&walkReader{}).Has([]byte{1, 2}); ok || err != nil {
		t.Errorf("Has on a reader with no node set = %v, %v", ok, err)
	}
}

func TestMutKill5ReadStringPropagatesTheError(t *testing.T) {
	s, err := ReadString(common.HexToHash("0x01"), &NodeSet{}, common.Hash{}, 10)
	if err == nil || s != "" {
		t.Errorf("ReadString over an empty node set = %q, %v", s, err)
	}
}

func TestMutKill5CheckTrieNodeRefusals(t *testing.T) {
	zero := make([]byte, 0)
	ref := bytes.Repeat([]byte{7}, 32)
	branch := func(last any) []byte {
		items := make([]any, 0, 17)
		for i := 0; i < 16; i++ {
			items = append(items, zero)
		}
		return mk5RLP(t, append(items, last)...)
	}
	cases := []struct {
		name string
		node []byte
		want string // "" = accepted
	}{
		{"leaf", mk5RLP(t, []byte{0x20}, []byte{1}), ""},
		{"truncated element list", []byte{0xc2, 0x81, 0x00}, "invalid element list"},
		{"path is a list", mk5RLP(t, []any{[]byte{1}}, []byte{1}), "hex-prefix path is not a string"},
		{"even path with a padding nibble", mk5RLP(t, []byte{0x21}, []byte{1}), "even-length path with a non-zero padding nibble"},
		{"leaf value is a list", mk5RLP(t, []byte{0x20}, []any{[]byte{1}}), "leaf value is not a string"},
		{"extension", mk5RLP(t, []byte{0x11}, ref), ""},
		{"extension without a child", mk5RLP(t, []byte{0x11}, zero), "extension without a child"},
		{"extension with an empty path", mk5RLP(t, []byte{0x00}, ref), "extension with an empty path"},
		{"extension child of five bytes", mk5RLP(t, []byte{0x11}, []byte{1, 2, 3, 4, 5}), "extension child: reference of 5 bytes"},
		{"branch value is a list", branch([]any{[]byte{1}}), "branch value is not a string"},
		{"branch carrying a value", branch([]byte{9}), "branch carrying a value"},
	}
	for _, c := range cases {
		err := checkTrieNode(c.node)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
}

func TestMutKill5CheckTrieRef(t *testing.T) {
	leaf := func(valueLen int) []byte {
		return mk5RLP(t, []byte{0x20}, bytes.Repeat([]byte{5}, valueLen))
	}
	l31, l32 := leaf(28), leaf(29)
	if len(l31) != 31 || len(l32) != 32 {
		t.Fatalf("fixture sizes %d %d", len(l31), len(l32))
	}
	tail := []byte{0xAA}
	rest, empty, err := checkTrieRef(append(append([]byte(nil), l31...), tail...))
	if err != nil || empty || !bytes.Equal(rest, tail) {
		t.Errorf("31-byte embedded node: rest=%x empty=%v err=%v", rest, empty, err)
	}
	rest, empty, err = checkTrieRef(l32)
	if err == nil || empty || rest != nil || !strings.Contains(err.Error(), "embedded node of 32 bytes") {
		t.Errorf("32-byte embedded node: rest=%x empty=%v err=%v", rest, empty, err)
	}
	bad := mk5RLP(t, []byte{0x20}, []byte{})
	rest, empty, err = checkTrieRef(bad)
	if err == nil || empty || rest != nil || !strings.Contains(err.Error(), "embedded node: leaf with an empty value") {
		t.Errorf("invalid embedded node: rest=%x empty=%v err=%v", rest, empty, err)
	}
	rest, empty, err = checkTrieRef([]byte{0x82, 0x01})
	if err == nil || empty || rest != nil || strings.Contains(err.Error(), "reference of") {
		t.Errorf("truncated reference: rest=%x empty=%v err=%v", rest, empty, err)
	}
	rest, empty, err = checkTrieRef([]byte{0x85, 1, 2, 3, 4, 5})
	if err == nil || empty || rest != nil || !strings.Contains(err.Error(), "reference of 5 bytes") {
		t.Errorf("five-byte reference: rest=%x empty=%v err=%v", rest, empty, err)
	}
	rest, empty, err = checkTrieRef([]byte{0x80, 0x01})
	if err != nil || !empty || !bytes.Equal(rest, []byte{0x01}) {
		t.Errorf("empty reference: rest=%x empty=%v err=%v", rest, empty, err)
	}
}
