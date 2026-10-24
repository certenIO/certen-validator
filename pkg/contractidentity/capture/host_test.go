// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestHostKeyIsOneProviderWhateverTheSpelling(t *testing.T) {
	same := [][]string{
		{"https://p.io", "https://p.io:443", "https://P.IO/", "https://p.io./v2/key", "p.io:443"},
		{"http://p.io:80", "http://p.io"},
		{"https://[::1]:8545", "https://[0:0:0:0:0:0:0:1]:8545"},
	}
	for _, g := range same {
		for _, s := range g[1:] {
			if hostKey(s) != hostKey(g[0]) {
				t.Fatalf("%q and %q are one host: %q vs %q", g[0], s, hostKey(g[0]), hostKey(s))
			}
		}
	}
	for _, p := range [][2]string{{"https://p.io", "https://q.io"}, {"https://p.io:8545", "https://p.io"}, {"https://p.io", "https://sub.p.io"}} {
		if hostKey(p[0]) == hostKey(p[1]) {
			t.Fatalf("%q and %q are two hosts", p[0], p[1])
		}
	}
}

func TestAsciiTextIsBoundedASCIIAndRedacted(t *testing.T) {
	long := strings.Repeat("é", 3000) + " https://eth.example/v2/SECRETKEY0123456789abcdef0123456789"
	out := asciiText(long)
	if len(out) > 1024 {
		t.Fatalf("%d bytes", len(out))
	}
	for _, c := range []byte(out) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("non-ASCII byte %#x", c)
		}
	}
	if strings.Contains(asciiText("Post https://eth.example/v2/SECRETKEY0123456789abcdef0123456789abcdef: 502\x00 bad"), "SECRETKEY") {
		t.Fatal("the key survived")
	}
}

func TestAbiEncodeStringsEqualsSolidityEncoding(t *testing.T) {
	// abi.encode("a","bc") by hand: offsets 0x40 and 0x80, then length+padded data of each
	want := common.FromHex("0x" + strings.Repeat("00", 31) + "40" + strings.Repeat("00", 31) + "80" +
		strings.Repeat("00", 31) + "01" + "61" + strings.Repeat("00", 31) + strings.Repeat("00", 31) + "02" + "6263" + strings.Repeat("00", 30))
	if got := abiEncodeStrings([]byte("a"), []byte("bc")); !bytes.Equal(got, want) {
		t.Fatalf("got %x\nwant %x", got, want)
	}
	// 32-byte and empty strings: the padding rule
	long := bytes.Repeat([]byte{7}, 32)
	got := abiEncodeStrings(long, nil)
	if len(got) != 32*2+32+32+32 || common.BytesToHash(got[32:64]).Big().Uint64() != 64+32+32 || !bytes.Equal(crypto.Keccak256(got[:32]), crypto.Keccak256(common.LeftPadBytes([]byte{0x40}, 32))) {
		t.Fatalf("encoding of a 32-byte and an empty string: %x", got)
	}
}
