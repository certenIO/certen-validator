// Copyright 2026 Certen Protocol

package adiri

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// RB12-EPS-MUTKILL-3: the genesis-link chain rules, the 0x decoder and the empty batch, each with literal expectations.

type linkSpec struct {
	num    uint64
	parent *[32]byte // nil: the previous header's hash (the genesis hash for the first)
}

func buildLink(t *testing.T, genesis [32]byte, specs ...linkSpec) ([]byte, [][32]byte) {
	t.Helper()
	var file []byte
	var hashes [][32]byte
	prev := genesis
	for _, s := range specs {
		p := prev
		if s.parent != nil {
			p = *s.parent
		}
		raw := gateSpineHeader(t, s.num, p)
		h := crypto.Keccak256Hash(raw)
		file = append(file, raw...)
		hashes = append(hashes, h)
		prev = h
	}
	return file, hashes
}

func shaOf(file []byte) string { s := sha256.Sum256(file); return hex.EncodeToString(s[:]) }

func TestVerifyGenesisLinkJudgesTheShaTheChainAndTheEndByName(t *testing.T) {
	genesis := [32]byte{0x77}
	file, hs := buildLink(t, genesis, linkSpec{num: 1}, linkSpec{num: 2}, linkSpec{num: 3})
	n, err := VerifyGenesisLink(file, shaOf(file), genesis, NumHash{Number: 3, Hash: hs[2]})
	if err != nil || n != 3 {
		t.Fatalf("a linked chain: %d %v", n, err)
	}
	// a single header is a chain (block 1 on the genesis hash)
	one, oh := buildLink(t, genesis, linkSpec{num: 1})
	if n, err = VerifyGenesisLink(one, shaOf(one), genesis, NumHash{Number: 1, Hash: oh[0]}); err != nil || n != 1 {
		t.Fatalf("a one-header chain: %d %v", n, err)
	}
	// the sha is the first judgement
	_, err = VerifyGenesisLink(file, shaOf(one), genesis, NumHash{Number: 3, Hash: hs[2]})
	if err == nil || !strings.HasPrefix(err.Error(), "genesis link sha256 ") {
		t.Fatalf("a file with another sha: %v", err)
	}
	// an empty file with its own sha is empty, by that name
	_, err = VerifyGenesisLink(nil, shaOf(nil), genesis, NumHash{Number: 3, Hash: hs[2]})
	if err == nil || err.Error() != "the genesis link is empty" {
		t.Fatalf("an empty link: %v", err)
	}
	// bytes that are not a concatenation of RLP lists are refused by the splitter, not called empty
	junk := []byte("not a header chain")
	_, err = VerifyGenesisLink(junk, shaOf(junk), genesis, NumHash{Number: 3, Hash: hs[2]})
	if err == nil || err.Error() == "the genesis link is empty" {
		t.Fatalf("a non-RLP file: %v", err)
	}
	// an RLP list that is not a header is refused as header 0
	_, err = VerifyGenesisLink([]byte{0xc0}, shaOf([]byte{0xc0}), genesis, NumHash{Number: 3, Hash: hs[2]})
	if err == nil || !strings.HasPrefix(err.Error(), "header 0: ") {
		t.Fatalf("an unreadable header: %v", err)
	}
	// header 2 (index 1) does not carry the hash of header 1, yet the last header is the pinned tip: refused at the broken link
	bogus := [32]byte{0xbb}
	broken, bh := buildLink(t, genesis, linkSpec{num: 1}, linkSpec{num: 2, parent: &bogus}, linkSpec{num: 3})
	_, err = VerifyGenesisLink(broken, shaOf(broken), genesis, NumHash{Number: 3, Hash: bh[2]})
	if err == nil || !strings.Contains(err.Error(), "does not link") {
		t.Fatalf("a broken parent link: %v", err)
	}
	// the parent links hold but a number is skipped (5 after 1): refused as unlinked
	gap, gh := buildLink(t, genesis, linkSpec{num: 1}, linkSpec{num: 5}, linkSpec{num: 6})
	_, err = VerifyGenesisLink(gap, shaOf(gap), genesis, NumHash{Number: 6, Hash: gh[2]})
	if err == nil || !strings.Contains(err.Error(), "does not link") {
		t.Fatalf("a skipped number: %v", err)
	}
	// the tip must be the pinned number and hash
	if _, err = VerifyGenesisLink(file, shaOf(file), genesis, NumHash{Number: 2, Hash: hs[2]}); err == nil || !strings.HasPrefix(err.Error(), "the link ends at 3 ") {
		t.Fatalf("another tip number: %v", err)
	}
}

func TestDecode0xAcceptsExactlyTheEmptyPayloadAndNothingLoose(t *testing.T) {
	b, err := decode0x("0x")
	if err != nil || len(b) != 0 {
		t.Fatalf("0x: %v %v", b, err)
	}
	b, err = decode0x("0xab01")
	if err != nil || len(b) != 2 || b[0] != 0xab || b[1] != 0x01 {
		t.Fatalf("0xab01: %v %v", b, err)
	}
	for _, bad := range []string{"", "0", "ab", "1x", "0xa", "0xzz", "0Xab"} {
		if _, err := decode0x(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestAnEmptyBatchHasNoFailureInEitherMode(t *testing.T) {
	for _, mode := range []Mode{ModeOneByOne, ModeBatched} {
		i, reason, err := firstFailure(nil, mode, nil)
		if i != -1 || reason != "" || err != nil {
			t.Fatalf("mode %d: %d %q %v", mode, i, reason, err)
		}
	}
}
