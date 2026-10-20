// Copyright 2026 Certen Protocol

// Package pinsderive re-derives the Adiri pins from public data. It is separate from package adiri so that the verifier does
// not link go-ethereum core (genesis recomputation).
package pinsderive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
	"gopkg.in/yaml.v3"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// Re-derivation of the Adiri pins from public data (V2_SPEC_S7 4.4, annex A7). Everything here is a pure function of files
// anyone can fetch: telcoin-network chain-configs/testnet/committee.yaml at tag v0.16.0-adiri, the node's tn_genesis, the
// 290-header genesis link and tn_epochRecord(0). The tests re-run them offline against files stored under testdata; the
// recorder (vectorgen) fetches them.

// CommitteeFromYAML reads the protocol keys of committee.yaml in file order as 96-byte compressed G2 keys.
func CommitteeFromYAML(raw []byte) ([][]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("committee.yaml is empty")
	}
	root := doc.Content[0]
	var auth *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "authorities" {
			auth = root.Content[i+1]
		}
	}
	if auth == nil {
		return nil, fmt.Errorf("committee.yaml has no authorities")
	}
	var keys [][]byte
	for i := 0; i+1 < len(auth.Content); i += 2 {
		k, err := base58.Decode(auth.Content[i].Value)
		if err != nil || len(k) != adiri.KeyBytes {
			return nil, fmt.Errorf("authority %d is not a 96-byte base58 key", i/2)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// SplitHeaders splits a concatenation of raw RLP headers (the genesis link file) into headers.
func SplitHeaders(file []byte) ([][]byte, error) {
	var out [][]byte
	rest := file
	for len(rest) > 0 {
		n, err := rlpListLen(rest)
		if err != nil {
			return nil, fmt.Errorf("header %d: %v", len(out), err)
		}
		out = append(out, rest[:n])
		rest = rest[n:]
	}
	return out, nil
}

func rlpListLen(b []byte) (int, error) {
	if len(b) == 0 || b[0] < 0xc0 {
		return 0, fmt.Errorf("not an RLP list")
	}
	if b[0] <= 0xf7 {
		n := 1 + int(b[0]-0xc0)
		if n > len(b) {
			return 0, fmt.Errorf("truncated")
		}
		return n, nil
	}
	l := int(b[0] - 0xf7)
	if len(b) < 1+l {
		return 0, fmt.Errorf("truncated")
	}
	n := 0
	for _, c := range b[1 : 1+l] {
		n = n<<8 | int(c)
	}
	if n+1+l > len(b) {
		return 0, fmt.Errorf("truncated")
	}
	return 1 + l + n, nil
}

// VerifyGenesisLink checks the pinned genesis link: the file hashes to wantSHA and holds the headers of blocks 1..epoch0.Number
// (290 headers, 176,758 B) as a parentHash chain whose first header has parentHash = the genesis block hash and number 1 and
// whose last is epoch0 (number and hash). The genesis block itself is recomputed from tn_genesis by package genesis. It returns
// the number of headers. This is what binds the committee chain to this incarnation's genesis block (annex A7 step 3).
func VerifyGenesisLink(file []byte, wantSHA string, genesisHash [32]byte, epoch0 adiri.NumHash) (int, error) {
	sum := sha256.Sum256(file)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return 0, fmt.Errorf("genesis link sha256 %x, want %s", sum, wantSHA)
	}
	hs, err := SplitHeaders(file)
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 {
		return 0, fmt.Errorf("the genesis link is empty")
	}
	var prev finality.HeaderFields
	for i, raw := range hs {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return 0, fmt.Errorf("header %d: %v", i, err)
		}
		if i == 0 && (h.ParentHash != genesisHash || h.Number != 1) {
			return 0, fmt.Errorf("the first header is %d with parent %x, want block 1 with the genesis hash %x", h.Number, h.ParentHash, genesisHash)
		}
		if i > 0 && (h.ParentHash != prev.Hash || h.Number != prev.Number+1) {
			return 0, fmt.Errorf("header %d does not link to header %d", h.Number, prev.Number)
		}
		prev = h
	}
	if prev.Number != epoch0.Number || prev.Hash != epoch0.Hash {
		return 0, fmt.Errorf("the link ends at %d %x, want epoch0_final_state %d %x", prev.Number, prev.Hash, epoch0.Number, epoch0.Hash)
	}
	return len(hs), nil
}

// RawEqual reports byte equality (test helper kept here so the tests need no extra import).
func RawEqual(a, b []byte) bool { return bytes.Equal(a, b) }
