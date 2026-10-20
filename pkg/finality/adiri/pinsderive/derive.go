// Copyright 2026 Certen Protocol

// Package pinsderive re-derives the Adiri pins from public data. It is separate from package adiri so that the verifier does
// not link go-ethereum core (genesis recomputation).
package pinsderive

import (
	"bytes"
	"fmt"

	"github.com/mr-tron/base58"
	"gopkg.in/yaml.v3"

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

// SplitHeaders splits a concatenation of raw RLP headers (the genesis link file) into headers (implemented in package adiri,
// which checks the link at load).
func SplitHeaders(file []byte) ([][]byte, error) { return adiri.SplitHeaders(file) }

// VerifyGenesisLink checks the pinned genesis link (implemented in package adiri, where the embedded link is checked at load).
func VerifyGenesisLink(file []byte, wantSHA string, genesisHash [32]byte, epoch0 adiri.NumHash) (int, error) {
	return adiri.VerifyGenesisLink(file, wantSHA, genesisHash, epoch0)
}

// RawEqual reports byte equality (test helper kept here so the tests need no extra import).
func RawEqual(a, b []byte) bool { return bytes.Equal(a, b) }
