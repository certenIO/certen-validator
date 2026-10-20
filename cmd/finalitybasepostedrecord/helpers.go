// Copyright 2026 Certen Protocol

package main

import (
	"context"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

func l2Header(ctx context.Context, number uint64) ([]byte, [32]byte, uint64, error) {
	s := &baseposted.JSONRPCSource{BlockURLs: []string{"https://sepolia.base.org"}}
	return s.HeaderByNumber(ctx, number)
}

func headerItems(raw []byte) []rlp.RawValue {
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil {
		panic(err)
	}
	return items
}

func setItem(raw []byte, idx int, item []byte) []byte {
	items := headerItems(raw)
	enc, _ := rlp.EncodeToBytes(item)
	items[idx] = enc
	out, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return out
}

// forgeParent returns the header with parentHash (item 0) flipped in its first byte.
func forgeParent(raw []byte) []byte {
	var p []byte
	_ = rlp.DecodeBytes(headerItems(raw)[0], &p)
	q := append([]byte(nil), p...)
	q[0] ^= 1
	return setItem(raw, 0, q)
}

// timestampOutside returns the header with its timestamp (item 11) set to ts.
func timestampOutside(raw []byte, ts int) ([]byte, [32]byte) {
	items := headerItems(raw)
	enc, _ := rlp.EncodeToBytes(uint64(ts))
	items[11] = enc
	out, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return out, hashOf(out)
}

func timestampOf(raw []byte) uint64 {
	var ts uint64
	_ = rlp.DecodeBytes(headerItems(raw)[11], &ts)
	return ts
}

func hashOf(b []byte) [32]byte { return [32]byte(crypto.Keccak256Hash(b)) }

// depositData returns the data string of a type-0x7e deposit (its last RLP item, which ends the encoding) and its offset.
func depositData(dep []byte) (int, []byte) {
	content, _, err := rlp.SplitList(dep[1:])
	if err != nil {
		panic(err)
	}
	var last []byte
	for len(content) > 0 {
		_, val, tail, err := rlp.Split(content)
		if err != nil {
			panic(err)
		}
		last = val
		content = tail
	}
	return len(dep) - len(last), last
}
