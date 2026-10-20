// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func hexLower(b []byte) string { return hex.EncodeToString(b) }

// HeaderFields are the items of a raw execution-block header that S7 reads (V2_SPEC_S7 section 0). A header is raw RLP,
// hashed as given and read POSITIONALLY, never decoded into a typed Header: the item count is not fixed (Sepolia L1 headers
// have 23 items, Fulu-era 21), and a typed decode fails on an unknown future trailing field while hashing succeeds.
// pkg/ethproof/settlement.go decodes a typed Header and is not changed by RB11 (finding RB11-F4).
type HeaderFields struct {
	Hash            [32]byte  // keccak256 of the raw header
	ParentHash      [32]byte  // item 0
	StateRoot       [32]byte  // item 3
	TransactionRoot [32]byte  // item 4
	ReceiptsRoot    [32]byte  // item 5
	Number          uint64    // item 8
	Timestamp       uint64    // item 11
	WithdrawalsRoot *[32]byte // item 16, present iff the header has at least 17 items
	Items           int
}

// ReadHeader reads the fields positionally from a raw RLP header. It refuses (finality_evidence_malformed, part "header")
// anything that is not one RLP list of at least 12 items whose positional fields have the right shapes.
func ReadHeader(raw []byte) (HeaderFields, error) {
	var h HeaderFields
	content, rest, err := rlp.SplitList(raw)
	if err != nil {
		return h, Malformed("header", "not an RLP list: "+err.Error(), len(raw), 0)
	}
	if len(rest) != 0 {
		return h, Malformed("header", "trailing bytes after the RLP list", len(rest), 0)
	}
	var items [][]byte
	for len(content) > 0 {
		kind, val, tail, err := rlp.Split(content)
		if err != nil {
			return h, MalformedAt("header", len(items), "bad RLP item: "+err.Error(), len(content), 0)
		}
		if kind == rlp.List {
			val = nil // positional fields are strings; a list in a positional slot fails the shape check below
		}
		items = append(items, val)
		content = tail
	}
	h.Items = len(items)
	if h.Items < 12 {
		return h, Malformed("header", "fewer than 12 items", h.Items, 12)
	}
	hashAt := func(i int, dst *[32]byte) error {
		if len(items[i]) != 32 {
			return MalformedAt("header", i, "not a 32-byte string", len(items[i]), 32)
		}
		copy(dst[:], items[i])
		return nil
	}
	uintAt := func(i int, dst *uint64) error {
		v := items[i]
		if len(v) > 8 || (len(v) > 0 && v[0] == 0) {
			return MalformedAt("header", i, "not a canonical unsigned integer of at most 8 bytes", len(v), 8)
		}
		var n uint64
		for _, c := range v {
			n = n<<8 | uint64(c)
		}
		*dst = n
		return nil
	}
	for _, f := range []struct {
		i   int
		dst *[32]byte
	}{{0, &h.ParentHash}, {3, &h.StateRoot}, {4, &h.TransactionRoot}, {5, &h.ReceiptsRoot}} {
		if err := hashAt(f.i, f.dst); err != nil {
			return h, err
		}
	}
	if err := uintAt(8, &h.Number); err != nil {
		return h, err
	}
	if err := uintAt(11, &h.Timestamp); err != nil {
		return h, err
	}
	if h.Items >= 17 {
		var w [32]byte
		if err := hashAt(16, &w); err != nil {
			return h, err
		}
		h.WithdrawalsRoot = &w
	}
	h.Hash = [32]byte(crypto.Keccak256Hash(raw))
	return h, nil
}
