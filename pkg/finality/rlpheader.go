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

// headerItem is one RLP item of the header: its content bytes and whether it was an RLP list.
type headerItem struct {
	val    []byte
	isList bool
}

// ReadHeader reads the fields positionally from a raw RLP header. It refuses (finality_evidence_malformed, part "header")
// anything that is not one RLP list of at least 12 items whose positional fields (items 0, 3, 4, 5, 8, 11 and, when the header
// has 17 or more items, 16) are RLP STRINGS of the right shape: an item that is an RLP list in one of those slots is refused
// as header_item_is_list with its index, in ascending slot order. The first failing slot is the one reported.
func ReadHeader(raw []byte) (HeaderFields, error) {
	var h HeaderFields
	content, rest, err := rlp.SplitList(raw)
	if err != nil {
		return h, Malformed("header", ReasonHeaderNotRLPList, len(raw), 0)
	}
	if len(rest) != 0 {
		return h, Malformed("header", ReasonHeaderTrailingBytes, len(rest), 0)
	}
	var items []headerItem
	for len(content) > 0 {
		kind, val, tail, err := rlp.Split(content)
		if err != nil {
			return h, MalformedAt("header", len(items), ReasonHeaderBadItem, len(content), 0)
		}
		items = append(items, headerItem{val: val, isList: kind == rlp.List})
		content = tail
	}
	h.Items = len(items)
	if h.Items < 12 {
		return h, Malformed("header", ReasonHeaderTooFewItems, h.Items, 12)
	}
	hashAt := func(i int, dst *[32]byte) error {
		if items[i].isList {
			return MalformedAt("header", i, ReasonHeaderItemIsList, len(items[i].val), 32)
		}
		if len(items[i].val) != 32 {
			return MalformedAt("header", i, ReasonHeaderItemNot32Bytes, len(items[i].val), 32)
		}
		copy(dst[:], items[i].val)
		return nil
	}
	uintAt := func(i int, dst *uint64) error {
		if items[i].isList {
			return MalformedAt("header", i, ReasonHeaderItemIsList, len(items[i].val), 8)
		}
		v := items[i].val
		if len(v) > 8 || (len(v) > 0 && v[0] == 0) {
			return MalformedAt("header", i, ReasonHeaderItemNotCanonUint, len(v), 8)
		}
		var n uint64
		for _, c := range v {
			n = n<<8 | uint64(c)
		}
		*dst = n
		return nil
	}
	var w [32]byte
	// ascending slot order: 0, 3, 4, 5, 8, 11, 16
	steps := []func() error{
		func() error { return hashAt(0, &h.ParentHash) },
		func() error { return hashAt(3, &h.StateRoot) },
		func() error { return hashAt(4, &h.TransactionRoot) },
		func() error { return hashAt(5, &h.ReceiptsRoot) },
		func() error { return uintAt(8, &h.Number) },
		func() error { return uintAt(11, &h.Timestamp) },
	}
	if h.Items >= 17 {
		steps = append(steps, func() error { return hashAt(16, &w) })
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return h, err
		}
	}
	if h.Items >= 17 {
		h.WithdrawalsRoot = &w
	}
	h.Hash = [32]byte(crypto.Keccak256Hash(raw))
	return h, nil
}
