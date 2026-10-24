// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// Transaction trie rebuild and type census (step 22, rule IB2; Freeze item 1: blockTxs).
//
// The container carries EVERY transaction of the attestation block B_v in index order, as the typed wire encodings (EIP-2718: a legacy
// transaction is its RLP list, a typed one is `type || payload`). RebuildTxRoot rebuilds the ordered transaction trie (key rlp(index), value
// the wire encoding) with ethproof.TrieRoot - the formula a header's transactionsRoot commits to - and VerifyBlockTxs compares it with the
// header root and the attestation transaction's own leaf. The nodes of that trie are not carried; the list authenticates against the header.
//
// ClassifyTx reads only the envelope: the type byte and, for the standard types 0-4, that the payload is exactly one RLP list. Every other type
// byte (the L2 types 0x7e, 0x64-0x6a, 0x78 of the manifest txScan lists and anything unknown, 0x05..0x7f) is returned AS IT IS with its payload
// undecoded: whether a type is covered, a system type or unsupported is the verifier's judgement against policy.txScan[chain], never guessed here.

// Standard transaction types decoded by ClassifyTx.
const (
	TxTypeLegacy     byte = 0x00
	TxTypeAccessList byte = 0x01
	TxTypeDynamicFee byte = 0x02
	TxTypeBlob       byte = 0x03
	TxTypeSetCode    byte = 0x04
)

// TxKind names why a block transaction list was refused.
type TxKind string

// Transaction list refusal kinds.
const (
	TxEmpty          TxKind = "empty_transaction"
	TxBadEnvelope    TxKind = "bad_envelope"
	TxTooMany        TxKind = "too_many_transactions"
	TxTooLarge       TxKind = "transactions_too_large"
	TxRootMismatch   TxKind = "root_mismatch"
	TxLeafMismatch   TxKind = "leaf_mismatch"
	TxIndexOutOfList TxKind = "index_out_of_list"
)

// TxError is a named refusal of the transaction list.
type TxError struct {
	Kind  TxKind
	Index int
	// Got and Limit carry the numbers of a bound refusal.
	Got, Limit uint64
	Detail     string
}

func (e *TxError) Error() string {
	s := fmt.Sprintf("block transactions: %s (index %d)", e.Kind, e.Index)
	if e.Kind == TxTooMany || e.Kind == TxTooLarge {
		s += fmt.Sprintf(": %d against %d", e.Got, e.Limit)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// TxInfo is the envelope of one transaction.
type TxInfo struct {
	// Type is the EIP-2718 type byte; a legacy transaction is type 0x00.
	Type byte
	// Typed is true when the wire encoding starts with a type byte (0x01-0x7f), false for a legacy RLP list.
	Typed bool
	// Standard is true for types 0x00-0x04, whose payload ClassifyTx checked to be exactly one RLP list.
	Standard bool
	// Payload is the bytes after the type byte (the whole encoding for a legacy transaction), undecoded.
	Payload []byte
}

// ClassifyTx reads the envelope of one transaction wire encoding. An empty encoding, a first byte in 0x80-0xbf (an RLP string is no
// transaction) and a malformed standard payload are TxBadEnvelope; an unknown type byte is returned as it is.
func ClassifyTx(raw []byte) (TxInfo, error) {
	if len(raw) == 0 {
		return TxInfo{}, &TxError{Kind: TxEmpty}
	}
	b := raw[0]
	switch {
	case b >= 0xc0: // a legacy transaction: one RLP list and nothing after it
		_, rest, err := rlp.SplitList(raw)
		if err != nil {
			return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: "legacy transaction: " + err.Error()}
		}
		if len(rest) != 0 {
			return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: fmt.Sprintf("legacy transaction: %d bytes after the list", len(rest))}
		}
		return TxInfo{Type: TxTypeLegacy, Standard: true, Payload: raw}, nil
	case b >= 0x80:
		return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: fmt.Sprintf("first byte 0x%02x is an RLP string, not a transaction", b)}
	}
	info := TxInfo{Type: b, Typed: true, Payload: raw[1:]}
	if b <= TxTypeSetCode {
		if b == TxTypeLegacy { // 0x00 as a type byte is not a transaction encoding
			return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: "type byte 0x00 prefix"}
		}
		_, rest, err := rlp.SplitList(info.Payload)
		if err != nil {
			return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: fmt.Sprintf("type 0x%02x payload: %v", b, err)}
		}
		if len(rest) != 0 {
			return TxInfo{}, &TxError{Kind: TxBadEnvelope, Detail: fmt.Sprintf("type 0x%02x payload: %d bytes after the list", b, len(rest))}
		}
		info.Standard = true
	}
	return info, nil
}

// RebuildTxRoot is the transaction trie root over the wire encodings in index order: the value a header's transactionsRoot commits to
// (the empty root for no transaction). It does not judge the entries; VerifyBlockTxs does.
func RebuildTxRoot(blockTxs [][]byte) common.Hash { return ethproof.TrieRoot(blockTxs) }

// TxCensus is what VerifyBlockTxs establishes about an authenticated block transaction list.
type TxCensus struct {
	// Root is the rebuilt transaction trie root (equal to the header's).
	Root common.Hash
	// Types is the type byte of every transaction in index order.
	Types []byte
	// Distinct is the sorted set of the type bytes present.
	Distinct []byte
	// Infos is the envelope of every transaction in index order.
	Infos []TxInfo
	// TotalBytes is the summed length of the encodings.
	TotalBytes int
}

// VerifyBlockTxs bounds the list (count and total bytes by lim, BEFORE any trie work), classifies every entry, rebuilds the trie root and
// requires it to equal headerTxRoot and blockTxs[txIndex] to equal txLeaf. The census is returned only for a list the header authenticates.
func VerifyBlockTxs(headerTxRoot common.Hash, blockTxs [][]byte, txIndex int, txLeaf []byte, lim Limits) (*TxCensus, error) {
	if len(blockTxs) > lim.MaxBlockTxs {
		return nil, &TxError{Kind: TxTooMany, Got: uint64(len(blockTxs)), Limit: uint64(lim.MaxBlockTxs)}
	}
	total := 0
	for _, t := range blockTxs {
		total += len(t)
	}
	if total > lim.MaxBlockTxsBytes {
		return nil, &TxError{Kind: TxTooLarge, Got: uint64(total), Limit: uint64(lim.MaxBlockTxsBytes)}
	}
	c := &TxCensus{TotalBytes: total, Types: make([]byte, 0, len(blockTxs)), Infos: make([]TxInfo, 0, len(blockTxs))}
	seen := map[byte]bool{}
	for i, t := range blockTxs {
		info, err := ClassifyTx(t)
		if err != nil {
			te := err.(*TxError)
			te.Index = i
			return nil, te
		}
		c.Infos = append(c.Infos, info)
		c.Types = append(c.Types, info.Type)
		seen[info.Type] = true
	}
	for ty := range seen {
		c.Distinct = append(c.Distinct, ty)
	}
	sort.Slice(c.Distinct, func(a, b int) bool { return c.Distinct[a] < c.Distinct[b] })
	c.Root = RebuildTxRoot(blockTxs)
	if c.Root != headerTxRoot {
		return nil, &TxError{Kind: TxRootMismatch, Detail: fmt.Sprintf("rebuilt %s, header %s", c.Root.Hex(), headerTxRoot.Hex())}
	}
	if txIndex < 0 || txIndex >= len(blockTxs) {
		return nil, &TxError{Kind: TxIndexOutOfList, Index: txIndex, Got: uint64(len(blockTxs))}
	}
	if !bytes.Equal(blockTxs[txIndex], txLeaf) {
		return nil, &TxError{Kind: TxLeafMismatch, Index: txIndex}
	}
	return c, nil
}
