// Copyright 2026 Certen Protocol

package contractidentity

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Storage-slot derivation (V2_SPEC_S8 conventions of the algorithm, step 6, step 14, manifest item 11, and the F-S8-5 correction).
//
//   - a mapping slot is keccak256(abi.encode(key, base)): the key is its 32-byte ABI form (value types only), the base the 32-byte slot;
//   - a nested mapping m[k1][k2] at base b is mapping(k2, mapping(k1, b)) (the inner mapping's slot is the base of the outer lookup), which is
//     the step 14 form keccak256(abi.encode(uint256(page), keccak256(abi.encode(book, uint256(slot)))));
//   - a dynamic array element is keccak256(abi.encode(uint256(base))) + floor(index / itemsPerSlot), itemsPerSlot = floor(32 / elementBytes)
//     (1 for address[] and bytes32[]), added modulo 2^256 as the EVM adds;
//   - a packed field is addressed by a byte offset counted from the LEAST-significant end of the word: byte b(i) is word[31-i]
//     (anchors[id] word 10: validator b0-b19, valid b20, proofExecuted b21, governanceExecuted b22, governanceLevel b23);
//   - bytes and string: short (< 32 bytes) data in the high bytes and 2*len in the low byte; long (>= 32) the word holds 2*len+1 and the
//     data starts at keccak256(abi.encode(uint256(slot))).
//
// Every helper refuses what it cannot derive exactly (a named SlotError); none returns a partial value.

// ErrSlot is the class of every slot-derivation or word-decoding refusal; the SlotError carries the named reason.
var ErrSlot = errors.New("storage slot")

// SlotError is a named slot-derivation refusal.
type SlotError struct {
	// Reason is one of the SlotReason* names.
	Reason string
	// Detail is human text (never judged).
	Detail string
}

// Slot refusal reasons.
const (
	SlotReasonKeyRange        = "key_range"
	SlotReasonElementBytes    = "element_bytes"
	SlotReasonIndexRange      = "index_range"
	SlotReasonOffsetRange     = "offset_range"
	SlotReasonWordNotUint64   = "word_not_uint64"
	SlotReasonWordNotAddress  = "word_not_address"
	SlotReasonWordNotBool     = "word_not_bool"
	SlotReasonDynHeadInvalid  = "dyn_head_invalid"
	SlotReasonDynTooLong      = "dyn_too_long"
	SlotReasonDynPadding      = "dyn_padding"
	SlotReasonDynWordCount    = "dyn_word_count"
	SlotReasonPackedNotUint64 = "packed_length"
)

func (e *SlotError) Error() string {
	if e.Detail == "" {
		return "storage slot: " + e.Reason
	}
	return "storage slot: " + e.Reason + ": " + e.Detail
}

// Is reports the class ErrSlot.
func (e *SlotError) Is(target error) bool { return target == ErrSlot }

func slotErr(reason, format string, args ...any) error {
	return &SlotError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// SlotKey is the 32-byte ABI encoding of a mapping key of a value type.
type SlotKey [32]byte

// KeyAddress is abi.encode(address): left-padded with zeros.
func KeyAddress(a common.Address) SlotKey {
	var k SlotKey
	copy(k[12:], a[:])
	return k
}

// KeyUint64 is abi.encode(uint256(v)) for a value that fits 64 bits.
func KeyUint64(v uint64) SlotKey {
	var k SlotKey
	new(big.Int).SetUint64(v).FillBytes(k[:])
	return k
}

// KeyUint is abi.encode(uint256(v)); a negative or 257-bit value is refused.
func KeyUint(v *big.Int) (SlotKey, error) {
	var k SlotKey
	if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
		return k, slotErr(SlotReasonKeyRange, "not a uint256")
	}
	v.FillBytes(k[:])
	return k, nil
}

// KeyBytes32 is abi.encode(bytes32).
func KeyBytes32(b [32]byte) SlotKey { return SlotKey(b) }

// KeyBytes4 is abi.encode(bytes4): right-padded with zeros (manifest item 11).
func KeyBytes4(b [4]byte) SlotKey {
	var k SlotKey
	copy(k[:], b[:])
	return k
}

// KeyBool is abi.encode(bool).
func KeyBool(v bool) SlotKey {
	var k SlotKey
	if v {
		k[31] = 1
	}
	return k
}

// SlotIndex is the 32-byte slot number of a declared state variable.
func SlotIndex(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n)) }

// MappingSlot is keccak256(abi.encode(key, base)) for a mapping whose declaration slot (or enclosing mapping's value slot) is base.
func MappingSlot(key SlotKey, base common.Hash) common.Hash {
	var buf [64]byte
	copy(buf[:32], key[:])
	copy(buf[32:], base[:])
	return common.BytesToHash(crypto.Keccak256(buf[:]))
}

// MappingSlotAt is MappingSlot for a declared variable at slot number base.
func MappingSlotAt(key SlotKey, base uint64) common.Hash { return MappingSlot(key, SlotIndex(base)) }

// NestedMappingSlot is the slot of m[outer][inner] for `mapping(K1 => mapping(K2 => V)) m` declared at slot base:
// keccak256(abi.encode(inner, keccak256(abi.encode(outer, base)))).
func NestedMappingSlot(base uint64, outer, inner SlotKey) common.Hash {
	return MappingSlot(inner, MappingSlotAt(outer, base))
}

// PageSlot is the slot of `_pageLevel[book][page]` / `_pageLevelSet[book][page]` (step 14, manifest item 11): the two key encodings are
// bytes32 (book) at the first level and uint256(page) at the second.
func PageSlot(base uint64, book [32]byte, page uint64) common.Hash {
	return NestedMappingSlot(base, KeyBytes32(book), KeyUint64(page))
}

// MemberSlot is base + word (modulo 2^256): the slot of the word-th 32-byte word of a struct or fixed-size record that starts at base.
func MemberSlot(base common.Hash, word uint64) common.Hash {
	return addToSlot(base, new(big.Int).SetUint64(word))
}

var mod256 = new(big.Int).Lsh(big.NewInt(1), 256)

func addToSlot(base common.Hash, n *big.Int) common.Hash {
	v := new(big.Int).SetBytes(base[:])
	v.Add(v, n)
	v.Mod(v, mod256)
	return common.BigToHash(v)
}

// ArrayDataStart is keccak256(abi.encode(uint256(base))): the slot of element 0 of the dynamic array declared at slot base.
func ArrayDataStart(base uint64) common.Hash {
	return common.BytesToHash(crypto.Keccak256(SlotIndex(base).Bytes()))
}

// ArrayItemsPerSlot is floor(32 / elementBytes) for an element of 1 to 32 bytes (1 for address and bytes32 elements, 2 for uint128).
func ArrayItemsPerSlot(elementBytes int) (uint64, error) {
	if elementBytes < 1 || elementBytes > 32 {
		return 0, slotErr(SlotReasonElementBytes, "%d bytes", elementBytes)
	}
	return uint64(32 / elementBytes), nil
}

// ArrayElementSlot is keccak256(abi.encode(uint256(base))) + floor(index / itemsPerSlot) and the element's byte offset inside that word
// (counted from the least-significant end): (index % itemsPerSlot) * elementBytes. itemsPerSlot must be floor(32 / elementBytes).
func ArrayElementSlot(base uint64, index uint64, elementBytes int) (slot common.Hash, byteOffset int, err error) {
	per, err := ArrayItemsPerSlot(elementBytes)
	if err != nil {
		return common.Hash{}, 0, err
	}
	slot = addToSlot(ArrayDataStart(base), new(big.Int).SetUint64(index/per))
	return slot, int(index%per) * elementBytes, nil
}

// PackedBytes returns length bytes of word starting at byte offset (counted from the least-significant end: b(offset) is word[31-offset]),
// in big-endian order: the value of the packed field.
func PackedBytes(word common.Hash, offset, length int) ([]byte, error) {
	if offset < 0 || length < 1 || offset+length > 32 {
		return nil, slotErr(SlotReasonOffsetRange, "offset %d length %d", offset, length)
	}
	out := make([]byte, length)
	copy(out, word[32-offset-length:32-offset])
	return out, nil
}

// PackedUint64 is the packed unsigned field of at most 8 bytes.
func PackedUint64(word common.Hash, offset, length int) (uint64, error) {
	if length > 8 {
		return 0, slotErr(SlotReasonPackedNotUint64, "%d bytes", length)
	}
	b, err := PackedBytes(word, offset, length)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// PackedAddress is the packed 20-byte address at offset.
func PackedAddress(word common.Hash, offset int) (common.Address, error) {
	b, err := PackedBytes(word, offset, 20)
	if err != nil {
		return common.Address{}, err
	}
	return common.BytesToAddress(b), nil
}

// PackedBool is the packed bool byte at offset: 0 or 1 only.
func PackedBool(word common.Hash, offset int) (bool, error) {
	b, err := PackedBytes(word, offset, 1)
	if err != nil {
		return false, err
	}
	if b[0] > 1 {
		return false, slotErr(SlotReasonWordNotBool, "byte %d is 0x%02x", offset, b[0])
	}
	return b[0] == 1, nil
}

// WordUint64 reads a whole word as uint64: the upper 24 bytes must be zero.
func WordUint64(word common.Hash) (uint64, error) {
	for _, c := range word[:24] {
		if c != 0 {
			return 0, slotErr(SlotReasonWordNotUint64, "word %s", word.Hex())
		}
	}
	return new(big.Int).SetBytes(word[24:]).Uint64(), nil
}

// WordAddress reads a whole word as an address: the upper 12 bytes must be zero.
func WordAddress(word common.Hash) (common.Address, error) {
	for _, c := range word[:12] {
		if c != 0 {
			return common.Address{}, slotErr(SlotReasonWordNotAddress, "word %s", word.Hex())
		}
	}
	return common.BytesToAddress(word[12:]), nil
}

// WordBool reads a whole word as a bool: exactly 0 or 1.
func WordBool(word common.Hash) (bool, error) {
	for _, c := range word[:31] {
		if c != 0 {
			return false, slotErr(SlotReasonWordNotBool, "word %s", word.Hex())
		}
	}
	if word[31] > 1 {
		return false, slotErr(SlotReasonWordNotBool, "word %s", word.Hex())
	}
	return word[31] == 1, nil
}

// DynHead is the decoded first word of a bytes or string storage variable (step 6).
type DynHead struct {
	// Long is true when the data lives at keccak256(abi.encode(uint256(slot))) + i and the head holds 2*len+1.
	Long bool
	// Length is the byte length.
	Length uint64
	// Short is the inline data of a short value (len(Short) == Length); nil for a long one.
	Short []byte
}

// ParseDynHead decodes the head word of a bytes/string variable. Short form: the low byte is 2*len (even, len <= 31) and the data sits in
// the high bytes with every other byte zero. Long form: the word is 2*len+1 as a 256-bit integer with len >= 32 (a long head for a short
// length is non-canonical and refused). maxLen bounds the length BEFORE anything is allocated or read.
func ParseDynHead(word common.Hash, maxLen uint64) (DynHead, error) {
	low := word[31]
	if low&1 == 0 {
		if low > 62 {
			return DynHead{}, slotErr(SlotReasonDynHeadInvalid, "short head low byte 0x%02x is an even length above 31", low)
		}
		n := int(low / 2)
		for _, c := range word[n:31] {
			if c != 0 {
				return DynHead{}, slotErr(SlotReasonDynPadding, "short value of %d bytes has non-zero padding", n)
			}
		}
		if uint64(n) > maxLen {
			return DynHead{}, slotErr(SlotReasonDynTooLong, "%d bytes, limit %d", n, maxLen)
		}
		return DynHead{Length: uint64(n), Short: append([]byte{}, word[:n]...)}, nil
	}
	for _, c := range word[:24] {
		if c != 0 {
			return DynHead{}, slotErr(SlotReasonDynTooLong, "length does not fit 64 bits")
		}
	}
	v := new(big.Int).SetBytes(word[24:]).Uint64()
	n := v >> 1
	if n < 32 {
		return DynHead{}, slotErr(SlotReasonDynHeadInvalid, "long head for the short length %d", n)
	}
	if n > maxLen {
		return DynHead{}, slotErr(SlotReasonDynTooLong, "%d bytes, limit %d", n, maxLen)
	}
	return DynHead{Long: true, Length: n}, nil
}

// DynWordCount is the number of data words of a long value: ceil(length / 32).
func (h DynHead) DynWordCount() uint64 {
	if !h.Long {
		return 0
	}
	return (h.Length + 31) / 32
}

// DynDataSlot is the slot of data word i of the long bytes/string variable declared at slot: keccak256(abi.encode(uint256(slot))) + i.
func DynDataSlot(slot common.Hash, i uint64) common.Hash {
	return addToSlot(common.BytesToHash(crypto.Keccak256(slot[:])), new(big.Int).SetUint64(i))
}

// Assemble returns the value of a bytes/string variable from its head and, for a long one, exactly DynWordCount data words: the bytes after
// Length in the last word must be zero.
func (h DynHead) Assemble(words []common.Hash) ([]byte, error) {
	if !h.Long {
		if len(words) != 0 {
			return nil, slotErr(SlotReasonDynWordCount, "a short value takes no data words, got %d", len(words))
		}
		return append([]byte{}, h.Short...), nil
	}
	if uint64(len(words)) != h.DynWordCount() {
		return nil, slotErr(SlotReasonDynWordCount, "want %d data words, got %d", h.DynWordCount(), len(words))
	}
	out := make([]byte, 0, len(words)*32)
	for _, w := range words {
		out = append(out, w[:]...)
	}
	for _, c := range out[h.Length:] {
		if c != 0 {
			return nil, slotErr(SlotReasonDynPadding, "non-zero byte after the %d value bytes", h.Length)
		}
	}
	return out[:h.Length], nil
}
