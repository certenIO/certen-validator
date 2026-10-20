// Copyright 2026 Certen Protocol

package ethl1

import (
	"golang.org/x/crypto/sha3"
)

// Positions of the execution-header RLP items the verifier reads (spec section 0). The item count is not fixed: Sepolia
// L1 headers have 23 items since 2026-10-06 and Fulu-era ones 21, so headers are hashed as given and read positionally,
// never decoded into a typed header.
const (
	hdrParentHash = 0
	hdrStateRoot  = 3
	hdrNumber     = 8
	hdrTimestamp  = 11
	hdrReadItems  = 12
)

func keccak256(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// rlpHeaderItems walks the whole RLP list in b (canonical lengths, no trailing byte) and returns the payloads of the first
// hdrReadItems items, which must be strings, together with the item count. reason is "" on success.
func rlpHeaderItems(b []byte) (items [hdrReadItems][]byte, count int, reason string) {
	if len(b) == 0 || b[0] < 0xc0 {
		return items, 0, "not_a_list"
	}
	var payloadLen, hdr int
	if b[0] <= 0xf7 {
		payloadLen, hdr = int(b[0]-0xc0), 1
	} else {
		ll := int(b[0] - 0xf7)
		if ll > 4 || 1+ll > len(b) || b[1] == 0 {
			return items, 0, "list_length"
		}
		for i := 0; i < ll; i++ {
			payloadLen = payloadLen<<8 | int(b[1+i])
		}
		if payloadLen < 56 {
			return items, 0, "list_length_noncanonical"
		}
		hdr = 1 + ll
	}
	if hdr+payloadLen != len(b) {
		return items, 0, "list_length_mismatch"
	}
	p := b[hdr:]
	for len(p) > 0 {
		var start, n int
		b0 := p[0]
		isList := false
		switch {
		case b0 < 0x80:
			start, n = 0, 1
		case b0 <= 0xb7:
			start, n = 1, int(b0-0x80)
			if n == 1 && len(p) > 1 && p[1] < 0x80 {
				return items, 0, "string_noncanonical"
			}
		case b0 <= 0xbf:
			ll := int(b0 - 0xb7)
			if ll > 4 || 1+ll > len(p) || p[1] == 0 {
				return items, 0, "string_length"
			}
			for i := 0; i < ll; i++ {
				n = n<<8 | int(p[1+i])
			}
			if n < 56 {
				return items, 0, "string_length_noncanonical"
			}
			start = 1 + ll
		case b0 <= 0xf7:
			isList = true
			start, n = 1, int(b0-0xc0)
		default:
			isList = true
			ll := int(b0 - 0xf7)
			if ll > 4 || 1+ll > len(p) || p[1] == 0 {
				return items, 0, "list_length"
			}
			for i := 0; i < ll; i++ {
				n = n<<8 | int(p[1+i])
			}
			if n < 56 {
				return items, 0, "list_length_noncanonical"
			}
			start = 1 + ll
		}
		if n < 0 || start+n > len(p) {
			return items, 0, "item_overruns"
		}
		if count < hdrReadItems {
			if isList {
				return items, 0, "item_not_string"
			}
			items[count] = p[start : start+n]
		}
		count++
		p = p[start+n:]
	}
	if count < hdrReadItems {
		return items, count, "too_few_items"
	}
	return items, count, ""
}

func rlpUint64(b []byte) (uint64, bool) {
	if len(b) > 8 || (len(b) > 0 && b[0] == 0) {
		return 0, false
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, true
}

type spineHeader struct {
	hash      [32]byte
	parent    [32]byte
	stateRoot [32]byte
	number    uint64
	timestamp uint64
}

func readSpineHeader(raw []byte) (spineHeader, string) {
	items, _, reason := rlpHeaderItems(raw)
	if reason != "" {
		return spineHeader{}, reason
	}
	var h spineHeader
	if len(items[hdrParentHash]) != 32 || len(items[hdrStateRoot]) != 32 {
		return h, "hash_item_length"
	}
	copy(h.parent[:], items[hdrParentHash])
	copy(h.stateRoot[:], items[hdrStateRoot])
	var ok bool
	if h.number, ok = rlpUint64(items[hdrNumber]); !ok {
		return h, "number_item"
	}
	if h.timestamp, ok = rlpUint64(items[hdrTimestamp]); !ok {
		return h, "timestamp_item"
	}
	h.hash = keccak256(raw)
	return h, ""
}

// Covers is spec section 5.2 step 5: keccak256(spine[0]) is the finalized execution head, every further header is the
// parent of the one before it (hash and number), and at most max headers are accepted. It returns each header's hash,
// number, state root and timestamp, read positionally from the raw RLP; callers take every L1 state root and timestamp
// from this list by number and never from a field the evidence states.
func (h FinalizedHead) Covers(spine [][]byte, max int) ([]L1Block, error) {
	if len(spine) == 0 {
		return nil, EvidenceMalformed("spine", 0, "empty", 0, 1)
	}
	if len(spine) > max {
		return nil, EvidenceTooLarge("spine", len(spine), max)
	}
	out := make([]L1Block, 0, len(spine))
	var prev spineHeader
	for i, raw := range spine {
		cur, reason := readSpineHeader(raw)
		if reason != "" {
			want := h.ExecHash
			if i > 0 {
				want = prev.parent
			}
			var at uint64
			if i > 0 {
				at = prev.number - 1
			}
			return nil, HeaderChainBroken("l1", at, want, keccak256(raw), "rlp")
		}
		if i == 0 {
			if cur.hash != h.ExecHash {
				return nil, HeaderChainBroken("l1", cur.number, h.ExecHash, cur.hash, "hash")
			}
		} else {
			if cur.hash != prev.parent {
				return nil, HeaderChainBroken("l1", prev.number-1, prev.parent, cur.hash, "hash")
			}
			if prev.number == 0 || cur.number != prev.number-1 {
				return nil, HeaderChainBroken("l1", prev.number-1, prev.parent, cur.hash, "number")
			}
		}
		out = append(out, L1Block{Hash: cur.hash, Number: cur.number, StateRoot: cur.stateRoot, Timestamp: cur.timestamp})
		prev = cur
	}
	return out, nil
}

// BlockAt returns the covered header with this number, or finality_block_not_covered when the number lies above the
// spine's top (the builder maps that to pending) or below its bottom.
func BlockAt(covered []L1Block, number uint64) (L1Block, error) {
	if len(covered) == 0 {
		return L1Block{}, BlockNotCovered(number, 0)
	}
	top := covered[0].Number
	if number > top || number+uint64(len(covered)) <= top {
		return L1Block{}, BlockNotCovered(number, top)
	}
	return covered[top-number], nil
}
