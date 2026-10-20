// Copyright 2026 Certen Protocol

package ethl1

import (
	"encoding/binary"
)

// EncodeLC renders the LC part of an evidence container (spec section 3.2):
// STR profile || u8 anchorKind || u64 anchorPeriod || B32 anchorRoot || LB anchorBody || LIST<LB> links || LB finalUpdate,
// with LB = u8 layout || LP ssz, LP = u32be length || bytes, STR = LP(ASCII) and LIST = u32be count || items.
func EncodeLC(lc LC) []byte {
	var b []byte
	lp := func(x []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(x)))
		b = append(b, x...)
	}
	lb := func(x LB) {
		b = append(b, byte(x.Layout))
		lp(x.SSZ)
	}
	lp([]byte(lc.Profile))
	b = append(b, lc.AnchorKind)
	b = binary.BigEndian.AppendUint64(b, lc.AnchorPeriod)
	b = append(b, lc.AnchorRoot[:]...)
	lb(lc.AnchorBody)
	b = binary.BigEndian.AppendUint32(b, uint32(len(lc.Links)))
	for _, l := range lc.Links {
		lb(l)
	}
	lb(lc.FinalUpdate)
	return b
}

// DecodeLC is the strict inverse of EncodeLC: no trailing byte, every length within the buffer, the link count bounded by
// maxLinks before anything is allocated, and encode(decode(x)) == x. A container that is not well formed is returned as a
// *Fault (finality_evidence_malformed, or finality_evidence_too_large for a link count over maxLinks); the pins carry the bound
// (Pins.MaxLinks, see Pins.DecodeLC).
func DecodeLC(b []byte, maxLinks int) (LC, error) {
	var lc LC
	pos := 0
	need := func(part string, n int) *Fault {
		if n < 0 || pos+n > len(b) {
			return EvidenceMalformed(part, 0, "truncated", len(b)-pos, n)
		}
		return nil
	}
	lp := func(part string) ([]byte, *Fault) {
		if f := need(part, 4); f != nil {
			return nil, f
		}
		n := int(binary.BigEndian.Uint32(b[pos:]))
		pos += 4
		if f := need(part, n); f != nil {
			return nil, f
		}
		x := b[pos : pos+n]
		pos += n
		return x, nil
	}
	lb := func(part string) (LB, *Fault) {
		if f := need(part, 1); f != nil {
			return LB{}, f
		}
		l := Layout(b[pos])
		pos++
		x, f := lp(part)
		return LB{Layout: l, SSZ: x}, f
	}
	prof, f := lp("profile")
	if f != nil {
		return LC{}, f
	}
	lc.Profile = string(prof)
	if f := need("anchor", 1+8+32); f != nil {
		return LC{}, f
	}
	lc.AnchorKind = b[pos]
	pos++
	lc.AnchorPeriod = binary.BigEndian.Uint64(b[pos:])
	pos += 8
	copy(lc.AnchorRoot[:], b[pos:pos+32])
	pos += 32
	if lc.AnchorBody, f = lb("anchor_body"); f != nil {
		return LC{}, f
	}
	if f := need("links", 4); f != nil {
		return LC{}, f
	}
	n := int(binary.BigEndian.Uint32(b[pos:]))
	pos += 4
	if n > maxLinks {
		return LC{}, EvidenceTooLarge("links", n, maxLinks)
	}
	// each link is at least 5 bytes (layout byte and length), so the bytes left bound how many links can follow; the slice is never
	// sized by the declared count alone (a failing link is still refused at its own position, as before)
	room := (len(b) - pos) / 5
	if n < room {
		room = n
	}
	lc.Links = make([]LB, 0, room)
	for i := 0; i < n; i++ {
		l, f := lb("link")
		if f != nil {
			return LC{}, f
		}
		lc.Links = append(lc.Links, l)
	}
	if lc.FinalUpdate, f = lb("final_update"); f != nil {
		return LC{}, f
	}
	if pos != len(b) {
		return LC{}, EvidenceMalformed("lc", 0, "trailing_bytes", len(b), pos)
	}
	return lc, nil
}
