// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// A payload that carries a few bytes more than 64 per declared transaction is past the short check and fails on what follows: the
// check is exactly 64 bytes per transaction, not 65.
func TestAPayloadOfLittleMoreThanTheSignaturesFailsOnWhatFollowsNotOnTheShortCheck(t *testing.T) {
	const total = 100
	head := rawPayload(uvs(0, 9), spanParent, spanOrigin, uvs(1), []byte{0}, uvs(total))
	allCreation := bitlist(func() []bool {
		b := make([]bool, total)
		for i := range b {
			b[i] = true
		}
		return b
	}())
	p := rawPayload(head, allCreation, make([]byte, (total+7)/8), make([]byte, 64*total), bytes.Repeat([]byte{0xff}, 10))
	_, err := decodeSpanBatch(p, spanSP)
	if err == nil || err.Error() != "span: tx data" {
		t.Fatalf("64 bytes per transaction and ten more: %v", err)
	}
	// one byte fewer than 64 per transaction is short
	_, err = decodeSpanBatch(p[:len(p)-10-1], spanSP)
	if err == nil || err.Error() != "span: short" {
		t.Fatalf("one signature byte missing: %v", err)
	}
}

// A byte below 0x80 begins a transaction as its type; 0x80 and above is the RLP of a legacy transaction.
func TestTheFirstByteOfATransactionIsATypeBelow0x80AndLegacyRLPFromThere(t *testing.T) {
	head := rawPayload(uvs(0, 9), spanParent, spanOrigin, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes())
	// 0x80 is an empty RLP string: a legacy transaction (it has a protected bit), whose body is not a list
	legacy := rawPayload(head, []byte{0x80}, uvs(1), uvs(1), []byte{0})
	_, err := decodeSpanBatch(legacy, spanSP)
	if err == nil || err.Error() != "span: legacy tx" {
		t.Fatalf("0x80: %v", err)
	}
	// 0x7f is a transaction type nobody decodes
	typed := rawPayload(head, []byte{0x7f, 0xc0}, uvs(1), uvs(1))
	_, err = decodeSpanBatch(typed, spanSP)
	if bf, ok := err.(*batchFormatError); !ok || bf.typ != 0x7f {
		t.Fatalf("0x7f: %T %v", err, err)
	}
	// a blob whose length prefix is over the blob size is refused on that prefix
	w := loadPostedWire(t)
	var empty Body
	empty.LC, empty.L1Spine = w.body.LC, [][]byte{{1}}
	base := EncodeBody(empty)
	b := append([]byte(nil), base[:len(base)-12]...)
	b = append(b, 0, 0, 0, 1)           // one frame
	b = append(b, make([]byte, 8+4)...) // l1Block, txIndex
	b = append(b, 0, 0, 0, 0)           // txRaw empty
	b = append(b, 0, 0, 0, 1)           // one blob
	b = append(b, 0, 2, 0, 1)           // its raw length 131073: over BlobSize
	b = append(b, make([]byte, 200)...)
	_, err = DecodeBody(b, w.lim, w.ep, 32)
	se, ok := finality.AsNamed(err)
	if !ok || se.Code != finality.CodeEvidenceTooLarge {
		t.Fatalf("a blob length over the blob size: %v", err)
	}
}
