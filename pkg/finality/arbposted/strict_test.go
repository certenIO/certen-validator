// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"math/rand"
	"testing"
)

// A batch whose brotli stream ends one byte early used to decode to a prefix with a nil error (the library answers a clean EOF
// when its source is exhausted mid-stream), so a message the sequencer never completed could be "found" in it. Nitro's decoder
// refuses such a stream; so must the verifier.
func shortBatchSegments(t *testing.T) (needed []byte, tail []byte) {
	t.Helper()
	rnd := rand.New(rand.NewSource(3))
	tail = make([]byte, 400)
	rnd.Read(tail)
	return seg(segL2Message, signedTxMsg(legacyTx(1))), seg(segL2Message, signedTxMsg(tail))
}

func TestABatchStreamCutShortIsUndecodableAtEveryByte(t *testing.T) {
	needed, tail := shortBatchSegments(t)
	full := payloadOf(needed, tail)
	if r := decodePayload(full, 1<<20, 100); r.status != payloadOK || len(r.messages) != 2 {
		t.Fatalf("the complete payload: %+v", r)
	}
	for i := 2; i < len(full); i++ { // i = 1 would be the header byte alone
		if r := decodePayload(full[:i], 1<<20, 100); r.status != payloadUndecodable {
			t.Fatalf("a payload cut to %d of %d bytes decodes to %d messages with status %d", i, len(full), len(r.messages), r.status)
		}
	}
}

func TestAHeaderOnlyOrEmptyBrotliPayloadIsUndecodable(t *testing.T) {
	if r := decodePayload([]byte{headerBrotli}, 1<<20, 100); r.status != payloadUndecodable {
		t.Fatalf("header only: status %d", r.status)
	}
	if r := decodePayload(nil, 1<<20, 100); r.status != payloadUndecodable {
		t.Fatalf("empty: status %d", r.status)
	}
}

func TestATrailingByteAfterTheBatchStreamIsUndecodable(t *testing.T) {
	needed, tail := shortBatchSegments(t)
	full := payloadOf(needed, tail)
	if r := decodePayload(append(append([]byte(nil), full...), 0), 1<<20, 100); r.status != payloadUndecodable {
		t.Fatalf("status %d", r.status)
	}
}

// A per-message brotli segment cut short is dropped like nitro drops it, not kept as a partial message.
func TestAMessageSegmentCutShortIsDropped(t *testing.T) {
	rnd := rand.New(rand.NewSource(4))
	big := make([]byte, 600)
	rnd.Read(big)
	t1 := legacyTx(1)
	msg := batchMsg(signedTxMsg(t1), signedTxMsg(big)) // the first transaction is complete well before the stream's last byte
	comp := brotliBytes(msg)
	whole := decodePayload(payloadOf(seg(segL2MessageBrotli, comp)), 1<<20, 100)
	if whole.status != payloadOK || len(whole.messages) != 1 || len(whole.messages[0].txs) != 2 {
		t.Fatalf("the complete message: %+v", whole)
	}
	for i := 1; i < len(comp); i++ {
		r := decodePayload(payloadOf(seg(segL2MessageBrotli, comp[:i])), 1<<20, 100)
		if r.status != payloadOK || len(r.messages) != 0 {
			t.Fatalf("a message segment cut to %d of %d bytes produced %d messages (status %d)", i, len(comp), len(r.messages), r.status)
		}
	}
	// an empty brotli segment and one with a byte after the stream are dropped too
	for name, body := range map[string][]byte{"empty": nil, "trailing": append(append([]byte(nil), comp...), 0)} {
		r := decodePayload(payloadOf(seg(segL2MessageBrotli, body)), 1<<20, 100)
		if r.status != payloadOK || len(r.messages) != 0 {
			t.Fatalf("%s segment: %d messages", name, len(r.messages))
		}
	}
	if !bytes.Equal(comp, brotliBytes(msg)) {
		t.Fatal("the compressor is not deterministic")
	}
}
