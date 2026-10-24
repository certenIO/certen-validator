// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"errors"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality/strictbrotli"
)

// This file is the Nitro batch payload decoder the verifier replays (annex A6.3 steps 4-6): blobs -> RLP payload -> brotli ->
// segments -> L2 messages -> signed transactions. Sources: nitro@ccc5c82 util/blobs/blobs.go (DecodeBlobs),
// arbstate/inbox.go (parseSequencerMessage / segment kinds), arbos/parse_l2.go (L2 message kinds), daprovider header bytes.

// Payload header bytes (the first byte of a decoded batch payload or of calldata batch data).
const (
	headerBrotli    = 0x00
	headerZeroheavy = 0x20
	headerDACert    = 0x01
	headerDAS       = 0x80
	headerDASTree   = 0x88
)

// Segment kinds of a decompressed batch (nitro inbox.go).
const (
	segL2Message       = 0
	segL2MessageBrotli = 1
	segDelayed         = 2
	segAdvanceTime     = 3
	segAdvanceL1Block  = 4
)

// L2 message kinds (nitro arbos/parse_l2.go).
const (
	l2Batch    = 3
	l2SignedTx = 4
)

// maxL2MessageSize is nitro's MaxL2MessageSize (256 KiB): a top-level message, a nested message or a brotli-compressed segment larger than
// this is dropped.
const maxL2MessageSize = 256 * 1024

// maxL2Depth is nitro's nesting limit for batch messages inside batch messages.
const maxL2Depth = 16

// Blob field-element layout (EIP-4844): 4096 elements of 32 bytes; nitro stores 31 data bytes per element and the 6 spare low
// bits of byte 0 of each element as a packed bit stream.
const (
	fieldElements    = 4096
	blobDataBytes    = fieldElements * 31
	blobBitStreamLen = fieldElements * 6 / 8
)

// decodeBlobs is nitro's DecodeBlobs: per blob, the 31 high bytes of every field element followed by the packed 6-bit
// groups; the concatenation is one RLP byte string, whose content is the payload. Bytes after the string must be zero padding.
func decodeBlobs(blobs [][]byte) ([]byte, error) {
	rlpData := make([]byte, 0, len(blobs)*(blobDataBytes+blobBitStreamLen))
	for _, blob := range blobs {
		if len(blob) != BlobBytes {
			return nil, errors.New("blob length")
		}
		for fe := 0; fe < fieldElements; fe++ {
			rlpData = append(rlpData, blob[fe*32+1:fe*32+32]...)
		}
		var acc uint16
		accBits := 0
		for fe := 0; fe < fieldElements; fe++ {
			acc |= uint16(blob[fe*32]&0x3f) << accBits
			accBits += 6
			if accBits >= 8 {
				rlpData = append(rlpData, byte(acc))
				acc >>= 8
				accBits -= 8
			}
		}
	}
	payload, rest, err := rlp.SplitString(rlpData)
	if err != nil {
		return nil, err
	}
	for _, c := range rest {
		if c != 0 {
			return nil, errors.New("non-zero bytes after the payload")
		}
	}
	return payload, nil
}

// uncompress is brotli decompression capped at max bytes: it reports exceeded when the stream would produce more. A stream that is
// incomplete, empty or followed by extra bytes is an error (package strictbrotli: the library alone would return a prefix).
func uncompress(in []byte, max int) (out []byte, exceeded bool, err error) {
	return strictbrotli.Decompress(in, max)
}

// segment is one decoded batch segment.
type segment struct {
	kind byte
	body []byte
}

// splitSegments reads the decompressed stream as RLP byte strings, exactly as nitro's parseSequencerMessage does: the first
// string that fails to parse ends the batch (what was read stays). More than maxSegments strings is reported as exceeded
// (nitro stops at the limit; the verifier refuses, spec 8.2).
func splitSegments(stream []byte, maxSegments int) (segs []segment, exceeded bool) {
	s := rlp.NewStream(bytes.NewReader(stream), uint64(len(stream)))
	for {
		var raw []byte
		if err := s.Decode(&raw); err != nil {
			return segs, false
		}
		if len(segs) >= maxSegments {
			return segs, true
		}
		if len(raw) == 0 {
			continue // an empty segment carries no kind
		}
		segs = append(segs, segment{kind: raw[0], body: raw[1:]})
	}
}

// l2Message is one decoded L2 message and its signed transactions (each as the bytes the message carries).
type l2Message struct {
	ordinal int
	txs     [][]byte
}

// parseL2 returns the signed transactions of one sequencer-batch L2 message, as Nitro's parseL2Message (arbos/parse_l2.go) builds it
// with no L1 request id: kind 4 is one transaction, kind 3 a batch of nested messages (depth < 16; a length prefix that is cut,
// oversize or past the data ends the batch quietly), kind 0 is an unsigned transaction whose fields must parse (it is built from
// the poster and is not a signed transaction, so it contributes none). Everything else fails the message: kind 1 (a contract
// transaction needs a request id), 2, 6 (heartbeats are disabled), 7, unknown kinds, a short field, and ANY nested failure fails the
// WHOLE message. A failed message has no transactions: a malformed message is not a message. ok is false for those.
func parseL2(msg []byte, depth int) ([][]byte, bool) {
	// ParseL2Transactions (arbos/parse_l2.go) drops a message whose L2msg is larger than MaxL2MessageSize before it reads a byte of it:
	// the limit holds for the top-level message of a sequencer batch exactly as for a nested one.
	if len(msg) > maxL2MessageSize {
		return nil, false
	}
	txs, ok := parseL2Msg(msg, common.Address{}, nil, big.NewInt(0), depth, false)
	if !ok {
		return nil, false
	}
	var signed [][]byte
	for _, tx := range txs {
		if ethproof.TxType(tx) <= 4 {
			signed = append(signed, tx)
		}
	}
	return signed, true
}

// decodePayload turns a batch payload (header byte then brotli) into messages. res.state is "" on success; otherwise it
// names why the payload cannot be read as signed-transaction messages.
type payloadResult struct {
	messages []l2Message
	segments int
	// delayedSegments counts the kind-2 (delayed message) segments: the number of delayed messages the batch consumed.
	delayedSegments int
	// off is the payload header byte for data that is not on L1 (DAS / DACert), unknown for an unrecognised byte.
	headerByte byte
	status     payloadStatus
	// exceededUncompressed / exceededSegments report the bound that was exceeded.
	exceededUncompressed bool
	exceededSegments     bool
}

type payloadStatus int

const (
	payloadOK payloadStatus = iota
	payloadOffL1
	payloadUnknownHeader
	payloadUndecodable
	payloadTooLarge
)

// zeroheavyLimit is Nitro's cap of the zero-heavy layer, 101% of the batch bound plus 64 (max + max/100 + 64), computed without wrapping: where
// the sum does not fit an int it is the largest (or, for a negative bound, the smallest) int, never a number of the other sign. A pin is
// bounded to (0, MaxUncompressedBatchLimit]; the function is total for the callers that pass a bound of their own.
func zeroheavyLimit(max int) int {
	extra := max/100 + 64
	switch {
	case extra > 0 && max > math.MaxInt-extra:
		return math.MaxInt
	case extra < 0 && max < math.MinInt-extra:
		return math.MinInt
	}
	return max + extra
}

func decodePayload(payload []byte, maxUncompressed, maxSegments int) payloadResult {
	var res payloadResult
	if len(payload) == 0 {
		res.status = payloadUndecodable
		return res
	}
	res.headerByte = payload[0]
	switch payload[0] {
	case headerBrotli:
	case headerDAS, headerDASTree, headerDACert:
		res.status = payloadOffL1
		return res
	case headerZeroheavy:
		// Nitro decodes the zero-heavy layer once (limit 101% of the batch bound + 64) and then reads the result as an ordinary
		// payload: it must begin with the Brotli header byte, nothing else is decoded after it.
		dec, big := zeroheavyDecode(payload[1:], zeroheavyLimit(maxUncompressed))
		if big {
			res.status, res.exceededUncompressed = payloadTooLarge, true
			return res
		}
		if len(dec) == 0 {
			res.status = payloadUndecodable
			return res
		}
		res.headerByte = dec[0]
		if dec[0] != headerBrotli {
			res.status = payloadUnknownHeader
			return res
		}
		payload = dec
	default:
		res.status = payloadUnknownHeader
		return res
	}
	stream, exceeded, err := uncompress(payload[1:], maxUncompressed)
	if exceeded {
		res.status, res.exceededUncompressed = payloadTooLarge, true
		return res
	}
	if err != nil {
		res.status = payloadUndecodable
		return res
	}
	segs, tooMany := splitSegments(stream, maxSegments)
	if tooMany {
		res.status, res.exceededSegments = payloadTooLarge, true
		return res
	}
	res.segments = len(segs)
	ord := 0
	for _, sg := range segs {
		var msg []byte
		switch sg.kind {
		case segL2Message:
			msg = sg.body
		case segL2MessageBrotli:
			m, big, err := uncompress(sg.body, maxL2MessageSize)
			if err != nil || big {
				continue // nitro drops a message it cannot decompress
			}
			msg = m
		case segDelayed:
			res.delayedSegments++
			continue
		default:
			continue
		}
		txs, _ := parseL2(msg, 0)
		res.messages = append(res.messages, l2Message{ordinal: ord, txs: txs})
		ord++
	}
	return res
}
