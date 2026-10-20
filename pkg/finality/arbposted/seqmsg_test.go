// Copyright 2026 Certen Protocol

package arbposted

import (
	"encoding/binary"
	"testing"
)

func w32b(v uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], v)
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// A sequencer-batch message is parsed as Nitro's parseL2Message with no request id: any nested failure fails the whole message.
func TestASequencerMessageIsAllOrNothing(t *testing.T) {
	t1, t2 := legacyTx(1), legacyTx(2)
	unsignedOK := cat([]byte{0}, w32b(50000), w32b(8), w32b(1), w32b(7), w32b(0), []byte{1})
	both := func(extra ...[]byte) []byte {
		return batchMsg(append([][]byte{signedTxMsg(t1), signedTxMsg(t2)}, extra...)...)
	}
	for name, c := range map[string]struct {
		msg   []byte
		ok    bool
		count int
	}{
		"two signed":                        {both(), true, 2},
		"one signed alone":                  {signedTxMsg(t1), true, 1},
		"valid unsigned nested adds none":   {both(unsignedOK), true, 2},
		"unsigned alone adds none":          {unsignedOK, true, 0},
		"cut length tail":                   {append(both(), 0, 0, 0), true, 2},
		"oversize length tail":              {append(both(), binary.BigEndian.AppendUint64(nil, maxL2MessageSize+1)...), true, 2},
		"cut nested tail":                   {append(both(), append(binary.BigEndian.AppendUint64(nil, 40), 1)...), true, 2},
		"empty batch":                       {[]byte{l2Batch}, true, 0},
		"nested kind 2":                     {both([]byte{2}), false, 0},
		"nested kind 6":                     {both([]byte{6}), false, 0},
		"nested kind 7":                     {both([]byte{7, 1}), false, 0},
		"nested unknown kind":               {both([]byte{0x7f}), false, 0},
		"nested contract tx":                {both(cat([]byte{1}, w32b(1), w32b(1), w32b(1), w32b(1))), false, 0},
		"nested unsigned cut":               {both(cat([]byte{0}, w32b(1))), false, 0},
		"nested unsigned gas >= 2^64":       {both(cat([]byte{0}, append([]byte{1}, make([]byte, 31)...), w32b(1), w32b(1), w32b(1), w32b(1))), false, 0},
		"nested unsigned nonce >= 2^64":     {both(cat([]byte{0}, w32b(1), w32b(1), append([]byte{1}, make([]byte, 31)...), w32b(1), w32b(1))), false, 0},
		"nested empty signed":               {both([]byte{4}), false, 0},
		"nested empty message":              {both([]byte{}), false, 0},
		"nested Arbitrum type":              {both([]byte{4, 0x64, 0xc0}), false, 0},
		"nested blob type":                  {both([]byte{4, 0x03, 0xc0}), false, 0},
		"nested unknown type":               {both([]byte{4, 0x05, 0xc0}), false, 0},
		"nested type zero byte":             {both([]byte{4, 0x00, 0xc0}), false, 0},
		"nested access-list type is kept":   {batchMsg(signedTxMsg(append([]byte{1}, 0xc0))), true, 1},
		"nested dynamic-fee type is kept":   {batchMsg(signedTxMsg(append([]byte{2}, 0xc0))), true, 1},
		"nested set-code type is kept":      {batchMsg(signedTxMsg(append([]byte{4}, 0xc0))), true, 1},
		"inner batch with a failing nested": {both(batchMsg(signedTxMsg(t1), []byte{2})), false, 0},
		"inner batch with a good nested":    {both(batchMsg(signedTxMsg(t1))), true, 3},
		"top-level kind 2":                  {[]byte{2, 1}, false, 0},
		"top-level kind 6":                  {[]byte{6}, false, 0},
		"top-level kind 7":                  {[]byte{7}, false, 0},
		"top-level contract tx":             {cat([]byte{1}, w32b(1), w32b(1), w32b(1), w32b(1)), false, 0},
		"empty message":                     {nil, false, 0},
		"unsigned with trailing calldata":   {cat(unsignedOK, []byte{9, 9, 9}), true, 0},
	} {
		got, ok := parseL2(c.msg, 0)
		if ok != c.ok || len(got) != c.count {
			t.Errorf("%s: ok %v (want %v), %d txs (want %d)", name, ok, c.ok, len(got), c.count)
		}
	}
	// a failed message keeps its ordinal and yields no transactions
	r := decodePayload(payloadOf(seg(segL2Message, both([]byte{2})), seg(segL2Message, both())), 1<<20, 100)
	if r.status != payloadOK || len(r.messages) != 2 || len(r.messages[0].txs) != 0 || len(r.messages[1].txs) != 2 || r.messages[1].ordinal != 1 {
		t.Fatalf("%+v", r)
	}
}
