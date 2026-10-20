// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// ---- the zero-heavy layer ---------------------------------------------------------------------------------------------------

// zhEncode is nitro@ccc5c82 zeroheavy.ZeroheavyEncoder over a byte slice (the inverse the decoder is tested against).
func zhEncode(in []byte) []byte {
	var out []byte
	pos, bitsRead := 0, uint8(8)
	var buffer byte
	padding, atEOF := false, false
	next := func() bool {
		if padding {
			return true
		}
		if bitsRead == 8 {
			if pos >= len(in) {
				padding = true
				return false
			}
			buffer = in[pos]
			pos++
			bitsRead = 0
		}
		r := buffer&(1<<(7-bitsRead)) != 0
		bitsRead++
		return r
	}
	for !atEOF {
		var ret byte
		if !next() {
			if next() {
				ret = 1
				for i := 0; i < 6; i++ {
					ret <<= 1
					if next() {
						ret++
					}
				}
				if ret == 64 {
					ret = 1
				} else {
					ret = (ret << 1) & 0x7f
					if next() {
						ret++
					}
				}
			}
		} else {
			ret = 1
			for i := 0; i < 7; i++ {
				ret <<= 1
				if next() {
					ret++
				}
			}
		}
		out = append(out, ret)
		if padding {
			atEOF = true
		}
	}
	return out
}

func TestZeroheavyDecodesWhatNitrosEncoderWrites(t *testing.T) {
	if got, ex := zeroheavyDecode(nil, 10); len(got) != 0 || ex {
		t.Fatalf("null input: %x %v", got, ex)
	}
	for i := 0; i < 256; i++ {
		got, ex := zeroheavyDecode(zhEncode([]byte{byte(i)}), 10)
		if ex || !bytes.Equal(got, []byte{byte(i)}) {
			t.Fatalf("one byte %d: %x", i, got)
		}
	}
	rnd := rand.New(rand.NewSource(9))
	for n := 0; n < 300; n++ {
		in := make([]byte, 1+rnd.Intn(300))
		for i := range in {
			if rnd.Intn(3) != 0 {
				in[i] = 0
			} else {
				in[i] = byte(rnd.Intn(256))
			}
		}
		got, ex := zeroheavyDecode(zhEncode(in), len(in))
		if ex || !bytes.Equal(got, in) {
			t.Fatalf("round trip of %d bytes failed", len(in))
		}
		if _, ex := zeroheavyDecode(zhEncode(in), len(in)-1); !ex {
			t.Fatalf("a decode of %d bytes under a bound of %d was not reported as exceeding it", len(in), len(in)-1)
		}
	}
}

func zhPayload(inner []byte) []byte { return append([]byte{headerZeroheavy}, zhEncode(inner)...) }

func TestAZeroheavyPayloadIsDecodedOnceAndThenReadAsBrotli(t *testing.T) {
	a, b := legacyTx(1), legacyTx(2)
	inner := payloadOf(seg(segL2Message, signedTxMsg(a)), seg(segL2Message, batchMsg(signedTxMsg(a), signedTxMsg(b))))
	r := decodePayload(zhPayload(inner), 1<<20, 100)
	if r.status != payloadOK || len(r.messages) != 2 || !sameTxs(r.messages[1].txs, [][]byte{a, b}) {
		t.Fatalf("zero-heavy payload: %+v", r)
	}
	for name, c := range map[string]struct {
		inner  []byte
		status payloadStatus
		hdr    byte
	}{
		"das after the layer is not a DAS payload": {append([]byte{headerDAS}, inner[1:]...), payloadUnknownHeader, headerDAS},
		"a second zero-heavy layer is not decoded": {zhPayload(inner), payloadUnknownHeader, headerZeroheavy},
		"unknown byte": {append([]byte{0x07}, inner[1:]...), payloadUnknownHeader, 0x07},
	} {
		r := decodePayload(zhPayload(c.inner), 1<<20, 100)
		if r.status != c.status || r.headerByte != c.hdr {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := decodePayload([]byte{headerZeroheavy}, 1<<20, 100); r.status != payloadUndecodable {
		t.Errorf("zero-heavy header alone: %+v", r)
	}
	// a brotli stream cut short inside the layer is refused like any other
	if r := decodePayload(zhPayload(inner[:len(inner)-1]), 1<<20, 100); r.status != payloadUndecodable {
		t.Errorf("truncated inner stream: %+v", r)
	}
	// the layer's own bound is 101% of the batch bound plus 64: a longer decode is a bomb
	bomb := append([]byte{0}, bytes.Repeat([]byte{0}, 5000)...)
	if r := decodePayload(zhPayload(bomb), 1000, 100); r.status != payloadTooLarge || !r.exceededUncompressed {
		t.Errorf("zero-heavy bomb: %+v", r)
	}
}

// ---- delayed-message derivation ------------------------------------------------------------------------------------------------

func word(v *big.Int) []byte        { return common.LeftPadBytes(v.Bytes(), 32) }
func wordU(v uint64) []byte         { return word(new(big.Int).SetUint64(v)) }
func wordA(a common.Address) []byte { return common.LeftPadBytes(a[:], 32) }

// The expected encodings are restated here from go-ethereum's arb_types.go (field order) so the derivation is not tested against itself.
type expUnsigned struct {
	ChainID   *big.Int
	From      common.Address
	Nonce     uint64
	GasFeeCap *big.Int
	Gas       uint64
	To        []byte
	Value     *big.Int
	Data      []byte
}
type expContract struct {
	ChainID   *big.Int
	RequestID common.Hash
	From      common.Address
	GasFeeCap *big.Int
	Gas       uint64
	To        []byte
	Value     *big.Int
	Data      []byte
}
type expRetryable struct {
	ChainID          *big.Int
	RequestID        common.Hash
	From             common.Address
	L1BaseFee        *big.Int
	DepositValue     *big.Int
	GasFeeCap        *big.Int
	Gas              uint64
	RetryTo          []byte
	RetryValue       *big.Int
	Beneficiary      common.Address
	MaxSubmissionFee *big.Int
	FeeRefundAddr    common.Address
	RetryData        []byte
}
type expDeposit struct {
	ChainID   *big.Int
	RequestID common.Hash
	From      common.Address
	To        common.Address
	Value     *big.Int
}

func typed(t byte, v any) []byte {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return append([]byte{t}, b...)
}

func TestDelayedMessagesDeriveWhatNitroBuilds(t *testing.T) {
	cid := big.NewInt(421614)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	refund := common.HexToAddress("0x3333333333333333333333333333333333333333")
	k := uint64(77)
	req := w32(k)
	base := Delayed{Sender: sender, MsgBlockNumber: 5, MsgTimestamp: 6, K: k}
	base.BaseFeeL1[31] = 9

	// kind 9: submit retryable
	retryData := []byte{1, 2, 3, 4}
	rd := bytes.Join([][]byte{wordA(to), wordU(5), wordU(100), wordU(7), wordA(refund), wordA(refund), wordU(21000), wordU(3), wordU(uint64(len(retryData))), retryData}, nil)
	m9 := base
	m9.MsgKind, m9.Data = msgKindSubmitRetryable, rd
	want9 := typed(0x69, expRetryable{ChainID: cid, RequestID: req, From: sender, L1BaseFee: big.NewInt(9), DepositValue: big.NewInt(100), GasFeeCap: big.NewInt(3), Gas: 21000,
		RetryTo: to[:], RetryValue: big.NewInt(5), Beneficiary: refund, MaxSubmissionFee: big.NewInt(7), FeeRefundAddr: refund, RetryData: retryData})
	if got, ok := deriveDelayed(421614, m9); !ok || !sameTxs(got, [][]byte{want9}) {
		t.Fatalf("submit retryable: ok %v", ok)
	}
	m9.Data = bytes.Join([][]byte{wordA(common.Address{}), wordU(5), wordU(100), wordU(7), wordA(refund), wordA(refund), wordU(21000), wordU(3), wordU(0)}, nil)
	want9c := typed(0x69, expRetryable{ChainID: cid, RequestID: req, From: sender, L1BaseFee: big.NewInt(9), DepositValue: big.NewInt(100), GasFeeCap: big.NewInt(3), Gas: 21000,
		RetryTo: []byte{}, RetryValue: big.NewInt(5), Beneficiary: refund, MaxSubmissionFee: big.NewInt(7), FeeRefundAddr: refund, RetryData: []byte{}})
	if got, ok := deriveDelayed(421614, m9); !ok || !sameTxs(got, [][]byte{want9c}) {
		t.Fatalf("submit retryable to the zero address: ok %v", ok)
	}
	for name, d := range map[string][]byte{"short data": rd[:len(rd)-2], "gas over 2^64": bytes.Join([][]byte{wordA(to), wordU(5), wordU(100), wordU(7), wordA(refund), wordA(refund), word(new(big.Int).Lsh(big.NewInt(1), 70)), wordU(3), wordU(0)}, nil)} {
		m := base
		m.MsgKind, m.Data = msgKindSubmitRetryable, d
		if _, ok := deriveDelayed(421614, m); ok {
			t.Errorf("%s: derived", name)
		}
	}

	// kind 3: L2 message holding an unsigned tx (0), a contract tx (1), a batch of both (3) and a signed tx (4)
	unsignedBody := bytes.Join([][]byte{wordU(50000), wordU(8), wordU(4), wordA(to), wordU(11), {9, 9}}, nil)
	contractBody := bytes.Join([][]byte{wordU(60000), wordU(8), wordA(to), wordU(12), {8}}, nil)
	m3 := base
	m3.MsgKind, m3.Data = msgKindL2Message, append([]byte{l2KindUnsigned}, unsignedBody...)
	wantU := typed(0x65, expUnsigned{ChainID: cid, From: sender, Nonce: 4, GasFeeCap: big.NewInt(8), Gas: 50000, To: to[:], Value: big.NewInt(11), Data: []byte{9, 9}})
	if got, ok := deriveDelayed(421614, m3); !ok || !sameTxs(got, [][]byte{wantU}) {
		t.Fatalf("unsigned: ok %v", ok)
	}
	m3.Data = append([]byte{l2KindContract}, contractBody...)
	wantC := typed(0x66, expContract{ChainID: cid, RequestID: req, From: sender, GasFeeCap: big.NewInt(8), Gas: 60000, To: to[:], Value: big.NewInt(12), Data: []byte{8}})
	if got, ok := deriveDelayed(421614, m3); !ok || !sameTxs(got, [][]byte{wantC}) {
		t.Fatalf("contract: ok %v", ok)
	}
	// a batch: the contract tx inside it gets the sub-request id keccak(requestId || index)
	sub := crypto.Keccak256Hash(req[:], common.BigToHash(big.NewInt(1)).Bytes())
	m3.Data = batchMsg(append([]byte{l2KindUnsigned}, unsignedBody...), append([]byte{l2KindContract}, contractBody...))
	wantCsub := typed(0x66, expContract{ChainID: cid, RequestID: sub, From: sender, GasFeeCap: big.NewInt(8), Gas: 60000, To: to[:], Value: big.NewInt(12), Data: []byte{8}})
	if got, ok := deriveDelayed(421614, m3); !ok || !sameTxs(got, [][]byte{wantU, wantCsub}) {
		t.Fatalf("batch: ok %v", ok)
	}
	// a nested failure fails the whole message, and so does every L2 kind Nitro refuses
	m3.Data = batchMsg(append([]byte{l2KindUnsigned}, unsignedBody...), []byte{2, 0, 0})
	if _, ok := deriveDelayed(421614, m3); ok {
		t.Error("a batch with a NonmutatingCall inside was derived")
	}
	for _, kind := range []byte{2, 5, 6, 7, 8, 9} {
		m3.Data = []byte{kind, 1, 2, 3}
		if _, ok := deriveDelayed(421614, m3); ok {
			t.Errorf("L2 kind %d derived", kind)
		}
	}
	// depth limit: 16 nested batches are the most
	deep := append([]byte{l2KindContract}, contractBody...)
	for i := 0; i < 16; i++ {
		deep = batchMsg(deep)
	}
	m3.Data = deep
	if got, ok := deriveDelayed(421614, m3); !ok || len(got) != 1 {
		t.Errorf("16 nested batches: ok %v", ok)
	}
	m3.Data = batchMsg(deep)
	if _, ok := deriveDelayed(421614, m3); ok {
		t.Error("17 nested batches were derived")
	}
	// a signed transaction delivered through the delayed inbox stays a standard transaction
	m3.Data = signedTxMsg(legacyTx(5))
	if got, ok := deriveDelayed(421614, m3); !ok || len(got) != 1 {
		t.Errorf("signed tx: ok %v", ok)
	}

	// kind 7: L2 funded by L1: a deposit to the poster with From unset, then the unsigned tx under the second sub-request id
	m7 := base
	m7.MsgKind, m7.Data = msgKindL2FundedByL1, append([]byte{l2KindContract}, contractBody...)
	depID := crypto.Keccak256Hash(req[:], common.BigToHash(big.NewInt(0)).Bytes())
	unID := crypto.Keccak256Hash(req[:], common.BigToHash(big.NewInt(1)).Bytes())
	wantDep := typed(txDeposit, expDeposit{ChainID: cid, RequestID: depID, From: common.Address{}, To: sender, Value: big.NewInt(12)})
	wantCt := typed(0x66, expContract{ChainID: cid, RequestID: unID, From: sender, GasFeeCap: big.NewInt(8), Gas: 60000, To: to[:], Value: big.NewInt(12), Data: []byte{8}})
	if got, ok := deriveDelayed(421614, m7); !ok || !sameTxs(got, [][]byte{wantDep, wantCt}) {
		t.Fatalf("funded by L1: ok %v", ok)
	}
	m7.Data = append([]byte{4}, contractBody...)
	if _, ok := deriveDelayed(421614, m7); ok {
		t.Error("funded by L1 with L2 kind 4 was derived")
	}

	// kinds with no derivation, and an oversize message
	for _, kind := range []uint8{6, 8, 10, 11, 13, 0xff} {
		m := base
		m.MsgKind, m.Data = kind, []byte{1}
		if _, ok := deriveDelayed(421614, m); ok {
			t.Errorf("message kind %d derived", kind)
		}
	}
	huge := base
	huge.MsgKind, huge.Data = msgKindEthDeposit, make([]byte, maxL2MessageSize+1)
	if _, ok := deriveDelayed(421614, huge); ok {
		t.Error("an oversize message was derived")
	}
}

// Malformed delayed messages: every refusal path of the derivation, each by a message that reaches exactly that path.
func TestMalformedDelayedMessagesAreNotDerived(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	base := Delayed{Sender: sender, K: 5}
	mk := func(kind uint8, data []byte) Delayed {
		d := base
		d.MsgKind, d.Data = kind, data
		return d
	}
	over64 := word(new(big.Int).Lsh(big.NewInt(1), 70))
	for name, d := range map[string]Delayed{
		"ETH deposit with 51 bytes":            mk(msgKindEthDeposit, make([]byte, 51)),
		"ETH deposit empty":                    mk(msgKindEthDeposit, nil),
		"L2 message empty":                     mk(msgKindL2Message, nil),
		"unsigned tx with a gas limit >= 2^64": mk(msgKindL2Message, append([]byte{l2KindUnsigned}, bytes.Join([][]byte{over64, wordU(1), wordU(1), wordA(to), wordU(1)}, nil)...)),
		"unsigned tx with a nonce >= 2^64":     mk(msgKindL2Message, append([]byte{l2KindUnsigned}, bytes.Join([][]byte{wordU(1), wordU(1), over64, wordA(to), wordU(1)}, nil)...)),
		"unsigned tx cut after the gas limit":  mk(msgKindL2Message, append([]byte{l2KindUnsigned}, wordU(1)...)),
		"contract tx cut before the value":     mk(msgKindL2Message, append([]byte{l2KindContract}, bytes.Join([][]byte{wordU(1), wordU(1), wordA(to)}, nil)...)),
		"signed tx that is not a transaction":  mk(msgKindL2Message, []byte{l2SignedTx, 0xde, 0xad}),
		"signed tx of an Arbitrum type":        mk(msgKindL2Message, []byte{l2SignedTx, 0x64, 0xc0}),
		"signed tx of the blob type":           mk(msgKindL2Message, []byte{l2SignedTx, 0x03, 0xc0}),
		"funded by L1 empty":                   mk(msgKindL2FundedByL1, nil),
		"funded by L1 cut":                     mk(msgKindL2FundedByL1, []byte{l2KindContract, 1, 2}),
		"retryable cut before the data":        mk(msgKindSubmitRetryable, bytes.Join([][]byte{wordA(to), wordU(1), wordU(1), wordU(1), wordA(to), wordA(to), wordU(1), wordU(1), wordU(10), {1, 2}}, nil)),
		"retryable data length >= 2^64":        mk(msgKindSubmitRetryable, bytes.Join([][]byte{wordA(to), wordU(1), wordU(1), wordU(1), wordA(to), wordA(to), wordU(1), wordU(1), over64}, nil)),
		"retryable data length over the limit": mk(msgKindSubmitRetryable, bytes.Join([][]byte{wordA(to), wordU(1), wordU(1), wordU(1), wordA(to), wordA(to), wordU(1), wordU(1), wordU(maxL2MessageSize + 1)}, nil)),
	} {
		if got, ok := deriveDelayed(421614, d); ok {
			t.Errorf("%s: derived %d transactions", name, len(got))
		}
	}
	// a batch whose last length prefix is cut, or oversize, or whose nested message is cut, ends quietly with what it has
	good := append([]byte{l2KindContract}, bytes.Join([][]byte{wordU(1), wordU(1), wordA(to), wordU(1)}, nil)...)
	one := batchMsg(good)
	for name, tail := range map[string][]byte{"cut length": {0, 0, 0}, "oversize length": binary.BigEndian.AppendUint64(nil, maxL2MessageSize+1), "cut nested": append(binary.BigEndian.AppendUint64(nil, 50), 1, 2)} {
		got, ok := deriveDelayed(421614, mk(msgKindL2Message, append(append([]byte(nil), one...), tail...)))
		if !ok || len(got) != 1 {
			t.Errorf("%s: ok %v, %d transactions", name, ok, len(got))
		}
	}
	// a nested length of exactly the limit is read (and then fails as a message because it is empty padding)
	if _, ok := deriveDelayed(421614, mk(msgKindL2Message, append(append([]byte(nil), one...), binary.BigEndian.AppendUint64(nil, 0)...))); ok {
		t.Error("a batch holding an empty nested message was derived")
	}
	// a message of exactly the size limit is accepted by the size check (it then fails to parse, not on size)
	exact := mk(msgKindEthDeposit, make([]byte, maxL2MessageSize))
	if _, ok := deriveDelayed(421614, exact); !ok {
		t.Error("an ETH deposit message of exactly the size limit was refused on size")
	}
}

func TestHeaderNonceIsReadFromTheFifteenthItemOnly(t *testing.T) {
	raw, _ := l2Header([][]byte{{0x6a, 0xc0}}, 5, 0x0102030405060708)
	if n, ok := headerNonce(raw); !ok || n != 0x0102030405060708 {
		t.Fatalf("nonce %x ok %v", n, ok)
	}
	if _, ok := headerNonce([]byte{0x01}); ok {
		t.Error("a non-list header gave a nonce")
	}
	short, _ := rlp.EncodeToBytes([]any{[]byte{1}, []byte{2}})
	if _, ok := headerNonce(short); ok {
		t.Error("a two-item header gave a nonce")
	}
	// the 15th item is a list, or not 8 bytes long
	var items []any
	for i := 0; i < 14; i++ {
		items = append(items, []byte{byte(i)})
	}
	for name, last := range map[string]any{"a list": []any{}, "seven bytes": make([]byte, 7), "nine bytes": make([]byte, 9)} {
		hdr, _ := rlp.EncodeToBytes(append(append([]any(nil), items...), last))
		if _, ok := headerNonce(hdr); ok {
			t.Errorf("item 14 as %s gave a nonce", name)
		}
	}
	// a 16th item after a good nonce does not matter
	hdr, _ := rlp.EncodeToBytes(append(append([]any(nil), items...), make([]byte, 8), []byte{9}))
	if n, ok := headerNonce(hdr); !ok || n != 0 {
		t.Errorf("a 16-item header: %d %v", n, ok)
	}
}
