// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// An independent span-batch ENCODER written from the Delta specification (span-batches.md): the transactions are built as go-ethereum
// transactions (the oracle: their consensus encoding is what the decoder must reproduce) and laid out as
//   prefix  = rel_timestamp ++ l1_origin_num ++ parent_check(20) ++ l1_origin_check(20)
//   payload = block_count ++ origin_bits ++ block_tx_counts ++ contract_creation_bits ++ y_parity_bits ++ tx_sigs ++ tx_tos ++ tx_datas
//             ++ tx_nonces ++ tx_gases ++ protected_bits
// so a decoder that agrees with it agrees with the specification, not with itself.

type stx struct {
	typ       byte // 0 legacy, 1 access list, 2 dynamic fee, 4 set code
	nonce     uint64
	gas       uint64
	to        *common.Address // nil: contract creation
	value     int64
	price     int64 // legacy / access list gas price; the dynamic fee cap otherwise
	tip       int64 // dynamic fee tip
	data      []byte
	al        types.AccessList
	auth      []types.SetCodeAuthorization
	y         uint // y parity
	protected bool // legacy: EIP-155
	r, s      int64
}

const spanChain = 84532

func (x stx) rb() *big.Int { return new(big.Int).Lsh(big.NewInt(x.r), 200) }
func (x stx) sb() *big.Int { return new(big.Int).Lsh(big.NewInt(x.s), 100) }

// tx is the oracle transaction.
func (x stx) tx() *types.Transaction {
	chain := big.NewInt(spanChain)
	switch x.typ {
	case 0:
		v := big.NewInt(27 + int64(x.y))
		if x.protected {
			v = new(big.Int).Add(new(big.Int).Mul(chain, big.NewInt(2)), big.NewInt(35+int64(x.y)))
		}
		return types.NewTx(&types.LegacyTx{Nonce: x.nonce, GasPrice: big.NewInt(x.price), Gas: x.gas, To: x.to, Value: big.NewInt(x.value), Data: x.data, V: v, R: x.rb(), S: x.sb()})
	case 1:
		return types.NewTx(&types.AccessListTx{ChainID: chain, Nonce: x.nonce, GasPrice: big.NewInt(x.price), Gas: x.gas, To: x.to, Value: big.NewInt(x.value), Data: x.data,
			AccessList: x.al, V: big.NewInt(int64(x.y)), R: x.rb(), S: x.sb()})
	case 2:
		return types.NewTx(&types.DynamicFeeTx{ChainID: chain, Nonce: x.nonce, GasTipCap: big.NewInt(x.tip), GasFeeCap: big.NewInt(x.price), Gas: x.gas, To: x.to,
			Value: big.NewInt(x.value), Data: x.data, AccessList: x.al, V: big.NewInt(int64(x.y)), R: x.rb(), S: x.sb()})
	case 4:
		return types.NewTx(&types.SetCodeTx{ChainID: uint256.NewInt(spanChain), Nonce: x.nonce, GasTipCap: uint256.NewInt(uint64(x.tip)), GasFeeCap: uint256.NewInt(uint64(x.price)),
			Gas: x.gas, To: *x.to, Value: uint256.NewInt(uint64(x.value)), Data: x.data, AccessList: x.al, AuthList: x.auth, V: uint256.NewInt(uint64(x.y)),
			R: uint256.MustFromBig(x.rb()), S: uint256.MustFromBig(x.sb())})
	}
	panic("tx type")
}

func rlpOf(v any) []byte {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return b
}

// spanData is the type-specific part of tx_datas: legacy has no type byte.
func (x stx) spanData() []byte {
	u := func(v int64) *uint256.Int { return uint256.NewInt(uint64(v)) }
	switch x.typ {
	case 0:
		return rlpOf([]any{u(x.value), u(x.price), x.data})
	case 1:
		return append([]byte{1}, rlpOf([]any{u(x.value), u(x.price), x.data, x.al})...)
	case 2:
		return append([]byte{2}, rlpOf([]any{u(x.value), u(x.tip), u(x.price), x.data, x.al})...)
	case 4:
		return append([]byte{4}, rlpOf([]any{u(x.value), u(x.tip), u(x.price), x.data, x.al, x.auth})...)
	}
	panic("tx type")
}

type spanBlk struct {
	advance bool
	txs     []stx
}

func bitlist(bits []bool) []byte {
	v := new(big.Int)
	for i, b := range bits {
		if b {
			v.SetBit(v, i, 1)
		}
	}
	return v.FillBytes(make([]byte, (len(bits)+7)/8))
}

func uvs(vs ...uint64) []byte {
	var out []byte
	for _, v := range vs {
		out = binary.AppendUvarint(out, v)
	}
	return out
}

func encodeSpan(rel, originNum uint64, parent, origin []byte, blocks []spanBlk) []byte {
	var adv, create, ypar, prot []bool
	var counts []uint64
	var sigs, tos, datas []byte
	var nonces, gases []uint64
	for _, b := range blocks {
		adv = append(adv, b.advance)
		counts = append(counts, uint64(len(b.txs)))
		for _, x := range b.txs {
			create = append(create, x.to == nil)
			ypar = append(ypar, x.y == 1)
			if x.typ == 0 {
				prot = append(prot, x.protected)
			}
			sigs = append(sigs, x.rb().FillBytes(make([]byte, 32))...)
			sigs = append(sigs, x.sb().FillBytes(make([]byte, 32))...)
			if x.to != nil {
				tos = append(tos, x.to.Bytes()...)
			}
			datas = append(datas, x.spanData()...)
			nonces = append(nonces, x.nonce)
			gases = append(gases, x.gas)
		}
	}
	var out []byte
	out = append(out, uvs(rel, originNum)...)
	out = append(out, parent...)
	out = append(out, origin...)
	out = append(out, uvs(uint64(len(blocks)))...)
	out = append(out, bitlist(adv)...)
	out = append(out, uvs(counts...)...)
	out = append(out, bitlist(create)...)
	out = append(out, bitlist(ypar)...)
	out = append(out, sigs...)
	out = append(out, tos...)
	out = append(out, datas...)
	out = append(out, uvs(nonces...)...)
	out = append(out, uvs(gases...)...)
	out = append(out, bitlist(prot)...)
	return out
}

var (
	spanSP     = spanParams{GenesisTime: 1695768288, BlockTime: 2, ChainID: spanChain}
	spanParent = bytes.Repeat([]byte{0x11}, 20)
	spanOrigin = bytes.Repeat([]byte{0x22}, 20)
	addrA      = common.HexToAddress("0x00000000000000000000000000000000000000a1")
	addrB      = common.HexToAddress("0x00000000000000000000000000000000000000b2")
)

func sampleTxs() []stx {
	al := types.AccessList{{Address: addrB, StorageKeys: []common.Hash{{1}, {2}}}}
	auth := []types.SetCodeAuthorization{{ChainID: *uint256.NewInt(spanChain), Address: addrA, Nonce: 7, V: 1, R: *uint256.NewInt(5), S: *uint256.NewInt(6)}}
	return []stx{
		{typ: 0, nonce: 1, gas: 21000, to: &addrA, value: 5, price: 7, data: []byte{1, 2, 3}, y: 0, protected: true, r: 3, s: 4},
		{typ: 0, nonce: 2, gas: 22000, to: &addrB, value: 6, price: 8, data: nil, y: 1, protected: false, r: 5, s: 6},
		{typ: 1, nonce: 300, gas: 200000, to: nil, value: 0, price: 9, data: []byte{9, 9}, al: al, y: 1, r: 7, s: 8},
		{typ: 2, nonce: 4, gas: 90000, to: &addrA, value: 1, price: 100, tip: 3, data: []byte{0xde, 0xad}, al: al, y: 0, r: 9, s: 10},
		{typ: 4, nonce: 5, gas: 91000, to: &addrB, value: 2, price: 101, tip: 4, data: nil, al: types.AccessList{}, auth: auth, y: 1, r: 11, s: 12},
		{typ: 0, nonce: 6, gas: 23000, to: nil, value: 7, price: 10, data: []byte{4}, y: 1, protected: true, r: 13, s: 14},
	}
}

func TestSpanBatchesRoundTripEveryTransactionTypeBitListAndBlockLayout(t *testing.T) {
	txs := sampleTxs()
	blocks := []spanBlk{
		{advance: false, txs: []stx{txs[0], txs[1]}}, // block 0: the origin bit 0 is never read
		{advance: true, txs: nil},                    // an empty block that advances the origin
		{advance: true, txs: []stx{txs[2], txs[3]}},
		{advance: false, txs: []stx{txs[4], txs[5]}},
	}
	payload := encodeSpan(1234, 500, spanParent, spanOrigin, blocks)
	got, err := decodeSpanBatch(payload, spanSP)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d batches", len(got))
	}
	// origins count back from the last block through the advance bits: blocks 3, 2 and 1 carry 500, 500, 499 (block 3 does not
	// advance, block 2 advances to 499 for block 1, block 1 advances to 498 for block 0)
	wantEpoch := []uint64{498, 499, 500, 500}
	var tot int
	for i, b := range got {
		if b.Type != 1 || b.EpochNum != wantEpoch[i] || b.Timestamp != 1695768288+1234+2*uint64(i) || b.SpanIndex != i || b.SpanBlocks != 4 {
			t.Errorf("block %d: %+v", i, b)
		}
		wantParent, wantEpochLen := 0, 0
		if i == 0 {
			wantParent = 20
		}
		if i == 3 {
			wantEpochLen = 20
		}
		if b.ParentLen != wantParent || b.EpochLen != wantEpochLen {
			t.Errorf("block %d: parentLen %d epochLen %d", i, b.ParentLen, b.EpochLen)
		}
		if i == 0 && !bytes.Equal(b.ParentHash[:20], spanParent) || i != 0 && b.ParentHash != [32]byte{} {
			t.Errorf("block %d: parent hash %x", i, b.ParentHash)
		}
		if i == 3 && !bytes.Equal(b.EpochHash[:20], spanOrigin) || i != 3 && b.EpochHash != [32]byte{} {
			t.Errorf("block %d: epoch hash %x", i, b.EpochHash)
		}
		if len(b.Txs) != len(blocks[i].txs) {
			t.Fatalf("block %d: %d txs, want %d", i, len(b.Txs), len(blocks[i].txs))
		}
		for k, x := range blocks[i].txs {
			want, err := x.tx().MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b.Txs[k], want) {
				t.Errorf("block %d tx %d (type %d):\n got  %x\n want %x", i, k, x.typ, b.Txs[k], want)
			}
			tot++
		}
	}
	if tot != 6 {
		t.Fatalf("%d transactions", tot)
	}
	// the decoded stream is judged through decodeBatches the same way (a singular batch before it and after it)
	stream := rlpOf(append([]byte{1}, payload...))
	viaStream, err := decodeBatches(stream, spanSP)
	if err != nil || len(viaStream) != 4 {
		t.Fatalf("%d, %v", len(viaStream), err)
	}
}

func TestOriginNumbersCountBackThroughTheAdvanceBitsAndNeverUnderflow(t *testing.T) {
	two := func(origin uint64, adv ...bool) error {
		var bl []spanBlk
		for _, a := range adv {
			bl = append(bl, spanBlk{advance: a})
		}
		_, err := decodeSpanBatch(encodeSpan(0, origin, spanParent, spanOrigin, bl), spanSP)
		return err
	}
	// a set bit 0 is not an advance: origin 0 with a single advancing first block is fine
	if err := two(0, true); err != nil {
		t.Fatalf("bit 0 at origin 0: %v", err)
	}
	// block 1 advancing from origin 0 would be origin -1 for block 0
	if err := two(0, false, true); err == nil || err.Error() != "span: origin underflow" {
		t.Fatalf("underflow: %v", err)
	}
	// from origin 1 it is origin 0 for block 0
	got, err := decodeSpanBatch(encodeSpan(0, 1, spanParent, spanOrigin, []spanBlk{{}, {advance: true}}), spanSP)
	if err != nil || got[0].EpochNum != 0 || got[1].EpochNum != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	// two advances in a row at origin 1 underflow on the second
	if err := two(1, false, true, true); err == nil || err.Error() != "span: origin underflow" {
		t.Fatalf("second advance: %v", err)
	}
}

func rawPayload(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestSpanBatchRefusalsNameTheirCheck(t *testing.T) {
	head := rawPayload(uvs(0, 9), spanParent, spanOrigin)
	overflow := bytes.Repeat([]byte{0xff}, 11)
	for _, c := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"empty", nil, "span: uvarint"},
		{"rel truncated mid-uvarint", []byte{0x80}, "span: uvarint"},
		{"origin number missing", uvs(5), "span: uvarint"},
		{"uvarint overflow", overflow, "span: uvarint"},
		{"parent check short", rawPayload(uvs(0, 9), spanParent[:19]), "span: short"},
		{"origin check short", rawPayload(uvs(0, 9), spanParent, spanOrigin[:19]), "span: short"},
		{"block count missing", head, "span: uvarint"},
		{"block count 0", rawPayload(head, uvs(0)), "span: block count"},
		{"block count over the bound", rawPayload(head, uvs(maxSpanBlocks+1)), "span: block count"},
		{"origin bits missing", rawPayload(head, uvs(3)), "span: short"},
		{"origin bit beyond the list", rawPayload(head, uvs(3), []byte{0x08}), "span: bit list longer than its length"},
		{"a count missing", rawPayload(head, uvs(2), []byte{0}, uvs(0)), "span: uvarint"},
		{"trailing bytes", rawPayload(encodeSpan(0, 9, spanParent, spanOrigin, []spanBlk{{}}), []byte{0}), "span: trailing bytes"},
		{"creation bits missing", rawPayload(head, uvs(1), []byte{0}, uvs(1)), "span: short"},
		{"tx data missing", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes()), "span: short"},
		{"tx data not RLP", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), []byte{2, 0xf9, 0xff}), "span: tx data"},
		{"nonces missing", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), sampleTxs()[3].spanData()), "span: uvarint"},
		{"gases missing", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), sampleTxs()[3].spanData(), uvs(4)), "span: uvarint"},
		{"protected bits missing", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), sampleTxs()[0].spanData(), uvs(4), uvs(21000)), "span: short"},
		{"protected bit beyond the list", rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), sampleTxs()[0].spanData(), uvs(4), uvs(21000), []byte{2}), "span: bit list longer than its length"},
	} {
		_, err := decodeSpanBatch(c.payload, spanSP)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// the block count bound itself is admitted: 2^16 empty blocks decode
	full := encodeSpan(0, 1<<20, spanParent, spanOrigin, make([]spanBlk, maxSpanBlocks))
	got, err := decodeSpanBatch(full, spanSP)
	if err != nil || len(got) != maxSpanBlocks {
		t.Fatalf("%d batches, %v", len(got), err)
	}
	// a legacy transaction whose RLP is not [value, gasPrice, data], and the other types' counterparts
	bad := func(typed []byte, tx stx) []byte {
		p := rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), typed, uvs(tx.nonce), uvs(tx.gas))
		if typed[0] >= 0xc0 { // a legacy transaction has a protected bit
			p = append(p, 0)
		}
		return p
	}
	tx := sampleTxs()
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"legacy list of two", rlpOf([]any{uint64(1), uint64(2)}), "span: legacy tx"},
		{"2930 list of three", append([]byte{1}, rlpOf([]any{uint64(1), uint64(2), []byte{}})...), "span: 2930 tx"},
		{"1559 list of four", append([]byte{2}, rlpOf([]any{uint64(1), uint64(2), uint64(3), []byte{}})...), "span: 1559 tx"},
		{"7702 list of five", append([]byte{4}, rlpOf([]any{uint64(1), uint64(2), uint64(3), []byte{}, []any{}})...), "span: 7702 tx"},
	} {
		_, err := decodeSpanBatch(bad(c.data, tx[0]), spanSP)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// a 7702 transaction cannot create a contract
	noTo := rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{1}, []byte{0}, make([]byte, 64), tx[4].spanData(), uvs(5), uvs(91000))
	if _, err := decodeSpanBatch(noTo, spanSP); err == nil || err.Error() != "span: 7702 tx without to" {
		t.Errorf("7702 without to: %v", err)
	}
	// a transaction type this verifier does not decode is a batchFormatError carrying the type, and only after the plain checks
	three := rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), []byte{3}, rlpOf([]any{uint64(1)}), uvs(1), uvs(1))
	_, err = decodeSpanBatch(three, spanSP)
	if bf, ok := err.(*batchFormatError); !ok || bf.typ != 3 {
		t.Errorf("type 3: %T %v", err, err)
	}
	trailing := rawPayload(three, []byte{0})
	if _, err = decodeSpanBatch(trailing, spanSP); err == nil || err.Error() != "span: trailing bytes" {
		t.Errorf("a plain check outranks the type refusal: %v", err)
	}
}

func TestBatchStreamRefusalsNameTheirCheck(t *testing.T) {
	good := rlpOf(append([]byte{0}, rlpOf(singularRLP{ParentHash: [32]byte{1}, EpochNum: 5, EpochHash: [32]byte{2}, Timestamp: 9, Txs: [][]byte{{1, 2}}})...))
	got, err := decodeBatches(good, spanSP)
	if err != nil || len(got) != 1 || got[0].Type != 0 || got[0].EpochNum != 5 || got[0].Timestamp != 9 || got[0].ParentLen != 32 || got[0].EpochLen != 32 || got[0].SpanBlocks != 1 || len(got[0].Txs) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	// a one-byte stream: the lone byte < 0x80 is a Byte, not a String
	for _, c := range []struct {
		name   string
		stream []byte
		want   string
	}{
		{"a lone byte", []byte{0x05}, "batch stream"},
		{"an empty string", []byte{0x80}, "batch stream"},
		{"a list", []byte{0xc0}, "batch stream"},
		{"truncated string", []byte{0x85, 1, 2}, "batch stream"},
		{"singular batch that is not RLP", rlpOf([]byte{0, 0xc3, 1}), "singular batch"},
		{"singular batch with a trailing item", rlpOf(append([]byte{0}, rlpOf([]any{[32]byte{}, uint64(1), [32]byte{}, uint64(2), [][]byte{}, uint64(3)})...)), "singular batch"},
	} {
		_, err := decodeBatches(c.stream, spanSP)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// a batch type this verifier does not decode
	_, err = decodeBatches(rlpOf([]byte{7, 1}), spanSP)
	if bf, ok := err.(*batchFormatError); !ok || bf.typ != 7 {
		t.Errorf("type 7: %T %v", err, err)
	}
	// two batches in one stream are both read, a single trailing byte is not a batch
	two, err := decodeBatches(append(append([]byte(nil), good...), good...), spanSP)
	if err != nil || len(two) != 2 {
		t.Fatalf("%d %v", len(two), err)
	}
	if _, err = decodeBatches(append(append([]byte(nil), good...), 0x00), spanSP); err == nil {
		t.Fatal("a trailing lone byte must be refused")
	}
	// the empty stream has no batch and no error
	if empty, err := decodeBatches(nil, spanSP); err != nil || len(empty) != 0 {
		t.Fatalf("%d %v", len(empty), err)
	}
}
