// Copyright 2026 Certen Protocol

package baseposted

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// spanParams are the chain constants a span batch is read against: the L2 genesis time (rel_timestamp is relative to it),
// the L2 block time and the L2 chain id (transactions are rebuilt for it).
type spanParams struct {
	GenesisTime uint64
	BlockTime   uint64
	ChainID     uint64
}

// Bounds on what one span batch may declare, so a hostile count never allocates.
const (
	maxSpanBlocks = 1 << 16
	maxSpanTxs    = 1 << 20
)

type spanReader struct {
	b   []byte
	err error
}

func (r *spanReader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errors.New("span: uvarint")
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *spanReader) fixed(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errors.New("span: short")
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

// bits reads a bitlist of n bits: ceil(n/8) bytes, a big-endian integer whose bit i (least significant first) is item i.
func (r *spanReader) bits(n uint64) *big.Int {
	if r.err != nil {
		return new(big.Int)
	}
	l := n / 8
	if n%8 != 0 {
		l++
	}
	raw := r.fixed(int(l))
	if r.err != nil {
		return new(big.Int)
	}
	v := new(big.Int).SetBytes(raw)
	if uint64(v.BitLen()) > n {
		r.err = errors.New("span: bit list longer than its length")
	}
	return v
}

// decodeSpanBatch decodes a span batch payload (batch type byte already removed) into one Batch per L2 block, per the Delta
// specification (span-batches.md): prefix = rel_timestamp ++ l1_origin_num ++ parent_check(20) ++ l1_origin_check(20); payload =
// block_count ++ origin_bits ++ block_tx_counts ++ txs. The parent hash is committed only for the first block (20 bytes) and the
// epoch hash only for the last (20 bytes); the others carry none (ParentLen/EpochLen 0) and the verifier refuses to bind them.
func decodeSpanBatch(payload []byte, sp spanParams) ([]Batch, error) {
	r := &spanReader{b: payload}
	rel := r.uvarint()
	originNum := r.uvarint()
	parentCheck := r.fixed(20)
	originCheck := r.fixed(20)
	blockCount := r.uvarint()
	if r.err == nil && (blockCount == 0 || blockCount > maxSpanBlocks) {
		return nil, errors.New("span: block count")
	}
	originBits := r.bits(blockCount)
	counts := make([]uint64, 0, 8)
	var total uint64
	for i := uint64(0); i < blockCount && r.err == nil; i++ {
		c := r.uvarint()
		total += c
		if total > maxSpanTxs {
			return nil, errors.New("span: tx count")
		}
		counts = append(counts, c)
	}
	creation := r.bits(total)
	yParity := r.bits(total)
	sigs := make([][64]byte, total)
	for i := range sigs {
		copy(sigs[i][:], r.fixed(64))
	}
	tos := make([]*common.Address, total)
	for i := range tos {
		if creation.Bit(i) == 0 {
			a := common.BytesToAddress(r.fixed(20))
			tos[i] = &a
		}
	}
	// tx_datas: per tx the type-specific RLP payload (legacy has no type byte); the rest of the payload is read through an RLP
	// stream so each item ends where its list ends.
	type spanTx struct {
		typ  byte
		data []byte // the RLP list
	}
	txs := make([]spanTx, total)
	for i := range txs {
		if r.err != nil {
			break
		}
		if len(r.b) == 0 {
			r.err = errors.New("span: short")
			break
		}
		t := byte(0)
		if r.b[0] < 0x80 {
			t = r.b[0]
			r.b = r.b[1:]
		}
		_, _, rest, err := rlp.Split(r.b)
		if err != nil {
			return nil, errors.New("span: tx data")
		}
		txs[i] = spanTx{typ: t, data: r.b[:len(r.b)-len(rest)]}
		r.b = rest
	}
	nonces := make([]uint64, total)
	for i := range nonces {
		nonces[i] = r.uvarint()
	}
	gases := make([]uint64, total)
	for i := range gases {
		gases[i] = r.uvarint()
	}
	var legacy uint64
	for _, t := range txs {
		if t.typ == 0 {
			legacy++
		}
	}
	protected := r.bits(legacy)
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, errors.New("span: trailing bytes")
	}
	// L1 origin numbers: counted back from the last block through the origin bits (a set bit i > 0 means block i advanced the origin).
	origins := make([]uint64, blockCount)
	cur := originNum
	for i := int(blockCount) - 1; i >= 0; i-- {
		origins[i] = cur
		if originBits.Bit(i) == 1 && i > 0 {
			if cur == 0 {
				return nil, errors.New("span: origin underflow")
			}
			cur--
		}
	}
	chainID := new(big.Int).SetUint64(sp.ChainID)
	out := make([]Batch, 0, blockCount)
	ti, li := 0, 0
	for i := uint64(0); i < blockCount; i++ {
		b := Batch{Type: 1, EpochNum: origins[i], Timestamp: sp.GenesisTime + rel + sp.BlockTime*i, SpanIndex: int(i), SpanBlocks: int(blockCount)}
		if i == 0 {
			copy(b.ParentHash[:], parentCheck)
			b.ParentLen = 20
		}
		if i == blockCount-1 {
			copy(b.EpochHash[:], originCheck)
			b.EpochLen = 20
		}
		for k := uint64(0); k < counts[i]; k++ {
			raw, err := rebuildTx(txs[ti].typ, txs[ti].data, nonces[ti], gases[ti], tos[ti], sigs[ti], yParity.Bit(ti), chainID,
				func() uint { v := protected.Bit(li); return v }, txs[ti].typ == 0)
			if err != nil {
				return nil, err
			}
			if txs[ti].typ == 0 {
				li++
			}
			b.Txs = append(b.Txs, raw)
			ti++
		}
		out = append(out, b)
	}
	return out, nil
}

// rebuildTx reconstructs the consensus encoding of one span-batch transaction.
func rebuildTx(typ byte, data []byte, nonce, gas uint64, to *common.Address, sig [64]byte, yPar uint, chainID *big.Int, prot func() uint, isLegacy bool) ([]byte, error) {
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	u := func(x *uint256.Int) *big.Int {
		if x == nil {
			return new(big.Int)
		}
		return x.ToBig()
	}
	var tx *types.Transaction
	switch typ {
	case 0:
		var d struct {
			Value    *uint256.Int
			GasPrice *uint256.Int
			Data     []byte
		}
		if err := rlp.DecodeBytes(data, &d); err != nil {
			return nil, errors.New("span: legacy tx")
		}
		v := new(big.Int).SetUint64(27 + uint64(yPar))
		if prot() == 1 {
			v = new(big.Int).Add(new(big.Int).Mul(chainID, big.NewInt(2)), big.NewInt(35+int64(yPar)))
		}
		tx = types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: u(d.GasPrice), Gas: gas, To: to, Value: u(d.Value), Data: d.Data, V: v, R: r, S: s})
	case types.AccessListTxType:
		var d struct {
			Value      *uint256.Int
			GasPrice   *uint256.Int
			Data       []byte
			AccessList types.AccessList
		}
		if err := rlp.DecodeBytes(data, &d); err != nil {
			return nil, errors.New("span: 2930 tx")
		}
		tx = types.NewTx(&types.AccessListTx{ChainID: chainID, Nonce: nonce, GasPrice: u(d.GasPrice), Gas: gas, To: to, Value: u(d.Value), Data: d.Data,
			AccessList: d.AccessList, V: new(big.Int).SetUint64(uint64(yPar)), R: r, S: s})
	case types.DynamicFeeTxType:
		var d struct {
			Value      *uint256.Int
			GasTipCap  *uint256.Int
			GasFeeCap  *uint256.Int
			Data       []byte
			AccessList types.AccessList
		}
		if err := rlp.DecodeBytes(data, &d); err != nil {
			return nil, errors.New("span: 1559 tx")
		}
		tx = types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: u(d.GasTipCap), GasFeeCap: u(d.GasFeeCap), Gas: gas, To: to,
			Value: u(d.Value), Data: d.Data, AccessList: d.AccessList, V: new(big.Int).SetUint64(uint64(yPar)), R: r, S: s})
	case types.SetCodeTxType:
		var d struct {
			Value             *uint256.Int
			GasTipCap         *uint256.Int
			GasFeeCap         *uint256.Int
			Data              []byte
			AccessList        types.AccessList
			AuthorizationList []types.SetCodeAuthorization
		}
		if err := rlp.DecodeBytes(data, &d); err != nil {
			return nil, errors.New("span: 7702 tx")
		}
		if to == nil {
			return nil, errors.New("span: 7702 tx without to")
		}
		tx = types.NewTx(&types.SetCodeTx{ChainID: uint256.MustFromBig(chainID), Nonce: nonce, GasTipCap: d.GasTipCap, GasFeeCap: d.GasFeeCap, Gas: gas,
			To: *to, Value: d.Value, Data: d.Data, AccessList: d.AccessList, AuthList: d.AuthorizationList,
			V: uint256.NewInt(uint64(yPar)), R: uint256.MustFromBig(r), S: uint256.MustFromBig(s)})
	default:
		return nil, &batchFormatError{typ: typ}
	}
	return tx.MarshalBinary()
}
