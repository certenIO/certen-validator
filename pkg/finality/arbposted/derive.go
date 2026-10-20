// Copyright 2026 Certen Protocol

package arbposted

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// This file derives, from one delayed-inbox message, the transactions Nitro's ParseL2Transactions builds from it (nitro@ccc5c82
// arbos/parse_l2.go), as consensus encodings (type byte || rlp(fields), field order of OffchainLabs go-ethereum core/types/
// arb_types.go, the order pkg/ethproof/encode.go already reproduces for whole blocks). The header Nitro gives such a message is
// {Poster: the Bridge message's sender, RequestId: the delayed message index k as a hash, L1BaseFee: the message's baseFeeL1}.

// L1 message kinds (nitro arbos/arbostypes/incomingmessage.go) that become transactions.
const (
	msgKindL2Message       = 3
	msgKindL2FundedByL1    = 7
	msgKindSubmitRetryable = 9
	// msgKindEthDeposit is 12 (delayed.go)
)

// L2 message kinds (parse_l2.go).
const (
	l2KindUnsigned = 0
	l2KindContract = 1
)

// Arbitrum transaction types a delayed message produces.
const (
	txUnsigned        = 0x65
	txContract        = 0x66
	txSubmitRetryable = 0x69
)

// derivedMaxDepth is parse_l2.go's batch nesting limit.
const derivedMaxDepth = 16

type msgReader struct {
	b   []byte
	off int
	bad bool
}

func (r *msgReader) take(n int) []byte {
	if r.bad || n < 0 || r.off+n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *msgReader) hash() common.Hash { return common.BytesToHash(r.take(32)) }

// addr256 is util.AddressFrom256FromReader: the low 20 bytes of a 32-byte word.
func (r *msgReader) addr256() common.Address {
	w := r.take(32)
	if w == nil {
		return common.Address{}
	}
	return common.BytesToAddress(w[12:])
}

func (r *msgReader) rest() []byte {
	if r.bad {
		return nil
	}
	out := r.b[r.off:]
	r.off = len(r.b)
	return out
}

func optAddr(a common.Address) []byte {
	if a == (common.Address{}) {
		return []byte{}
	}
	return a[:]
}

func encTx(typ byte, fields ...any) []byte {
	b, err := rlp.EncodeToBytes(fields)
	if err != nil {
		panic(err) // the field types are fixed above
	}
	return append([]byte{typ}, b...)
}

// parseUnsigned is parseUnsignedTx: gas limit, max fee, nonce (kind 0 only), to, value, calldata.
func parseUnsigned(r *msgReader, poster common.Address, requestID *common.Hash, chainID *big.Int, kind byte) ([]byte, *big.Int, bool) {
	gasW := r.hash()
	maxFee := r.hash()
	var nonce *big.Int
	if kind == l2KindUnsigned {
		nonce = r.hash().Big()
	}
	to := r.addr256()
	value := r.hash().Big()
	data := r.rest()
	if r.bad || !gasW.Big().IsUint64() || (nonce != nil && !nonce.IsUint64()) {
		return nil, nil, false
	}
	gas := gasW.Big().Uint64()
	switch kind {
	case l2KindUnsigned:
		return encTx(txUnsigned, chainID, poster, nonce.Uint64(), maxFee.Big(), gas, optAddr(to), value, data), value, true
	case l2KindContract:
		if requestID == nil {
			return nil, nil, false
		}
		return encTx(txContract, chainID, *requestID, poster, maxFee.Big(), gas, optAddr(to), value, data), value, true
	}
	return nil, nil, false
}

// parseL2Msg is parseL2Message for the kinds a delayed L2 message can hold: unsigned (0), contract (1), batch (3), signed (4).
// Any other kind, a short field or a nested failure fails the whole message, as in Nitro.
func parseL2Msg(msg []byte, poster common.Address, requestID *common.Hash, chainID *big.Int, depth int, unmarshalSigned bool) ([][]byte, bool) {
	r := &msgReader{b: msg}
	k := r.take(1)
	if k == nil {
		return nil, false
	}
	switch k[0] {
	case l2KindUnsigned, l2KindContract:
		tx, _, ok := parseUnsigned(r, poster, requestID, chainID, k[0])
		if !ok {
			return nil, false
		}
		return [][]byte{tx}, true
	case l2Batch:
		if depth >= derivedMaxDepth {
			return nil, false
		}
		var out [][]byte
		index := big.NewInt(0)
		for {
			lenBytes := r.take(8)
			if lenBytes == nil {
				return out, true // no further messages in the batch
			}
			n := new(big.Int).SetBytes(lenBytes)
			if !n.IsUint64() || n.Uint64() > maxL2MessageSize {
				return out, true
			}
			nested := r.take(int(n.Uint64()))
			if nested == nil {
				return out, true
			}
			var sub *common.Hash
			if requestID != nil {
				h := crypto.Keccak256Hash(requestID[:], common.BigToHash(index).Bytes())
				sub = &h
			}
			txs, ok := parseL2Msg(nested, poster, sub, chainID, depth+1, unmarshalSigned)
			if !ok {
				return nil, false
			}
			out = append(out, txs...)
			index.Add(index, big.NewInt(1))
		}
	case l2SignedTx:
		rest := r.rest()
		if !unmarshalSigned {
			// sequencer batches: the bytes are compared with the block's own transactions, which are valid by construction, so
			// a message transaction that is not valid can never equal one and needs no unmarshalling to be unmatched
			if len(rest) == 0 || (rest[0] < 0xc0 && rest[0] != 1 && rest[0] != 2 && rest[0] != 4) {
				return nil, false // empty, or a type Nitro refuses (Arbitrum types, blob, unknown): it fails the message
			}
			return [][]byte{append([]byte(nil), rest...)}, true
		}
		var tx types.Transaction
		if err := tx.UnmarshalBinary(rest); err != nil || tx.Type() >= 0x64 || tx.Type() == types.BlobTxType {
			return nil, false
		}
		enc, err := tx.MarshalBinary()
		if err != nil {
			return nil, false
		}
		return [][]byte{enc}, true
	}
	return nil, false
}

// deriveDelayed returns the transactions Nitro builds from the delayed message d on the chain chainID, in order. ok is false for a
// message kind this verifier does not derive (end-of-block, rollup event, batch posting report, ...) and for a message Nitro
// itself would refuse.
func deriveDelayed(chainID uint64, d Delayed) (txs [][]byte, ok bool) {
	if len(d.Data) > maxL2MessageSize {
		return nil, false
	}
	cid := new(big.Int).SetUint64(chainID)
	req := common.BigToHash(new(big.Int).SetUint64(d.K))
	poster := common.Address(d.Sender)
	r := &msgReader{b: d.Data}
	switch d.MsgKind {
	case msgKindEthDeposit:
		to := r.take(20)
		value := r.hash().Big()
		if r.bad {
			return nil, false
		}
		body, err := rlp.EncodeToBytes(depositTx{ChainID: cid, RequestID: req, From: poster, To: common.BytesToAddress(to), Value: value})
		if err != nil {
			return nil, false
		}
		return [][]byte{append([]byte{txDeposit}, body...)}, true
	case msgKindSubmitRetryable:
		retryTo := r.addr256()
		callvalue := r.hash().Big()
		deposit := r.hash().Big()
		maxSubmission := r.hash().Big()
		feeRefund := r.addr256()
		callvalueRefund := r.addr256()
		gasW := r.hash()
		maxFee := r.hash().Big()
		dataLenW := r.hash()
		if r.bad || !gasW.Big().IsUint64() || !dataLenW.Big().IsUint64() || dataLenW.Big().Uint64() > maxL2MessageSize {
			return nil, false
		}
		data := r.take(int(dataLenW.Big().Uint64()))
		if r.bad {
			return nil, false
		}
		l1BaseFee := new(big.Int).SetBytes(d.BaseFeeL1[:])
		return [][]byte{encTx(txSubmitRetryable, cid, req, poster, l1BaseFee, deposit, maxFee, gasW.Big().Uint64(), optAddr(retryTo), callvalue,
			callvalueRefund, maxSubmission, feeRefund, data)}, true
	case msgKindL2Message:
		return parseL2Msg(d.Data, poster, &req, cid, 0, true)
	case msgKindL2FundedByL1:
		kind := r.take(1)
		if kind == nil {
			return nil, false
		}
		depositID := crypto.Keccak256Hash(req[:], common.BigToHash(big.NewInt(0)).Bytes())
		unsignedID := crypto.Keccak256Hash(req[:], common.BigToHash(big.NewInt(1)).Bytes())
		tx, value, ok := parseUnsigned(r, poster, &unsignedID, cid, kind[0])
		if !ok {
			return nil, false
		}
		// Nitro leaves the deposit's From unset (the zero address) and funds the poster
		return [][]byte{encTx(txDeposit, cid, depositID, common.Address{}, poster, value), tx}, true
	}
	return nil, false
}

// DeriveDelayedTxs is deriveDelayed for tools that build delayed-origin blocks (vector generators): the transactions Nitro derives
// from the delayed message d on chain chainID, or false when the kind has no derivation or Nitro would refuse the message.
func DeriveDelayedTxs(chainID uint64, d Delayed) ([][]byte, bool) { return deriveDelayed(chainID, d) }
