// Copyright 2026 Certen Protocol

package ethproof

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// Consensus encodings from a block's JSON.
//
// A proof is built from EVERY entry in the block and its roots must equal the header's. go-ethereum's decoded block
// rejects the whole block on the first transaction type it does not know - every OP-stack block (Base) carries a type-0x7e
// deposit transaction, and Arbitrum Nitro blocks carry Nitro's own types - and it re-encodes an OP-stack deposit receipt
// without its deposit fields. So the entries are taken from the block's JSON and encoded here: by go-ethereum for the
// types it knows, by hand for the rest. A root that does not match the header means an encoding is wrong for that chain,
// and the answer is then no proof, never a wrong one (ReadBlock refuses).
//
// Encodings implemented beyond go-ethereum's:
//   - OP-stack deposit transaction (0x7e): 0x7e || rlp([sourceHash, from, to, mint, value, gas, isSystemTx, data])
//   - OP-stack deposit receipt (0x7e), post-Canyon: 0x7e || rlp([status, cumulativeGasUsed, logsBloom, logs, depositNonce,
//     depositReceiptVersion]) (pre-Canyon receipts carry depositNonce only; each field is included when present)
//   - Arbitrum Nitro internal transaction (0x6a): 0x6a || rlp([chainId, data])
//   - Arbitrum Nitro receipts: the standard typed receipt encoding (Nitro's extra receipt fields are not consensus).
//
// Any other unknown type is refused by name.

type rawTx struct {
	Type       hexutil.Uint64  `json:"type"`
	Hash       common.Hash     `json:"hash"`
	SourceHash *common.Hash    `json:"sourceHash"`
	From       common.Address  `json:"from"`
	To         *common.Address `json:"to"`
	Mint       *hexutil.Big    `json:"mint"`
	Value      *hexutil.Big    `json:"value"`
	Gas        hexutil.Uint64  `json:"gas"`
	IsSystemTx bool            `json:"isSystemTx"`
	Input      hexutil.Bytes   `json:"input"`
	ChainID    *hexutil.Big    `json:"chainId"`
	Data       hexutil.Bytes   `json:"data"`
}

type rawLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

type rawReceipt struct {
	Type                  hexutil.Uint64  `json:"type"`
	Status                *hexutil.Uint64 `json:"status"`
	Root                  hexutil.Bytes   `json:"root"`
	CumulativeGasUsed     hexutil.Uint64  `json:"cumulativeGasUsed"`
	LogsBloom             hexutil.Bytes   `json:"logsBloom"`
	Logs                  []rawLog        `json:"logs"`
	TransactionHash       common.Hash     `json:"transactionHash"`
	TransactionIndex      hexutil.Uint64  `json:"transactionIndex"`
	BlockHash             common.Hash     `json:"blockHash"`
	DepositNonce          *hexutil.Uint64 `json:"depositNonce"`
	DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion"`
}

const (
	opDepositTxType    = 0x7e
	arbInternalTxType  = 0x6a
	maxGethKnownTxType = types.SetCodeTxType // every type go-ethereum decodes natively
)

// EncodeTxJSON returns a transaction's consensus encoding from its JSON form (eth_getBlockByHash with full transactions),
// and the hash the JSON states for it. The hash is checked by the caller against keccak256 of the encoding.
func EncodeTxJSON(raw json.RawMessage) ([]byte, common.Hash, error) {
	var t rawTx
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, common.Hash{}, fmt.Errorf("decode transaction json: %w", err)
	}
	switch {
	case uint64(t.Type) <= uint64(maxGethKnownTxType):
		var tx types.Transaction
		if err := tx.UnmarshalJSON(raw); err != nil {
			return nil, t.Hash, fmt.Errorf("decode type-%d transaction %s: %w", t.Type, t.Hash.Hex(), err)
		}
		enc, err := tx.MarshalBinary()
		return enc, t.Hash, err
	case uint64(t.Type) == opDepositTxType:
		if t.SourceHash == nil {
			return nil, t.Hash, fmt.Errorf("deposit transaction %s has no sourceHash", t.Hash.Hex())
		}
		mint := new(big.Int)
		if t.Mint != nil {
			mint = t.Mint.ToInt()
		}
		value := new(big.Int)
		if t.Value != nil {
			value = t.Value.ToInt()
		}
		body, err := rlp.EncodeToBytes([]interface{}{
			*t.SourceHash, t.From, t.To, mint, value, uint64(t.Gas), t.IsSystemTx, []byte(t.Input),
		})
		if err != nil {
			return nil, t.Hash, err
		}
		return append([]byte{opDepositTxType}, body...), t.Hash, nil
	case uint64(t.Type) == arbInternalTxType:
		if t.ChainID == nil {
			return nil, t.Hash, fmt.Errorf("arbitrum internal transaction %s has no chainId", t.Hash.Hex())
		}
		data := t.Input
		if len(data) == 0 {
			data = t.Data
		}
		body, err := rlp.EncodeToBytes([]interface{}{t.ChainID.ToInt(), []byte(data)})
		if err != nil {
			return nil, t.Hash, err
		}
		return append([]byte{arbInternalTxType}, body...), t.Hash, nil
	default:
		return nil, t.Hash, fmt.Errorf("transaction type 0x%x (%s) has no encoder here; no inclusion proof can be built for its block until one is added",
			uint64(t.Type), t.Hash.Hex())
	}
}

// ReceiptRef is where a receipt's JSON says it belongs. It is not consensus content; ReadBlock checks it against the block.
type ReceiptRef struct {
	TxHash    common.Hash
	TxIndex   uint64
	BlockHash common.Hash
}

// EncodeReceiptJSON returns a receipt's consensus encoding from its JSON form (eth_getBlockReceipts or
// eth_getTransactionReceipt), with the transaction hash, index and block hash the JSON states.
func EncodeReceiptJSON(raw json.RawMessage) ([]byte, ReceiptRef, error) {
	enc, r, err := encodeReceiptJSON(raw)
	if err != nil {
		return nil, ReceiptRef{}, err
	}
	return enc, ReceiptRef{TxHash: r.TransactionHash, TxIndex: uint64(r.TransactionIndex), BlockHash: r.BlockHash}, nil
}

func encodeReceiptJSON(raw json.RawMessage) ([]byte, *rawReceipt, error) {
	var r rawReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, fmt.Errorf("decode receipt json: %w", err)
	}
	// Post-Byzantium receipts carry a status; pre-Byzantium ones a state root.
	var postStateOrStatus []byte
	switch {
	case len(r.Root) > 0:
		postStateOrStatus = r.Root
	case r.Status != nil && uint64(*r.Status) == 1:
		postStateOrStatus = []byte{1}
	case r.Status != nil && uint64(*r.Status) == 0:
		postStateOrStatus = []byte{}
	default:
		return nil, nil, fmt.Errorf("receipt of %s states neither a status nor a root", r.TransactionHash.Hex())
	}
	var bloom types.Bloom
	if len(r.LogsBloom) != types.BloomByteLength {
		return nil, nil, fmt.Errorf("receipt of %s: logsBloom is %d bytes, want %d", r.TransactionHash.Hex(), len(r.LogsBloom), types.BloomByteLength)
	}
	copy(bloom[:], r.LogsBloom)
	logs := make([]*types.Log, len(r.Logs))
	for i, l := range r.Logs {
		logs[i] = &types.Log{Address: l.Address, Topics: l.Topics, Data: l.Data}
	}
	fields := []interface{}{postStateOrStatus, uint64(r.CumulativeGasUsed), bloom, logs}
	if uint64(r.Type) == opDepositTxType && r.DepositNonce != nil {
		fields = append(fields, uint64(*r.DepositNonce))
		if r.DepositReceiptVersion != nil {
			fields = append(fields, uint64(*r.DepositReceiptVersion))
		}
	}
	body, err := rlp.EncodeToBytes(fields)
	if err != nil {
		return nil, nil, err
	}
	if uint64(r.Type) == types.LegacyTxType {
		return body, &r, nil
	}
	if uint64(r.Type) > 0x7f {
		return nil, nil, fmt.Errorf("receipt of %s has type 0x%x, outside EIP-2718", r.TransactionHash.Hex(), uint64(r.Type))
	}
	return append([]byte{byte(r.Type)}, body...), &r, nil
}
