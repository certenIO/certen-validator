package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// Inclusion proofs on chains whose transactions go-ethereum cannot decode.
//
// The RB-2 gate needs a transaction inclusion proof and a receipt inclusion proof, each built
// from EVERY entry in the block and verified against the header's TransactionsRoot and
// ReceiptsRoot. ethclient.BlockByNumber builds those lists with go-ethereum's own transaction
// types and rejects the block on the first type it does not know. Every OP-stack block (Base,
// Optimism) carries a type-0x7e deposit transaction, and every Arbitrum Nitro block carries a
// type-0x6a internal transaction, so on those chains the decoded path never works.
//
// This file takes the other route: fetch the block and its receipts as raw JSON, encode each
// entry into its consensus RLP ourselves (go-ethereum for the types it knows, hand-written for
// the ones it does not), build the two tries, and REFUSE unless the roots match the header. A
// mismatched root means an encoding here is wrong for this chain, and the right answer is then
// no proof, not a wrong one. The self-check is what makes hand-written encoders safe to ship.
//
// Encodings implemented beyond go-ethereum's:
//   - OP-stack deposit transaction (0x7e):
//       0x7e || rlp([sourceHash, from, to, mint, value, gas, isSystemTx, data])
//   - OP-stack deposit receipt (0x7e), post-Canyon:
//       0x7e || rlp([status, cumulativeGasUsed, logsBloom, logs, depositNonce, depositReceiptVersion])
//     (pre-Canyon blocks carry only depositNonce; the field is included when present)
//   - Arbitrum Nitro internal transaction (0x6a):
//       0x6a || rlp([chainId, data])
//   - Arbitrum Nitro receipts: standard typed receipt encoding (Nitro's extra receipt fields are
//     not part of the consensus RLP). The root check proves or disproves this per block.
//
// Anything else with an unknown type fails closed with a message naming the type.

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

type rawBlockJSON struct {
	Hash         common.Hash       `json:"hash"`
	Number       hexutil.Uint64    `json:"number"`
	Transactions []json.RawMessage `json:"transactions"`
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
	TransactionIndex      hexutil.Uint64  `json:"transactionIndex"`
	DepositNonce          *hexutil.Uint64 `json:"depositNonce"`
	DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion"`
}

const (
	opDepositTxType    = 0x7e
	arbInternalTxType  = 0x6a
	maxGethKnownTxType = types.SetCodeTxType // every type go-ethereum decodes natively
)

// rawBlockProofs is the header plus the consensus encodings of every transaction and receipt in
// the block, already checked against the header roots.
type rawBlockProofs struct {
	header   *types.Header
	txs      [][]byte
	receipts [][]byte
}

// fetchRawBlockProofs fetches the block and its receipts as JSON and encodes both lists. The
// returned value is safe to prove from: both roots matched the (receipt-bound) header.
func (o *ExternalChainObserver) fetchRawBlockProofs(ctx context.Context, header *types.Header) (*rawBlockProofs, error) {
	if o.rpcClient == nil {
		return nil, fmt.Errorf("no raw rpc client")
	}
	var blk rawBlockJSON
	if err := o.rpcClient.CallContext(ctx, &blk, "eth_getBlockByHash", header.Hash(), true); err != nil {
		return nil, fmt.Errorf("eth_getBlockByHash: %w", err)
	}
	if blk.Hash != header.Hash() {
		return nil, fmt.Errorf("eth_getBlockByHash returned %s for %s", blk.Hash.Hex(), header.Hash().Hex())
	}
	txs := make([][]byte, len(blk.Transactions))
	for i, raw := range blk.Transactions {
		enc, err := encodeRawTx(raw)
		if err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		txs[i] = enc
	}
	if root := trieRoot(txs); root != header.TxHash {
		return nil, fmt.Errorf("transactions root mismatch: encoded %s, header %s — an encoding is wrong for this chain; refusing to prove", root.Hex(), header.TxHash.Hex())
	}

	// Receipts: one call when the RPC offers it; otherwise one per transaction. The per-tx path
	// exists because some public endpoints (sepolia.base.org among them) do not serve
	// eth_getBlockReceipts at all, and a chain we can execute on but not prove on is the failure
	// this file exists to remove.
	var rcpts []json.RawMessage
	if err := o.rpcClient.CallContext(ctx, &rcpts, "eth_getBlockReceipts", header.Hash()); err != nil {
		hashes := make([]common.Hash, len(blk.Transactions))
		for i, raw := range blk.Transactions {
			var t rawTx
			if jerr := json.Unmarshal(raw, &t); jerr != nil {
				return nil, fmt.Errorf("tx %d hash: %w", i, jerr)
			}
			hashes[i] = t.Hash
		}
		rcpts = make([]json.RawMessage, len(hashes))
		for i, h := range hashes {
			if rerr := o.rpcClient.CallContext(ctx, &rcpts[i], "eth_getTransactionReceipt", h); rerr != nil {
				return nil, fmt.Errorf("eth_getBlockReceipts unavailable (%v) and eth_getTransactionReceipt %s: %w", err, h.Hex(), rerr)
			}
			if len(rcpts[i]) == 0 || string(rcpts[i]) == "null" {
				return nil, fmt.Errorf("eth_getTransactionReceipt %s returned null", h.Hex())
			}
		}
	}
	if len(rcpts) != len(txs) {
		return nil, fmt.Errorf("block receipts count %d != tx count %d", len(rcpts), len(txs))
	}
	receipts := make([][]byte, len(rcpts))
	for i, raw := range rcpts {
		enc, err := encodeRawReceipt(raw)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		receipts[i] = enc
	}
	if root := trieRoot(receipts); root != header.ReceiptHash {
		return nil, fmt.Errorf("receipts root mismatch: encoded %s, header %s — an encoding is wrong for this chain; refusing to prove", root.Hex(), header.ReceiptHash.Hex())
	}
	return &rawBlockProofs{header: header, txs: txs, receipts: receipts}, nil
}

// encodeRawTx returns the consensus encoding of one transaction from its JSON form.
func encodeRawTx(raw json.RawMessage) ([]byte, error) {
	var t rawTx
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("decode tx json: %w", err)
	}
	switch {
	case uint64(t.Type) <= uint64(maxGethKnownTxType):
		var tx types.Transaction
		if err := tx.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("decode type-%d tx: %w", t.Type, err)
		}
		return tx.MarshalBinary()
	case uint64(t.Type) == opDepositTxType:
		if t.SourceHash == nil {
			return nil, fmt.Errorf("deposit tx %s has no sourceHash", t.Hash.Hex())
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
			return nil, err
		}
		return append([]byte{opDepositTxType}, body...), nil
	case uint64(t.Type) == arbInternalTxType:
		if t.ChainID == nil {
			return nil, fmt.Errorf("arbitrum internal tx %s has no chainId", t.Hash.Hex())
		}
		data := t.Input
		if len(data) == 0 {
			data = t.Data
		}
		body, err := rlp.EncodeToBytes([]interface{}{t.ChainID.ToInt(), []byte(data)})
		if err != nil {
			return nil, err
		}
		return append([]byte{arbInternalTxType}, body...), nil
	default:
		return nil, fmt.Errorf("transaction type 0x%x (%s) has no encoder here; inclusion proofs cannot be built on this chain until one is added", uint64(t.Type), t.Hash.Hex())
	}
}

// encodeRawReceipt returns the consensus encoding of one receipt from its JSON form.
func encodeRawReceipt(raw json.RawMessage) ([]byte, error) {
	var r rawReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode receipt json: %w", err)
	}
	// Post-Byzantium receipts carry a status; pre-Byzantium ones a state root. Testnets we run
	// are all post-Byzantium, but the pre-Byzantium form costs nothing to keep correct.
	var postStateOrStatus []byte
	if len(r.Root) > 0 {
		postStateOrStatus = r.Root
	} else if r.Status != nil && uint64(*r.Status) == 1 {
		postStateOrStatus = []byte{1}
	} else {
		postStateOrStatus = []byte{}
	}
	var bloom types.Bloom
	if len(r.LogsBloom) == types.BloomByteLength {
		copy(bloom[:], r.LogsBloom)
	} else {
		return nil, fmt.Errorf("logsBloom is %d bytes, want %d", len(r.LogsBloom), types.BloomByteLength)
	}
	logs := make([]*types.Log, len(r.Logs))
	for i, l := range r.Logs {
		logs[i] = &types.Log{Address: l.Address, Topics: l.Topics, Data: l.Data}
	}
	fields := []interface{}{postStateOrStatus, uint64(r.CumulativeGasUsed), bloom, logs}
	if uint64(r.Type) == opDepositTxType {
		if r.DepositNonce != nil {
			fields = append(fields, uint64(*r.DepositNonce))
			if r.DepositReceiptVersion != nil {
				fields = append(fields, uint64(*r.DepositReceiptVersion))
			}
		}
	}
	body, err := rlp.EncodeToBytes(fields)
	if err != nil {
		return nil, err
	}
	if uint64(r.Type) == types.LegacyTxType {
		return body, nil
	}
	return append([]byte{byte(r.Type)}, body...), nil
}

// trieRoot is the root of the transactions/receipts trie over the given consensus encodings,
// keyed by rlp(index) exactly as the block header commits to them.
func trieRoot(values [][]byte) common.Hash {
	t := trie.NewEmpty(nil)
	for i, v := range values {
		key, _ := rlp.EncodeToBytes(uint(i))
		t.Update(key, v)
	}
	return t.Hash()
}

// proveIndex builds the inclusion proof for values[index] against root, in the observer's
// MerkleInclusionProof form. Callers pass a root that already matched the header.
func proveIndex(values [][]byte, index uint, root common.Hash) (*MerkleInclusionProof, error) {
	if int(index) >= len(values) {
		return nil, fmt.Errorf("index %d out of range (%d entries)", index, len(values))
	}
	t := trie.NewEmpty(nil)
	for i, v := range values {
		key, _ := rlp.EncodeToBytes(uint(i))
		t.Update(key, v)
	}
	key, _ := rlp.EncodeToBytes(index)
	collector := NewMerkleProofCollector()
	if err := t.Prove(key, collector); err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}
	leaf := values[index]
	return &MerkleInclusionProof{
		LeafHash:        [32]byte(crypto.Keccak256Hash(leaf)),
		LeafIndex:       uint64(index),
		ProofHashes:     collector.GetHashes(),
		ProofDirections: collector.GetDirections(),
		ExpectedRoot:    [32]byte(root),
		ProofNodes:      collector.GetNodes(),
		LeafValue:       leaf,
		Verified:        true,
	}, nil
}

// inclusionProofsFromRaw builds both RB-2 proofs for the transaction at txIndex from the raw
// block, or returns an error naming why this chain's block could not be encoded.
func (o *ExternalChainObserver) inclusionProofsFromRaw(ctx context.Context, header *types.Header, txIndex uint) (*MerkleInclusionProof, *MerkleInclusionProof, error) {
	rb, err := o.fetchRawBlockProofs(ctx, header)
	if err != nil {
		return nil, nil, err
	}
	txProof, err := proveIndex(rb.txs, txIndex, header.TxHash)
	if err != nil {
		return nil, nil, fmt.Errorf("tx proof: %w", err)
	}
	receiptProof, err := proveIndex(rb.receipts, txIndex, header.ReceiptHash)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt proof: %w", err)
	}
	return txProof, receiptProof, nil
}
