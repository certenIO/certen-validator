// Copyright 2026 Certen Protocol

package ethproof

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Settlement is the offline-verifiable inclusion of one transaction and its receipt in one block: everything
// VerifySettlement needs, and nothing it has to take on trust.
type Settlement struct {
	BlockHash common.Hash     `json:"block_hash"`
	Header    hexutil.Bytes   `json:"block_header_rlp"`
	TxHash    common.Hash     `json:"tx_hash"`
	Tx        *InclusionProof `json:"tx_inclusion_proof"`
	Receipt   *InclusionProof `json:"receipt_inclusion_proof"`
}

// Verify is VerifySettlement over s.
func (s *Settlement) Verify() (*types.Header, *ReceiptLeaf, error) {
	if s == nil {
		return nil, nil, invalid("no settlement proof")
	}
	return VerifySettlement(s.BlockHash, s.Header, s.TxHash, s.Tx, s.Receipt)
}

// VerifySettlement verifies, offline, that transaction txHash and the receipt the receipt proof carries are the entries at
// one index of the block whose hash is blockHash:
//   - headerRLP hashes to blockHash, so the roots read from it are that block's;
//   - the transaction proof resolves from the header's transactionsRoot, and its leaf hashes to txHash;
//   - the receipt proof resolves from the header's receiptsRoot at the transaction's index.
//
// It returns the header and the decoded receipt (status and logs), which are then the block's own.
func VerifySettlement(blockHash common.Hash, headerRLP []byte, txHash common.Hash, tx, receipt *InclusionProof) (*types.Header, *ReceiptLeaf, error) {
	if len(headerRLP) == 0 {
		return nil, nil, invalid("no block header")
	}
	if got := crypto.Keccak256Hash(headerRLP); got != blockHash {
		return nil, nil, invalid("the header hashes to %s, not block %s", got.Hex(), blockHash.Hex())
	}
	var header types.Header
	if err := rlp.DecodeBytes(headerRLP, &header); err != nil {
		return nil, nil, invalid("the header does not decode: %v", err)
	}
	if tx == nil || receipt == nil {
		return nil, nil, invalid("a transaction and a receipt proof are both required")
	}
	txLeaf, err := VerifyInclusion(tx, header.TxHash, tx.LeafIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("transaction proof: %w", err)
	}
	if got := crypto.Keccak256Hash(txLeaf); got != txHash {
		return nil, nil, invalid("the proven transaction at index %d is %s, not %s", tx.LeafIndex, got.Hex(), txHash.Hex())
	}
	rcLeaf, err := VerifyInclusion(receipt, header.ReceiptHash, tx.LeafIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt proof: %w", err)
	}
	decoded, err := DecodeReceiptLeaf(rcLeaf)
	if err != nil {
		return nil, nil, invalid("the proven receipt does not decode: %v", err)
	}
	return &header, decoded, nil
}

// ReceiptLeaf is a receipt's consensus content, decoded from its proven encoding.
type ReceiptLeaf struct {
	Type              uint8
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             types.Bloom
	Logs              []*types.Log
}

// Succeeded reports a post-Byzantium receipt's status 1.
func (r *ReceiptLeaf) Succeeded() bool {
	return len(r.PostStateOrStatus) == 1 && r.PostStateOrStatus[0] == 1
}

// DecodeReceiptLeaf decodes a receipt's consensus encoding: rlp([status, cumulativeGasUsed, bloom, logs, ...]), prefixed
// by its type byte unless it is a legacy receipt. Chain-specific trailing fields (an OP-stack deposit's nonce and version)
// are allowed and not interpreted.
func DecodeReceiptLeaf(enc []byte) (*ReceiptLeaf, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("empty receipt")
	}
	out := &ReceiptLeaf{}
	body := enc
	if enc[0] < 0x80 { // an EIP-2718 type byte; an RLP list starts at 0xc0
		out.Type, body = enc[0], enc[1:]
	}
	var fields struct {
		PostStateOrStatus []byte
		CumulativeGasUsed uint64
		Bloom             types.Bloom
		Logs              []*types.Log
		Rest              []rlp.RawValue `rlp:"tail"`
	}
	if err := rlp.DecodeBytes(body, &fields); err != nil {
		return nil, err
	}
	out.PostStateOrStatus, out.CumulativeGasUsed, out.Bloom, out.Logs = fields.PostStateOrStatus, fields.CumulativeGasUsed, fields.Bloom, fields.Logs
	return out, nil
}
