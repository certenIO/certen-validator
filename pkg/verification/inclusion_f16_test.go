// Copyright 2026 Certen Protocol

package verification

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

// RB5-F16: the Level 4 verifier checked "inclusion proofs" as a hash list (leaf, sibling hashes, left/right directions),
// which no Merkle-Patricia proof the system emits can satisfy, and which a fabricated list satisfies trivially. It now
// verifies the emitted proofs (pkg/ethproof) against the result's own roots.

// fixtureResult is a Level 4 result for Base Sepolia's real settlement, its proofs built from the captured block.
func fixtureResult(t *testing.T) (*ExternalChainResultData, *UnifiedVerifier) {
	t.Helper()
	f := ethprooftest.Load(t, ethprooftest.BaseSepolia)
	header := f.Header(t)
	var txs, rcs [][]byte
	for _, tx := range f.Transactions() {
		raw, _ := json.Marshal(tx)
		enc, _, err := ethproof.EncodeTxJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, enc)
	}
	for _, rc := range f.ReceiptList() {
		raw, _ := json.Marshal(rc)
		enc, _, err := ethproof.EncodeReceiptJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		rcs = append(rcs, enc)
	}
	idx := f.SettlementIndex()
	txProof, err := ethproof.Prove(txs, idx, header.TxHash)
	if err != nil {
		t.Fatal(err)
	}
	rcProof, err := ethproof.Prove(rcs, idx, header.ReceiptHash)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(p *ethproof.InclusionProof) *MerkleInclusionProofData {
		raw, _ := json.Marshal(p)
		var d MerkleInclusionProofData
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		return &d
	}
	r := &ExternalChainResultData{Chain: "base-sepolia", ChainID: f.ChainID, TxHash: f.SettlementTx, BlockNumber: header.Number.Uint64(),
		BlockHash: f.BlockHash(), TransactionsRoot: header.TxHash, ReceiptsRoot: header.ReceiptHash, StateRoot: header.Root, Status: 1,
		TxInclusionProof: convert(txProof), ReceiptInclusionProof: convert(rcProof)}
	v := NewUnifiedVerifier(&UnifiedVerifierConfig{})
	r.ResultHash = v.computeResultHash(r)
	return r, v
}

func TestLevel4VerifiesTheEmittedInclusionProofs(t *testing.T) {
	r, v := fixtureResult(t)
	res := &VerificationResult{Details: map[string]interface{}{}}
	if err := v.verifyExecutionProof(&ExecutionProofBundle{Result: r}, res); err != nil {
		t.Fatalf("THE regression: a real inclusion proof of the settlement is refused: %v", err)
	}
}

func TestLevel4RefusesAHashListPresentedAsAnInclusionProof(t *testing.T) {
	r, v := fixtureResult(t)
	// A hash "list" that reconciles by the old rule: keccak(leaf || sibling) == the stated transactions root.
	sibling := crypto.Keccak256Hash([]byte("sibling"))
	root := crypto.Keccak256Hash(append(append([]byte{}, r.TxHash[:]...), sibling[:]...))
	raw, _ := json.Marshal(map[string]interface{}{"leaf_hash": r.TxHash, "leaf_index": 0, "proof_hashes": [][32]byte{sibling},
		"proof_directions": []int{1}, "expected_root": root})
	var list MerkleInclusionProofData
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	r.TxInclusionProof = &list
	r.TransactionsRoot = root
	r.ResultHash = v.computeResultHash(r)
	res := &VerificationResult{Details: map[string]interface{}{}}
	if err := v.verifyExecutionProof(&ExecutionProofBundle{Result: r}, res); err == nil {
		t.Fatal("THE regression: a fabricated hash list verified as the transaction's inclusion proof")
	}
}
