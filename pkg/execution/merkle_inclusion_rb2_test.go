package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// RB-2: independent trie.VerifyProof inclusion-proof tests.
//
// These build a real Ethereum tx/receipt Patricia trie, produce an inclusion proof the
// same way the observer does, and assert MerkleInclusionProof.Verify() (a) accepts a
// valid proof against the true root, and rejects when (b) a proof node is flipped,
// (c) the leaf value is swapped, and (d) ExpectedRoot != the header root. It also
// asserts the built trie root equals types.DeriveSha (the block header's root formula),
// which is what binds the proof to the header.

func buildTestTxs(n int) []*types.Transaction {
	txs := make([]*types.Transaction, n)
	to := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	for i := 0; i < n; i++ {
		// Mix legacy and EIP-1559 (typed) txs to exercise MarshalBinary encoding.
		if i%2 == 0 {
			txs[i] = types.NewTx(&types.DynamicFeeTx{
				ChainID:   big.NewInt(11155111),
				Nonce:     uint64(i),
				GasTipCap: big.NewInt(1),
				GasFeeCap: big.NewInt(100),
				Gas:       21000,
				To:        &to,
				Value:     big.NewInt(int64(i) * 1000),
			})
		} else {
			txs[i] = types.NewTx(&types.LegacyTx{
				Nonce:    uint64(i),
				GasPrice: big.NewInt(10),
				Gas:      21000,
				To:       &to,
				Value:    big.NewInt(int64(i) * 500),
			})
		}
	}
	return txs
}

// buildTxProof mirrors ExternalChainObserver.constructTxInclusionProof without RPC.
func buildTxProof(t *testing.T, txs []*types.Transaction, idx uint) (*MerkleInclusionProof, common.Hash) {
	t.Helper()
	txTrie := trie.NewEmpty(nil)
	for i, tx := range txs {
		key, _ := rlp.EncodeToBytes(uint(i))
		val, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal tx %d: %v", i, err)
		}
		txTrie.Update(key, val)
	}
	root := txTrie.Hash()

	key, _ := rlp.EncodeToBytes(uint(idx))
	collector := NewMerkleProofCollector()
	if err := txTrie.Prove(key, collector); err != nil {
		t.Fatalf("prove: %v", err)
	}
	leafVal, _ := txs[idx].MarshalBinary()
	return &MerkleInclusionProof{
		LeafHash:     [32]byte(crypto.Keccak256Hash(leafVal)),
		LeafIndex:    uint64(idx),
		ExpectedRoot: [32]byte(root),
		ProofNodes:   collector.GetNodes(),
		LeafValue:    leafVal,
		Verified:     true,
	}, root
}

func TestRB2_InclusionProofVerifiesAndBindsHeaderRoot(t *testing.T) {
	txs := buildTestTxs(7)

	// The built trie root MUST equal the block header's TransactionsRoot formula
	// (types.DeriveSha), which is what makes the inclusion proof header-bound.
	derived := types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil))

	for idx := uint(0); idx < uint(len(txs)); idx++ {
		proof, root := buildTxProof(t, txs, idx)
		if root != derived {
			t.Fatalf("trie root %s != DeriveSha %s — proof would not bind to header", root.Hex(), derived.Hex())
		}
		if !proof.Verify() {
			t.Fatalf("valid proof for idx %d rejected", idx)
		}
	}
}

func TestRB2_RejectsFlippedProofNode(t *testing.T) {
	txs := buildTestTxs(6)
	proof, _ := buildTxProof(t, txs, 3)
	if !proof.Verify() {
		t.Fatal("precondition: valid proof should verify")
	}
	// Flip a byte in the first proof node (the root node).
	if len(proof.ProofNodes) == 0 || len(proof.ProofNodes[0]) == 0 {
		t.Fatal("no proof nodes")
	}
	proof.ProofNodes[0] = append([]byte(nil), proof.ProofNodes[0]...)
	proof.ProofNodes[0][len(proof.ProofNodes[0])-1] ^= 0xFF
	if proof.Verify() {
		t.Error("Verify() accepted a proof with a flipped node (should fail closed)")
	}
}

func TestRB2_RejectsSwappedLeaf(t *testing.T) {
	txs := buildTestTxs(6)
	proof, _ := buildTxProof(t, txs, 2)
	// Swap the claimed leaf value to a different tx's encoding.
	otherVal, _ := txs[5].MarshalBinary()
	proof.LeafValue = otherVal
	proof.LeafHash = [32]byte(crypto.Keccak256Hash(otherVal))
	if proof.Verify() {
		t.Error("Verify() accepted a proof whose leaf was swapped (should fail: proven value != claimed)")
	}
}

func TestRB2_RejectsWrongExpectedRoot(t *testing.T) {
	txs := buildTestTxs(6)
	proof, root := buildTxProof(t, txs, 1)
	// Corrupt the expected root; the proof no longer reconciles.
	bad := root
	bad[0] ^= 0xFF
	proof.ExpectedRoot = [32]byte(bad)
	if proof.Verify() {
		t.Error("Verify() accepted a proof against the wrong root (should fail closed)")
	}
}

func TestRB2_RejectsEmptyProofSet(t *testing.T) {
	txs := buildTestTxs(4)
	proof, _ := buildTxProof(t, txs, 0)
	proof.ProofNodes = nil // no independent proof set ⇒ cannot trustlessly verify
	if proof.Verify() {
		t.Error("Verify() accepted an empty proof set (should fail closed, not trust a flag)")
	}
}
