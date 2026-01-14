// Copyright 2025 Certen Protocol
//
// Merkle Tree Tests

package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestBuildTree_SingleLeaf(t *testing.T) {
	leaf := sha256.Sum256([]byte("test data"))
	tree, err := BuildTree([][]byte{leaf[:]})
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Single leaf tree: root equals leaf
	if !bytes.Equal(tree.Root(), leaf[:]) {
		t.Errorf("single leaf root mismatch: got %x, want %x", tree.Root(), leaf[:])
	}

	if tree.LeafCount() != 1 {
		t.Errorf("leaf count mismatch: got %d, want 1", tree.LeafCount())
	}
}

func TestBuildTree_TwoLeaves(t *testing.T) {
	leaf1 := sha256.Sum256([]byte("leaf 1"))
	leaf2 := sha256.Sum256([]byte("leaf 2"))

	tree, err := BuildTree([][]byte{leaf1[:], leaf2[:]})
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Expected root = hash(leaf1 || leaf2)
	combined := make([]byte, 64)
	copy(combined[:32], leaf1[:])
	copy(combined[32:], leaf2[:])
	expectedRoot := sha256.Sum256(combined)

	if !bytes.Equal(tree.Root(), expectedRoot[:]) {
		t.Errorf("two leaf root mismatch: got %x, want %x", tree.Root(), expectedRoot[:])
	}
}

func TestBuildTree_FourLeaves(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		hash := sha256.Sum256([]byte{byte(i)})
		leaves[i] = hash[:]
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	if tree.LeafCount() != 4 {
		t.Errorf("leaf count mismatch: got %d, want 4", tree.LeafCount())
	}

	// Root should not be nil
	if tree.Root() == nil {
		t.Error("root is nil")
	}

	// Root should be 32 bytes
	if len(tree.Root()) != 32 {
		t.Errorf("root length mismatch: got %d, want 32", len(tree.Root()))
	}
}

func TestBuildTree_OddLeaves(t *testing.T) {
	// Test with 3 leaves (odd number)
	leaves := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256([]byte{byte(i)})
		leaves[i] = hash[:]
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatalf("failed to build tree with odd leaves: %v", err)
	}

	if tree.LeafCount() != 3 {
		t.Errorf("leaf count mismatch: got %d, want 3", tree.LeafCount())
	}

	if tree.Root() == nil {
		t.Error("root is nil for odd-leaf tree")
	}
}

func TestGenerateProof_TwoLeaves(t *testing.T) {
	leaf1 := sha256.Sum256([]byte("leaf 1"))
	leaf2 := sha256.Sum256([]byte("leaf 2"))

	tree, err := BuildTree([][]byte{leaf1[:], leaf2[:]})
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Generate proof for leaf 0
	proof0, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("failed to generate proof for leaf 0: %v", err)
	}

	if proof0.LeafIndex != 0 {
		t.Errorf("proof leaf index mismatch: got %d, want 0", proof0.LeafIndex)
	}

	if len(proof0.Path) != 1 {
		t.Errorf("proof path length mismatch: got %d, want 1", len(proof0.Path))
	}

	if proof0.Path[0].Position != Right {
		t.Errorf("sibling position mismatch: got %s, want right", proof0.Path[0].Position)
	}

	// Verify the proof
	valid, err := VerifyProof(leaf1[:], proof0, tree.Root())
	if err != nil {
		t.Fatalf("failed to verify proof: %v", err)
	}
	if !valid {
		t.Error("proof verification failed for valid proof")
	}

	// Generate proof for leaf 1
	proof1, err := tree.GenerateProof(1)
	if err != nil {
		t.Fatalf("failed to generate proof for leaf 1: %v", err)
	}

	if proof1.Path[0].Position != Left {
		t.Errorf("sibling position mismatch: got %s, want left", proof1.Path[0].Position)
	}

	valid, err = VerifyProof(leaf2[:], proof1, tree.Root())
	if err != nil {
		t.Fatalf("failed to verify proof: %v", err)
	}
	if !valid {
		t.Error("proof verification failed for valid proof")
	}
}

func TestGenerateProof_FourLeaves(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		hash := sha256.Sum256([]byte{byte(i)})
		leaves[i] = hash[:]
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Generate and verify proof for each leaf
	for i := 0; i < 4; i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("failed to generate proof for leaf %d: %v", i, err)
		}

		// Path should have 2 nodes (4 leaves = 2 levels above leaves)
		if len(proof.Path) != 2 {
			t.Errorf("leaf %d: proof path length mismatch: got %d, want 2", i, len(proof.Path))
		}

		valid, err := VerifyProof(leaves[i], proof, tree.Root())
		if err != nil {
			t.Fatalf("leaf %d: failed to verify proof: %v", i, err)
		}
		if !valid {
			t.Errorf("leaf %d: proof verification failed", i)
		}
	}
}

func TestGenerateProof_LargeTree(t *testing.T) {
	// Test with 100 leaves
	leaves := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		hash := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		leaves[i] = hash[:]
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Verify proofs for a sample of leaves
	testIndices := []int{0, 1, 49, 50, 99}
	for _, i := range testIndices {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("failed to generate proof for leaf %d: %v", i, err)
		}

		valid, err := VerifyProof(leaves[i], proof, tree.Root())
		if err != nil {
			t.Fatalf("leaf %d: failed to verify proof: %v", i, err)
		}
		if !valid {
			t.Errorf("leaf %d: proof verification failed", i)
		}
	}
}

func TestVerifyProof_InvalidProof(t *testing.T) {
	leaf1 := sha256.Sum256([]byte("leaf 1"))
	leaf2 := sha256.Sum256([]byte("leaf 2"))

	tree, err := BuildTree([][]byte{leaf1[:], leaf2[:]})
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// Try to verify with wrong leaf
	wrongLeaf := sha256.Sum256([]byte("wrong leaf"))
	valid, err := VerifyProof(wrongLeaf[:], proof, tree.Root())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("proof should not be valid for wrong leaf")
	}

	// Try to verify with wrong root
	wrongRoot := sha256.Sum256([]byte("wrong root"))
	valid, err = VerifyProof(leaf1[:], proof, wrongRoot[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("proof should not be valid for wrong root")
	}
}

func TestGenerateProofByHash(t *testing.T) {
	leaf1 := sha256.Sum256([]byte("leaf 1"))
	leaf2 := sha256.Sum256([]byte("leaf 2"))

	tree, err := BuildTree([][]byte{leaf1[:], leaf2[:]})
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	// Generate proof by hash
	proof, err := tree.GenerateProofByHash(leaf2[:])
	if err != nil {
		t.Fatalf("failed to generate proof by hash: %v", err)
	}

	if proof.LeafIndex != 1 {
		t.Errorf("leaf index mismatch: got %d, want 1", proof.LeafIndex)
	}

	// Verify the proof
	valid, err := VerifyProof(leaf2[:], proof, tree.Root())
	if err != nil {
		t.Fatalf("failed to verify proof: %v", err)
	}
	if !valid {
		t.Error("proof verification failed")
	}
}

func TestProofSerialization(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		hash := sha256.Sum256([]byte{byte(i)})
		leaves[i] = hash[:]
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	proof, err := tree.GenerateProof(2)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// Serialize to JSON
	jsonData, err := proof.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize proof: %v", err)
	}

	// Deserialize
	restored, err := ProofFromJSON(jsonData)
	if err != nil {
		t.Fatalf("failed to deserialize proof: %v", err)
	}

	// Verify restored proof works
	leafHash, _ := hex.DecodeString(restored.LeafHash)
	rootHash, _ := hex.DecodeString(restored.MerkleRoot)

	valid, err := VerifyProof(leafHash, restored, rootHash)
	if err != nil {
		t.Fatalf("failed to verify restored proof: %v", err)
	}
	if !valid {
		t.Error("restored proof verification failed")
	}
}

func TestEmptyTree(t *testing.T) {
	_, err := BuildTree([][]byte{})
	if err != ErrEmptyTree {
		t.Errorf("expected ErrEmptyTree, got %v", err)
	}
}

func TestInvalidLeafHash(t *testing.T) {
	invalidLeaf := []byte("not 32 bytes")
	_, err := BuildTree([][]byte{invalidLeaf})
	if err == nil {
		t.Error("expected error for invalid leaf hash")
	}
}

func TestHashData(t *testing.T) {
	data := []byte("test data")
	hash := HashData(data)

	if len(hash) != 32 {
		t.Errorf("hash length mismatch: got %d, want 32", len(hash))
	}

	// Verify deterministic
	hash2 := HashData(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("hash is not deterministic")
	}
}

func TestCombineHashes(t *testing.T) {
	h1 := sha256.Sum256([]byte("hash1"))
	h2 := sha256.Sum256([]byte("hash2"))

	combined := CombineHashes(h1[:], h2[:])

	if len(combined) != 32 {
		t.Errorf("combined hash length mismatch: got %d, want 32", len(combined))
	}

	// Order matters
	combined2 := CombineHashes(h2[:], h1[:])
	if bytes.Equal(combined, combined2) {
		t.Error("combine order should matter")
	}
}
