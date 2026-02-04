package execution

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestMerkle4LeafTree tests that Go merkle computation matches Solidity
func TestMerkle4LeafTree(t *testing.T) {
	// Test values from Solidity test (test_MerkleRoot_MatchesGoImplementation)
	// These are keccak256 hashes computed in Solidity

	// testAdiURL = keccak256("acc://test.acme/data")
	// testOp = keccak256("test-operation")
	// testCC = keccak256("test-crosschain")
	// testGov = keccak256("test-governance")

	testAdiURL := crypto.Keccak256([]byte("acc://test.acme/data"))
	testOp := crypto.Keccak256([]byte("test-operation"))
	testCC := crypto.Keccak256([]byte("test-crosschain"))
	testGov := crypto.Keccak256([]byte("test-governance"))

	// Expected values from Solidity test output
	expectedAdiURL := "50dc7044c572a5980847023696b4428cd3f59f649e367a3f99fd7f55ad3e6758"
	expectedOp := "1cdce19456de24d02b98e3fdcf912be874a55d99273cc83e9279f237f08e3dbe"
	expectedCC := "2304e9e072ed01b16e5bb8703ab17b5236278697da9c319148eeffcb38060db7"
	expectedGov := "b53c9ac7f12855f690d7a18f56df8c6e6338e3084fd4219f23ccf3a677e3c90e"
	expectedMerkleRoot := "63ab298965fa34fe6f71fb35f9ffbc294f613a0a8123d000d4ccf64d5c3edfaf"

	// Verify leaf hashes match
	if hex.EncodeToString(testAdiURL) != expectedAdiURL {
		t.Errorf("AdiURL hash mismatch: got %s, expected %s", hex.EncodeToString(testAdiURL), expectedAdiURL)
	}
	if hex.EncodeToString(testOp) != expectedOp {
		t.Errorf("Op hash mismatch: got %s, expected %s", hex.EncodeToString(testOp), expectedOp)
	}
	if hex.EncodeToString(testCC) != expectedCC {
		t.Errorf("CC hash mismatch: got %s, expected %s", hex.EncodeToString(testCC), expectedCC)
	}
	if hex.EncodeToString(testGov) != expectedGov {
		t.Errorf("Gov hash mismatch: got %s, expected %s", hex.EncodeToString(testGov), expectedGov)
	}

	// Compute 4-leaf merkle root using sorted hash
	merkleRoot := computeMerkleRoot4(testAdiURL, testOp, testCC, testGov)

	if hex.EncodeToString(merkleRoot) != expectedMerkleRoot {
		t.Errorf("Merkle root mismatch: got %s, expected %s", hex.EncodeToString(merkleRoot), expectedMerkleRoot)
	}

	t.Logf("✓ All hashes match Solidity implementation")
	t.Logf("  Merkle root: 0x%s", hex.EncodeToString(merkleRoot))
}

// TestMerkleProofForAdiURL tests building and verifying merkle proof for adiURLHash
func TestMerkleProofForAdiURL(t *testing.T) {
	adiURL := crypto.Keccak256([]byte("acc://certen-kermit-20.acme/data"))
	opComm := crypto.Keccak256([]byte("operation-commitment"))
	ccComm := crypto.Keccak256([]byte("crosschain-commitment"))
	govRoot := crypto.Keccak256([]byte("governance-root"))

	// Compute merkle root
	merkleRoot := computeMerkleRoot4(adiURL, opComm, ccComm, govRoot)

	// Build proof for adiURL (leaf 0)
	// Proof elements: [sibling of leaf, sibling of parent]
	hash23 := sortedHash(ccComm, govRoot)
	proof := [][]byte{opComm, hash23}

	// Verify proof
	if !verifyMerkleProof(merkleRoot, adiURL, proof) {
		t.Error("Merkle proof verification failed for adiURL")
	}

	t.Logf("✓ Merkle proof verified for adiURL")
}

// TestMerkleProofForAllLeaves tests merkle proofs for all 4 leaves
func TestMerkleProofForAllLeaves(t *testing.T) {
	adiURL := crypto.Keccak256([]byte("acc://test.acme/data"))
	opComm := crypto.Keccak256([]byte("op"))
	ccComm := crypto.Keccak256([]byte("cc"))
	govRoot := crypto.Keccak256([]byte("gov"))

	merkleRoot := computeMerkleRoot4(adiURL, opComm, ccComm, govRoot)
	hash01 := sortedHash(adiURL, opComm)
	hash23 := sortedHash(ccComm, govRoot)

	tests := []struct {
		name  string
		leaf  []byte
		proof [][]byte
	}{
		{"adiURL (leaf 0)", adiURL, [][]byte{opComm, hash23}},
		{"opComm (leaf 1)", opComm, [][]byte{adiURL, hash23}},
		{"ccComm (leaf 2)", ccComm, [][]byte{govRoot, hash01}},
		{"govRoot (leaf 3)", govRoot, [][]byte{ccComm, hash01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !verifyMerkleProof(merkleRoot, tt.leaf, tt.proof) {
				t.Errorf("Merkle proof verification failed for %s", tt.name)
			}
		})
	}

	t.Logf("✓ All 4 leaves verified successfully")
}

// sortedHash computes keccak256(a || b) where a and b are sorted
func sortedHash(a, b []byte) []byte {
	var data []byte
	if compareBytes(a, b) < 0 {
		data = append(a, b...)
	} else {
		data = append(b, a...)
	}
	return crypto.Keccak256(data)
}

// compareBytes compares two byte slices lexicographically
func compareBytes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// computeMerkleRoot4 computes merkle root from 4 leaves using sorted hash
func computeMerkleRoot4(leaf0, leaf1, leaf2, leaf3 []byte) []byte {
	hash01 := sortedHash(leaf0, leaf1)
	hash23 := sortedHash(leaf2, leaf3)
	return sortedHash(hash01, hash23)
}

// verifyMerkleProof verifies a merkle proof for a leaf
func verifyMerkleProof(root, leaf []byte, proof [][]byte) bool {
	computedHash := leaf
	for _, proofElement := range proof {
		computedHash = sortedHash(computedHash, proofElement)
	}
	return compareBytes(computedHash, root) == 0
}

// buildMerkleProofForAdiURL builds the merkle proof for adiURLHash (leaf 0)
func buildMerkleProofForAdiURL(adiURL, opComm, ccComm, govRoot []byte) [][]byte {
	hash23 := sortedHash(ccComm, govRoot)
	return [][]byte{opComm, hash23}
}
