// Copyright 2025 Certen Protocol
//
// Merkle Tree Implementation for Anchor Batching
// Per Whitepaper Section 3.4.2: Validators batch transactions and compute Merkle root
//
// This implementation provides:
// - Binary Merkle tree construction from transaction hashes
// - Inclusion proof generation for any leaf
// - Verification of inclusion proofs
// - Thread-safe operations for concurrent batch building

package merkle

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Common errors
var (
	ErrEmptyTree       = errors.New("cannot build tree from empty leaves")
	ErrInvalidProof    = errors.New("invalid merkle proof")
	ErrLeafNotFound    = errors.New("leaf not found in tree")
	ErrInvalidLeafHash = errors.New("leaf hash must be 32 bytes")
)

// Position indicates whether a sibling is on the left or right
type Position string

const (
	Left  Position = "left"
	Right Position = "right"
)

// ProofNode represents a single node in a Merkle inclusion proof
type ProofNode struct {
	Hash     string   `json:"hash"`     // Hex-encoded 32-byte hash
	Position Position `json:"position"` // "left" or "right"
}

// InclusionProof represents a complete Merkle inclusion proof
// This can be used to verify that a leaf exists in the tree
type InclusionProof struct {
	LeafHash   string      `json:"leaf_hash"`   // The leaf being proven
	LeafIndex  int         `json:"leaf_index"`  // Position of leaf (0-indexed)
	MerkleRoot string      `json:"merkle_root"` // Root of the tree
	Path       []ProofNode `json:"path"`        // Path from leaf to root
	TreeSize   int         `json:"tree_size"`   // Number of leaves in tree
}

// Tree represents a Merkle tree
type Tree struct {
	mu       sync.RWMutex
	leaves   [][]byte   // Original leaf hashes (32 bytes each)
	nodes    [][]byte   // All nodes in the tree (level by level)
	levels   [][][]byte // Tree organized by levels (for proof generation)
	root     []byte     // The Merkle root (32 bytes)
	built    bool       // Whether the tree has been built
}

// NewTree creates a new empty Merkle tree
func NewTree() *Tree {
	return &Tree{
		leaves: make([][]byte, 0),
		nodes:  make([][]byte, 0),
		levels: make([][][]byte, 0),
		built:  false,
	}
}

// BuildTree creates a new Merkle tree from the given leaf hashes
// Each leaf must be exactly 32 bytes (SHA256 hash)
func BuildTree(leaves [][]byte) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyTree
	}

	// Validate all leaves are 32 bytes
	for i, leaf := range leaves {
		if len(leaf) != 32 {
			return nil, fmt.Errorf("%w: leaf %d has %d bytes", ErrInvalidLeafHash, i, len(leaf))
		}
	}

	tree := &Tree{
		leaves: make([][]byte, len(leaves)),
		levels: make([][][]byte, 0),
	}

	// Copy leaves
	for i, leaf := range leaves {
		tree.leaves[i] = make([]byte, 32)
		copy(tree.leaves[i], leaf)
	}

	// Build the tree
	if err := tree.build(); err != nil {
		return nil, err
	}

	return tree, nil
}

// build constructs the Merkle tree from leaves
func (t *Tree) build() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.leaves) == 0 {
		return ErrEmptyTree
	}

	// Start with leaves as level 0
	currentLevel := make([][]byte, len(t.leaves))
	for i, leaf := range t.leaves {
		currentLevel[i] = make([]byte, 32)
		copy(currentLevel[i], leaf)
	}
	t.levels = append(t.levels, currentLevel)

	// Build up the tree level by level
	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, 0, (len(currentLevel)+1)/2)

		for i := 0; i < len(currentLevel); i += 2 {
			var combined []byte

			if i+1 < len(currentLevel) {
				// Two nodes to combine
				combined = hashPair(currentLevel[i], currentLevel[i+1])
			} else {
				// Odd node - duplicate it (standard Merkle tree behavior)
				combined = hashPair(currentLevel[i], currentLevel[i])
			}

			nextLevel = append(nextLevel, combined)
		}

		t.levels = append(t.levels, nextLevel)
		currentLevel = nextLevel
	}

	// The root is the single node at the top level
	t.root = currentLevel[0]
	t.built = true

	return nil
}

// hashPair combines two 32-byte hashes into one
// Uses SHA256(left || right) - standard Merkle tree construction
func hashPair(left, right []byte) []byte {
	combined := make([]byte, 64)
	copy(combined[:32], left)
	copy(combined[32:], right)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// Root returns the Merkle root as a 32-byte slice
func (t *Tree) Root() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.built || t.root == nil {
		return nil
	}

	root := make([]byte, 32)
	copy(root, t.root)
	return root
}

// RootHex returns the Merkle root as a hex string
func (t *Tree) RootHex() string {
	root := t.Root()
	if root == nil {
		return ""
	}
	return hex.EncodeToString(root)
}

// LeafCount returns the number of leaves in the tree
func (t *Tree) LeafCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.leaves)
}

// GetLeaf returns the leaf at the given index
func (t *Tree) GetLeaf(index int) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if index < 0 || index >= len(t.leaves) {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", index, len(t.leaves))
	}

	leaf := make([]byte, 32)
	copy(leaf, t.leaves[index])
	return leaf, nil
}

// GenerateProof generates an inclusion proof for the leaf at the given index
func (t *Tree) GenerateProof(leafIndex int) (*InclusionProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if !t.built {
		return nil, errors.New("tree not built")
	}

	if leafIndex < 0 || leafIndex >= len(t.leaves) {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, len(t.leaves))
	}

	proof := &InclusionProof{
		LeafHash:   hex.EncodeToString(t.leaves[leafIndex]),
		LeafIndex:  leafIndex,
		MerkleRoot: hex.EncodeToString(t.root),
		Path:       make([]ProofNode, 0),
		TreeSize:   len(t.leaves),
	}

	// Walk up the tree, collecting sibling hashes
	currentIndex := leafIndex
	for level := 0; level < len(t.levels)-1; level++ {
		levelNodes := t.levels[level]

		// Determine sibling index and position
		var siblingIndex int
		var position Position

		if currentIndex%2 == 0 {
			// Current node is on the left, sibling is on the right
			siblingIndex = currentIndex + 1
			position = Right
		} else {
			// Current node is on the right, sibling is on the left
			siblingIndex = currentIndex - 1
			position = Left
		}

		// Get sibling hash (handle odd-length levels)
		var siblingHash []byte
		if siblingIndex < len(levelNodes) {
			siblingHash = levelNodes[siblingIndex]
		} else {
			// No sibling - use the current node as sibling (odd case)
			siblingHash = levelNodes[currentIndex]
			position = Right
		}

		proof.Path = append(proof.Path, ProofNode{
			Hash:     hex.EncodeToString(siblingHash),
			Position: position,
		})

		// Move to parent index for next level
		currentIndex = currentIndex / 2
	}

	return proof, nil
}

// GenerateProofByHash generates an inclusion proof for a leaf by its hash
func (t *Tree) GenerateProofByHash(leafHash []byte) (*InclusionProof, error) {
	if len(leafHash) != 32 {
		return nil, ErrInvalidLeafHash
	}

	// Find the leaf index (with read lock)
	t.mu.RLock()
	foundIndex := -1
	for i, leaf := range t.leaves {
		if bytes.Equal(leaf, leafHash) {
			foundIndex = i
			break
		}
	}
	t.mu.RUnlock()

	if foundIndex == -1 {
		return nil, ErrLeafNotFound
	}

	return t.GenerateProof(foundIndex)
}

// VerifyProof verifies that a leaf is included in a tree with the given root
// This is a static function that doesn't require the full tree
// Uses constant-time comparison to prevent timing attacks
func VerifyProof(leafHash []byte, proof *InclusionProof, expectedRoot []byte) (bool, error) {
	if len(leafHash) != 32 {
		return false, ErrInvalidLeafHash
	}
	if len(expectedRoot) != 32 {
		return false, fmt.Errorf("expected root must be 32 bytes, got %d", len(expectedRoot))
	}

	if proof == nil || len(proof.Path) == 0 {
		// Single-leaf tree: leaf is the root
		// Use constant-time comparison to prevent timing attacks
		return subtle.ConstantTimeCompare(leafHash, expectedRoot) == 1, nil
	}

	// Start with the leaf hash
	currentHash := make([]byte, 32)
	copy(currentHash, leafHash)

	// Walk up the tree using the proof path
	for _, node := range proof.Path {
		siblingHash, err := hex.DecodeString(node.Hash)
		if err != nil {
			return false, fmt.Errorf("invalid sibling hash: %w", err)
		}

		if len(siblingHash) != 32 {
			return false, fmt.Errorf("sibling hash must be 32 bytes, got %d", len(siblingHash))
		}

		if node.Position == Left {
			// Sibling is on the left
			currentHash = hashPair(siblingHash, currentHash)
		} else {
			// Sibling is on the right
			currentHash = hashPair(currentHash, siblingHash)
		}
	}

	// Compare computed root with expected root using constant-time comparison
	// to prevent timing attacks that could leak information about the root
	return subtle.ConstantTimeCompare(currentHash, expectedRoot) == 1, nil
}

// VerifyProofHex verifies a proof using hex-encoded strings
func VerifyProofHex(leafHashHex string, proof *InclusionProof, expectedRootHex string) (bool, error) {
	leafHash, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return false, fmt.Errorf("invalid leaf hash hex: %w", err)
	}

	expectedRoot, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		return false, fmt.Errorf("invalid root hash hex: %w", err)
	}

	return VerifyProof(leafHash, proof, expectedRoot)
}

// ProofToJSON serializes an inclusion proof to JSON
func (p *InclusionProof) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// ProofFromJSON deserializes an inclusion proof from JSON
func ProofFromJSON(data []byte) (*InclusionProof, error) {
	var proof InclusionProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// PathToJSON returns just the path portion as JSON (for database storage)
func (p *InclusionProof) PathToJSON() ([]byte, error) {
	return json.Marshal(p.Path)
}

// HashData creates a SHA256 hash of arbitrary data
// This is a helper for creating leaf hashes from transaction data
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashDataHex creates a SHA256 hash and returns it as hex
func HashDataHex(data []byte) string {
	return hex.EncodeToString(HashData(data))
}

// CombineHashes combines multiple byte slices and hashes them
// Useful for creating composite hashes from multiple fields
func CombineHashes(hashes ...[]byte) []byte {
	var combined []byte
	for _, h := range hashes {
		combined = append(combined, h...)
	}
	return HashData(combined)
}
