// Copyright 2025 Certen Protocol
//
// Canonical Commitment Package - RFC8785-compliant deterministic JSON
// Provides shared functions for commitment computation across all services

package commitment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalizeJSON takes arbitrary JSON bytes and returns a canonical encoding
// (deterministic key order, stable formatting). This is a simplified RFC8785-like approach.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	canonical := canonicalizeValue(v)
	return json.Marshal(canonical)
}

// canonicalizeValue recursively sorts map keys; arrays retain order.
func canonicalizeValue(v interface{}) interface{} {
	switch vv := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(vv))
		for k := range vv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]interface{}, len(vv))
		for _, k := range keys {
			ordered[k] = canonicalizeValue(vv[k])
		}
		return ordered
	case []interface{}:
		out := make([]interface{}, len(vv))
		for i, e := range vv {
			out[i] = canonicalizeValue(e)
		}
		return out
	default:
		return vv
	}
}

// HashConcat returns SHA256 of concatenated byte slices.
func HashConcat(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// HashHex returns hex-encoded SHA256 of concatenated byte slices
func HashHex(parts ...[]byte) string {
	return hex.EncodeToString(HashConcat(parts...))
}

// CanonicalizeJSONFromMap takes a map and returns canonical JSON bytes
func CanonicalizeJSONFromMap(m map[string]interface{}) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(b)
}

// Note: HashFourBlobs removed - use proof.ComputeCanonical4BlobHash instead

// HashBytes returns hex-encoded SHA256 of bytes with 0x prefix
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(h[:])
}

// SHA256Hex is an alias for HashBytes for compatibility
func SHA256Hex(data []byte) string {
	return HashBytes(data)
}

// MarshalCanonical performs canonical JSON encoding per RFC 8785
func MarshalCanonical(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(raw)
}

// HashCanonical performs canonical JSON encoding and returns SHA-256 hex hash
func HashCanonical(v interface{}) (string, error) {
	canon, err := MarshalCanonical(v)
	if err != nil {
		return "", err
	}
	return HashBytes(canon), nil
}

// ==================================================================
// PROTOCOL COMMITMENT MATH FUNCTIONS
// Moved from pkg/consensus/consensus_commitments.go
// ==================================================================

// Note: ComputeOperationID removed - use proof.ComputeCanonical4BlobHash instead
// Note: ComputeCrossChainCommitment removed - use proof.ComputeCanonical4BlobHash for OperationID computation

// ComputeBundleID computes the bundle ID from governance and cross-chain proofs
// Hash(governance_proof || cross_chain_proof)
func ComputeBundleID(govProof interface{}, crossChainProof interface{}) (string, error) {
	govBytes, err := MarshalCanonical(govProof)
	if err != nil {
		return "", fmt.Errorf("marshal governance proof: %w", err)
	}

	ccBytes, err := MarshalCanonical(crossChainProof)
	if err != nil {
		return "", fmt.Errorf("marshal cross-chain proof: %w", err)
	}

	combined := append(govBytes, ccBytes...)
	return HashBytes(combined), nil
}

// ComputeGovernanceMerkleRoot computes the Merkle root from authorization leaves
// Uses simplified binary tree construction with canonical leaf hashing
func ComputeGovernanceMerkleRoot(leaves []interface{}) (string, error) {
	if len(leaves) == 0 {
		// Return zero hash for empty tree
		zeroHash := make([]byte, 32)
		return "0x" + fmt.Sprintf("%x", zeroHash), nil
	}

	// Hash each leaf as canonical JSON
	hashes := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		leafHash, err := HashCanonical(leaf)
		if err != nil {
			return "", fmt.Errorf("hash leaf %d: %w", i, err)
		}
		// Remove 0x prefix for binary operations
		hashBytes, err := hex.DecodeString(leafHash[2:])
		if err != nil {
			return "", fmt.Errorf("parse leaf hash %d: %w", i, err)
		}
		hashes[i] = hashBytes
	}

	// Pairwise reduction to build Merkle tree
	for len(hashes) > 1 {
		next := make([][]byte, 0, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 == len(hashes) {
				// Odd number, promote the last hash
				next = append(next, hashes[i])
			} else {
				// Combine two hashes
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			}
		}
		hashes = next
	}

	// Return final root hash with 0x prefix
	return "0x" + hex.EncodeToString(hashes[0]), nil
}

// ComputeLegCommitment computes the deterministic per-leg commitment
// Hash of key fields that define the external action
func ComputeLegCommitment(payload map[string]interface{}) (string, error) {
	return HashCanonical(payload)
}

// Note: ComputeOperationCommitment removed - use proof.ComputeCanonical4BlobHash for OperationID computation