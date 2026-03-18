// Copyright 2025 Certen Protocol
//
// Canonical 4-Blob Hash Computation for CertenProof
// Implements the canonical 4-blob intent model per lead developer guidance
// This is the SINGLE SOURCE OF TRUTH for canonical intent OperationID computation

package proof

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/certen/independant-validator/pkg/commitment"
)

// ComputeGovernanceRoot returns SHA256(canonical(governanceJSON)).
func ComputeGovernanceRoot(governanceJSON []byte) ([]byte, string, error) {
	if len(governanceJSON) == 0 {
		return nil, "", nil
	}
	canon, err := commitment.CanonicalizeJSON(governanceJSON)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(canon)
	return h[:], hex.EncodeToString(h[:]), nil
}

// ComputeCrossChainCommitment returns SHA256(canonical(crossChainJSON)).
func ComputeCrossChainCommitment(crossChainJSON []byte) ([]byte, string, error) {
	if len(crossChainJSON) == 0 {
		return nil, "", nil
	}
	canon, err := commitment.CanonicalizeJSON(crossChainJSON)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(canon)
	return h[:], hex.EncodeToString(h[:]), nil
}

// ComputeCanonical4BlobHash computes the canonical OperationID from the 4-blob intent model.
// This is the SINGLE SOURCE OF TRUTH for OperationID computation across all components.
// Used by: intent discovery, BFT consensus, proof generation, API bridge
//
// CRITICAL-002: Uses length-prefixed canonical concatenation to prevent ambiguity.
// Each blob is canonicalized (RFC 8785 sorted-key JSON), then prefixed with a 4-byte
// big-endian uint32 length before concatenation. This eliminates the possibility that
// two different blob tuples could produce the same byte stream.
//
// Format:
//   SHA256(
//     len(canon(blob0)) || canon(blob0) ||
//     len(canon(blob1)) || canon(blob1) ||
//     len(canon(blob2)) || canon(blob2) ||
//     len(canon(blob3)) || canon(blob3)
//   )
//
// The API bridge (TypeScript) MUST use the identical algorithm:
//   - canonicalizeJSON: recursively sort keys alphabetically, stringify with no whitespace
//   - 4-byte big-endian length prefix per blob
//   - SHA-256 of the full concatenation
func ComputeCanonical4BlobHash(intentJSON, crossChainJSON, governanceJSON, replayJSON []byte) ([]byte, string, error) {
	blobs := [][]byte{intentJSON, crossChainJSON, governanceJSON, replayJSON}

	h := sha256.New()
	for _, blob := range blobs {
		canon, err := commitment.CanonicalizeJSON(blob)
		if err != nil {
			return nil, "", err
		}
		// Write 4-byte big-endian length prefix before each canonicalized blob
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(canon)))
		h.Write(lenBuf)
		h.Write(canon)
	}

	hashBytes := h.Sum(nil)
	return hashBytes, hex.EncodeToString(hashBytes), nil
}

// Legacy ComputeOperationCommitment function removed - use ComputeCanonical4BlobHash instead