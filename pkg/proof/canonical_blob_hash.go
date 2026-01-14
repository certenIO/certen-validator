// Copyright 2025 Certen Protocol
//
// Canonical 4-Blob Hash Computation for CertenProof
// Implements the canonical 4-blob intent model per lead developer guidance
// This is the SINGLE SOURCE OF TRUTH for canonical intent OperationID computation

package proof

import (
	"crypto/sha256"
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

// ComputeCanonical4BlobHash returns SHA256(canonical(intentJSON) || canonical(crossChainJSON) || canonical(governanceJSON) || canonical(replayJSON))
// This implements the canonical 4-blob intent model and is the SINGLE SOURCE OF TRUTH for OperationID computation
// Used by: intent discovery, BFT consensus, proof generation
func ComputeCanonical4BlobHash(intentJSON, crossChainJSON, governanceJSON, replayJSON []byte) ([]byte, string, error) {
	// Canonicalize each blob
	canonIntent, err := commitment.CanonicalizeJSON(intentJSON)
	if err != nil {
		return nil, "", err
	}
	canonCross, err := commitment.CanonicalizeJSON(crossChainJSON)
	if err != nil {
		return nil, "", err
	}
	canonGov, err := commitment.CanonicalizeJSON(governanceJSON)
	if err != nil {
		return nil, "", err
	}
	canonReplay, err := commitment.CanonicalizeJSON(replayJSON)
	if err != nil {
		return nil, "", err
	}

	// Concatenate and hash
	h := sha256.New()
	h.Write(canonIntent)
	h.Write(canonCross)
	h.Write(canonGov)
	h.Write(canonReplay)

	hashBytes := h.Sum(nil)
	return hashBytes, hex.EncodeToString(hashBytes), nil
}

// Legacy ComputeOperationCommitment function removed - use ComputeCanonical4BlobHash instead