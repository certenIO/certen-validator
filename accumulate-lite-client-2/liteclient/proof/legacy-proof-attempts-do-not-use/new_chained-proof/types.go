// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package chained_proof implements the CERTEN chained proof specification
// for Layers 1-3 using Accumulate v3 query() receipts with receipt stitching.
//
// This implementation follows the canonical CERTEN proof model as specified in:
// services\validator\docs\new_CERTEN_CHAINED_PROOF_SPEC.md
//
// Key principles:
// 1. Receipts are directed edges: start → anchor @ localBlock
// 2. Layer 1 MUST start from chain-entry receipts (NOT account receipts)
// 3. Stitching requires exact hash equality between layers
// 4. Heights are partition-local and must not be conflated
package chained_proof

import (
	"encoding/json"
	"time"
)

// MerkleReceipt represents a canonical Merkle receipt following the CERTEN specification.
// This is the fundamental building block for all proof layers.
type MerkleReceipt struct {
	Start      []byte         `json:"start"`      // Leaf hash (source node)
	Anchor     []byte         `json:"anchor"`     // Root hash reached (destination node)
	Entries    []ReceiptEntry `json:"entries"`    // Merkle path
	LocalBlock uint64         `json:"localBlock"` // Block height where anchor is valid
}

// ReceiptEntry represents a single step in a Merkle path.
type ReceiptEntry struct {
	Hash  []byte `json:"hash"`            // Sibling hash
	Right *bool  `json:"right,omitempty"` // true = sibling on right, false/nil = sibling on left
}

// Layer1EntryInclusion implements Layer 1: Entry Inclusion → Partition Anchor
//
// Goal: Prove EntryHash is included in some partition root at partition height Hbvn.
// Source: MUST be recordType:"chainEntry" with receipt
type Layer1EntryInclusion struct {
	Scope           string        `json:"scope"`           // e.g. "acc://<adi>/<acct>"
	ChainName       string        `json:"chainName"`       // e.g. "main"
	ChainIndex      uint64        `json:"chainIndex"`      // index queried
	Leaf            []byte        `json:"leaf"`            // MUST equal chainEntry.entry
	Receipt         MerkleReceipt `json:"receipt"`         // start=leaf, anchor=partition anchor
	Anchor          []byte        `json:"anchor"`          // MUST equal receipt.anchor
	LocalBlock      uint64        `json:"localBlock"`      // MUST equal receipt.localBlock
	SourcePartition string        `json:"sourcePartition"` // e.g. "acc://bvn-BVN1.acme" from block query
}

// Layer2AnchorToDN implements Layer 2: Partition Anchor → DN Anchor Root
//
// Goal: Prove the partition anchor is anchored into DN at DN height Hdn.
// Method: dn.acme/anchors anchorSearch with includeReceipt=true
type Layer2AnchorToDN struct {
	Scope      string        `json:"scope"`      // MUST be "acc://dn.acme/anchors"
	RecordName string        `json:"recordName"` // e.g. "anchor(bvn2)-root" (auditing)
	Start      []byte        `json:"start"`      // MUST equal L1.Anchor
	Receipt    MerkleReceipt `json:"receipt"`    // start=L1.anchor, anchor=DN root
	Anchor     []byte        `json:"anchor"`     // DN root
	LocalBlock uint64        `json:"localBlock"` // DN height (Hdn)
}

// ConsensusFinality implements consensus finality verification for both BVN and DN partitions
// This is used for both Layer 1C (BVN/DN consensus) and Layer 2C (DN consensus) per spec section 5.4
type ConsensusFinality struct {
	Partition     string      `json:"partition"`     // "bvn-BVN1" or "dn"
	Network       string      `json:"network"`       // e.g. "DevNet.BVN1" from /status
	Height        uint64      `json:"height"`        // MUST be localBlock+1
	Root          []byte      `json:"root"`          // expected root/app_hash
	Commit        interface{} `json:"commit"`        // self-contained commit payload
	Validators    interface{} `json:"validators"`    // self-contained validator payload
	PowerOK       bool        `json:"powerOk"`       // ≥2/3 voting power achieved
	RootBindingOK bool        `json:"rootBindingOk"` // Commit binds the same root
}

// AccumulateAnchoringProof represents the complete proof following CERTEN specification v3-receipt-stitch-2
// Per spec section 5.5: Updated structure with separate consensus finality objects
//
// This is the normative data structure for embedding in ValidatorBlock
// and for independent verification of Accumulate anchoring proofs.
type AccumulateAnchoringProof struct {
	Version        string               `json:"version"`                  // "v3-receipt-stitch-2"
	Timestamp      time.Time            `json:"timestamp"`                // Proof generation time
	Layer1         Layer1EntryInclusion `json:"layer1"`                   // Entry → Partition anchor
	Layer1Finality *ConsensusFinality   `json:"layer1Finality,omitempty"` // BVN/DN consensus (depending on source)
	Layer2         Layer2AnchorToDN     `json:"layer2"`                   // Partition anchor → DN root
	Layer2Finality *ConsensusFinality   `json:"layer2Finality,omitempty"` // DN consensus finality
}

// ProofVerificationResult contains the results of proof verification
type ProofVerificationResult struct {
	Valid         bool                   `json:"valid"`
	TrustLevel    string                 `json:"trustLevel"` // "Layer1", "Layer2", "Layer3"
	ErrorMessage  string                 `json:"error,omitempty"`
	LayerResults  map[string]LayerResult `json:"layerResults"`
	VerifiedAt    time.Time              `json:"verifiedAt"`
	DurationNanos int64                  `json:"durationNanos"`
}

// LayerResult contains verification results for a single layer
type LayerResult struct {
	LayerName    string                 `json:"layerName"`
	Valid        bool                   `json:"valid"`
	ErrorMessage string                 `json:"error,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// ProofBuilder interfaces for constructing proofs
type ProofBuilder interface {
	// BuildLayer1 constructs Layer 1 proof from chain entry
	BuildLayer1(scope, chainName string, chainIndex uint64) (*Layer1EntryInclusion, error)

	// BuildLayer2 constructs Layer 2 proof by searching DN anchors
	BuildLayer2(layer1 *Layer1EntryInclusion) (*Layer2AnchorToDN, error)

	// BuildConsensusFinality constructs consensus finality proof for BVN or DN
	BuildConsensusFinality(layer *Layer1EntryInclusion, layer2 *Layer2AnchorToDN, partition string) (*ConsensusFinality, error)

	// BuildComplete constructs complete proof with consensus finality (proof-grade mode)
	BuildComplete(scope, chainName string, chainIndex uint64) (*AccumulateAnchoringProof, error)

	// BuildPartial constructs anchored-only proof (L1+L2 without consensus)
	BuildPartial(scope, chainName string, chainIndex uint64) (*AccumulateAnchoringProof, error)
}

// ProofVerifier interfaces for verifying proofs
type ProofVerifier interface {
	// VerifyLayer1 verifies Layer 1 entry inclusion proof
	VerifyLayer1(layer1 *Layer1EntryInclusion) (*LayerResult, error)

	// VerifyLayer2 verifies Layer 2 anchor stitching proof
	VerifyLayer2(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) (*LayerResult, error)

	// VerifyConsensusFinality verifies consensus finality proof (L1C or L2C)
	VerifyConsensusFinality(finality *ConsensusFinality) (*LayerResult, error)

	// VerifyComplete verifies complete proof with consensus finality
	VerifyComplete(proof *AccumulateAnchoringProof) (*ProofVerificationResult, error)
}

// ReceiptStitcher handles receipt stitching operations
type ReceiptStitcher interface {
	// StitchReceipts validates that two receipts can be stitched together
	// Returns true if L2.start == L1.anchor (exact byte equality)
	StitchReceipts(layer1Receipt, layer2Receipt *MerkleReceipt) (bool, error)

	// ValidateReceiptIntegrity verifies internal receipt validity
	// Recomputes root from Merkle path and validates against anchor
	ValidateReceiptIntegrity(receipt *MerkleReceipt) (bool, error)
}

// String returns a human-readable description of the layer result
func (lr *LayerResult) String() string {
	if lr.Valid {
		return lr.LayerName + ": VALID"
	}
	return lr.LayerName + ": INVALID - " + lr.ErrorMessage
}

// String returns a human-readable summary of verification results
func (pvr *ProofVerificationResult) String() string {
	if pvr.Valid {
		return "PROOF VALID - Trust Level: " + pvr.TrustLevel
	}
	return "PROOF INVALID - " + pvr.ErrorMessage
}

// ToJSON serializes the proof to JSON with proper formatting
func (aap *AccumulateAnchoringProof) ToJSON() ([]byte, error) {
	return json.MarshalIndent(aap, "", "  ")
}

// FromJSON deserializes a proof from JSON
func FromJSON(data []byte) (*AccumulateAnchoringProof, error) {
	var proof AccumulateAnchoringProof
	err := json.Unmarshal(data, &proof)
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

// GetTrustLevel determines the trust level based on which layers are valid per spec section 8.5
func (pvr *ProofVerificationResult) GetTrustLevel() string {
	// Check for proof-grade (both consensus finality objects present and valid)
	if pvr.LayerResults["Layer1Finality"].Valid && pvr.LayerResults["Layer2Finality"].Valid {
		return "Consensus Verified (Proof-Grade)"
	} else if pvr.LayerResults["Layer2"].Valid {
		return "DN Anchored (Not Consensus-Bound)"
	} else if pvr.LayerResults["Layer1"].Valid {
		return "Partition Trust (BVN Verified)"
	}
	return "No Trust (Invalid)"
}

// IsComplete returns true if all layers including consensus finality are present (proof-grade mode)
func (aap *AccumulateAnchoringProof) IsComplete() bool {
	return aap.Layer1Finality != nil && aap.Layer2Finality != nil
}

// GetLeafHash returns the original entry hash being proved
func (aap *AccumulateAnchoringProof) GetLeafHash() []byte {
	return aap.Layer1.Leaf
}

// GetDNRoot returns the final DN root from Layer 2
func (aap *AccumulateAnchoringProof) GetDNRoot() []byte {
	return aap.Layer2.Anchor
}

// GetDNHeight returns the DN height from Layer 2
func (aap *AccumulateAnchoringProof) GetDNHeight() uint64 {
	return aap.Layer2.LocalBlock
}
