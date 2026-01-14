// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"encoding/hex"
	"fmt"
)

// ========= Core Input/Output Types =========

// ProofInput is the canonical input to chained proof construction.
type ProofInput struct {
	Account string // acc://... (scope)
	TxHash  string // 32-byte hex (64 chars, no 0x)
	// Optional informational field (not relied upon for correctness)
	TxID string // acc://<txhash>@<account> (optional)
	// BVN label for DN anchor chain naming (e.g. "bvn1")
	BVN string
}

// ChainedProof is the canonical proof object (normative shape).
type ChainedProof struct {
	Input  ProofInput `json:"input"`
	Layer1 Layer1     `json:"layer1"`
	Layer2 Layer2     `json:"layer2"`
	Layer3 Layer3     `json:"layer3"`

	// Optional artifacts (marshaled JSON of query responses) for audit trails.
	Artifacts map[string][]byte `json:"artifacts,omitempty"`
}

// Layer1 implements L1: chain entry inclusion -> BVN rootChainAnchor witness.
type Layer1 struct {
	TxChainIndex       uint64 `json:"txChainIndex"`
	BVNMinorBlockIndex uint64 `json:"bvnMinorBlockIndex"`
	BVNRootChainAnchor string `json:"bvnRootChainAnchor"` // hex32
	Leaf               string `json:"leaf"`               // hex32 (txHash)
	Receipt            Receipt `json:"receipt"`
}

// Layer2 implements L2: BVN rootChainAnchor -> DN anchor pair -> BVN stateTreeAnchor.
type Layer2 struct {
	DNIndex          uint64 `json:"dnIndex"`
	DNMinorBlockIndex uint64 `json:"dnMinorBlockIndex"` // DN_MBI (anchor-recording MBI)
	DNRootChainAnchor string `json:"dnRootChainAnchor"` // hex32 (witness root)
	BVNStateTreeAnchor string `json:"bvnStateTreeAnchor"` // hex32 (from anchor(bvn)-bpt[IDX].entry)

	RootReceipt Receipt `json:"rootReceipt"`
	BptReceipt  Receipt `json:"bptReceipt"`
}

// Layer3 implements L3: DN rootChainAnchor -> DN stateTreeAnchor via DN self index oracle.
type Layer3 struct {
	DNRootChainIndex                    uint64 `json:"dnRootChainIndex"`
	DNAnchorMinorBlockIndex             uint64 `json:"dnAnchorMinorBlockIndex"` // = Layer2.DNMinorBlockIndex (DN_MBI)
	DNConsensusHeight                   uint64 `json:"dnConsensusHeight"`       // = DN_MBI + 1
	DNSelfAnchorRecordedAtMinorBlockIndex uint64 `json:"dnSelfAnchorRecordedAtMinorBlockIndex"` // DN_FINAL_MBI
	DNStateTreeAnchor                   string `json:"dnStateTreeAnchor"`       // hex32 (from anchor(directory)-bpt[index].entry)

	RootReceipt Receipt `json:"rootReceipt"`
	BptReceipt  Receipt `json:"bptReceipt"`
}

// Receipt is a portable receipt representation that can be validated deterministically.
type Receipt struct {
	Start      string        `json:"start"`      // hex32
	Anchor     string        `json:"anchor"`     // hex32
	LocalBlock uint64        `json:"localBlock"` // minor block index (MBI)
	Entries    []ReceiptStep `json:"entries"`
}

// ReceiptStep is one step in the Merkle path.
type ReceiptStep struct {
	Hash  string `json:"hash"`  // hex32
	Right bool   `json:"right"` // neighbor is on the right side
}

// ========= Hex / Bytes Helpers (Fail-Closed) =========

// MustHex32Lower validates a hex string is exactly 32 bytes (64 hex chars) and returns lowercase.
func MustHex32Lower(s string, label string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%s: empty", label)
	}
	if len(s) != 64 {
		return "", fmt.Errorf("%s: expected 64 hex chars (32 bytes), got len=%d (%q)", label, len(s), s)
	}
	_, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%s: invalid hex: %w", label, err)
	}
	// Normalize to lowercase for canonical comparisons.
	// hex.DecodeString accepts mixed-case; we canonicalize to lowercase here.
	return lowerHex(s), nil
}

func lowerHex(s string) string {
	// Avoid importing strings repeatedly in hot path
	b := []byte(s)
	for i := range b {
		c := b[i]
		if c >= 'A' && c <= 'F' {
			b[i] = c + 32
		}
	}
	return string(b)
}