// Copyright 2025 Certen Protocol
//
// Portable Merkle Receipt Implementation
// Provides cryptographically verifiable Merkle proof structures
// that can be independently re-verified without trusting any intermediary.

package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Receipt represents a portable Merkle proof that can be independently verified.
// This follows the Accumulate/ChainedProof pattern for deterministic verification.
//
// Verification invariants (fail-closed):
// 1. Start must be exactly 32 bytes
// 2. Anchor must be exactly 32 bytes
// 3. Each Entry.Hash must be exactly 32 bytes
// 4. Merkle recomputation from Start through Entries must equal Anchor
type Receipt struct {
	// Start is the leaf hash being proven (32 bytes, hex-encoded)
	Start string `json:"start"`

	// Anchor is the root hash reached by applying the proof (32 bytes, hex-encoded)
	Anchor string `json:"anchor"`

	// LocalBlock is the block height where this anchor is valid
	LocalBlock uint64 `json:"localBlock"`

	// Entries is the Merkle path from Start to Anchor
	Entries []ReceiptEntry `json:"entries"`
}

// ReceiptEntry represents a single step in the Merkle proof path.
type ReceiptEntry struct {
	// Hash is the sibling hash at this level (32 bytes, hex-encoded)
	Hash string `json:"hash"`

	// Right indicates the position of the sibling:
	// - true: sibling is on the right, compute SHA256(current || sibling)
	// - false: sibling is on the left, compute SHA256(sibling || current)
	Right bool `json:"right"`
}

// BinaryReceipt is the binary form of Receipt for efficient storage/transmission.
type BinaryReceipt struct {
	Start      [32]byte             `json:"start"`
	Anchor     [32]byte             `json:"anchor"`
	LocalBlock uint64               `json:"localBlock"`
	Entries    []BinaryReceiptEntry `json:"entries"`
}

// BinaryReceiptEntry is the binary form of ReceiptEntry.
type BinaryReceiptEntry struct {
	Hash  [32]byte `json:"hash"`
	Right bool     `json:"right"`
}

// Validate verifies the receipt structure and Merkle recomputation.
// Returns nil if valid, error otherwise (fail-closed).
func (r *Receipt) Validate() error {
	// Invariant 1: Start must be 32 bytes
	startHex, err := mustHex32Lower(r.Start, "receipt.start")
	if err != nil {
		return err
	}

	// Invariant 2: Anchor must be 32 bytes
	anchorHex, err := mustHex32Lower(r.Anchor, "receipt.anchor")
	if err != nil {
		return err
	}

	start, _ := hex.DecodeString(startHex)
	anchor, _ := hex.DecodeString(anchorHex)

	// Walk the Merkle path
	current := start
	for i, entry := range r.Entries {
		// Invariant 3: Each entry hash must be 32 bytes
		entryHex, err := mustHex32Lower(entry.Hash, fmt.Sprintf("receipt.entries[%d].hash", i))
		if err != nil {
			return err
		}
		sibling, _ := hex.DecodeString(entryHex)

		// Compute next level hash
		if entry.Right {
			current = receiptHashPair(current, sibling)
		} else {
			current = receiptHashPair(sibling, current)
		}
	}

	// Invariant 4: Computed root must equal anchor
	if !bytes.Equal(current, anchor) {
		return fmt.Errorf("merkle recomputation mismatch: computed=%x, expected=%x", current, anchor)
	}

	return nil
}

// ComputeRoot recomputes the Merkle root from Start through Entries.
// Returns the computed root hash. Does not validate - use Validate() first.
func (r *Receipt) ComputeRoot() ([32]byte, error) {
	startHex, err := mustHex32Lower(r.Start, "receipt.start")
	if err != nil {
		return [32]byte{}, err
	}
	start, _ := hex.DecodeString(startHex)

	current := start
	for i, entry := range r.Entries {
		entryHex, err := mustHex32Lower(entry.Hash, fmt.Sprintf("receipt.entries[%d].hash", i))
		if err != nil {
			return [32]byte{}, err
		}
		sibling, _ := hex.DecodeString(entryHex)

		if entry.Right {
			current = receiptHashPair(current, sibling)
		} else {
			current = receiptHashPair(sibling, current)
		}
	}

	var result [32]byte
	copy(result[:], current)
	return result, nil
}

// ToBinary converts the hex-encoded receipt to binary form.
func (r *Receipt) ToBinary() (*BinaryReceipt, error) {
	startBytes, err := hex.DecodeString(r.Start)
	if err != nil {
		return nil, fmt.Errorf("invalid start hash: %w", err)
	}
	anchorBytes, err := hex.DecodeString(r.Anchor)
	if err != nil {
		return nil, fmt.Errorf("invalid anchor hash: %w", err)
	}

	br := &BinaryReceipt{
		LocalBlock: r.LocalBlock,
		Entries:    make([]BinaryReceiptEntry, len(r.Entries)),
	}
	copy(br.Start[:], startBytes)
	copy(br.Anchor[:], anchorBytes)

	for i, entry := range r.Entries {
		entryBytes, err := hex.DecodeString(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid entry[%d] hash: %w", i, err)
		}
		copy(br.Entries[i].Hash[:], entryBytes)
		br.Entries[i].Right = entry.Right
	}

	return br, nil
}

// ToHex converts a binary receipt back to hex-encoded form.
func (br *BinaryReceipt) ToHex() *Receipt {
	r := &Receipt{
		Start:      hex.EncodeToString(br.Start[:]),
		Anchor:     hex.EncodeToString(br.Anchor[:]),
		LocalBlock: br.LocalBlock,
		Entries:    make([]ReceiptEntry, len(br.Entries)),
	}

	for i, entry := range br.Entries {
		r.Entries[i] = ReceiptEntry{
			Hash:  hex.EncodeToString(entry.Hash[:]),
			Right: entry.Right,
		}
	}

	return r
}

// Validate verifies the binary receipt structure and Merkle recomputation.
func (br *BinaryReceipt) Validate() error {
	// Walk the Merkle path
	current := br.Start[:]
	for _, entry := range br.Entries {
		if entry.Right {
			current = receiptHashPair(current, entry.Hash[:])
		} else {
			current = receiptHashPair(entry.Hash[:], current)
		}
	}

	// Computed root must equal anchor
	if !bytes.Equal(current, br.Anchor[:]) {
		return fmt.Errorf("merkle recomputation mismatch: computed=%x, expected=%x", current, br.Anchor)
	}

	return nil
}

// ComputeRoot recomputes the Merkle root from Start through Entries.
func (br *BinaryReceipt) ComputeRoot() [32]byte {
	current := br.Start[:]
	for _, entry := range br.Entries {
		if entry.Right {
			current = receiptHashPair(current, entry.Hash[:])
		} else {
			current = receiptHashPair(entry.Hash[:], current)
		}
	}

	var result [32]byte
	copy(result[:], current)
	return result
}

// JSON serialization helpers

func (r *Receipt) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

func ReceiptFromJSON(data []byte) (*Receipt, error) {
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// receiptHashPair computes SHA256(left || right).
// This is the canonical Merkle node compression for Accumulate receipts.
func receiptHashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// mustHex32Lower validates that a hex string is exactly 32 bytes (64 hex chars)
// and returns the lowercase form.
func mustHex32Lower(s string, label string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%s: empty", label)
	}
	if len(s) != 64 {
		return "", fmt.Errorf("%s: expected 64 hex chars (32 bytes), got len=%d", label, len(s))
	}
	_, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%s: invalid hex: %w", label, err)
	}
	return s, nil
}

// LayeredReceipt represents a multi-layer proof structure for Level 3.
// Each layer proves inclusion at a different level of the Accumulate hierarchy.
type LayeredReceipt struct {
	// Layer 1: Account → BPT (Binary Patricia Tree)
	Layer1 *Receipt `json:"layer1,omitempty"`

	// Layer 2: BPT → Partition Root
	Layer2 *Receipt `json:"layer2,omitempty"`

	// Layer 3: Partition → Network Root
	Layer3 *Receipt `json:"layer3,omitempty"`

	// NetworkRoot is the final network root hash
	NetworkRoot [32]byte `json:"network_root"`

	// NetworkBlockHeight is the DN block height for this root
	NetworkBlockHeight uint64 `json:"network_block_height"`
}

// ValidateAll verifies all layers and checks chain continuity.
func (lr *LayeredReceipt) ValidateAll() error {
	// Validate Layer 1 if present
	if lr.Layer1 != nil {
		if err := lr.Layer1.Validate(); err != nil {
			return fmt.Errorf("layer1: %w", err)
		}
	}

	// Validate Layer 2 if present
	if lr.Layer2 != nil {
		if err := lr.Layer2.Validate(); err != nil {
			return fmt.Errorf("layer2: %w", err)
		}
	}

	// Validate Layer 3 if present
	if lr.Layer3 != nil {
		if err := lr.Layer3.Validate(); err != nil {
			return fmt.Errorf("layer3: %w", err)
		}

		// Verify Layer 3 anchor matches NetworkRoot
		layer3Anchor, err := hex.DecodeString(lr.Layer3.Anchor)
		if err != nil {
			return fmt.Errorf("layer3 anchor decode: %w", err)
		}
		if !bytes.Equal(layer3Anchor, lr.NetworkRoot[:]) {
			return fmt.Errorf("layer3 anchor (%x) does not match network root (%x)",
				layer3Anchor, lr.NetworkRoot)
		}
	}

	// Verify chain continuity: Layer 1 anchor == Layer 2 start (if both present)
	if lr.Layer1 != nil && lr.Layer2 != nil {
		if lr.Layer1.Anchor != lr.Layer2.Start {
			return fmt.Errorf("layer1.anchor (%s) != layer2.start (%s): chain discontinuity",
				lr.Layer1.Anchor, lr.Layer2.Start)
		}
	}

	// Verify chain continuity: Layer 2 anchor == Layer 3 start (if both present)
	if lr.Layer2 != nil && lr.Layer3 != nil {
		if lr.Layer2.Anchor != lr.Layer3.Start {
			return fmt.Errorf("layer2.anchor (%s) != layer3.start (%s): chain discontinuity",
				lr.Layer2.Anchor, lr.Layer3.Start)
		}
	}

	return nil
}
