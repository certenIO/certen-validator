// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"crypto/sha256"
	"fmt"
	"log"
)

// ReceiptVerifier implements receipt verification and stitching operations
// following the CERTEN specification invariants.
type ReceiptVerifier struct {
	debug bool
}

// NewReceiptVerifier creates a new receipt verifier
func NewReceiptVerifier(debug bool) *ReceiptVerifier {
	return &ReceiptVerifier{debug: debug}
}

// ValidateIntegrity verifies internal receipt validity per Invariant 1
//
// This method recomputes the Merkle root by walking the path from start through entries
// and validates that the computed root equals receipt.anchor.
func (rv *ReceiptVerifier) ValidateIntegrity(receipt *MerkleReceipt) (bool, error) {
	if receipt == nil {
		return false, fmt.Errorf("receipt cannot be nil")
	}

	if len(receipt.Start) == 0 {
		return false, fmt.Errorf("receipt start cannot be empty")
	}

	if len(receipt.Anchor) == 0 {
		return false, fmt.Errorf("receipt anchor cannot be empty")
	}

	// CRITICAL: Enforce 32-byte hash discipline per CERTEN spec
	if len(receipt.Start) != 32 {
		return false, fmt.Errorf("receipt start must be exactly 32 bytes, got %d", len(receipt.Start))
	}

	if len(receipt.Anchor) != 32 {
		return false, fmt.Errorf("receipt anchor must be exactly 32 bytes, got %d", len(receipt.Anchor))
	}

	if rv.debug {
		log.Printf("[RECEIPT VERIFY] Validating integrity for receipt start=%x, anchor=%x",
			receipt.Start[:8], receipt.Anchor[:8])
	}

	// Start with the leaf hash
	currentHash := make([]byte, len(receipt.Start))
	copy(currentHash, receipt.Start)

	if rv.debug {
		log.Printf("[RECEIPT VERIFY] Starting with leaf: %x", currentHash[:8])
	}

	// Walk through the Merkle path
	for i, entry := range receipt.Entries {
		if len(entry.Hash) == 0 {
			return false, fmt.Errorf("entry %d has empty hash", i)
		}

		// Enforce 32-byte hash discipline for all Merkle path entries
		if len(entry.Hash) != 32 {
			return false, fmt.Errorf("entry %d hash must be exactly 32 bytes, got %d", i, len(entry.Hash))
		}

		// Determine sibling position
		// Per spec: if entry.right == true, sibling is on the right
		// If entry.right == false OR missing, sibling is on the left
		siblingOnRight := entry.Right != nil && *entry.Right

		// Concatenate hashes for next level (safe allocation to avoid append() mutation)
		var combined []byte
		if siblingOnRight {
			// Current hash on left, sibling on right
			combined = make([]byte, 0, len(currentHash)+len(entry.Hash))
			combined = append(combined, currentHash...)
			combined = append(combined, entry.Hash...)
		} else {
			// Sibling on left, current hash on right
			combined = make([]byte, 0, len(entry.Hash)+len(currentHash))
			combined = append(combined, entry.Hash...)
			combined = append(combined, currentHash...)
		}

		// Hash the combination
		hasher := sha256.New()
		hasher.Write(combined)
		currentHash = hasher.Sum(nil)

		if rv.debug {
			log.Printf("[RECEIPT VERIFY] Step %d: sibling=%x (right=%t) -> hash=%x",
				i, entry.Hash[:8], siblingOnRight, currentHash[:8])
		}
	}

	// Verify computed root matches the anchor
	if len(currentHash) != len(receipt.Anchor) {
		return false, fmt.Errorf("computed root length mismatch: computed=%d, anchor=%d",
			len(currentHash), len(receipt.Anchor))
	}

	for i := 0; i < len(currentHash); i++ {
		if currentHash[i] != receipt.Anchor[i] {
			if rv.debug {
				log.Printf("[RECEIPT VERIFY] ❌ Root mismatch: computed=%x, anchor=%x",
					currentHash, receipt.Anchor)
			}
			return false, fmt.Errorf("computed root does not match anchor at byte %d", i)
		}
	}

	if rv.debug {
		log.Printf("[RECEIPT VERIFY] ✅ Integrity validation successful")
	}

	return true, nil
}

// ValidateStitching verifies that two receipts can be stitched together per Invariant 2
//
// Returns true if layer2Receipt.start == layer1Receipt.anchor (exact byte equality)
func (rv *ReceiptVerifier) ValidateStitching(layer1Receipt, layer2Receipt *MerkleReceipt) (bool, error) {
	if rv.debug {
		log.Printf("[RECEIPT STITCH] Validating L1.anchor=%x -> L2.start=%x",
			layer1Receipt.Anchor[:8], layer2Receipt.Start[:8])
	}

	if layer1Receipt == nil {
		return false, fmt.Errorf("layer 1 receipt cannot be nil")
	}

	if layer2Receipt == nil {
		return false, fmt.Errorf("layer 2 receipt cannot be nil")
	}

	if len(layer1Receipt.Anchor) == 0 {
		return false, fmt.Errorf("layer 1 anchor cannot be empty")
	}

	if len(layer2Receipt.Start) == 0 {
		return false, fmt.Errorf("layer 2 start cannot be empty")
	}

	// Check exact byte equality per spec
	if len(layer1Receipt.Anchor) != len(layer2Receipt.Start) {
		if rv.debug {
			log.Printf("[RECEIPT STITCH] ❌ Length mismatch: L1.anchor=%d, L2.start=%d",
				len(layer1Receipt.Anchor), len(layer2Receipt.Start))
		}
		return false, fmt.Errorf("stitching length mismatch: L1.anchor=%d, L2.start=%d",
			len(layer1Receipt.Anchor), len(layer2Receipt.Start))
	}

	for i := 0; i < len(layer1Receipt.Anchor); i++ {
		if layer1Receipt.Anchor[i] != layer2Receipt.Start[i] {
			if rv.debug {
				log.Printf("[RECEIPT STITCH] ❌ Byte mismatch at position %d", i)
			}
			return false, fmt.Errorf("stitching failed: L1.anchor != L2.start at byte %d", i)
		}
	}

	if rv.debug {
		log.Printf("[RECEIPT STITCH] ✅ Stitching validation successful")
	}

	return true, nil
}

// ValidateHeightDiscipline validates that heights follow partition-local rules per Invariant 3
//
// Heights must be partition-local and not conflated between BVN and DN
func (rv *ReceiptVerifier) ValidateHeightDiscipline(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) error {
	if layer1 == nil {
		return fmt.Errorf("layer 1 cannot be nil")
	}

	if layer2 == nil {
		return fmt.Errorf("layer 2 cannot be nil")
	}

	// Validate that heights are reasonable (basic sanity check)
	if layer1.LocalBlock == 0 {
		return fmt.Errorf("layer 1 local block cannot be zero")
	}

	if layer2.LocalBlock == 0 {
		return fmt.Errorf("layer 2 local block cannot be zero")
	}

	// Heights are from different partitions and should not be directly compared
	// but we can validate they are both reasonable values
	if layer1.LocalBlock > 1<<63-1 {
		return fmt.Errorf("layer 1 local block too large: %d", layer1.LocalBlock)
	}

	if layer2.LocalBlock > 1<<63-1 {
		return fmt.Errorf("layer 2 local block too large: %d", layer2.LocalBlock)
	}

	if rv.debug {
		log.Printf("[HEIGHT DISCIPLINE] L1 BVN height: %d, L2 DN height: %d",
			layer1.LocalBlock, layer2.LocalBlock)
	}

	return nil
}

// StitchReceipts is the main interface method implementing the ReceiptStitcher interface
func (rv *ReceiptVerifier) StitchReceipts(layer1Receipt, layer2Receipt *MerkleReceipt) (bool, error) {
	return rv.ValidateStitching(layer1Receipt, layer2Receipt)
}

// ValidateReceiptIntegrity is the main interface method implementing the ReceiptStitcher interface
func (rv *ReceiptVerifier) ValidateReceiptIntegrity(receipt *MerkleReceipt) (bool, error) {
	return rv.ValidateIntegrity(receipt)
}

// ValidateReceiptChain validates an entire chain of receipts
//
// This method validates:
// 1. Each receipt's internal integrity
// 2. Proper stitching between consecutive receipts
// 3. Height discipline across layers
func (rv *ReceiptVerifier) ValidateReceiptChain(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) error {
	if rv.debug {
		log.Printf("[RECEIPT CHAIN] Validating complete L1->L2 receipt chain")
	}

	// Validate Layer 1 receipt integrity
	valid, err := rv.ValidateIntegrity(&layer1.Receipt)
	if err != nil {
		return fmt.Errorf("Layer 1 receipt integrity failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("Layer 1 receipt integrity validation failed")
	}

	// Validate Layer 2 receipt integrity
	valid, err = rv.ValidateIntegrity(&layer2.Receipt)
	if err != nil {
		return fmt.Errorf("Layer 2 receipt integrity failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("Layer 2 receipt integrity validation failed")
	}

	// Validate receipt stitching
	valid, err = rv.ValidateStitching(&layer1.Receipt, &layer2.Receipt)
	if err != nil {
		return fmt.Errorf("receipt stitching failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("receipt stitching validation failed")
	}

	// Validate height discipline
	if err := rv.ValidateHeightDiscipline(layer1, layer2); err != nil {
		return fmt.Errorf("height discipline validation failed: %w", err)
	}

	if rv.debug {
		log.Printf("[RECEIPT CHAIN] ✅ Complete receipt chain validation successful")
	}

	return nil
}
