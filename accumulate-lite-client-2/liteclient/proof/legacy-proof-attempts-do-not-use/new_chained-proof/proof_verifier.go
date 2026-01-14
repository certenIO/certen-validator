// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"fmt"
	"log"
	"time"
)

// CertenProofVerifier implements complete verification of CERTEN chained proofs
// following the canonical specification v3-receipt-stitch-2 requirements and invariants.
//
// This verifier validates all layers independently and ensures proper stitching
// between layers according to the specification.
type CertenProofVerifier struct {
	layer1Verifier    *Layer1Verifier
	layer2Verifier    *Layer2Verifier
	consensusVerifier *ConsensusVerifier
	receiptVerifier   *ReceiptVerifier
	debug             bool
}

// NewCertenProofVerifier creates a new CERTEN proof verifier
func NewCertenProofVerifier(debug bool) *CertenProofVerifier {
	return &CertenProofVerifier{
		layer1Verifier:    NewLayer1Verifier(debug),
		layer2Verifier:    NewLayer2Verifier(debug),
		consensusVerifier: NewConsensusVerifier(debug),
		receiptVerifier:   NewReceiptVerifier(debug),
		debug:             debug,
	}
}

// VerifyLayer1 verifies Layer 1 entry inclusion proof
func (cpv *CertenProofVerifier) VerifyLayer1(layer1 *Layer1EntryInclusion) (*LayerResult, error) {
	return cpv.layer1Verifier.Verify(layer1)
}

// VerifyLayer2 verifies Layer 2 anchor stitching proof
func (cpv *CertenProofVerifier) VerifyLayer2(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) (*LayerResult, error) {
	return cpv.layer2Verifier.Verify(layer1, layer2)
}

// VerifyLayer1Consensus verifies Layer 1C consensus finality proof
func (cpv *CertenProofVerifier) VerifyLayer1Consensus(layer1 *Layer1EntryInclusion, layer1Finality *ConsensusFinality) (*LayerResult, error) {
	// Validate height consistency per spec section 4.4 (height must be localBlock + 1)
	expectedHeight := layer1.LocalBlock + 1
	if layer1Finality.Height != expectedHeight {
		return &LayerResult{
			LayerName:    "Layer1Finality",
			Valid:        false,
			ErrorMessage: fmt.Sprintf("height mismatch: expected %d (L1.localBlock+1), got %d", expectedHeight, layer1Finality.Height),
		}, nil
	}

	// Validate root consistency between layers
	for i := 0; i < len(layer1Finality.Root); i++ {
		if layer1Finality.Root[i] != layer1.Anchor[i] {
			return &LayerResult{
				LayerName:    "Layer1Finality",
				Valid:        false,
				ErrorMessage: fmt.Sprintf("root mismatch: L1.anchor != L1C.root at byte %d", i),
			}, nil
		}
	}

	return cpv.consensusVerifier.VerifyConsensusFinality(layer1Finality, "Layer1Finality")
}

// VerifyLayer2Consensus verifies Layer 2C DN consensus finality proof
func (cpv *CertenProofVerifier) VerifyLayer2Consensus(layer2 *Layer2AnchorToDN, layer2Finality *ConsensusFinality) (*LayerResult, error) {
	// Validate height consistency per spec section 4.4 (height must be localBlock + 1)
	expectedHeight := layer2.LocalBlock + 1
	if layer2Finality.Height != expectedHeight {
		return &LayerResult{
			LayerName:    "Layer2Finality",
			Valid:        false,
			ErrorMessage: fmt.Sprintf("height mismatch: expected %d (L2.localBlock+1), got %d", expectedHeight, layer2Finality.Height),
		}, nil
	}

	// Validate root consistency between layers
	for i := 0; i < len(layer2Finality.Root); i++ {
		if layer2Finality.Root[i] != layer2.Anchor[i] {
			return &LayerResult{
				LayerName:    "Layer2Finality",
				Valid:        false,
				ErrorMessage: fmt.Sprintf("root mismatch: L2.anchor != L2C.root at byte %d", i),
			}, nil
		}
	}

	return cpv.consensusVerifier.VerifyConsensusFinality(layer2Finality, "Layer2Finality")
}

// VerifyLayer3 provides legacy interface (deprecated)
func (cpv *CertenProofVerifier) VerifyLayer3(layer2 *Layer2AnchorToDN, layer3 *ConsensusFinality) (*LayerResult, error) {
	return cpv.VerifyLayer2Consensus(layer2, layer3)
}

// VerifyComplete verifies complete L1-L3 proof following all specification invariants
//
// This method implements comprehensive verification including:
// 1. Individual layer verification
// 2. Receipt integrity validation
// 3. Stitching invariant enforcement
// 4. Height discipline validation
// 5. Trust level determination
func (cpv *CertenProofVerifier) VerifyComplete(proof *AccumulateAnchoringProof) (*ProofVerificationResult, error) {
	if cpv.debug {
		log.Printf("[PROOF VERIFIER] Starting complete verification for proof version %s", proof.Version)
	}

	startTime := time.Now()

	result := &ProofVerificationResult{
		Valid:        false,
		TrustLevel:   "No Trust",
		LayerResults: make(map[string]LayerResult),
		VerifiedAt:   startTime,
	}

	// Validate basic structure
	if proof == nil {
		result.ErrorMessage = "proof cannot be nil"
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	if proof.Version == "" {
		result.ErrorMessage = "proof version cannot be empty"
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// Step 1: Verify Layer 1 - Entry Inclusion
	if cpv.debug {
		log.Printf("[PROOF VERIFIER] Step 1/4: Verifying Layer 1...")
	}

	layer1Result, err := cpv.VerifyLayer1(&proof.Layer1)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Layer 1 verification error: %v", err)
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}
	result.LayerResults["Layer1"] = *layer1Result

	if !layer1Result.Valid {
		result.ErrorMessage = "Layer 1 verification failed: " + layer1Result.ErrorMessage
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// Step 2: Verify Layer 2 - Anchor Stitching
	if cpv.debug {
		log.Printf("[PROOF VERIFIER] Step 2/4: Verifying Layer 2...")
	}

	layer2Result, err := cpv.VerifyLayer2(&proof.Layer1, &proof.Layer2)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Layer 2 verification error: %v", err)
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}
	result.LayerResults["Layer2"] = *layer2Result

	if !layer2Result.Valid {
		result.ErrorMessage = "Layer 2 verification failed: " + layer2Result.ErrorMessage
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// At this point we have valid L1-L2, set minimum trust level per spec section 8.5
	result.TrustLevel = "DN Anchored (Not Consensus-Bound)"
	result.Valid = true

	// Declare variables for consensus finality results
	var layer1FinalityResult *LayerResult
	var layer2FinalityResult *LayerResult

	// Step 3: Verify Layer 1C - Consensus Finality (if present)
	if proof.Layer1Finality != nil {
		if cpv.debug {
			log.Printf("[PROOF VERIFIER] Step 3/5: Verifying Layer 1C consensus finality...")
		}

		layer1FinalityResult, err = cpv.VerifyLayer1Consensus(&proof.Layer1, proof.Layer1Finality)
		if err != nil {
			layer1FinalityResult = &LayerResult{
				LayerName:    "Layer1Finality",
				Valid:        false,
				ErrorMessage: err.Error(),
			}
		}
		result.LayerResults["Layer1Finality"] = *layer1FinalityResult

		if !layer1FinalityResult.Valid {
			result.Valid = false
			result.ErrorMessage = "Layer 1C consensus finality verification failed: " + layer1FinalityResult.ErrorMessage
			result.TrustLevel = "No Trust"
			result.DurationNanos = time.Since(startTime).Nanoseconds()
			return result, nil
		}
	} else {
		result.LayerResults["Layer1Finality"] = LayerResult{
			LayerName:    "Layer1Finality",
			Valid:        false,
			ErrorMessage: "Layer 1C consensus finality not present",
		}
	}

	// Step 4: Verify Layer 2C - DN Consensus Finality (if present)
	if proof.Layer2Finality != nil {
		if cpv.debug {
			log.Printf("[PROOF VERIFIER] Step 4/5: Verifying Layer 2C DN consensus finality...")
		}

		layer2FinalityResult, err = cpv.VerifyLayer2Consensus(&proof.Layer2, proof.Layer2Finality)
		if err != nil {
			layer2FinalityResult = &LayerResult{
				LayerName:    "Layer2Finality",
				Valid:        false,
				ErrorMessage: err.Error(),
			}
		}
		result.LayerResults["Layer2Finality"] = *layer2FinalityResult

		if !layer2FinalityResult.Valid {
			result.Valid = false
			result.ErrorMessage = "Layer 2C DN consensus finality verification failed: " + layer2FinalityResult.ErrorMessage
			result.TrustLevel = "No Trust"
			result.DurationNanos = time.Since(startTime).Nanoseconds()
			return result, nil
		}

		// Update trust level based on consensus finality presence per spec section 8.5
		if proof.Layer1Finality != nil && layer1FinalityResult.Valid && layer2FinalityResult.Valid {
			result.TrustLevel = "Consensus Verified (Proof-Grade)"
		}
	} else {
		result.LayerResults["Layer2Finality"] = LayerResult{
			LayerName:    "Layer2Finality",
			Valid:        false,
			ErrorMessage: "Layer 2C DN consensus finality not present",
		}
	}

	// Step 5: Comprehensive receipt chain validation
	if cpv.debug {
		log.Printf("[PROOF VERIFIER] Step 5/5: Validating complete receipt chain...")
	}

	if err := cpv.receiptVerifier.ValidateReceiptChain(&proof.Layer1, &proof.Layer2); err != nil {
		result.Valid = false
		result.ErrorMessage = fmt.Sprintf("Receipt chain validation failed: %v", err)
		result.TrustLevel = "No Trust"
	}

	result.DurationNanos = time.Since(startTime).Nanoseconds()

	if cpv.debug {
		if result.Valid {
			log.Printf("[PROOF VERIFIER] ✅ Verification successful - Trust Level: %s (duration: %v)",
				result.TrustLevel, time.Duration(result.DurationNanos))
		} else {
			log.Printf("[PROOF VERIFIER] ❌ Verification failed: %s", result.ErrorMessage)
		}
	}

	return result, nil
}

// VerifyPartial verifies L1-L2 proof without requiring Layer 3
//
// This method is useful for validating partial proofs where consensus finality
// is not available or not required.
func (cpv *CertenProofVerifier) VerifyPartial(proof *AccumulateAnchoringProof) (*ProofVerificationResult, error) {
	if cpv.debug {
		log.Printf("[PROOF VERIFIER] Starting partial verification (L1-L2)")
	}

	startTime := time.Now()

	result := &ProofVerificationResult{
		Valid:        false,
		TrustLevel:   "No Trust",
		LayerResults: make(map[string]LayerResult),
		VerifiedAt:   startTime,
	}

	// Validate basic structure
	if proof == nil {
		result.ErrorMessage = "proof cannot be nil"
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// Verify Layer 1
	layer1Result, err := cpv.VerifyLayer1(&proof.Layer1)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Layer 1 verification error: %v", err)
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}
	result.LayerResults["Layer1"] = *layer1Result

	if !layer1Result.Valid {
		result.ErrorMessage = "Layer 1 verification failed: " + layer1Result.ErrorMessage
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// Verify Layer 2
	layer2Result, err := cpv.VerifyLayer2(&proof.Layer1, &proof.Layer2)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Layer 2 verification error: %v", err)
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}
	result.LayerResults["Layer2"] = *layer2Result

	if !layer2Result.Valid {
		result.ErrorMessage = "Layer 2 verification failed: " + layer2Result.ErrorMessage
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	// Validate receipt chain
	if err := cpv.receiptVerifier.ValidateReceiptChain(&proof.Layer1, &proof.Layer2); err != nil {
		result.ErrorMessage = fmt.Sprintf("Receipt chain validation failed: %v", err)
		result.DurationNanos = time.Since(startTime).Nanoseconds()
		return result, nil
	}

	result.Valid = true
	result.TrustLevel = "DN Anchored (Not Consensus-Bound)"
	result.DurationNanos = time.Since(startTime).Nanoseconds()

	if cpv.debug {
		log.Printf("[PROOF VERIFIER] ✅ Anchored-only verification successful - Trust Level: %s",
			result.TrustLevel)
	}

	return result, nil
}

// VerifyReceiptIntegrity verifies the integrity of all receipts in the proof
func (cpv *CertenProofVerifier) VerifyReceiptIntegrity(proof *AccumulateAnchoringProof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify Layer 1 receipt
	valid, err := cpv.receiptVerifier.ValidateIntegrity(&proof.Layer1.Receipt)
	if err != nil {
		return fmt.Errorf("Layer 1 receipt integrity check failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("Layer 1 receipt integrity validation failed")
	}

	// Verify Layer 2 receipt
	valid, err = cpv.receiptVerifier.ValidateIntegrity(&proof.Layer2.Receipt)
	if err != nil {
		return fmt.Errorf("Layer 2 receipt integrity check failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("Layer 2 receipt integrity validation failed")
	}

	return nil
}

// VerifyStitching verifies that receipts are properly stitched between layers
func (cpv *CertenProofVerifier) VerifyStitching(proof *AccumulateAnchoringProof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	valid, err := cpv.receiptVerifier.ValidateStitching(&proof.Layer1.Receipt, &proof.Layer2.Receipt)
	if err != nil {
		return fmt.Errorf("receipt stitching validation failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("receipt stitching validation failed")
	}

	return nil
}
