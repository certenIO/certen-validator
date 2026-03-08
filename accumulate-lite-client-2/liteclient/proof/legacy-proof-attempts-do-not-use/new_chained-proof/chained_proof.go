// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package chained_proof provides the canonical CERTEN implementation
// for Accumulate anchoring proofs using v3 receipt stitching.
//
// This package implements the complete specification from:
// services\validator\docs\new_CERTEN_CHAINED_PROOF_SPEC.md
//
// USAGE EXAMPLES:
//
// 1. Building a complete L1-L3 proof:
//
//	builder, err := chained_proof.NewCertenProofBuilder(
//		"http://localhost:26660/v3",  // V3 API endpoint
//		"http://localhost:26657",     // CometBFT RPC endpoint
//		true,                         // debug mode
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	proof, err := builder.BuildComplete(
//		"acc://alice.acme/tokens",    // scope
//		"main",                       // chain name
//		205,                          // chain index
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Proof built: %s\n", proof.String())
//
// 2. Verifying a proof:
//
//	verifier := chained_proof.NewCertenProofVerifier(true)
//	result, err := verifier.VerifyComplete(proof)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Verification result: %s\n", result.String())
//
// 3. Building partial L1-L2 proof (when Layer 3 not needed):
//
//	proof, err := builder.BuildPartial(
//		"acc://alice.acme/tokens",
//		"main",
//		205,
//	)
//
// KEY SPECIFICATIONS IMPLEMENTED:
//
// - Layer 1: Entry Inclusion → Partition Anchor (from chainEntry receipts)
// - Layer 2: Partition Anchor → DN Anchor Root (via anchorSearch)
// - Layer 3: DN Anchor Root Consensus Finality (via CometBFT verification)
// - Receipt Stitching: Exact hash equality between layer outputs/inputs
// - Receipt Integrity: Merkle path verification for all receipts
// - Height Discipline: Partition-local height handling
//
// NORMATIVE RULES ENFORCED:
//
// 1. Layer 1 leaf selection MUST start from chain-entry receipts
// 2. Receipts are treated as edges: start → anchor @ localBlock
// 3. Stitching requires exact byte equality: L2.start == L1.anchor
// 4. Each receipt must verify internally via Merkle path
// 5. Heights are partition-local (BVN height != DN height)
// 6. Layer 3 binds (DN height, DN root) through consensus
package chained_proof

import (
	"fmt"
	"log"
)

// CERTEN specification version
const (
	SpecificationVersion = "v3-receipt-stitch-2"
	PackageVersion       = "1.0.0"
)

// NewProofSystem creates a complete CERTEN proof system with builder and verifier
//
// This is the main entry point for creating a complete proof system.
// It returns both builder and verifier configured with the same debug settings.
//
// cometEndpointMap: partition -> CometBFT RPC endpoint mapping (e.g., {"dn": "http://localhost:26657", "bvn-BVN1": "http://localhost:26757"})
func NewProofSystem(v3Endpoint string, cometEndpointMap map[string]string, debug bool) (*CertenProofBuilder, *CertenProofVerifier, error) {
	builder, err := NewCertenProofBuilder(v3Endpoint, cometEndpointMap, debug)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof builder: %w", err)
	}

	verifier := NewCertenProofVerifier(debug)

	if debug {
		log.Printf("[CERTEN] Proof system initialized - Spec: %s, Package: %s",
			SpecificationVersion, PackageVersion)
		log.Printf("[CERTEN] V3 Endpoint: %s", v3Endpoint)
		log.Printf("[CERTEN] CometBFT Endpoints: %v", cometEndpointMap)
	}

	return builder, verifier, nil
}

// NewProofSystemLegacy creates a proof system with legacy single CometBFT endpoint
// Deprecated: Use NewProofSystem with endpoint mapping per spec section 9.1
func NewProofSystemLegacy(v3Endpoint, cometEndpoint string, debug bool) (*CertenProofBuilder, *CertenProofVerifier, error) {
	// Create default mapping for DN partition
	endpointMap := map[string]string{
		"acc://dn.acme": cometEndpoint,
		"dn":            cometEndpoint,
	}
	return NewProofSystem(v3Endpoint, endpointMap, debug)
}

// BuildAndVerifyProof is a convenience method that builds and immediately verifies a proof
//
// This method is useful for one-shot proof generation and validation.
// It returns both the proof and verification result.
//
// cometEndpointMap: partition -> CometBFT RPC endpoint mapping
func BuildAndVerifyProof(v3Endpoint string, cometEndpointMap map[string]string, scope, chainName string, chainIndex uint64, debug bool) (*AccumulateAnchoringProof, *ProofVerificationResult, error) {
	builder, verifier, err := NewProofSystem(v3Endpoint, cometEndpointMap, debug)
	if err != nil {
		return nil, nil, err
	}

	// Build the proof
	proof, err := builder.BuildComplete(scope, chainName, chainIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("proof building failed: %w", err)
	}

	// Verify the proof
	result, err := verifier.VerifyComplete(proof)
	if err != nil {
		return proof, nil, fmt.Errorf("proof verification failed: %w", err)
	}

	return proof, result, nil
}

// BuildAndVerifyProofLegacy provides legacy interface with single CometBFT endpoint
// Deprecated: Use BuildAndVerifyProof with endpoint mapping
func BuildAndVerifyProofLegacy(v3Endpoint, cometEndpoint, scope, chainName string, chainIndex uint64, debug bool) (*AccumulateAnchoringProof, *ProofVerificationResult, error) {
	endpointMap := map[string]string{
		"acc://dn.acme": cometEndpoint,
		"dn":            cometEndpoint,
	}
	return BuildAndVerifyProof(v3Endpoint, endpointMap, scope, chainName, chainIndex, debug)
}

// ValidateSpecificationCompliance validates that a proof conforms to the CERTEN specification
//
// This method performs comprehensive validation of specification compliance:
// - Version compatibility
// - Structural requirements
// - Invariant enforcement
// - Data integrity
func ValidateSpecificationCompliance(proof *AccumulateAnchoringProof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Check version compatibility
	if proof.Version != SpecificationVersion {
		return fmt.Errorf("unsupported proof version: %s (expected: %s)",
			proof.Version, SpecificationVersion)
	}

	// Validate Layer 1 structure
	if err := validateLayer1Structure(&proof.Layer1); err != nil {
		return fmt.Errorf("Layer 1 structure validation failed: %w", err)
	}

	// Validate Layer 2 structure
	if err := validateLayer2Structure(&proof.Layer2); err != nil {
		return fmt.Errorf("Layer 2 structure validation failed: %w", err)
	}

	// Validate consensus finality structures (if present)
	if proof.Layer1Finality != nil {
		if err := validateConsensusFinality(proof.Layer1Finality, "Layer1Finality"); err != nil {
			return fmt.Errorf("Layer 1 consensus finality validation failed: %w", err)
		}
	}

	if proof.Layer2Finality != nil {
		if err := validateConsensusFinality(proof.Layer2Finality, "Layer2Finality"); err != nil {
			return fmt.Errorf("Layer 2 consensus finality validation failed: %w", err)
		}
	}

	// Validate stitching requirements
	verifier := NewReceiptVerifier(false)
	valid, err := verifier.ValidateStitching(&proof.Layer1.Receipt, &proof.Layer2.Receipt)
	if err != nil {
		return fmt.Errorf("stitching validation failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("stitching validation failed: L2.start != L1.anchor")
	}

	return nil
}

// validateLayer1Structure validates Layer 1 specification requirements
func validateLayer1Structure(layer1 *Layer1EntryInclusion) error {
	if layer1.SourcePartition == "" {
		return fmt.Errorf("sourcePartition cannot be empty per spec section 5.2")
	}

	if layer1.Scope == "" {
		return fmt.Errorf("scope cannot be empty")
	}

	if layer1.ChainName == "" {
		return fmt.Errorf("chainName cannot be empty")
	}

	if len(layer1.Leaf) == 0 {
		return fmt.Errorf("leaf cannot be empty")
	}

	if len(layer1.Anchor) == 0 {
		return fmt.Errorf("anchor cannot be empty")
	}

	if layer1.LocalBlock == 0 {
		return fmt.Errorf("localBlock cannot be zero")
	}

	return nil
}

// validateLayer2Structure validates Layer 2 specification requirements
func validateLayer2Structure(layer2 *Layer2AnchorToDN) error {
	if layer2.Scope != "acc://dn.acme/anchors" {
		return fmt.Errorf("invalid scope: expected 'acc://dn.acme/anchors', got '%s'", layer2.Scope)
	}

	if len(layer2.Start) == 0 {
		return fmt.Errorf("start cannot be empty")
	}

	if len(layer2.Anchor) == 0 {
		return fmt.Errorf("anchor cannot be empty")
	}

	if layer2.LocalBlock == 0 {
		return fmt.Errorf("localBlock cannot be zero")
	}

	return nil
}

// validateConsensusFinality validates consensus finality specification requirements per spec section 5.4
func validateConsensusFinality(finality *ConsensusFinality, context string) error {
	if finality.Partition == "" {
		return fmt.Errorf("%s: partition cannot be empty", context)
	}

	if finality.Network == "" {
		return fmt.Errorf("%s: network cannot be empty per spec section 5.4", context)
	}

	if finality.Height == 0 {
		return fmt.Errorf("%s: height cannot be zero", context)
	}

	if len(finality.Root) == 0 {
		return fmt.Errorf("%s: root cannot be empty", context)
	}

	if finality.Commit == nil {
		return fmt.Errorf("%s: commit cannot be nil", context)
	}

	if finality.Validators == nil {
		return fmt.Errorf("%s: validators cannot be nil", context)
	}

	// Validate proof-grade requirements per spec section 7.1
	if !finality.PowerOK {
		return fmt.Errorf("%s: PowerOK must be true for proof-grade mode", context)
	}

	if !finality.RootBindingOK {
		return fmt.Errorf("%s: RootBindingOK must be true for proof-grade mode", context)
	}

	return nil
}

// GetSpecificationInfo returns information about the implemented specification
func GetSpecificationInfo() map[string]string {
	return map[string]string{
		"specification": "CERTEN Chained Proof Specification",
		"version":       SpecificationVersion,
		"package":       PackageVersion,
		"document":      "services\\validator\\docs\\new_CERTEN_CHAINED_PROOF_SPEC.md",
		"layers":        "1-3 (Entry → Partition → DN → Consensus)",
		"method":        "v3 receipt stitching with exact hash equality",
		"trust_levels":  "Partition Trust, DN Anchored, Consensus Verified",
	}
}
