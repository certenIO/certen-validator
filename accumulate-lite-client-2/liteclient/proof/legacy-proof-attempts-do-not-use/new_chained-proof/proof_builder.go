// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"
	"log"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// CertenProofBuilder implements the complete CERTEN chained proof construction
// following the canonical specification v3-receipt-stitch-2.
//
// This is the main orchestrator that coordinates Layer 1, Layer 2, and consensus
// finality builders to create complete AccumulateAnchoringProof objects.
type CertenProofBuilder struct {
	layer1Builder    *Layer1Builder
	layer2Builder    *Layer2Builder
	consensusBuilder *ConsensusBuilder
	verifier         *ReceiptVerifier
	debug            bool
	proofMode        string // "proof-grade" or "anchored-only"
}

// NewCertenProofBuilder creates a new CERTEN proof builder with all required components
// cometEndpointMap: partition -> CometBFT RPC endpoint mapping (e.g., {"dn": "http://localhost:26657", "bvn-BVN1": "http://localhost:26757"})
func NewCertenProofBuilder(v3Endpoint string, cometEndpointMap map[string]string, debug bool) (*CertenProofBuilder, error) {
	// Create V3 API client
	v3Client := jsonrpc.NewClient(v3Endpoint)

	// Create consensus builder with partition mapping per spec section 9.1
	consensusBuilder := NewConsensusBuilder(cometEndpointMap, debug)

	return &CertenProofBuilder{
		layer1Builder:    NewLayer1Builder(v3Client, debug),
		layer2Builder:    NewLayer2Builder(v3Client, debug),
		consensusBuilder: consensusBuilder,
		verifier:         NewReceiptVerifier(debug),
		debug:            debug,
		proofMode:        "proof-grade", // Default to proof-grade mode per spec section 7.1
	}, nil
}

// NewCertenProofBuilderLegacy creates a proof builder with legacy single CometBFT endpoint
// Deprecated: Use NewCertenProofBuilder with endpoint mapping
func NewCertenProofBuilderLegacy(v3Endpoint, cometEndpoint string, debug bool) (*CertenProofBuilder, error) {
	// Create default mapping for DN partition
	endpointMap := map[string]string{
		"acc://dn.acme": cometEndpoint,
		"dn":            cometEndpoint,
	}
	return NewCertenProofBuilder(v3Endpoint, endpointMap, debug)
}

// SetProofMode sets the proof construction mode per spec section 7
func (cpb *CertenProofBuilder) SetProofMode(mode string) error {
	if mode != "proof-grade" && mode != "anchored-only" {
		return fmt.Errorf("invalid proof mode: %s (must be 'proof-grade' or 'anchored-only')", mode)
	}
	cpb.proofMode = mode
	return nil
}

// BuildLayer1 constructs Layer 1 proof from chain entry
func (cpb *CertenProofBuilder) BuildLayer1(scope, chainName string, chainIndex uint64) (*Layer1EntryInclusion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return cpb.layer1Builder.BuildFromChainEntry(ctx, scope, chainName, chainIndex)
}

// BuildLayer2 constructs Layer 2 proof by searching DN anchors
func (cpb *CertenProofBuilder) BuildLayer2(layer1 *Layer1EntryInclusion) (*Layer2AnchorToDN, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try primary method first
	layer2, err := cpb.layer2Builder.BuildFromLayer1(ctx, layer1)
	if err != nil {
		if cpb.debug {
			log.Printf("[PROOF BUILDER] Layer 2 primary method failed: %v, trying fallback", err)
		}
		// Try fallback strategies
		return cpb.layer2Builder.BuildWithFallback(ctx, layer1)
	}

	return layer2, nil
}

// BuildLayer1Consensus constructs Layer 1C consensus finality per spec section 2.3
func (cpb *CertenProofBuilder) BuildLayer1Consensus(layer1 *Layer1EntryInclusion) (*ConsensusFinality, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return cpb.consensusBuilder.BuildConsensusFinality(ctx, layer1.SourcePartition, layer1.LocalBlock, layer1.Anchor)
}

// BuildLayer2Consensus constructs Layer 2C DN consensus finality per spec section 2.5
func (cpb *CertenProofBuilder) BuildLayer2Consensus(layer2 *Layer2AnchorToDN) (*ConsensusFinality, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return cpb.consensusBuilder.BuildConsensusFinality(ctx, "acc://dn.acme", layer2.LocalBlock, layer2.Anchor)
}

// BuildLayer3 provides legacy interface (deprecated)
func (cpb *CertenProofBuilder) BuildLayer3(layer2 *Layer2AnchorToDN) (*ConsensusFinality, error) {
	return cpb.BuildLayer2Consensus(layer2)
}

// BuildComplete constructs complete L1-L3 proof following the canonical algorithm
//
// This method implements the deterministic construction algorithm from the spec:
// 1. Build Layer 1 from chain-entry receipt
// 2. Build Layer 2 through DN anchor search with stitching validation
// 3. Build Layer 3 through consensus finality verification
// 4. Validate the complete proof chain
func (cpb *CertenProofBuilder) BuildComplete(scope, chainName string, chainIndex uint64) (*AccumulateAnchoringProof, error) {
	if cpb.debug {
		log.Printf("[PROOF BUILDER] Building complete proof for %s/%s[%d]", scope, chainName, chainIndex)
	}

	startTime := time.Now()

	// Step 1: Build Layer 1 - Entry Inclusion → Partition Anchor
	if cpb.debug {
		log.Printf("[PROOF BUILDER] Step 1/3: Building Layer 1 proof...")
	}

	layer1, err := cpb.BuildLayer1(scope, chainName, chainIndex)
	if err != nil {
		return nil, fmt.Errorf("Layer 1 construction failed: %w", err)
	}

	if cpb.debug {
		log.Printf("[PROOF BUILDER] Layer 1 complete: leaf=%x, anchor=%x",
			layer1.Leaf[:8], layer1.Anchor[:8])
	}

	// Step 2: Build Layer 2 - Partition Anchor → DN Anchor Root
	if cpb.debug {
		log.Printf("[PROOF BUILDER] Step 2/3: Building Layer 2 proof...")
	}

	layer2, err := cpb.BuildLayer2(layer1)
	if err != nil {
		return nil, fmt.Errorf("Layer 2 construction failed: %w", err)
	}

	if cpb.debug {
		log.Printf("[PROOF BUILDER] Layer 2 complete: start=%x, anchor=%x, DN height=%d",
			layer2.Start[:8], layer2.Anchor[:8], layer2.LocalBlock)
	}

	// Validate receipt chain before proceeding to Layer 3
	if err := cpb.verifier.ValidateReceiptChain(layer1, layer2); err != nil {
		return nil, fmt.Errorf("receipt chain validation failed: %w", err)
	}

	// Step 3: Build consensus finality proofs per spec sections 2.3 & 2.5
	var layer1Finality, layer2Finality *ConsensusFinality

	if cpb.proofMode == "proof-grade" {
		if cpb.debug {
			log.Printf("[PROOF BUILDER] Step 3/4: Building Layer 1C consensus finality...")
		}

		layer1Finality, err = cpb.BuildLayer1Consensus(layer1)
		if err != nil {
			return nil, fmt.Errorf("Layer 1C consensus finality failed: %w", err)
		}

		if cpb.debug {
			log.Printf("[PROOF BUILDER] Step 4/4: Building Layer 2C DN consensus finality...")
		}

		layer2Finality, err = cpb.BuildLayer2Consensus(layer2)
		if err != nil {
			return nil, fmt.Errorf("Layer 2C DN consensus finality failed: %w", err)
		}

		if cpb.debug {
			log.Printf("[PROOF BUILDER] Consensus finality complete: L1C(height=%d, powerOK=%t) L2C(height=%d, powerOK=%t)",
				layer1Finality.Height, layer1Finality.PowerOK, layer2Finality.Height, layer2Finality.PowerOK)
		}
	} else {
		if cpb.debug {
			log.Printf("[PROOF BUILDER] Skipping consensus finality (anchored-only mode)")
		}
	}

	// Construct complete proof per spec section 5.5
	proof := &AccumulateAnchoringProof{
		Version:        "v3-receipt-stitch-2",
		Timestamp:      startTime,
		Layer1:         *layer1,
		Layer1Finality: layer1Finality,
		Layer2:         *layer2,
		Layer2Finality: layer2Finality,
	}

	duration := time.Since(startTime)
	if cpb.debug {
		trustLevel := "DN Anchored (Not Consensus-Bound)"
		if layer1Finality != nil && layer2Finality != nil {
			trustLevel = "Consensus Verified (Proof-Grade)"
		}
		log.Printf("[PROOF BUILDER] ✅ Complete proof built in %v - Trust Level: %s",
			duration, trustLevel)
	}

	return proof, nil
}

// BuildPartial constructs a partial proof (L1-L2 only) when Layer 3 is not required
//
// This is useful for cases where consensus finality is not needed or not available.
func (cpb *CertenProofBuilder) BuildPartial(scope, chainName string, chainIndex uint64) (*AccumulateAnchoringProof, error) {
	if cpb.debug {
		log.Printf("[PROOF BUILDER] Building partial proof (L1-L2) for %s/%s[%d]", scope, chainName, chainIndex)
	}

	startTime := time.Now()

	// Build Layer 1
	layer1, err := cpb.BuildLayer1(scope, chainName, chainIndex)
	if err != nil {
		return nil, fmt.Errorf("Layer 1 construction failed: %w", err)
	}

	// Build Layer 2
	layer2, err := cpb.BuildLayer2(layer1)
	if err != nil {
		return nil, fmt.Errorf("Layer 2 construction failed: %w", err)
	}

	// Validate receipt chain
	if err := cpb.verifier.ValidateReceiptChain(layer1, layer2); err != nil {
		return nil, fmt.Errorf("receipt chain validation failed: %w", err)
	}

	proof := &AccumulateAnchoringProof{
		Version:        "v3-receipt-stitch-2",
		Timestamp:      startTime,
		Layer1:         *layer1,
		Layer1Finality: nil, // Explicitly nil for anchored-only proof
		Layer2:         *layer2,
		Layer2Finality: nil, // Explicitly nil for anchored-only proof
	}

	if cpb.debug {
		log.Printf("[PROOF BUILDER] ✅ Anchored-only proof built - Trust Level: DN Anchored (Not Consensus-Bound)")
	}

	return proof, nil
}

// ValidateProofChain validates an existing proof's receipt chain integrity
func (cpb *CertenProofBuilder) ValidateProofChain(proof *AccumulateAnchoringProof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	return cpb.verifier.ValidateReceiptChain(&proof.Layer1, &proof.Layer2)
}
