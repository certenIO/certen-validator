// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"
	"strings"
)

// ProofVerifier verifies proof objects, fail-closed.
//
// Verification is entirely offline. It previously hard-failed without live
// CometBFT clients ("proof-grade verification requires comet clients"), which
// contradicted the governance spec's requirement that a proof be verifiable
// offline. L4 now carries its own evidence, so no network access is needed and
// none is performed.
type ProofVerifier struct {
	Debug bool
}

func NewProofVerifier(debug bool) *ProofVerifier {
	return &ProofVerifier{Debug: debug}
}

// Verify enforces all normative invariants from the spec.
//
// Proof-grade behavior (default):
//   - validates receipt integrity for all receipts (merkle recomputation)
//   - validates pairing + ordering invariants
//   - validates both L4 legs: signatures, validator membership, quorum
//   - validates that each L4 leg binds the layer beneath it
//
// The ctx parameter is retained for signature compatibility with callers; no
// network call is made.
func (pv *ProofVerifier) Verify(ctx context.Context, p *ChainedProof) error {
	_ = ctx
	if p == nil {
		return fmt.Errorf("proof: nil")
	}

	// Basic hex validation
	if _, err := MustHex32Lower(p.Input.TxHash, "input.txHash"); err != nil {
		return err
	}
	if _, err := MustHex32Lower(p.Layer1.Leaf, "layer1.leaf"); err != nil {
		return err
	}
	if p.Layer1.Leaf != lowerHex(p.Input.TxHash) {
		return fmt.Errorf("layer1.leaf must equal input.txHash")
	}

	// 4.1 Receipt integrity
	rv := NewReceiptVerifier(pv.Debug)

	if err := rv.ValidateIntegrity(p.Layer1.Receipt); err != nil {
		return fmt.Errorf("L1 receipt invalid: %w", err)
	}
	if err := rv.ValidateIntegrity(p.Layer2.RootReceipt); err != nil {
		return fmt.Errorf("L2 root receipt invalid: %w", err)
	}
	if err := rv.ValidateIntegrity(p.Layer2.BptReceipt); err != nil {
		return fmt.Errorf("L2 bpt receipt invalid: %w", err)
	}
	if err := rv.ValidateIntegrity(p.Layer3.RootReceipt); err != nil {
		return fmt.Errorf("L3 root receipt invalid: %w", err)
	}
	if err := rv.ValidateIntegrity(p.Layer3.BptReceipt); err != nil {
		return fmt.Errorf("L3 bpt receipt invalid: %w", err)
	}

	// 2.1 L1 invariants
	if lowerHex(p.Layer1.Receipt.Start) != lowerHex(p.Layer1.Leaf) {
		return fmt.Errorf("L1 invariant failed: receipt.start != leaf")
	}
	if p.Layer1.BVNMinorBlockIndex != p.Layer1.Receipt.LocalBlock {
		return fmt.Errorf("L1 invariant failed: bvnMinorBlockIndex != receipt.localBlock")
	}
	if lowerHex(p.Layer1.BVNRootChainAnchor) != lowerHex(p.Layer1.Receipt.Anchor) {
		return fmt.Errorf("L1 invariant failed: bvnRootChainAnchor != receipt.anchor")
	}

	// 2.2 pairing invariants for anchor(<bvn>) pair
	if p.Layer2.RootReceipt.Anchor != p.Layer2.BptReceipt.Anchor {
		return fmt.Errorf("L2 pairing invariant failed: root.receipt.anchor != bpt.receipt.anchor")
	}
	if p.Layer2.RootReceipt.LocalBlock != p.Layer2.BptReceipt.LocalBlock {
		return fmt.Errorf("L2 pairing invariant failed: root.receipt.localBlock != bpt.receipt.localBlock")
	}

	// 2.4 DN-self pairing invariants
	if p.Layer3.RootReceipt.Anchor != p.Layer3.BptReceipt.Anchor {
		return fmt.Errorf("L3 DN-self pairing invariant failed: root.receipt.anchor != bpt.receipt.anchor")
	}
	if p.Layer3.RootReceipt.LocalBlock != p.Layer3.BptReceipt.LocalBlock {
		return fmt.Errorf("L3 DN-self pairing invariant failed: root.receipt.localBlock != bpt.receipt.localBlock")
	}

	// 3 ordering invariant
	if p.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex < p.Layer2.DNMinorBlockIndex {
		return fmt.Errorf("ordering invariant failed: DN_FINAL_MBI < DN_MBI")
	}

	// 2.5 / 3 semantics
	if p.Layer3.DNAnchorMinorBlockIndex != p.Layer2.DNMinorBlockIndex {
		return fmt.Errorf("semantic invariant failed: layer3.dnAnchorMinorBlockIndex must equal layer2.dnMinorBlockIndex")
	}
	if p.Layer3.DNConsensusHeight != p.Layer2.DNMinorBlockIndex+1 {
		return fmt.Errorf("semantic invariant failed: dnConsensusHeight must equal DN_MBI+1")
	}

	// L4 - both legs required. A missing leg is a failure, never a pass.
	if p.Layer4BVN == nil {
		return fmt.Errorf("L4 BVN leg missing: a proof without a signed BVN anchor is not proof-grade")
	}
	if p.Layer4DN == nil {
		return fmt.Errorf("L4 DN leg missing: a proof without a signed DN anchor is not proof-grade")
	}
	if err := p.Layer4BVN.VerifyOffline(); err != nil {
		return fmt.Errorf("L4 BVN leg invalid: %w", err)
	}
	if err := p.Layer4DN.VerifyOffline(); err != nil {
		return fmt.Errorf("L4 DN leg invalid: %w", err)
	}

	// L4 must bind the layer beneath it, or it proves something unrelated.
	if !strings.EqualFold(p.Layer4BVN.StateTreeAnchor, p.Layer2.BVNStateTreeAnchor) {
		return fmt.Errorf("L4 BVN bind failed: layer4Bvn.stateTreeAnchor=%s != layer2.bvnStateTreeAnchor=%s",
			p.Layer4BVN.StateTreeAnchor, p.Layer2.BVNStateTreeAnchor)
	}
	if !strings.EqualFold(p.Layer4BVN.RootChainAnchor, p.Layer1.BVNRootChainAnchor) {
		return fmt.Errorf("L4 BVN bind failed: layer4Bvn.rootChainAnchor=%s != layer1.bvnRootChainAnchor=%s",
			p.Layer4BVN.RootChainAnchor, p.Layer1.BVNRootChainAnchor)
	}
	if p.Layer4BVN.MinorBlockIndex != p.Layer1.BVNMinorBlockIndex {
		return fmt.Errorf("L4 BVN bind failed: layer4Bvn.minorBlockIndex=%d != layer1.bvnMinorBlockIndex=%d",
			p.Layer4BVN.MinorBlockIndex, p.Layer1.BVNMinorBlockIndex)
	}

	if !strings.EqualFold(p.Layer4DN.StateTreeAnchor, p.Layer3.DNStateTreeAnchor) {
		return fmt.Errorf("L4 DN bind failed: layer4Dn.stateTreeAnchor=%s != layer3.dnStateTreeAnchor=%s",
			p.Layer4DN.StateTreeAnchor, p.Layer3.DNStateTreeAnchor)
	}
	if !strings.EqualFold(p.Layer4DN.RootChainAnchor, p.Layer2.DNRootChainAnchor) {
		return fmt.Errorf("L4 DN bind failed: layer4Dn.rootChainAnchor=%s != layer2.dnRootChainAnchor=%s",
			p.Layer4DN.RootChainAnchor, p.Layer2.DNRootChainAnchor)
	}
	if p.Layer4DN.MinorBlockIndex != p.Layer2.DNMinorBlockIndex {
		return fmt.Errorf("L4 DN bind failed: layer4Dn.minorBlockIndex=%d != layer2.dnMinorBlockIndex=%d",
			p.Layer4DN.MinorBlockIndex, p.Layer2.DNMinorBlockIndex)
	}

	// The two legs must be signed by DIFFERENT partitions. If both legs came
	// from the same signing set, one leg is redundant and the end-to-end bind
	// is severed.
	if p.Layer4DN.Partition != "Directory" {
		return fmt.Errorf("L4 DN leg is signed by %q, expected Directory", p.Layer4DN.Partition)
	}
	if strings.EqualFold(p.Layer4BVN.Partition, "Directory") {
		return fmt.Errorf("L4 BVN leg is signed by Directory, expected a block validator partition")
	}

	return nil
}
