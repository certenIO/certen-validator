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
	if err := p.Layer4DN.VerifyOffline(); err != nil {
		return fmt.Errorf("L4 DN leg invalid: %w", err)
	}

	// EVERY partition leg, not just the principal's.
	//
	// A proof whose signers span two BVNs carries a leg for each, and a verifier
	// that checked only the first would accept a proof whose second leg is
	// forged, absent or grafted from another proof. The principal's leg goes
	// through the SAME function as the others: two code paths for "the first
	// one" and "the rest" is how the first one ends up with a check the rest do
	// not have.
	legs := p.Legs()
	seenPartition := map[string]bool{}
	for i, leg := range legs {
		if err := verifyLegBinding(leg); err != nil {
			return fmt.Errorf("partition leg %d of %d: %w", i+1, len(legs), err)
		}
		key := strings.ToLower(leg.Partition)
		if seenPartition[key] {
			return fmt.Errorf("two legs claim partition %s; a proof carries at most one leg "+
				"per partition, and two would be counted twice by anything walking them",
				leg.Partition)
		}
		seenPartition[key] = true

		// Each leg's receipts must recompute, exactly as the principal's do.
		if err := rv.ValidateIntegrity(leg.Layer1.Receipt); err != nil {
			return fmt.Errorf("partition %s: L1 receipt invalid: %w", leg.Partition, err)
		}
		if err := rv.ValidateIntegrity(leg.Layer2.RootReceipt); err != nil {
			return fmt.Errorf("partition %s: L2 root receipt invalid: %w", leg.Partition, err)
		}
		if err := rv.ValidateIntegrity(leg.Layer2.BptReceipt); err != nil {
			return fmt.Errorf("partition %s: L2 bpt receipt invalid: %w", leg.Partition, err)
		}
		if leg.Layer2.RootReceipt.Anchor != leg.Layer2.BptReceipt.Anchor {
			return fmt.Errorf("partition %s: L2 pairing invariant failed: root.anchor != bpt.anchor",
				leg.Partition)
		}
		if leg.Layer1.BVNMinorBlockIndex != leg.Layer1.Receipt.LocalBlock {
			return fmt.Errorf("partition %s: L1 invariant failed: bvnMinorBlockIndex != receipt.localBlock",
				leg.Partition)
		}
		if lowerHex(leg.Layer1.BVNRootChainAnchor) != lowerHex(leg.Layer1.Receipt.Anchor) {
			return fmt.Errorf("partition %s: L1 invariant failed: bvnRootChainAnchor != receipt.anchor",
				leg.Partition)
		}

		// Every leg must reach the SAME Directory state, or the proof is several
		// unrelated claims stapled together.
		//
		// L3 proves one DN root chain anchor into one DN state tree. A leg whose
		// DN anchor is that same root reaches it directly - which is the case for
		// every single-partition proof, and for any two partitions whose anchors
		// landed in the same DN block.
		//
		// A leg anchored at an EARLIER DN block does not reach it directly. Its
		// DN root is a real ancestor of the proof's DN root on the DN root chain,
		// so a receipt from one to the other exists and would complete the
		// chain - but this proof does not carry one, and a missing link is not a
		// link. Refusing with the reason named is the only honest option: the
		// alternative is accepting a leg whose path to the proven Directory state
		// is asserted rather than shown.
		if !strings.EqualFold(leg.Layer2.DNRootChainAnchor, p.Layer2.DNRootChainAnchor) {
			if leg.Layer2.DNMinorBlockIndex > p.Layer2.DNMinorBlockIndex {
				return fmt.Errorf("partition %s anchors into DN block %d, LATER than the DN "+
					"block %d this proof's L3 proves - a leg cannot be anchored after the "+
					"Directory state that is supposed to contain it",
					leg.Partition, leg.Layer2.DNMinorBlockIndex, p.Layer2.DNMinorBlockIndex)
			}
			return fmt.Errorf("partition %s anchors into DN block %d and witnesses DN root %s, "+
				"while this proof's L3 proves DN root %s at block %d. The earlier root is an "+
				"ancestor of the later one on the DN root chain, so a receipt binding them "+
				"exists - but this proof does not carry it, and this leg's path to the proven "+
				"Directory state is therefore asserted rather than shown",
				leg.Partition, leg.Layer2.DNMinorBlockIndex, leg.Layer2.DNRootChainAnchor,
				p.Layer2.DNRootChainAnchor, p.Layer2.DNMinorBlockIndex)
		}
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
