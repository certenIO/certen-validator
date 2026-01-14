// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/rpc/client/http"
)

// ProofVerifier verifies proof objects (fail-closed), optionally re-checking consensus binds.
type ProofVerifier struct {
	CometDN  *http.HTTP
	CometBVN *http.HTTP
	Debug    bool
}

func NewProofVerifier(cometDN *http.HTTP, cometBVN *http.HTTP, debug bool) *ProofVerifier {
	return &ProofVerifier{CometDN: cometDN, CometBVN: cometBVN, Debug: debug}
}

// Verify enforces all normative invariants from the spec.
//
// Proof-grade behavior (default):
// - validates receipt integrity for all receipts
// - validates pairing + ordering invariants
// - validates consensus binds (requires comet clients)
func (pv *ProofVerifier) Verify(ctx context.Context, p *ChainedProof) error {
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

	// Consensus binds (proof-grade)
	if pv.CometBVN == nil || pv.CometDN == nil {
		return fmt.Errorf("proof-grade verification requires comet clients (BVN+DN); missing one or both")
	}

	// BVN bind at BVN_MBI+1 to BVN stateTreeAnchor
	if err := bindConsensusAppHash(ctx, pv.CometBVN, p.Layer1.BVNMinorBlockIndex+1, p.Layer2.BVNStateTreeAnchor, "BVN"); err != nil {
		return err
	}

	// DN bind at DN_MBI+1 to DN stateTreeAnchor (DN_MBI from L2)
	if err := bindConsensusAppHash(ctx, pv.CometDN, p.Layer2.DNMinorBlockIndex+1, p.Layer3.DNStateTreeAnchor, "DN"); err != nil {
		return err
	}

	return nil
}