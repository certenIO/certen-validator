// Copyright 2026 Certen Protocol

package ethl1

// VerifyBootstrapAnchor judges a block_root ledger entry by its bootstrap alone: it runs exactly the kind-2 anchor of spec 5.2 step 2
// (the same code VerifyFinalizedHead runs for an evidence whose anchor is the bootstrap of a pinned block root) and stops before
// any link. It establishes that
//   - the bootstrap parses in the stated layout and its header's slot lies in a fork of that layout,
//   - the header's slot is in sync-committee period `period`,
//   - the header's execution branch holds,
//   - hash_tree_root(bootstrap.header.beacon) is the block_root the pins carry for `period`, and
//   - the current-committee branch holds against the header's state_root and the committee hashes to the pinned committee_root.
//
// The pins must carry an anchor for `period` with a block_root. It returns nil, or the *Fault the walk would have returned
// (finality_pin_unknown, finality_pin_mismatch, finality_bootstrap_invalid, finality_fork_unsupported, finality_evidence_malformed).
// The ledger uses it for the root pin of a re-derived ledger, where no link is walked and the anchor would otherwise go unjudged.
func VerifyBootstrapAnchor(p Pins, period uint64, bootstrap LB) error {
	if err := CheckNetwork(p, SepoliaChainID); err != nil {
		return err
	}
	a, ok := p.anchorFor(period)
	if !ok || a.BlockRoot == nil {
		return PinUnknown(2, period, [32]byte{})
	}
	w := newWalker(p, specRules{}, mainnetPreset())
	bo, f := w.parseBootstrap(bootstrap)
	if f != nil {
		return f
	}
	if f := w.checkForkOfSlot(bo.Header.Beacon.Slot, bo.Shape); f != nil {
		return f
	}
	lc := LC{AnchorKind: 2, AnchorPeriod: period, AnchorRoot: *a.BlockRoot}
	if f := w.anchorStore(lc, &bo, nil); f != nil {
		return f
	}
	return nil
}
