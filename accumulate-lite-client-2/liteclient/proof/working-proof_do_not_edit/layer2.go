// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Layer2Builder implements L2 using DN partition-labeled anchor chains (index-oracle).
type Layer2Builder struct {
	Client    *jsonrpc.Client
	Debug     bool
	Artifacts map[string][]byte // optional

	// ReceiptForRootChainHeight asks for a receipt terminating at a SPECIFIC
	// height of the Directory minor root chain, instead of wherever Accumulate
	// would anchor it.
	//
	// WHY A CROSS-PARTITION PROOF NEEDS THIS, AND WHAT IS STILL MISSING.
	//
	// Two partitions' anchors are recorded in different DN blocks, so two
	// receipts taken "for any" anchor terminate at different DN roots - and L3
	// proves exactly one of them. Observed live on Kermit for corpus case F: the
	// principal's leg anchored at DN block 7769803, the delegated signer's at
	// 7769799. ProofVerifier refuses that pair, correctly, because the second
	// leg's path to the proven Directory state is asserted rather than shown.
	//
	// ReceiptOptions.ForHeight is the lever, and its name misleads. It is a
	// height ON THE DN MINOR ROOT CHAIN, not a block height:
	//
	//   ForHeight = a block number   -> "unable to locate index entry ...
	//                                    reached the end of the chain"
	//   ForHeight < entry's anchor   -> "cannot satisfy target height N: entry
	//                                    is anchored at height M"
	//   ForHeight = M                -> the same receipt ForAny returns
	//   ForHeight > M                -> a receipt at a LATER DN root
	//
	// All four verified against Kermit: entry anchored at height 1447063 gave DN
	// block 7769799; height 1447070 gave block 7769801. So the extension itself
	// works, and a leg CAN be bound forward to a later Directory root.
	//
	// What is missing is the mapping. Binding a leg to a chosen DN root needs
	// that root's own height on the minor root chain, and a DN root is the
	// chain's ANCHOR rather than an entry on it - querying dn.acme, dn.acme/
	// anchors and dn.acme/ledger for it by value returns "ElementIndex ... not
	// found" on every root, minor-root and anchor-sequence chain. Until there is
	// a way to ask for that height, this field is set by a caller that already
	// knows it and is left zero otherwise, and a multi-partition proof whose legs
	// land in different DN blocks is REFUSED at verification with the reason
	// named. Refusing is the honest answer: the alternative is a leg whose path
	// to the proven Directory state nobody checked.
	//
	// Zero means "for any", which is the single-partition behaviour and is
	// unchanged.
	ReceiptForRootChainHeight uint64
}

// receiptOptions asks for a receipt at the pinned root-chain height when one is
// set, and otherwise for any.
func (b *Layer2Builder) receiptOptions() *v3.ReceiptOptions {
	if b.ReceiptForRootChainHeight > 0 {
		return &v3.ReceiptOptions{ForHeight: b.ReceiptForRootChainHeight}
	}
	return &v3.ReceiptOptions{ForAny: true}
}

func NewLayer2Builder(client *jsonrpc.Client, debug bool) *Layer2Builder {
	return &Layer2Builder{Client: client, Debug: debug}
}

// Build constructs Layer2 per spec 2.2.
//
// Steps (normative):
// - L2.0: query dn.acme/anchors chain anchor(<bvn>)-root by entry=bvnRootChainAnchor -> dnIndex, DN_MBI, dnRootChainAnchor
// - L2.1: query anchor(<bvn>)-bpt[index=dnIndex] -> bvnStateTreeAnchor
// - enforce pairing invariants:
//   - root.receipt.anchor == bpt.receipt.anchor
//   - root.receipt.localBlock == bpt.receipt.localBlock
func (b *Layer2Builder) Build(ctx context.Context, bvn string, l1 Layer1) (Layer2, error) {
	if b.Client == nil {
		return Layer2{}, fmt.Errorf("layer2: missing v3 client")
	}
	if bvn == "" {
		return Layer2{}, fmt.Errorf("layer2: missing BVN label (e.g. bvn1)")
	}

	dnAnchors, _ := acc_url.Parse("acc://dn.acme/anchors")

	// L2.0: anchor(<bvn>)-root by entry
	rootChain := fmt.Sprintf("anchor(%s)-root", bvn)
	rootEntryHex, err := MustHex32Lower(l1.BVNRootChainAnchor, "layer2 input l1.BVNRootChainAnchor")
	if err != nil {
		return Layer2{}, err
	}
	rootEntry, _ := hex.DecodeString(rootEntryHex)

	qRoot := &v3.ChainQuery{
		Name:           rootChain,
		Entry:          rootEntry,
		IncludeReceipt: b.receiptOptions(),
	}
	respRoot, err := b.Client.Query(ctx, dnAnchors, qRoot)
	if err != nil {
		return Layer2{}, fmt.Errorf("layer2: query %s by entry failed: %w", rootChain, err)
	}
	if b.Artifacts != nil {
		if raw, mErr := json.Marshal(respRoot); mErr == nil {
			b.Artifacts["L2_dn_anchor_root_by_entry.json"] = raw
		}
	}

	ceRoot, err := pickExactlyOneChainEntry(respRoot, rootChain, rootEntryHex)
	if err != nil {
		return Layer2{}, fmt.Errorf("layer2: %w", err)
	}

	if ceRoot.Receipt == nil || ceRoot.Receipt.LocalBlock == 0 {
		return Layer2{}, fmt.Errorf("layer2: %s missing receipt/localBlock", rootChain)
	}

	// Invariant: receipt.start == bvnRootChainAnchor
	startHex := lowerHex(fmt.Sprintf("%x", ceRoot.Receipt.Start))
	if startHex != rootEntryHex {
		return Layer2{}, fmt.Errorf("layer2: %s receipt.start mismatch: got=%s expect=%s", rootChain, startHex, rootEntryHex)
	}

	dnRootChainAnchorHex := lowerHex(fmt.Sprintf("%x", ceRoot.Receipt.Anchor))
	dnRootChainAnchorHex, err = MustHex32Lower(dnRootChainAnchorHex, "layer2 dnRootChainAnchor")
	if err != nil {
		return Layer2{}, err
	}
	dnMBI := ceRoot.Receipt.LocalBlock
	dnIndex := ceRoot.Index

	rootReceipt := Receipt{
		Start:      rootEntryHex,
		Anchor:     dnRootChainAnchorHex,
		LocalBlock: dnMBI,
		Entries:    make([]ReceiptStep, 0, len(ceRoot.Receipt.Entries)),
	}
	for i, e := range ceRoot.Receipt.Entries {
		h := lowerHex(fmt.Sprintf("%x", e.Hash))
		h, err := MustHex32Lower(h, fmt.Sprintf("layer2 root receipt.entries[%d].hash", i))
		if err != nil {
			return Layer2{}, err
		}
		rootReceipt.Entries = append(rootReceipt.Entries, ReceiptStep{Hash: h, Right: e.Right})
	}
	if err := NewReceiptVerifier(b.Debug).ValidateIntegrity(rootReceipt); err != nil {
		return Layer2{}, fmt.Errorf("layer2: root receipt integrity failed: %w", err)
	}

	// L2.1: anchor(<bvn>)-bpt[index=dnIndex]
	bptChain := fmt.Sprintf("anchor(%s)-bpt", bvn)
	qBpt := &v3.ChainQuery{
		Name:           bptChain,
		Index:          &dnIndex,
		IncludeReceipt: b.receiptOptions(),
	}
	respBpt, err := b.Client.Query(ctx, dnAnchors, qBpt)
	if err != nil {
		return Layer2{}, fmt.Errorf("layer2: query %s[%d] failed: %w", bptChain, dnIndex, err)
	}
	if b.Artifacts != nil {
		if raw, mErr := json.Marshal(respBpt); mErr == nil {
			b.Artifacts["L2_dn_anchor_bpt_by_index.json"] = raw
		}
	}

	// By index query typically returns a single chainEntry record
	ceBpt, ok := respBpt.(*v3.ChainEntryRecord[v3.Record])
	if !ok {
		// tolerate RecordRange but fail-closed if ambiguous
		ceBpt, err = pickExactlyOneChainEntry(respBpt, bptChain, "")
		if err != nil {
			return Layer2{}, fmt.Errorf("layer2: %w", err)
		}
	}
	if ceBpt.Receipt == nil || ceBpt.Receipt.LocalBlock == 0 {
		return Layer2{}, fmt.Errorf("layer2: %s missing receipt/localBlock", bptChain)
	}
	if ceBpt.Index != dnIndex {
		return Layer2{}, fmt.Errorf("layer2: %s returned wrong index: got=%d expect=%d", bptChain, ceBpt.Index, dnIndex)
	}

	bvnStateTreeAnchorHex := lowerHex(fmt.Sprintf("%x", ceBpt.Entry[:]))
	bvnStateTreeAnchorHex, err = MustHex32Lower(bvnStateTreeAnchorHex, "layer2 bvnStateTreeAnchor")
	if err != nil {
		return Layer2{}, err
	}

	bptReceipt := Receipt{
		Start:      lowerHex(fmt.Sprintf("%x", ceBpt.Receipt.Start)),
		Anchor:     lowerHex(fmt.Sprintf("%x", ceBpt.Receipt.Anchor)),
		LocalBlock: ceBpt.Receipt.LocalBlock,
		Entries:    make([]ReceiptStep, 0, len(ceBpt.Receipt.Entries)),
	}
	bptReceipt.Start, err = MustHex32Lower(bptReceipt.Start, "layer2 bpt receipt.start")
	if err != nil {
		return Layer2{}, err
	}
	bptReceipt.Anchor, err = MustHex32Lower(bptReceipt.Anchor, "layer2 bpt receipt.anchor")
	if err != nil {
		return Layer2{}, err
	}
	for i, e := range ceBpt.Receipt.Entries {
		h := lowerHex(fmt.Sprintf("%x", e.Hash))
		h, err := MustHex32Lower(h, fmt.Sprintf("layer2 bpt receipt.entries[%d].hash", i))
		if err != nil {
			return Layer2{}, err
		}
		bptReceipt.Entries = append(bptReceipt.Entries, ReceiptStep{Hash: h, Right: e.Right})
	}
	if err := NewReceiptVerifier(b.Debug).ValidateIntegrity(bptReceipt); err != nil {
		return Layer2{}, fmt.Errorf("layer2: bpt receipt integrity failed: %w", err)
	}

	// Pairing invariants (fail-closed)
	if rootReceipt.Anchor != bptReceipt.Anchor {
		return Layer2{}, fmt.Errorf("layer2: pairing invariant failed: root.receipt.anchor != bpt.receipt.anchor")
	}
	if rootReceipt.LocalBlock != bptReceipt.LocalBlock {
		return Layer2{}, fmt.Errorf("layer2: pairing invariant failed: root.receipt.localBlock != bpt.receipt.localBlock")
	}

	return Layer2{
		DNIndex:            dnIndex,
		DNMinorBlockIndex:  dnMBI,
		DNRootChainAnchor:  dnRootChainAnchorHex,
		BVNStateTreeAnchor: bvnStateTreeAnchorHex,
		RootReceipt:        rootReceipt,
		BptReceipt:         bptReceipt,
	}, nil
}
