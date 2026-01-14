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
		Name: rootChain,
		Entry: rootEntry,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
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
		Name: bptChain,
		Index: &dnIndex,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
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
		DNIndex:           dnIndex,
		DNMinorBlockIndex: dnMBI,
		DNRootChainAnchor: dnRootChainAnchorHex,
		BVNStateTreeAnchor: bvnStateTreeAnchorHex,
		RootReceipt:       rootReceipt,
		BptReceipt:        bptReceipt,
	}, nil
}