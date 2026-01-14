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

// Layer3Builder implements L3 using DN self anchor chains as an index oracle.
type Layer3Builder struct {
	Client    *jsonrpc.Client
	Debug     bool
	Artifacts map[string][]byte // optional
}

func NewLayer3Builder(client *jsonrpc.Client, debug bool) *Layer3Builder {
	return &Layer3Builder{Client: client, Debug: debug}
}

// Build constructs Layer3 per spec 2.4 + 2.5.
//
// Steps (normative):
// - L3.0: query anchor(directory)-root by entry=dnRootChainAnchor -> dnRootChainIndex, DN_FINAL_MBI
//         require DN_FINAL_MBI >= DN_MBI
// - L3.0b: query anchor(directory)-bpt[index=dnRootChainIndex] -> dnStateTreeAnchor
//          enforce pairing invariants against L3.0 receipts
//
// Consensus binding is NOT performed here (it is done by ProofBuilder using DN_MBI+1).
func (b *Layer3Builder) Build(ctx context.Context, l2 Layer2) (Layer3, error) {
	if b.Client == nil {
		return Layer3{}, fmt.Errorf("layer3: missing v3 client")
	}

	dnAnchors, _ := acc_url.Parse("acc://dn.acme/anchors")

	// L3.0: anchor(directory)-root by entry = dnRootChainAnchor
	rootChain := "anchor(directory)-root"
	dnRootHex, err := MustHex32Lower(l2.DNRootChainAnchor, "layer3 input l2.DNRootChainAnchor")
	if err != nil {
		return Layer3{}, err
	}
	dnRootBytes, _ := hex.DecodeString(dnRootHex)

	qRoot := &v3.ChainQuery{
		Name: rootChain,
		Entry: dnRootBytes,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	}
	respRoot, err := b.Client.Query(ctx, dnAnchors, qRoot)
	if err != nil {
		return Layer3{}, fmt.Errorf("layer3: query %s by entry failed: %w", rootChain, err)
	}
	if b.Artifacts != nil {
		if raw, mErr := json.Marshal(respRoot); mErr == nil {
			b.Artifacts["L3_dn_self_root_by_entry.json"] = raw
		}
	}

	ceRoot, err := pickExactlyOneChainEntry(respRoot, rootChain, dnRootHex)
	if err != nil {
		return Layer3{}, fmt.Errorf("layer3: %w", err)
	}
	if ceRoot.Receipt == nil || ceRoot.Receipt.LocalBlock == 0 {
		return Layer3{}, fmt.Errorf("layer3: %s missing receipt/localBlock", rootChain)
	}

	dnRootIndex := ceRoot.Index
	dnFinalMBI := ceRoot.Receipt.LocalBlock

	// Ordering invariant: DN_FINAL_MBI >= DN_MBI
	if dnFinalMBI < l2.DNMinorBlockIndex {
		return Layer3{}, fmt.Errorf("layer3: ordering invariant failed: DN_FINAL_MBI=%d < DN_MBI=%d", dnFinalMBI, l2.DNMinorBlockIndex)
	}

	rootReceipt := Receipt{
		Start:      lowerHex(fmt.Sprintf("%x", ceRoot.Receipt.Start)),
		Anchor:     lowerHex(fmt.Sprintf("%x", ceRoot.Receipt.Anchor)),
		LocalBlock: dnFinalMBI,
		Entries:    make([]ReceiptStep, 0, len(ceRoot.Receipt.Entries)),
	}
	rootReceipt.Start, err = MustHex32Lower(rootReceipt.Start, "layer3 root receipt.start")
	if err != nil {
		return Layer3{}, err
	}
	rootReceipt.Anchor, err = MustHex32Lower(rootReceipt.Anchor, "layer3 root receipt.anchor")
	if err != nil {
		return Layer3{}, err
	}
	for i, e := range ceRoot.Receipt.Entries {
		h := lowerHex(fmt.Sprintf("%x", e.Hash))
		h, err := MustHex32Lower(h, fmt.Sprintf("layer3 root receipt.entries[%d].hash", i))
		if err != nil {
			return Layer3{}, err
		}
		rootReceipt.Entries = append(rootReceipt.Entries, ReceiptStep{Hash: h, Right: e.Right})
	}
	if err := NewReceiptVerifier(b.Debug).ValidateIntegrity(rootReceipt); err != nil {
		return Layer3{}, fmt.Errorf("layer3: root receipt integrity failed: %w", err)
	}

	// L3.0b: anchor(directory)-bpt[index=dnRootIndex] -> DN stateTreeAnchor
	bptChain := "anchor(directory)-bpt"
	qBpt := &v3.ChainQuery{
		Name: bptChain,
		Index: &dnRootIndex,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	}
	respBpt, err := b.Client.Query(ctx, dnAnchors, qBpt)
	if err != nil {
		return Layer3{}, fmt.Errorf("layer3: query %s[%d] failed: %w", bptChain, dnRootIndex, err)
	}
	if b.Artifacts != nil {
		if raw, mErr := json.Marshal(respBpt); mErr == nil {
			b.Artifacts["L3_dn_self_bpt_by_index.json"] = raw
		}
	}

	ceBpt, ok := respBpt.(*v3.ChainEntryRecord[v3.Record])
	if !ok {
		ceBpt, err = pickExactlyOneChainEntry(respBpt, bptChain, "")
		if err != nil {
			return Layer3{}, fmt.Errorf("layer3: %w", err)
		}
	}
	if ceBpt.Receipt == nil || ceBpt.Receipt.LocalBlock == 0 {
		return Layer3{}, fmt.Errorf("layer3: %s missing receipt/localBlock", bptChain)
	}
	if ceBpt.Index != dnRootIndex {
		return Layer3{}, fmt.Errorf("layer3: %s returned wrong index: got=%d expect=%d", bptChain, ceBpt.Index, dnRootIndex)
	}

	dnStateTreeAnchorHex := lowerHex(fmt.Sprintf("%x", ceBpt.Entry[:]))
	dnStateTreeAnchorHex, err = MustHex32Lower(dnStateTreeAnchorHex, "layer3 dnStateTreeAnchor")
	if err != nil {
		return Layer3{}, err
	}

	bptReceipt := Receipt{
		Start:      lowerHex(fmt.Sprintf("%x", ceBpt.Receipt.Start)),
		Anchor:     lowerHex(fmt.Sprintf("%x", ceBpt.Receipt.Anchor)),
		LocalBlock: ceBpt.Receipt.LocalBlock,
		Entries:    make([]ReceiptStep, 0, len(ceBpt.Receipt.Entries)),
	}
	bptReceipt.Start, err = MustHex32Lower(bptReceipt.Start, "layer3 bpt receipt.start")
	if err != nil {
		return Layer3{}, err
	}
	bptReceipt.Anchor, err = MustHex32Lower(bptReceipt.Anchor, "layer3 bpt receipt.anchor")
	if err != nil {
		return Layer3{}, err
	}
	for i, e := range ceBpt.Receipt.Entries {
		h := lowerHex(fmt.Sprintf("%x", e.Hash))
		h, err := MustHex32Lower(h, fmt.Sprintf("layer3 bpt receipt.entries[%d].hash", i))
		if err != nil {
			return Layer3{}, err
		}
		bptReceipt.Entries = append(bptReceipt.Entries, ReceiptStep{Hash: h, Right: e.Right})
	}
	if err := NewReceiptVerifier(b.Debug).ValidateIntegrity(bptReceipt); err != nil {
		return Layer3{}, fmt.Errorf("layer3: bpt receipt integrity failed: %w", err)
	}

	// DN-self pairing invariants (fail-closed)
	if rootReceipt.LocalBlock != bptReceipt.LocalBlock {
		return Layer3{}, fmt.Errorf("layer3: DN-self pairing invariant failed: root.receipt.localBlock != bpt.receipt.localBlock")
	}
	if rootReceipt.Anchor != bptReceipt.Anchor {
		return Layer3{}, fmt.Errorf("layer3: DN-self pairing invariant failed: root.receipt.anchor != bpt.receipt.anchor")
	}

	// Critical semantics:
	// DN consensus binds at DN_MBI+1 (DN_MBI is l2.DNMinorBlockIndex), not at DN_FINAL_MBI+1.
	dnConsensusHeight := l2.DNMinorBlockIndex + 1

	return Layer3{
		DNRootChainIndex:                     dnRootIndex,
		DNAnchorMinorBlockIndex:              l2.DNMinorBlockIndex,
		DNConsensusHeight:                    dnConsensusHeight,
		DNSelfAnchorRecordedAtMinorBlockIndex: dnFinalMBI,
		DNStateTreeAnchor:                    dnStateTreeAnchorHex,
		RootReceipt:                          rootReceipt,
		BptReceipt:                           bptReceipt,
	}, nil
}