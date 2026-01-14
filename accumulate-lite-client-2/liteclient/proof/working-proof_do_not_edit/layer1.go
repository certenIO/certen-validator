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

// Layer1Builder implements L1: account chainEntry inclusion -> BVN rootChainAnchor witness.
type Layer1Builder struct {
	Client   *jsonrpc.Client
	Debug    bool
	Artifacts map[string][]byte // optional (may be nil)
}

func NewLayer1Builder(client *jsonrpc.Client, debug bool) *Layer1Builder {
	return &Layer1Builder{Client: client, Debug: debug}
}

// Build constructs Layer1 per spec 2.1.
//
// Query (normative):
// - scope = <account>
// - queryType=chain, name=main, entry=<txHash>, includeReceipt=true
//
// Outputs:
// - leaf = txHash
// - bvnMinorBlockIndex = receipt.localBlock
// - bvnRootChainAnchor = receipt.anchor
func (b *Layer1Builder) Build(ctx context.Context, account string, txHashHex string) (Layer1, error) {
	if b.Client == nil {
		return Layer1{}, fmt.Errorf("layer1: missing v3 client")
	}

	txHashHex, err := MustHex32Lower(txHashHex, "txHash")
	if err != nil {
		return Layer1{}, err
	}
	leafBytes, _ := hex.DecodeString(txHashHex)

	scopeURL, err := acc_url.Parse(account)
	if err != nil {
		return Layer1{}, fmt.Errorf("layer1: invalid account URL %q: %w", account, err)
	}

	// Chain query by entry (fail-closed uniqueness enforced in extraction).
	q := &v3.ChainQuery{
		Name: "main",
		Entry: leafBytes,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	}

	resp, err := b.Client.Query(ctx, scopeURL, q)
	if err != nil {
		return Layer1{}, fmt.Errorf("layer1: query chainEntry failed: %w", err)
	}

	if b.Artifacts != nil {
		if raw, mErr := json.Marshal(resp); mErr == nil {
			b.Artifacts["L1_chain_main_by_entry.json"] = raw
		}
	}

	ce, err := pickExactlyOneChainEntry(resp, "main", txHashHex)
	if err != nil {
		return Layer1{}, fmt.Errorf("layer1: %w", err)
	}

	if ce.Receipt == nil {
		return Layer1{}, fmt.Errorf("layer1: missing receipt (includeReceipt required)")
	}
	if ce.Receipt.LocalBlock == 0 {
		return Layer1{}, fmt.Errorf("layer1: missing receipt.localBlock (required for consensus binding)")
	}

	// Fail-closed receipt invariants
	startHex := fmt.Sprintf("%x", ce.Receipt.Start)
	startHex = lowerHex(startHex)
	if startHex != txHashHex {
		return Layer1{}, fmt.Errorf("layer1: receipt.start mismatch: got=%s expect=%s", startHex, txHashHex)
	}

	anchorHex := lowerHex(fmt.Sprintf("%x", ce.Receipt.Anchor))
	anchorHex, err = MustHex32Lower(anchorHex, "layer1 receipt.anchor (BVN rootChainAnchor)")
	if err != nil {
		return Layer1{}, err
	}

	r := Receipt{
		Start:      txHashHex,
		Anchor:     anchorHex,
		LocalBlock: ce.Receipt.LocalBlock,
		Entries:    make([]ReceiptStep, 0, len(ce.Receipt.Entries)),
	}
	for i, e := range ce.Receipt.Entries {
		h := lowerHex(fmt.Sprintf("%x", e.Hash))
		h, err := MustHex32Lower(h, fmt.Sprintf("layer1 receipt.entries[%d].hash", i))
		if err != nil {
			return Layer1{}, err
		}
		r.Entries = append(r.Entries, ReceiptStep{Hash: h, Right: e.Right})
	}

	// Receipt integrity MUST be verifiable
	if err := NewReceiptVerifier(b.Debug).ValidateIntegrity(r); err != nil {
		return Layer1{}, fmt.Errorf("layer1: receipt integrity verification failed: %w", err)
	}

	out := Layer1{
		TxChainIndex:       ce.Index,
		BVNMinorBlockIndex: ce.Receipt.LocalBlock,
		BVNRootChainAnchor: anchorHex,
		Leaf:               txHashHex,
		Receipt:            r,
	}
	return out, nil
}

// pickExactlyOneChainEntry enforces the spec rule:
// - entry query MUST return exactly one matching chainEntry.
func pickExactlyOneChainEntry(resp any, expectName string, expectEntryHex string) (*v3.ChainEntryRecord[v3.Record], error) {
	var hits []*v3.ChainEntryRecord[v3.Record]

	switch v := resp.(type) {
	case *v3.ChainEntryRecord[v3.Record]:
		hits = append(hits, v)
	case *v3.RecordRange[v3.Record]:
		for _, r := range v.Records {
			ce, ok := r.(*v3.ChainEntryRecord[v3.Record])
			if !ok {
				continue
			}
			hits = append(hits, ce)
		}
	default:
		return nil, fmt.Errorf("unexpected v3 response type %T", resp)
	}

	// Filter by expected chain name + entry (fail-closed uniqueness)
	var filtered []*v3.ChainEntryRecord[v3.Record]
	for _, ce := range hits {
		if expectName != "" && ce.Name != expectName {
			continue
		}
		// ce.Entry is [32]byte in v3; compare hex
		got := lowerHex(fmt.Sprintf("%x", ce.Entry[:]))
		if expectEntryHex != "" && got != lowerHex(expectEntryHex) {
			continue
		}
		filtered = append(filtered, ce)
	}

	if len(filtered) != 1 {
		return nil, fmt.Errorf("expected exactly 1 chainEntry (name=%s entry=%s), got %d", expectName, expectEntryHex, len(filtered))
	}
	return filtered[0], nil
}