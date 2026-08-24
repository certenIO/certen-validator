// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const defaultV3Endpoint = "https://kermit.accumulatenetwork.io/v3"

// Fixture anchor from L4_DESIGN.md §4 / the runbook's known-good vector.
const (
	fixAnchorAccount = "acc://bvn-BVN1.acme/anchors"
	fixAnchorIndex   = uint64(169156)
	fixAnchorSigned  = "e6dd1988102e29aa5206cc1c5fcb0f3ff5b4cac0b4580928029d03ed93035572"
	fixAnchorTxn     = "353c84c71a7081b343dcb7e2b8a42433ee44c63b91ef924a574c934b7f056e9d"
	fixStateTree     = "e59fe47dc1e7ce6a73080f823a05fc9502b007f5d1f04845ad9518f949ca7395"
	fixMinorBlock    = uint64(7671708)
)

func liveClient(t *testing.T) *jsonrpc.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = defaultV3Endpoint
	}
	return jsonrpc.NewClient(ep)
}

// Phase 1.1 — includeReceipt is silently ignored on Range queries.
//
// This documents a live API bug. If Accumulate ever fixes it, this test fails
// and the L4 builder can be simplified. Until then, every receipt-bearing
// query in the proof tree MUST use Index or Entry, never Range.
func TestPhase1_IncludeReceiptIgnoredOnRangeQueries(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	scope, err := acc_url.Parse(fixAnchorAccount)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("range yields no receipt", func(t *testing.T) {
		count := uint64(2)
		q := &v3.ChainQuery{
			Name:           "main",
			Range:          &v3.RangeOptions{Start: fixAnchorIndex, Count: &count},
			IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
		}
		resp, err := c.Query(ctx, scope, q)
		if err != nil {
			t.Fatalf("range query: %v", err)
		}
		rng, ok := resp.(*v3.RecordRange[v3.Record])
		if !ok {
			t.Fatalf("expected RecordRange, got %T", resp)
		}
		if len(rng.Records) == 0 {
			t.Fatal("range returned no records")
		}
		for i, rec := range rng.Records {
			ce, ok := rec.(*v3.ChainEntryRecord[v3.Record])
			if !ok {
				t.Fatalf("record %d: expected ChainEntryRecord, got %T", i, rec)
			}
			if ce.Receipt != nil {
				t.Fatalf("record %d: range query returned a receipt — the silent-ignore bug is FIXED upstream; "+
					"revisit the Index/Entry-only rule", i)
			}
		}
	})

	t.Run("index yields a receipt", func(t *testing.T) {
		idx := fixAnchorIndex
		q := &v3.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &v3.ReceiptOptions{ForAny: true}}
		resp, err := c.Query(ctx, scope, q)
		if err != nil {
			t.Fatalf("index query: %v", err)
		}
		ce, ok := resp.(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			t.Fatalf("expected ChainEntryRecord, got %T", resp)
		}
		if ce.Receipt == nil {
			t.Fatal("index query returned no receipt")
		}
		if len(ce.Receipt.Entries) == 0 {
			t.Fatal("index query receipt has zero entries")
		}
	})
}

// Phase 1 (added) — the hash an anchor's validator signatures cover is the
// hash of the SequencedMessage wrapping the transaction, NOT the transaction's
// own hash.
//
// L4_DESIGN.md §3.3 names the field "anchorTxHash", which reads as the
// transaction hash. It is not. Getting this wrong yields a correct-looking
// digest that never verifies. This test pins the distinction.
func TestPhase1_AnchorSignedHashIsSequencedMessage(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	scope, err := acc_url.Parse(fixAnchorAccount)
	if err != nil {
		t.Fatal(err)
	}

	idx := fixAnchorIndex
	q := &v3.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &v3.ReceiptOptions{ForAny: true}}
	resp, err := c.Query(ctx, scope, q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	ce := resp.(*v3.ChainEntryRecord[v3.Record])
	mr, ok := ce.Value.(*v3.MessageRecord[messaging.Message])
	if !ok {
		t.Fatalf("expected MessageRecord, got %T", ce.Value)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok {
		t.Fatalf("expected TransactionMessage, got %T", mr.Message)
	}

	txnHash := tm.Transaction.Hash()
	if got := hex.EncodeToString(txnHash[:]); got != fixAnchorTxn {
		t.Fatalf("transaction hash drift: got %s want %s", got, fixAnchorTxn)
	}
	if hex.EncodeToString(txnHash[:]) == fixAnchorSigned {
		t.Fatal("transaction hash equals the signed hash — the sequenced-message distinction has collapsed")
	}

	if mr.Sequence == nil {
		t.Fatal("anchor message carries no sequence info")
	}
	seq := *mr.Sequence
	seq.Message = &messaging.TransactionMessage{Transaction: tm.Transaction}
	seqHash := seq.Hash()
	if got := hex.EncodeToString(seqHash[:]); got != fixAnchorSigned {
		t.Fatalf("sequenced-message hash drift: got %s want %s", got, fixAnchorSigned)
	}

	da, ok := tm.Transaction.Body.(*protocol.DirectoryAnchor)
	if !ok {
		t.Fatalf("expected DirectoryAnchor body, got %T", tm.Transaction.Body)
	}
	if got := hex.EncodeToString(da.StateTreeAnchor[:]); got != fixStateTree {
		t.Fatalf("stateTreeAnchor drift: got %s want %s", got, fixStateTree)
	}
	if da.MinorBlockIndex != fixMinorBlock {
		t.Fatalf("minorBlockIndex drift: got %d want %d", da.MinorBlockIndex, fixMinorBlock)
	}
}
