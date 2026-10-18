//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2). Read-only against the public Kermit node.

package proofv2

import (
	"context"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The Directory's own anchors on the real network: the anchor(directory)-root chain of the anchor pool and the Directory's anchor
// sequence agree entry for entry, a block is selected from them like any partition's, and the DirectoryAnchor the Directory executed
// for it is found in the pool's main chain with a receipt that validates - the D2b anchor of evidence 2.1, decoded and kind-checked.
func TestLiveDirectoryAnchorIsSelectedAndExecutedByTheDirectory(t *testing.T) {
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	log := NetLog{Net: c}
	n, err := log.Len(ctx, protocol.Directory)
	if err != nil || n < 10 {
		t.Fatalf("the Directory's anchor(directory)-root chain: %d entries, %v", n, err)
	}
	dn, err := log.DNBlock(ctx, protocol.Directory, n-5)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := SelectPartitionBlock(ctx, log, protocol.Directory, dn, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pb.Txn.Body.(*protocol.DirectoryAnchor); !ok || pb.Index != n-5 {
		t.Fatalf("selected anchor %d (%T) for the limit of anchor %d", pb.Index, pb.Txn.Body, n-5)
	}
	t.Logf("Directory block %d anchored at DN %d (anchor %d of %d)", pb.Block, pb.DNBlock, pb.Index, n)
	pa, h, err := AnchorAt(ctx, c, pb, 0)
	if err != nil {
		t.Fatalf("the Directory's own anchor for block %d: %v", pb.Block, err)
	}
	a, err := decodeAnchor21(pa.Message)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.partition()
	if err != nil || id != protocol.Directory || string(a.tx) != string(h[:]) {
		t.Fatalf("decoded %q (%v), anchor transaction %x vs %x", id, err, a.tx, h)
	}
	r, err := decodeReceipt(pa.Receipt)
	if err != nil || string(r.Start) != string(h[:]) || !r.Validate(nil) {
		t.Fatalf("the receipt does not prove the anchor transaction: %v", err)
	}
}
