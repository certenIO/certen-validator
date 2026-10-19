//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2). Read-only against the public Kermit node.

package proofv2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// D5 against the real network: acc://dn.acme/routing is read as of a recent certified Directory block, cut at the state tree root
// that block's DirectoryAnchor carries, verified offline, and routes the live accounts as the network does.
func TestLiveRoutingProofAtACertifiedDirectoryBlock(t *testing.T) {
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	// A recent DirectoryAnchor of the Directory's own anchor sequence: its block and the state tree root it certifies.
	pool := protocol.DnUrl().JoinPath(protocol.AnchorPool)
	r, err := c.Query(ctx, pool, &api.ChainQuery{Name: "anchor-sequence"})
	if err != nil {
		t.Fatal(err)
	}
	cr, ok := r.(*api.ChainRecord)
	if !ok || cr.Count < 6 {
		t.Fatalf("anchor-sequence: %T", r)
	}
	earliest, latest, err := (&ClientRetention{C: c}).Retained(ctx, protocol.Directory)
	if err != nil {
		t.Fatal(err)
	}
	var body *protocol.DirectoryAnchor
	for i := cr.Count - 1; i+12 > cr.Count && body == nil; i-- {
		idx := i
		er, err := c.Query(ctx, pool, &api.ChainQuery{Name: "anchor-sequence", Index: &idx})
		if err != nil {
			t.Fatal(err)
		}
		tm := er.(*api.ChainEntryRecord[api.Record]).Value.(*api.MessageRecord[messaging.Message]).Message.(*messaging.TransactionMessage)
		if b, ok := tm.Transaction.Body.(*protocol.DirectoryAnchor); ok && b.MinorBlockIndex >= earliest && b.MinorBlockIndex+2 <= latest {
			body = b
		}
	}
	if body == nil {
		t.Fatalf("no Directory anchor inside the retained range [%d, %d] among the newest of %d", earliest, latest, cr.Count)
	}
	built, err := proof.BuildRoutingProofAt(ctx, proof.NewHTTPQuerier(endpoint), body.MinorBlockIndex, body.StateTreeAnchor)
	if err != nil {
		t.Fatal(err)
	}
	table, height, err := proof.VerifyRoutingProof(built, hex.EncodeToString(body.StateTreeAnchor[:]))
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("PV2_WRITE_ROUTING_VECTOR"); path != "" {
		vec, _ := json.MarshalIndent(map[string]any{"format": "certen-routing-vector/1", "endpoint": endpoint, "capturedAt": time.Now().UTC().Format(time.RFC3339),
			"dnBlock": body.MinorBlockIndex, "stateRoot": hex.EncodeToString(body.StateTreeAnchor[:]), "proof": built}, "", " ")
		if err := os.WriteFile(path, append(vec, 0x0a), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("routing table proven into DN block %d state root %x: main chain height %d, %d routes, %d overrides", body.MinorBlockIndex, body.StateTreeAnchor, height, len(table.Routes), len(table.Overrides))
	if height != 1 {
		t.Fatalf("Kermit's routing table has been rewritten: main chain height %d", height)
	}
	for account, want := range map[string]string{"acc://pv2-cust-5.acme/data": "BVN1", "acc://pv2-bank-5.acme/book": "BVN2", "acc://pv2-dele-5.acme/book": "BVN3", "acc://dn.acme": "Directory"} {
		if got, err := proof.RoutePartition(table, account); err != nil || got != want {
			t.Errorf("%s routed to (%q, %v), want %s", account, got, err, want)
		}
	}
}
