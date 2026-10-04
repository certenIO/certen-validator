//go:build live

// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB5-F57 part 2, on Kermit (public reads only). Intent 0d316ec4 (cross-chain intent 55d23cb0) was written in BVN1 block
// 13430413 and discovered in Directory block 10252405, which anchored it two seconds later. Every path that states the
// member's commit time - discovery (admission), ResolveCommitTime (both lanes, peers) and the backfill - gives the
// BVN block's time; the Directory block's time, which the on-demand resolver used to read, is another number.
//
//	CERTEN_LIVE_ACCUMULATE_URL=https://kermit.accumulatenetwork.io go test -tags live -run TestLiveOneCommitTime ./pkg/execution/
func TestLiveOneCommitTimeOnEveryPath(t *testing.T) {
	accURL := os.Getenv("CERTEN_LIVE_ACCUMULATE_URL")
	if accURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_ACCUMULATE_URL")
	}
	const (
		tx        = "0d316ec4e96d24e3ac39771fdf94071fe17e3e334df21e2b02edbbca405c8e09"
		principal = "acc://rb4-phase-c-09282125.acme/data"
		dnHeight  = int64(10252405)
	)
	adapter, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{NetworkURL: accURL, RequestTimeout: 60 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Discovery, as admission sees the intent.
	txs, err := adapter.SearchCertenTransactions(ctx, dnHeight)
	if err != nil {
		t.Fatal(err)
	}
	var found *accumulate.CertenTransaction
	for _, c := range txs {
		if strings.EqualFold(strings.TrimPrefix(c.Hash, "0x"), tx) {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("Directory block %d does not carry %s", dnHeight, tx)
	}
	admitted := found.Timestamp.UTC()
	partition := accumulate.BVNPartitionURL(found.ProofPartition)
	t.Logf("discovery: Directory block %d (%s), commit block %d on %s at %s", found.BlockHeight, found.Partition,
		found.ProofBlockIndex, partition, admitted.Format(time.RFC3339))

	// ResolveCommitTime, as both lanes and every peer read a missing one.
	resolved, err := ResolveCommitTime(ctx, adapter.MinorBlockTime, partition, uint64(found.ProofBlockIndex))
	if err != nil {
		t.Fatal(err)
	}
	// The backfill, from the chain entry's receipt.
	_, backfilled, err := AccumulateIntentSource{Adapter: adapter, URL: accURL}.SignedIntent(ctx, tx, principal)
	if err != nil {
		t.Fatal(err)
	}
	// What the on-demand resolver used to read: the Directory block.
	directory, err := adapter.MinorBlockTime(ctx, found.Partition, uint64(found.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("admission %s, ResolveCommitTime %s, backfill %s; the Directory block %s", admitted.Format(time.RFC3339),
		resolved.Format(time.RFC3339), backfilled.UTC().Format(time.RFC3339), directory.UTC().Format(time.RFC3339))
	if !resolved.Equal(admitted) || !backfilled.Equal(admitted) {
		t.Fatalf("one member, several commit times: admission %s, ResolveCommitTime %s, backfill %s", admitted, resolved, backfilled)
	}
	if directory.Equal(admitted) {
		t.Fatalf("the Directory block's time equals the commit block's here; the evidence needs a block that differs")
	}
}
