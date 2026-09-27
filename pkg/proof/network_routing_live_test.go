//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2).

package proof

import (
	"context"
	"testing"
)

// RB3-F107: the router is built from the table Kermit publishes, and routes as the proof does.
func TestLiveTheNetworksRoutingTable(t *testing.T) {
	r, err := LoadNetworkRouter(context.Background(), "https://kermit.accumulatenetwork.io/v3")
	if err != nil {
		t.Fatal(err)
	}
	for account, want := range map[string]string{
		"acc://certen-seq-1790497115.acme/data": "bvn1",
		"acc://dn.acme":                         "directory",
	} {
		if got, err := r.Partition(account); err != nil || got != want {
			t.Errorf("%s: (%q, %v), want %q", account, got, err, want)
		}
	}
}
