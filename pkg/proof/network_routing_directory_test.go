// Copyright 2026 Certen Protocol

package proof

import "testing"

// D2b and D2c (docs/proof/G1_CROSS_PARTITION.md): every account of the Directory's identity routes to the Directory - a book, its
// pages and a data account - because the verifier requires Partition == route(URL) for each proven page. The route function needs no
// change for the Directory; this pins the premise on the network's own routing table.
func TestEveryAccountOfTheDirectoryIdentityRoutesToTheDirectory(t *testing.T) {
	r := kermitRouter(t)
	for _, account := range []string{"acc://dn.acme/operators", "acc://dn.acme/operators/1", "acc://dn.acme/globals", "acc://dn.acme/pv2-data", "acc://dn.acme/anchors"} {
		if got, err := r.PartitionID(account); err != nil || got != "Directory" {
			t.Errorf("%s routed to (%q, %v); want Directory", account, got, err)
		}
	}
}
