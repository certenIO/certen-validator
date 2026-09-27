// Copyright 2026 Certen Protocol

package proof

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB3-F107: partitions are named with the network's routing table and Accumulate's routing rule. The
// table written into this module ignored the network's overrides and could not follow a change to it.
func TestPartitionsAreRoutedWithTheNetworksTable(t *testing.T) {
	r := kermitRouter(t)
	for account, want := range map[string]string{
		"acc://dn.acme":                         "directory", // an override on the network
		"acc://ACME":                            "directory",
		"acc://bvn-BVN2.acme":                   "bvn2",
		"acc://certen-seq-1790497115.acme/data": "bvn1", // intent 47b7e925's account; its proof is on bvn1
	} {
		got, err := r.Partition(account)
		if err != nil || got != want {
			t.Errorf("%s routed to (%q, %v); want %q", account, got, err, want)
		}
	}
	if old := CalculateBVNFromAccountURL("acc://dn.acme"); old == "directory" {
		t.Log("the module's own table now agrees on the Directory override")
	} else {
		t.Logf("the module's own table sends acc://dn.acme to %q - the defect this router replaces", old)
	}
}

func TestARoutingTableThatIsNotAPartitionIsRefused(t *testing.T) {
	overlap := &protocol.RoutingTable{Routes: []protocol.Route{
		{Length: 1, Value: 0, Partition: "BVN1"},
		{Length: 2, Value: 0, Partition: "BVN2"}, // overlaps BVN1's half
		{Length: 1, Value: 1, Partition: "BVN3"},
	}}
	r, err := NewNetworkRouter(overlap)
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for _, a := range []string{"acc://a.acme", "acc://b.acme", "acc://c.acme", "acc://d.acme", "acc://e.acme"} {
		if _, err := r.Partition(a); err != nil {
			refused = true
		}
	}
	if !refused {
		t.Fatal("an overlapping table routed every account without complaint")
	}
	if _, err := NewNetworkRouter(&protocol.RoutingTable{}); err == nil {
		t.Fatal("an empty table was accepted")
	}
}

// A timing basis that does not decode is an error; it used to read as "no timing evidence".
func TestATimingBasisThatDoesNotDecodeIsAnError(t *testing.T) {
	if tb, err := TimingBasisFromRaw("G1", json.RawMessage(`{"timingBasis":"not a list"}`), kermitRouter(t)); err == nil {
		t.Fatalf("an undecodable timing basis read as %v", tb)
	}
	if _, err := TimingBasisFromRaw("G1", json.RawMessage(p8CrossPartitionG1), nil); err == nil {
		t.Fatal("records were named without a router")
	}
}

// Nothing outside tests routes with the module's own table.
func TestNothingRoutesWithTheModulesOwnTable(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() && (d.Name() == "accumulate-lite-client-2" || strings.HasPrefix(d.Name(), ".")) {
			if d != nil && d.IsDir() && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		src := string(raw)
		for _, call := range []string{"CalculateBVNFromAccountURL(", "calculateBVNFromAccountURL(", "routeByPrefixTable("} {
			if n := strings.Count(src, call) - strings.Count(src, "func "+call) - strings.Count(src, "func (g *LiteClientProofGenerator) "+call); n > 0 &&
				!(strings.HasSuffix(filepath.ToSlash(p), "pkg/proof/liteclient_adapter.go") && call != "CalculateBVNFromAccountURL(") {
				offenders = append(offenders, p+": "+call)
			}
		}
		return nil
	})
	if len(offenders) > 0 {
		t.Fatalf("still routing with the module's own table: %v", offenders)
	}
}
