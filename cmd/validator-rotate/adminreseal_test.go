package main

import (
	"strings"
	"testing"
)

func fleet(versions ...uint64) []*nodeView {
	var out []*nodeView
	for i, v := range versions {
		out = append(out, &nodeView{rpc: "http://v" + string(rune('1'+i)), chainID: "certen-testnet", height: 100, appVersion: v})
	}
	return out
}

// A transaction kind rules v<min> introduced needs every node on v<min> or later, all on the same version: nodes on
// different rules judge the same block differently. An exact pin would refuse every later fleet - which is how the
// rotation preflight, pinned at v8, refused rotations on the v9 and v10 fleets.
func TestTheFleetMustRunTheSameRulesAtLeastTheKindsVersion(t *testing.T) {
	if p := fleetRulesProblems(fleet(11, 11, 11), 8, "rotation"); len(p) != 0 {
		t.Fatalf("a v11 fleet refused a rotation: %v", p)
	}
	if p := fleetRulesProblems(fleet(10, 10), 10, "registry"); len(p) != 0 {
		t.Fatalf("a v10 fleet refused the registry: %v", p)
	}
	if p := fleetRulesProblems(fleet(9, 9), 10, "registry"); len(p) == 0 {
		t.Fatal("a v9 fleet was ready for the registry")
	}
	p := fleetRulesProblems(fleet(11, 10, 11), 10, "registry")
	if len(p) != 1 || !strings.Contains(p[0], "same rules") {
		t.Fatalf("a mixed fleet: %v", p)
	}
}

// The re-seal preflight: every node on rules v11, on one chain, none lagging.
func TestTheReSealPreflight(t *testing.T) {
	if p := adminResealPreflight(fleet(11, 11, 11, 11, 11, 11, 11)); len(p) != 0 {
		t.Fatalf("a ready fleet: %v", p)
	}
	if p := adminResealPreflight(fleet(11, 11, 10, 11, 11, 11, 11)); len(p) == 0 {
		t.Fatal("a node on v10 passed the re-seal preflight")
	}
	lag := fleet(11, 11, 11)
	lag[2].height = 90
	if p := adminResealPreflight(lag); len(p) == 0 {
		t.Fatal("a lagging node passed the re-seal preflight")
	}
	other := fleet(11, 11)
	other[1].chainID = "another-chain"
	if p := adminResealPreflight(other); len(p) == 0 {
		t.Fatal("a node on another chain passed the re-seal preflight")
	}
}
