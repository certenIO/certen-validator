// Copyright 2026 Certen Protocol

package proof_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func kermitTable(t *testing.T) *protocol.RoutingTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kermit_routing_2026-09-27.json"))
	if err != nil {
		t.Fatal(err)
	}
	table := new(protocol.RoutingTable)
	if err := json.Unmarshal(raw, table); err != nil {
		t.Fatal(err)
	}
	return table
}

// The route function the verifier and the capture share reproduces the routes measured live on Kermit (R9 M9: eleven accounts,
// each equal to the partition that served it) and the sub-identity rule (an account routes by its root identity).
func TestRoutePartitionReproducesTheMeasuredVectors(t *testing.T) {
	table := kermitTable(t)
	router, err := proof.NewNetworkRouter(table)
	if err != nil {
		t.Fatal(err)
	}
	for account, want := range map[string]string{
		"acc://harbor-mfg-tcl1.acme":          "BVN1",
		"acc://harbor-mfg-erp-tcl1.acme/book": "BVN3",
		"acc://fdb-risk-tcl1.acme/book/2":     "BVN2",
		"acc://fdb-compliance-tcl1.acme/book": "BVN1",
		"acc://certen-protocol.acme":          "BVN1",
		"acc://pv2-cust-5.acme/data":          "BVN1",
		"acc://pv2-bank-5.acme/book/2":        "BVN2",
		"acc://pv2-bank-5.acme/sub/anything":  "BVN2", // a sub-identity is on its root identity's partition
		"acc://pv2-dele-5.acme/book/1":        "BVN3",
		"acc://dn.acme/routing":               "Directory", // an override
		"acc://ACME":                          "Directory",
		"acc://bvn-BVN2.acme/anchors":         "BVN2",
	} {
		got, err := proof.RoutePartition(table, account)
		if err != nil || got != want {
			t.Errorf("%s routed to (%q, %v), want %q", account, got, err, want)
		}
		// The NetworkRouter delegates to the same function.
		if id, err := router.PartitionID(account); err != nil || id != got {
			t.Errorf("%s: NetworkRouter.PartitionID is (%q, %v), RoutePartition %q", account, id, err, got)
		}
	}
	// A table that is not a partition of the routing space is refused whole, never resolved by order.
	bad := &protocol.RoutingTable{Routes: []protocol.Route{{Length: 1, Value: 0, Partition: "BVN1"}, {Length: 2, Value: 0, Partition: "BVN2"}}}
	refused := false
	for _, a := range []string{"acc://a.acme", "acc://b.acme", "acc://c.acme", "acc://d.acme", "acc://e.acme"} {
		if _, err := proof.RoutePartition(bad, a); err != nil {
			refused = true
		}
	}
	if !refused {
		t.Fatal("an overlapping table routed every account")
	}
	if _, err := proof.RoutePartition(nil, "acc://a.acme"); err == nil {
		t.Fatal("no table routed an account")
	}
}

// fakeNode serves the two queries BuildRoutingProofAt makes from a proof built elsewhere, with the receipt extended past the
// certified root as a node's receipt for a past block is (it runs on to a later root).
type fakeNode struct {
	t       *testing.T
	p       *proof.AccountStateProof
	pending int
	asked   []string
}

func (f *fakeNode) Query(_ context.Context, params any) (json.RawMessage, error) {
	m := params.(map[string]any)
	q := m["query"].(map[string]any)
	f.asked = append(f.asked, m["scope"].(string)+" "+q["queryType"].(string))
	switch q["queryType"] {
	case "default":
		if ir, ok := q["includeReceipt"].(map[string]any); !ok || ir["forHeight"] == nil {
			f.t.Fatalf("the routing account was not read as of a block: %v", q["includeReceipt"])
		}
		raw, _ := hex.DecodeString(f.p.AccountState)
		acct, err := protocol.UnmarshalAccount(raw)
		if err != nil {
			f.t.Fatal(err)
		}
		aj, _ := json.Marshal(acct)
		r := f.p.StateReceipt
		r.Entries = append(append([]chained_proof.ReceiptStep(nil), r.Entries...), chained_proof.ReceiptStep{Hash: strings.Repeat("77", 32), Right: true})
		return json.Marshal(map[string]any{"account": json.RawMessage(aj), "receipt": r, "pending": map[string]int{"total": f.pending}})
	case "chain":
		type rec struct {
			Name  string    `json:"name"`
			Count uint64    `json:"count"`
			State []*string `json:"state"`
		}
		var recs []rec
		for _, c := range f.p.Chains {
			recs = append(recs, rec{c.Name, c.Count, c.Pending})
		}
		return json.Marshal(map[string]any{"records": recs})
	}
	f.t.Fatalf("unexpected query %v", q)
	return nil, nil
}

// The D5 routing proof is built end to end: acc://dn.acme/routing read as of the certified block, its receipt cut at the
// certified state tree root, verified before it is returned, and decoded as the RoutingTable with its main-chain height.
func TestBuildRoutingProofAtBuildsAndVerifies(t *testing.T) {
	w, err := xworld.Build(xworld.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := w.Evidence.Check.Routing
	var root [32]byte
	rb, _ := hex.DecodeString(want.StateReceipt.Anchor)
	copy(root[:], rb)

	node := &fakeNode{t: t, p: want}
	got, err := proof.BuildRoutingProofAt(context.Background(), node, 300, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.StateReceipt.Entries) != len(want.StateReceipt.Entries) || !strings.EqualFold(got.StateReceipt.Anchor, want.StateReceipt.Anchor) {
		t.Fatalf("the receipt was not cut at the certified root: %d steps ending %s, want %d ending %s",
			len(got.StateReceipt.Entries), got.StateReceipt.Anchor, len(want.StateReceipt.Entries), want.StateReceipt.Anchor)
	}
	table, height, err := proof.VerifyRoutingProof(got, want.StateReceipt.Anchor)
	if err != nil || height != 1 {
		t.Fatalf("verify: (%v, %d, %v)", table, height, err)
	}
	if id, err := proof.RoutePartition(table, "acc://pv2-bank-5.acme/book"); err != nil || id != "BVN2" {
		t.Fatalf("the proven table routes the bank book to (%q, %v)", id, err)
	}

	// A receipt that never passes through the certified root was not read at the certified block.
	other := root
	other[0] ^= 1
	if _, err := proof.BuildRoutingProofAt(context.Background(), &fakeNode{t: t, p: want}, 300, other); err == nil || !strings.Contains(err.Error(), "never passes through") {
		t.Fatalf("a root the receipt does not pass through: %v", err)
	}
	// A routing account with transactions pending has a pending component that is not 32 zero bytes: not assumed.
	if _, err := proof.BuildRoutingProofAt(context.Background(), &fakeNode{t: t, p: want, pending: 1}, 300, root); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("a pending routing account: %v", err)
	}

	// The verifier's refusals: another certified root, another account, an altered state.
	if _, _, err := proof.VerifyRoutingProof(got, strings.Repeat("22", 32)); err == nil || !strings.Contains(err.Error(), "not the certified state root") {
		t.Fatalf("a routing proof against another certified root: %v", err)
	}
	net := w.Evidence.Check.Set.Network
	if _, _, err := proof.VerifyRoutingProof(&net, net.StateReceipt.Anchor); err == nil || !strings.Contains(err.Error(), proof.RoutingAccountURL) {
		t.Fatalf("the network account passed as the routing table: %v", err)
	}
	forged := *got
	forged.AccountState = forged.AccountState[:len(forged.AccountState)-2] + "00"
	if _, _, err := proof.VerifyRoutingProof(&forged, want.StateReceipt.Anchor); err == nil {
		t.Fatal("a routing account with an altered state was accepted")
	}
}
