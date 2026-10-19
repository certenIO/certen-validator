package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// kermitTable is Kermit's routing table as acc://dn.acme/routing publishes it (measured 2026-10-18, sigtypelive g1route).
func kermitTable() *protocol.RoutingTable {
	return &protocol.RoutingTable{
		Routes: []protocol.Route{
			{Length: 1, Value: 0, Partition: "BVN1"},
			{Length: 2, Value: 2, Partition: "BVN2"},
			{Length: 2, Value: 3, Partition: "BVN3"},
		},
		Overrides: []protocol.RouteOverride{
			{Account: url.MustParse("acc://ACME"), Partition: "Directory"},
			{Account: url.MustParse("acc://dn.acme"), Partition: "Directory"},
		},
	}
}

// The placements the live run relied on are what the routing rule gives (so the numbers chosen from `g1route` are not a guess that a
// code change can silently invalidate): cust-508 on BVN2 with bank-508 on BVN3, cust-504 on BVN3 with bank-504 on BVN2, cust-537 on BVN2,
// bank-537 on BVN3 and deleg-537 on BVN1.
func TestTheChosenScenarioNumbersAreRoutedWhereTheRunNeedsThem(t *testing.T) {
	tb := kermitTable()
	for _, c := range []struct{ name, want string }{
		{"pv2-cust-508", "BVN2"}, {"pv2-bank-508", "BVN3"},
		{"pv2-cust-504", "BVN3"}, {"pv2-bank-504", "BVN2"},
		{"pv2-cust-537", "BVN2"}, {"pv2-bank-537", "BVN3"}, {"pv2-deleg-537", "BVN1"},
		{"pv2-cust-505", "BVN2"}, {"pv2-bank-505", "BVN2"},
		{"pv2-cust-555", "BVN2"}, {"pv2-bank-555", "BVN2"}, {"pv2-deleg-555", "BVN2"},
	} {
		if got := routeOf(tb, c.name); got != c.want {
			t.Errorf("%s routes to %s, the run needs %s", c.name, got, c.want)
		}
	}
	// No name an ADI can have routes to the Directory by the prefix rule: only the two overrides do.
	for i := 0; i < 5000; i++ {
		if p := routeOf(tb, fmt.Sprintf("probe-%d", i)); p == "Directory" {
			t.Fatalf("probe-%d routes to the Directory", i)
		}
	}
	if p := routeOf(tb, "acc://dn.acme"); p != "Directory" {
		t.Errorf("dn.acme routes to %s", p)
	}
}

// The names of a scenario follow its numbers, one hop book per hop, hosted round-robin by the hosts.
func TestG1TopologyNames(t *testing.T) {
	tp := g1Topo{Kind: "deleg", N: 532, Hosts: []int{532, 518, 502}, Depth: 20}
	if tp.cust() != "pv2-cust-532" || tp.bank() != "pv2-bank-532" {
		t.Fatalf("names %s %s", tp.cust(), tp.bank())
	}
	seen := map[string]bool{}
	for i := 1; i <= tp.Depth; i++ {
		b := tp.hopBook(i)
		if seen[b] {
			t.Fatalf("hop %d repeats the book %s", i, b)
		}
		seen[b] = true
		wantHost := []string{"pv2-deleg-532", "pv2-deleg-518", "pv2-deleg-502"}[(i-1)%3]
		if !strings.HasPrefix(b, "acc://"+wantHost+".acme/book-d") {
			t.Errorf("hop %d is %s, want a book of %s", i, b, wantHost)
		}
	}
}

// Accumulate refuses a CreateDataAccount body of exactly 32 or 64 bytes; no scenario's data account may land on either for the
// numbers of the programme (500-999).
func TestNoG1DataAccountCreationHasAnAmbiguousBodyLength(t *testing.T) {
	for n := 500; n <= 999; n++ {
		cust, bank := adiURL(fmt.Sprintf("pv2-cust-%d", n)), adiURL(fmt.Sprintf("pv2-bank-%d", n))
		for _, auths := range [][]string{{cust + "/book"}, {cust + "/book", bank + "/book"}, {bank + "/book"}} {
			var us []*url.URL
			for _, a := range auths {
				us = append(us, mustURL(a))
			}
			b, err := (&protocol.CreateDataAccount{Url: mustURL(cust + "/data"), Authorities: us}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) == 32 || len(b) == 64 {
				t.Errorf("%s with %d authorities: %d bytes", cust, len(auths), len(b))
			}
		}
	}
}

// Accumulate's API refuses an envelope whose signatures route to more than one partition ("conflicting routes", seen on Kermit when the
// bank's book on BVN3 co-signed a transaction on BVN2). split sends one envelope per partition, each carrying the transaction, the
// initiator's group first.
func TestSplitEnvelopeGroupsSignaturesByTheirPartition(t *testing.T) {
	tb := kermitTable()
	byPart := map[string]string{}
	for i := 0; len(byPart) < 3 && i < 1000; i++ {
		n := fmt.Sprintf("acc://split-%d.acme", i)
		p := routeOf(tb, n)
		if _, ok := byPart[p]; !ok {
			byPart[p] = n
		}
	}
	k := &kermit{table: tb}
	key, err := sigfixture.NewKey(protocol.SignatureTypeED25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	txn := sigfixture.Txn(byPart["BVN2"]+"/data", "x")
	mk := func(adi string, initiate bool) protocol.Signature {
		sig, err := sigfixture.Sign(key, txn, sigfixture.Opts{Signer: adi + "/book/1", Initiate: initiate})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	env := &messaging.Envelope{Transaction: []*protocol.Transaction{txn},
		Signatures: []protocol.Signature{mk(byPart["BVN2"], true), mk(byPart["BVN3"], false), mk(byPart["BVN1"], false)}}
	envs, err := k.split(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 3 {
		t.Fatalf("%d envelopes, want one per partition (3)", len(envs))
	}
	for i, e := range envs {
		if len(e.Signatures) != 1 || len(e.Transaction) != 1 {
			t.Errorf("envelope %d: %d signatures, %d transactions", i, len(e.Signatures), len(e.Transaction))
		}
	}
	if got := envs[0].Signatures[0].RoutingLocation().String(); !strings.EqualFold(got, byPart["BVN2"]+"/book/1") {
		t.Errorf("the first envelope is %s, want the initiator's group (%s)", got, byPart["BVN2"])
	}
	// signatures that all route alike stay one envelope
	one := &messaging.Envelope{Transaction: []*protocol.Transaction{txn}, Signatures: []protocol.Signature{mk(byPart["BVN2"], true), mk(byPart["BVN2"], false)}}
	if envs, err := k.split(context.Background(), one); err != nil || len(envs) != 1 || envs[0] != one {
		t.Fatalf("one partition: %d envelopes, %v", len(envs), err)
	}
	if _, err := proof.RoutePartition(tb, byPart["BVN3"]+"/book/1"); err != nil {
		t.Fatal(err)
	}
}

// The scenario intent declares the book and page it is given, and the shape of the signature-type run's intent is unchanged.
func TestBuildIntentSpecDeclaresTheGivenBookAndPage(t *testing.T) {
	blobs, err := buildIntentSpec(intentSpec{ADI: "acc://pv2-cust-508.acme", By: "g1-cross", Desc: "d", Book: "acc://pv2-cust-508.acme/book",
		Page: "acc://pv2-cust-508.acme/book/1", From: "0x0000000000000000000000000000000000000001", Tags: []string{"rb9-e"}, Leg: testLeg(t, "base-sepolia")})
	if err != nil {
		t.Fatal(err)
	}
	var gov struct {
		Authorization struct {
			Book string `json:"required_key_book"`
			Page string `json:"required_key_page"`
			Hash string `json:"authorization_hash"`
		} `json:"authorization"`
	}
	if err := json.Unmarshal(blobs.Blobs[2], &gov); err != nil {
		t.Fatal(err)
	}
	if gov.Authorization.Book != "acc://pv2-cust-508.acme/book" || gov.Authorization.Page != "acc://pv2-cust-508.acme/book/1" || gov.Authorization.Hash != blobs.OperationID {
		t.Fatalf("governance blob %+v, operation %s", gov.Authorization, blobs.OperationID)
	}
	old, err := buildIntent("acc://pv2-sig-1.acme", liveCases()[1], "0x0000000000000000000000000000000000000001", testLeg(t, "base-sepolia"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(old.Blobs[2], &gov); err != nil || gov.Authorization.Book != liveCases()[1].book("acc://pv2-sig-1.acme") {
		t.Fatalf("the signature-type intent declares %q (%v)", gov.Authorization.Book, err)
	}
}
