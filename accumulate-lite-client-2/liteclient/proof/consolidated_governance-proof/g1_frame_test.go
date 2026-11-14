// Copyright 2026 Certen Protocol

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DAX-1G-R2 (G-85): the key page is judged in the block numbers of ITS OWN partition (g1_frame.go).

const (
	frameErpPage   = "acc://dax1-r6a-erp.acme/book/1"
	framePrincipal = "acc://dax1-r6a.acme/data"
)

// bareLayer is a G1 layer over an empty recording: nothing it asks the network is answered.
func bareLayer(t *testing.T) *G1Layer {
	t.Helper()
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewG1Layer(&replayClient{responses: map[string][]byte{}}, am, "")
}

func frameTestLayer(t *testing.T) *G1Layer {
	t.Helper()
	g1 := bareLayer(t)
	g1.network = erpNetwork(t)
	return g1
}

// The decision, on the recorded routing table: one identity needs no table; two identities on one partition are one frame; two
// identities on two partitions are not.
func TestFrameOfKeyPage_DecidedByTheRoutingTable(t *testing.T) {
	g1 := frameTestLayer(t)
	for _, c := range []struct {
		name, principal, page string
		foreign               bool
		pp, kp                string
	}{
		{"one identity", "acc://dax1-r6a.acme/data", "acc://dax1-r6a.acme/book/1", false, "", ""},
		{"two identities, one partition (g7)", "acc://dax1-probe-g7.acme/data", "acc://dax1-probe-g7-erp.acme/book/1", false, "bvn1", "bvn1"},
		{"two identities, two partitions (r6a)", framePrincipal, frameErpPage, true, "bvn3", "bvn2"},
	} {
		f, err := g1.frameOfKeyPage(c.principal, c.page)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if f.foreign != c.foreign || f.principalPartition != c.pp || f.pagePartition != c.kp {
			t.Fatalf("%s: frame %+v, want foreign=%v principal=%q page=%q", c.name, f, c.foreign, c.pp, c.kp)
		}
	}
}

// One ADI identity is certainly one partition: the answer must not need the network (every proof to date rests on it).
func TestFrameOfKeyPage_OneIdentityNeedsNoRoutingTable(t *testing.T) {
	g1 := bareLayer(t) // no network set: a table read would fail
	f, err := g1.frameOfKeyPage("acc://pv2-cust-537.acme/data", "acc://pv2-cust-537.acme/book/1")
	if err != nil || f.foreign {
		t.Fatalf("one identity: frame %+v, err %v", f, err)
	}
}

// A routing table that cannot be read is an outage, named, and never a guess in either direction.
func TestFrameOfKeyPage_UnreadableRoutingTableIsAnOutageNotAVerdict(t *testing.T) {
	g1 := bareLayer(t) // endpoint "replay": network-status cannot be read
	_, err := g1.frameOfKeyPage(framePrincipal, frameErpPage)
	var inc *SignatureEvidenceIncomplete
	if !errors.As(err, &inc) {
		t.Fatalf("an unreadable routing table must be SignatureEvidenceIncomplete, got %T %v", err, err)
	}
	if inc.Route != "key-page-frame" || len(inc.Unavailable) != 1 || inc.Unavailable[0].Stage != (RoutingUnavailable{}).Reason() ||
		!strings.Contains(inc.Unavailable[0].Err, "NOT a governance rejection") {
		t.Fatalf("the outage is not named as one: %+v", inc)
	}
}

// F is the LAST block, on the page's own partition, of a counted signature of the transaction on the page: a user signature whose
// signer is the page, or a delegated vote recorded on it.
func TestLastBlockOnPage(t *testing.T) {
	ev := &govvote.Evidence{
		Signatures: []govvote.SignatureEvidence{
			{Fact: govvote.SigFact{Signer: frameErpPage, Block: 5}},
			{Fact: govvote.SigFact{Signer: strings.ToUpper(frameErpPage), Block: 9}}, // spelling does not matter
			{Fact: govvote.SigFact{Signer: "acc://other.acme/book/1", Block: 99}},
		},
		Arrivals: []govvote.ArrivalEvidence{
			{Fact: govvote.ArrivalFact{Page: frameErpPage + "/", Block: 12}},
			{Fact: govvote.ArrivalFact{Page: "acc://other.acme/book/1", Block: 200}},
		},
	}
	if got, ok := lastBlockOnPage(ev, frameErpPage); !ok || got != 12 {
		t.Fatalf("F = %d, %v; want 12 (the delegated vote recorded on the page is later than its signatures)", got, ok)
	}
	if got, ok := lastBlockOnPage(ev, "acc://other.acme/book/1"); !ok || got != 200 {
		t.Fatalf("F of the other page = %d, %v; want 200", got, ok)
	}
	if got, ok := lastBlockOnPage(ev, "acc://none.acme/book/1"); ok {
		t.Fatalf("a page with no counted message has no F, got %d", got)
	}
	if _, ok := lastBlockOnPage(nil, frameErpPage); ok {
		t.Fatal("no evidence, no F")
	}
	if _, ok := lastBlockOnPage(&govvote.Evidence{Signatures: []govvote.SignatureEvidence{{Fact: govvote.SigFact{Signer: frameErpPage}}}}, frameErpPage); ok {
		t.Fatal("a message with no recorded block is not a block")
	}
}

// pageAt builds the key page a timeline holds in one state.
func pageAt(t *testing.T, version, threshold uint64, keyHashes ...string) *protocol.KeyPage {
	t.Helper()
	u, err := url.Parse(frameErpPage)
	if err != nil {
		t.Fatal(err)
	}
	p := &protocol.KeyPage{Url: u, Version: version, AcceptThreshold: threshold}
	for _, h := range keyHashes {
		b := make([]byte, 32)
		copy(b, h)
		p.AddKeySpec(&protocol.KeySpec{PublicKeyHash: b})
	}
	return p
}

// frameTimeline is a page created at block 100 (v1), changed at 200 (v2) and at 300 (v3), all in the PAGE's block numbers.
func frameTimeline(t *testing.T) *pageTimeline {
	t.Helper()
	return &pageTimeline{
		Page:    normalizeAccURL(frameErpPage),
		Genesis: &GenesisEvent{LocalBlock: 100},
		Entries: 3,
		States: []timedState{
			{Block: 100, Page: pageAt(t, 1, 1, "k1")},
			{Block: 200, Page: pageAt(t, 2, 1, "k1", "k2")},
			{Block: 300, Page: pageAt(t, 3, 2, "k1", "k2", "k3")},
		},
	}
}

func frameEvidence(page string, blocks ...int64) *govvote.Evidence {
	ev := &govvote.Evidence{}
	for _, b := range blocks {
		ev.Signatures = append(ev.Signatures, govvote.SignatureEvidence{Fact: govvote.SigFact{Signer: page, Block: b}})
	}
	return ev
}

// The state is the page's state at F whether the page's partition counts LOWER or HIGHER than the principal's. At the principal's
// EXEC_MBI the answer was a number of another chain: with the page counting higher it did not exist yet (the live refusal), with the page
// counting lower it was the state of a block the page's signature had not reached, with a change in between taken as if it had happened.
func TestForeignPageSnapshotIsTheStateAtItsOwnArrivalBlock(t *testing.T) {
	g1 := bareLayer(t)
	tl := frameTimeline(t)
	f := keyPageFrame{principal: normalizeAccURL(framePrincipal), page: normalizeAccURL(frameErpPage), foreign: true, principalPartition: "bvn3", pagePartition: "bvn2"}
	ev := frameEvidence(frameErpPage, 250) // the page signed at its block 250: after its change at 200, before its change at 300
	for _, c := range []struct {
		name    string
		execMBI int64
	}{
		{"the principal's partition counts HIGHER than the page's (EXEC_MBI after every page change)", 5_000},
		{"the principal's partition counts LOWER than the page's (EXEC_MBI before the page existed)", 50},
		{"the two counters happen to agree", 250},
	} {
		g0 := &G0Result{ExecMBI: c.execMBI, ExecWitness: "w", TxHash: strings.Repeat("ab", 32)}
		snap, err := g1.foreignPageSnapshot(tl, f, g0, ev)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if snap.StateExec.Version != 2 || snap.StateExec.Threshold != 1 || len(snap.StateExec.Keys) != 2 {
			t.Fatalf("%s: the page's state at its block 250 is version 2, threshold 1, two keys; got %+v", c.name, snap.StateExec)
		}
		if snap.ExecTerms.MBI != c.execMBI || snap.ExecTerms.Witness != "w" {
			t.Fatalf("%s: the execution terms are the principal's and are carried unchanged, got %+v", c.name, snap.ExecTerms)
		}
		if snap.Page != f.page {
			t.Fatalf("%s: the snapshot names %q", c.name, snap.Page)
		}
	}
}

// A page with no counted signature of the transaction has no block of its own partition to be judged at: refused by name, never judged
// at EXEC_MBI, at its head or at its genesis.
func TestForeignPageWithoutACountedSignatureIsRefusedByName(t *testing.T) {
	g1 := bareLayer(t)
	tl := frameTimeline(t)
	f := keyPageFrame{principal: normalizeAccURL(framePrincipal), page: normalizeAccURL(frameErpPage), foreign: true, principalPartition: "bvn3", pagePartition: "bvn2"}
	g0 := &G0Result{ExecMBI: 250, ExecWitness: "w", TxHash: strings.Repeat("ab", 32)}
	for _, ev := range []*govvote.Evidence{nil, {}, frameEvidence("acc://someone-else.acme/book/1", 250)} {
		snap, err := g1.foreignPageSnapshot(tl, f, g0, ev)
		var verr ValidationError
		if snap != nil || !errors.As(err, &verr) || !strings.Contains(err.Error(), "carries no counted signature of this transaction") {
			t.Fatalf("a page with no counted signature must be refused by name, got %v, %v", snap, err)
		}
	}
}

// The timing record names the clock EXEC_MBI counts: the key page when it is on the principal's partition (every record to date), the
// principal when it is not.
func TestClockAccount(t *testing.T) {
	g1 := bareLayer(t)
	if got := g1.clockAccount(frameErpPage); got != frameErpPage {
		t.Fatalf("a layer that has not decided a frame behaves as before: %q", got)
	}
	g1.keyFrame = &keyPageFrame{principal: framePrincipal, page: frameErpPage}
	if got := g1.clockAccount(frameErpPage); got != frameErpPage {
		t.Fatalf("a key page on the principal's partition stands for the principal: %q", got)
	}
	g1.keyFrame = &keyPageFrame{principal: framePrincipal, page: frameErpPage, foreign: true}
	if got := g1.clockAccount(frameErpPage); got != framePrincipal {
		t.Fatalf("a key page on another partition is not the principal's clock: %q", got)
	}
}

// The signers that are compared with EXEC_MBI for the r6a intent: the principal's own authority page (same identity as the principal, so
// on its clock) and not the erp page (another partition), which was the other way round while the key page stood for the principal.
func TestTimingReferenceForTheR6aSigners(t *testing.T) {
	g1 := bareLayer(t)
	g1.keyFrame = &keyPageFrame{principal: normalizeAccURL(framePrincipal), page: normalizeAccURL(frameErpPage), foreign: true}
	clock := g1.clockAccount(frameErpPage)
	if !sameRoutingPartition("acc://dax1-r6a.acme/book/1", clock) {
		t.Fatal("the principal's authority page is on the principal's clock and must be compared with EXEC_MBI")
	}
	if sameRoutingPartition(frameErpPage, clock) {
		t.Fatal("the erp page is on another partition and must NOT be compared with the principal's EXEC_MBI")
	}
	// The old reference, for the record of what changed: the key page itself.
	if !sameRoutingPartition(frameErpPage, frameErpPage) || sameRoutingPartition("acc://dax1-r6a.acme/book/1", frameErpPage) {
		t.Fatal("the old reference compared the erp page and not the authority page")
	}
}

// Replayed over the recorded routing table the partition names are the ones the fixture table pins.
func TestRecordedRoutingTableNamesTheFixturePartitions(t *testing.T) {
	n := erpNetwork(t)
	for _, fx := range erpInitiatorFixtures {
		for _, c := range []struct{ acct, want string }{{fx.account, fx.principalPartition}, {fx.keyPage, fx.pagePartition}} {
			got, err := n.Partition(c.acct)
			if err != nil || got != c.want {
				t.Fatalf("%s: %s routes to %q (%v), the fixture pins %q", fx.name, c.acct, got, err, c.want)
			}
		}
	}
}
