// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// Real data (Kermit, captured live 2026-10-18 by cmd/proofv2xbuild): a transaction on certen-protocol.acme/billing-receipts (BVN1) with
// the governing pages of its book, the history of the voting key page (book/2) read from the network, the arrival proof of the signature
// that completed the vote from that page's signature-index chain, the production of the vote in the principal's signature chain, the
// carried transaction, and the routing table - assembled by Builder.Build21 from the collector's capture and verified end to end by
// Verify21FromGenesis. BVN2 and BVN3 were idle (RB9-B-F7), so every real page is on BVN1; the cross-partition documents are synthetic.
const realDir = "testdata/xpartition3/real-bvn1-billing-receipts/"

type real21 struct {
	ev  *Evidence
	ar  *Archive
	in  proof.IncarnationInputs
	pin [32]byte
}

func loadReal21(t *testing.T) real21 {
	t.Helper()
	var r real21
	var err error
	r.ev = new(Evidence)
	if err = json.Unmarshal(gunzip(t, realDir+"evidence21.json.gz"), r.ev); err != nil {
		t.Fatal(err)
	}
	if r.ar, err = UnmarshalArchive(gunzip(t, realDir+"archive.json.gz")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	r.in = ir.Inputs
	b, _ := hex.DecodeString(kermitPin)
	copy(r.pin[:], b)
	return r
}

func (r real21) clone(t *testing.T) *Evidence {
	t.Helper()
	raw, err := json.Marshal(r.ev)
	if err != nil {
		t.Fatal(err)
	}
	ev := new(Evidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// The assembled document of a real transaction verifies end to end, and its report is complete: every statement the design asks of the
// timeline is established from the document alone, nothing is left unproven, and the roles that depend on the intent certificate are the
// only ones declared.
func TestReal21AssembledFromALiveCaptureVerifiesEndToEnd(t *testing.T) {
	r := loadReal21(t)
	rep, err := Verify21FromGenesis(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != Version21 || rep.Tag != DomainG1V4 {
		t.Fatalf("version %q tag %q", rep.Version, rep.Tag)
	}
	if len(rep.Unproven) != 0 {
		t.Fatalf("the report is not complete: %v", rep.Unproven)
	}
	if rep.AuthorizationMode == "" || len(rep.Arrivals) == 0 {
		t.Fatalf("the votes were not re-evaluated on the certified timeline: mode %q, %d arrivals", rep.AuthorizationMode, len(rep.Arrivals))
	}
	if rep.RoutingHeight == 0 {
		t.Fatal("no routing table was proven")
	}
	var withHistory, withArrival int
	for _, p := range r.ev.Pages {
		if p.History != nil {
			withHistory++
			if len(p.History.Entries) < 2 {
				t.Fatalf("%s carries a history of %d entries", p.URL, len(p.History.Entries))
			}
		}
	}
	for _, v := range r.ev.Votes {
		for _, h := range v.allHops() {
			if h.Arrival != nil {
				withArrival++
			}
		}
		if v.Produced == nil {
			t.Fatalf("the vote of %s has no production proof", v.Authority)
		}
	}
	if withHistory == 0 || withArrival == 0 || r.ev.Transaction == "" {
		t.Fatalf("history %d, arrival proofs %d, transaction %v", withHistory, withArrival, r.ev.Transaction != "")
	}
	for _, p := range rep.Proven {
		for _, d := range p.Declared {
			if d != RoleCertifiedKeyPage && d != RoleInitiatorSigner {
				t.Fatalf("%s: role %s is still declared although the transaction is carried", p.URL, d)
			}
		}
	}
}

func mustFail(t *testing.T, what string, r real21, ev *Evidence, code string) {
	t.Helper()
	_, err := Verify21FromGenesis(ev, r.ar, r.in, r.pin)
	if err == nil {
		t.Fatalf("%s: the document verified", what)
	}
	ns, ok := err.(*NamedState)
	if !ok || ns.Code != code {
		t.Fatalf("%s: got %v, want %s", what, err, code)
	}
	if ns.Partition == "" || ns.Block == 0 {
		t.Fatalf("%s: the refusal does not carry the partition and block it was judged at: %v", what, err)
	}
}

// Tampering with the real document is refused by name, each at the partition and block it was judged at.
func TestReal21TamperedIsRefusedByName(t *testing.T) {
	r := loadReal21(t)
	histPage := -1
	for i, p := range r.ev.Pages {
		if p.History != nil {
			histPage = i
		}
	}
	if histPage < 0 {
		t.Fatal("the real document carries no history")
	}

	ev := r.clone(t)
	h := ev.Pages[histPage].History
	h.Entries[len(h.Entries)-1], h.Entries[len(h.Entries)-2] = h.Entries[len(h.Entries)-2], h.Entries[len(h.Entries)-1]
	mustFail(t, "two history entries swapped", r, ev, StateHistoryFoldMismatch)

	ev = r.clone(t)
	ev.Pages[histPage].History.Entries = ev.Pages[histPage].History.Entries[1:]
	mustFail(t, "the genesis entry of the history dropped", r, ev, StateHistoryFoldMismatch)

	ev = r.clone(t)
	last := ev.Pages[histPage].History.Index
	ev.Pages[histPage].History.Index = last[:len(last)-1]
	mustFail(t, "a main-index entry dropped", r, ev, StateHistoryFoldMismatch)

	ev = r.clone(t)
	for i := range ev.Votes {
		ev.Votes[i].Hops[0].Block--
	}
	mustFail(t, "a claimed arrival block", r, ev, StateArrivalUnproven)

	ev = r.clone(t)
	for i := range ev.Votes {
		if a := ev.Votes[i].Hops[0].Arrival; a != nil && a.Before != nil {
			a.At, *a.Before = *a.Before, a.At
		}
	}
	if _, err := Verify21FromGenesis(ev, r.ar, r.in, r.pin); err == nil {
		t.Fatal("arrival index entries swapped: the document verified")
	}

	ev = r.clone(t)
	ev.Transaction = ""
	rep, err := Verify21FromGenesis(ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatalf("a document without its transaction is judged, not refused: %v", err)
	}
	found := false
	for _, u := range rep.Unproven {
		if u.Code == StateCompletenessUnproven && strings.Contains(u.Detail, "transaction") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a document without its transaction must say g1_completeness_unproven by name: %v", rep.Unproven)
	}

	ev = r.clone(t)
	for i := range ev.Votes {
		if ev.Votes[i].Vote == "accept" {
			ev.Votes[i].Vote = "reject"
		}
	}
	mustFail(t, "a recorded vote value flipped", r, ev, StateVoteNotReproduced)

	ev = r.clone(t)
	ev.Votes[0].Produced = nil
	rep, err = Verify21FromGenesis(ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	held := false
	for _, u := range rep.Unproven {
		if u.Code == StateVoteHeld {
			held = true
		}
	}
	if !held {
		t.Fatalf("a vote without its production proof must report g1_vote_held: %v", rep.Unproven)
	}
}
