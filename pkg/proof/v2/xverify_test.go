// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9 Phase C1a: verification of evidence 2.1 over a whole synthetic document whose governing pages live on three partitions
// (xworld): the transaction's BVN1 (the principal), BVN2 (the authority book, two pages, the vote's key signature) and BVN3 (the
// delegate book), each at its own block through its own BlockValidatorAnchor, the routing table proven beside the validator set.

func runX(t *testing.T, o xworld.Options, mut func(*proofv2.Evidence)) (*proofv2.Report, error) {
	t.Helper()
	o.GenesisLinked = o.Chain == nil && len(o.MajorUpdates) == 0 // the document the offline walk requires (F-VE-2 (b)); the verdicts under test are the world's own
	b, err := xworld.Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(b.Evidence)
	}
	return proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
}

func named(t *testing.T, err error, code, partition string, block uint64) *proofv2.NamedState {
	t.Helper()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) {
		t.Fatalf("got %v, want the named state %s{%s,%d}", err, code, partition, block)
	}
	if ns.Code != code || ns.Partition != partition || ns.Block != block {
		t.Fatalf("got %s{%s,%d} (%v), want %s{%s,%d}", ns.Code, ns.Partition, ns.Block, err, code, partition, block)
	}
	return ns
}

func at(t *testing.T, ev *proofv2.Evidence, u string) int {
	t.Helper()
	for i, p := range ev.Pages {
		if strings.EqualFold(p.URL, u) {
			return i
		}
	}
	t.Fatalf("no page %s", u)
	return -1
}

// The valid mixed-partition document: every page is proven through its own partition's anchor, the report lists each as
// (partition, block, role), and what it could not establish is named, not implied.
func TestXMixedPartitionDocumentVerifies(t *testing.T) {
	b, err := xworld.Build(xworld.Options{GenesisLinked: true})
	if err != nil {
		t.Fatal(err)
	}
	// As another language's verifier reads it: through the portable form.
	p, err := b.Portable()
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back := new(proofv2.Portable)
	if err := json.Unmarshal(j, back); err != nil {
		t.Fatal(err)
	}
	rep, err := proofv2.VerifyPortable(back)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != proofv2.Version21 || rep.Tag != proofv2.DomainG1V4 || rep.RoutingHeight != 1 {
		t.Fatalf("version %q tag %q routing height %d", rep.Version, rep.Tag, rep.RoutingHeight)
	}
	want := []struct {
		url, part string
		block     uint64
		roles     string
	}{
		{xworld.Principal, xworld.PartBVN1, xworld.BlockBVN1, "principal-chain"},
		{xworld.BankBook, xworld.PartBVN2, xworld.BlockBVN2, "authority-book"},
		{xworld.BankPage1, xworld.PartBVN2, xworld.BlockBVN2, "authority-page,voter"},
		{xworld.BankPage2, xworld.PartBVN2, xworld.BlockBVN2, "authority-page"},
		{xworld.DeleBook, xworld.PartBVN3, xworld.BlockBVN3, "delegate-book"},
		{xworld.DelePage1, xworld.PartBVN3, xworld.BlockBVN3, "delegate-page"},
	}
	if len(rep.Proven) != len(want) || len(rep.Pages) != len(want) || len(rep.PageChains) != len(want) {
		t.Fatalf("%d proven pages, %d accounts, %d chain results, want %d", len(rep.Proven), len(rep.Pages), len(rep.PageChains), len(want))
	}
	for i, w := range want {
		g := rep.Proven[i]
		var roles []string
		for _, r := range g.Roles {
			roles = append(roles, string(r))
		}
		if g.URL != w.url || g.Partition != w.part || g.Block != w.block || strings.Join(roles, ",") != w.roles || len(g.Declared) != 0 {
			t.Fatalf("proven page %d is %+v, want %+v", i, g, w)
		}
		if !rep.PageChains[i].Bound || rep.PageChains[i].MainHeight != 1 {
			t.Fatalf("page %s: chains not bound at its block: %+v", w.url, rep.PageChains[i])
		}
	}
	if rep.Partition != xworld.PartBVN1 || rep.AnchorBlock != xworld.BlockBVN1 {
		t.Fatalf("the transaction's partition is %s block %d", rep.Partition, rep.AnchorBlock)
	}
	// Open states: only the vote's re-evaluation (RB9 Phase C1b) - the routing table is proven and unchanged since genesis.
	if len(rep.Unproven) != 1 || rep.Unproven[0].Code != proofv2.StateCompletenessUnproven {
		t.Fatalf("unproven: %+v", rep.Unproven)
	}
}

// A page proven at another block of its partition: its receipt is valid and ends at a different state root than the one the
// partition's anchor for B_Y carries.
func TestXForeignPageAtAnotherBlockIsRefused(t *testing.T) {
	_, err := runX(t, xworld.Options{AltBlockPage: xworld.BankPage1}, nil)
	named(t, err, proofv2.StatePageBlockMismatch, "BVN2", xworld.BlockBVN2)
	// The same attack on the delegate's partition names that partition and its block.
	_, err = runX(t, xworld.Options{AltBlockPage: xworld.DelePage1}, nil)
	named(t, err, proofv2.StatePageBlockMismatch, "BVN3", xworld.BlockBVN3)
}

// B_Y must be at or after every counted signature's arrival: a signature that is not a member of its page's signature chain at
// the page's own B_Y arrived after it (or never), and a claimed arrival block after B_Y is the same defect.
func TestXPartitionBlockBeforeACountedArrivalIsRefused(t *testing.T) {
	_, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Block = xworld.BlockBVN2 + 1 })
	named(t, err, proofv2.StateBlockBeforeArrival, "BVN2", xworld.BlockBVN2)

	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		ev.Votes[0].Hops[0].Message = strings.Repeat("ab", 32) // a signature the page's chain at B_Y does not hold
	})
	named(t, err, proofv2.StateBlockBeforeArrival, "BVN2", xworld.BlockBVN2)

	// The vote itself must be in the principal's signature chain at the transaction's block.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Votes[0].Message = strings.Repeat("cd", 32) })
	named(t, err, proofv2.StateBlockBeforeArrival, "BVN1", xworld.BlockBVN1)
}

// The partition is derived from the anchor message's Source, never trusted from the document.
func TestXAnchorSourceDifferentFromClaimedPartitionIsRefused(t *testing.T) {
	// The BVN2 slot holds BVN3's anchor.
	_, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		ev.Anchors[xworld.PartBVN2] = ev.Anchors[xworld.PartBVN3]
	})
	ns := named(t, err, proofv2.StateForeignPartitionMismatch, "BVN3", xworld.BlockBVN3)
	if !strings.Contains(ns.Detail, xworld.PartBVN2) || !strings.Contains(ns.Detail, xworld.PartBVN3) {
		t.Fatalf("the refusal names neither the claimed nor the derived partition: %q", ns.Detail)
	}
	// A page that claims a partition other than the one its anchor names.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Pages[at(t, ev, xworld.BankPage2)].Partition = "acc://bvn-bvn2.acme" })
	named(t, err, proofv2.StateForeignPartitionMismatch, "BVN2", xworld.BlockBVN2)
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Pages[at(t, ev, xworld.BankPage2)].Partition = "" })
	named(t, err, proofv2.StateForeignPartitionMismatch, "BVN1", xworld.BlockBVN1)
	// A page that claims a partition the evidence holds no anchor for.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Pages[at(t, ev, xworld.DelePage1)].Partition = "acc://bvn-BVN4.acme" })
	named(t, err, proofv2.StatePartitionAnchorUnavailable, "acc://bvn-BVN4.acme", 0)
}

// A book proves its PageCount; every page 1..PageCount must be among the proven pages, because the first ready page decides.
func TestXUnderstatedPageCountIsRefused(t *testing.T) {
	_, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		i := at(t, ev, xworld.BankPage2)
		ev.Pages = append(ev.Pages[:i], ev.Pages[i+1:]...)
	})
	ns := named(t, err, proofv2.StateBookPageCountUnproven, "BVN2", xworld.BlockBVN2)
	if !strings.Contains(ns.Detail, xworld.BankPage2) {
		t.Fatalf("the refusal does not name the missing page: %q", ns.Detail)
	}
	// The delegate book's page, reached only through the delegating page's entry.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		i := at(t, ev, xworld.DelePage1)
		ev.Pages = append(ev.Pages[:i], ev.Pages[i+1:]...)
	})
	named(t, err, proofv2.StateBookPageCountUnproven, "BVN3", xworld.BlockBVN3)
	// The delegate book itself.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		for _, u := range []string{xworld.DelePage1, xworld.DeleBook} {
			i := at(t, ev, u)
			ev.Pages = append(ev.Pages[:i], ev.Pages[i+1:]...)
		}
	})
	named(t, err, proofv2.StateCompletenessUnproven, "", 0)
}

// A page whose state is another account's, or whose URL names another account than its state, is not the page it claims to be.
func TestXPageOfADifferentAccountIsRefused(t *testing.T) {
	_, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Pages[at(t, ev, xworld.BankPage2)].URL = xworld.DelePage1 })
	if err == nil || !strings.Contains(err.Error(), "the proven state is") {
		t.Fatalf("a page with another account's URL: %v", err)
	}
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		ev.Pages[at(t, ev, xworld.BankPage2)].State = ev.Pages[at(t, ev, xworld.BankPage1)].State
	})
	if err == nil || !strings.Contains(err.Error(), "does not start at the state's hash") {
		t.Fatalf("a page with another account's state under its receipt: %v", err)
	}
}

// Roles are re-derived from the proven states: a role the states do not justify, and a justified role the document omits, are both
// refused; a page that records none is refused.
func TestXRoleClaimedButNotDerivedIsRefused(t *testing.T) {
	_, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		p := &ev.Pages[at(t, ev, xworld.BankPage1)]
		p.Roles = append(p.Roles, proofv2.RoleDelegatePage) // BankPage1 is no delegate's page
	})
	ns := named(t, err, proofv2.StateRoleMismatch, "BVN2", xworld.BlockBVN2)
	if !strings.Contains(ns.Detail, "delegate-page") {
		t.Fatalf("the refusal does not name the role: %q", ns.Detail)
	}
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { // the voter role is justified by the vote's origin
		ev.Pages[at(t, ev, xworld.BankPage1)].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage}
	})
	named(t, err, proofv2.StateRoleMismatch, "BVN2", xworld.BlockBVN2)
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) { ev.Pages[at(t, ev, xworld.DelePage1)].Roles = nil })
	named(t, err, proofv2.StateRoleMismatch, "BVN3", xworld.BlockBVN3)
	// A role the header or the certificate would justify is declared, not derived: it is listed beside the derived ones.
	rep, err := runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		p := &ev.Pages[at(t, ev, xworld.BankPage2)]
		p.Roles = append(p.Roles, proofv2.RoleCertifiedKeyPage)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Proven[3].Declared; len(got) != 1 || got[0] != proofv2.RoleCertifiedKeyPage {
		t.Fatalf("declared roles: %v", got)
	}
}

// The routing table, proven at the certified block and unchanged since genesis, sends every page to the partition its anchor names.
func TestXRoutingMismatchIsRefused(t *testing.T) {
	bank := func(rt *protocol.RoutingTable) {
		rt.Overrides = append(rt.Overrides, protocol.RouteOverride{Account: url.MustParse("acc://pv2-bank-5.acme"), Partition: "BVN3"})
	}
	_, err := runX(t, xworld.Options{Routing: bank}, nil)
	ns := named(t, err, proofv2.StateRoutingMismatch, "BVN2", xworld.BlockBVN2)
	if !strings.Contains(ns.Detail, "BVN3") {
		t.Fatalf("the refusal does not name the routed partition: %q", ns.Detail)
	}
	// The same table written after genesis (main chain height 2): what it was at B_Y is not proven, so the mismatch cannot be
	// judged - the report carries the named state with the height, and is not a verified S3.
	rep, err := runX(t, xworld.Options{Routing: bank, RoutingHeight: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found *proofv2.NamedState
	for i := range rep.Unproven {
		if rep.Unproven[i].Code == proofv2.StateRoutingHistoryUnproven {
			found = &rep.Unproven[i]
		}
	}
	if found == nil || rep.RoutingHeight != 2 || !strings.Contains(found.Detail, "height 2") {
		t.Fatalf("routing height %d, unproven %+v", rep.RoutingHeight, rep.Unproven)
	}
	// Without a routing proof the derivation is unchecked by name.
	rep, err = runX(t, xworld.Options{NoRouting: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unproven[0].Code != proofv2.StateRoutingUnproven {
		t.Fatalf("unproven: %+v", rep.Unproven)
	}
	// A routing proof bound to another state root than the certified one is tampering.
	_, err = runX(t, xworld.Options{}, func(ev *proofv2.Evidence) {
		ev.Check.Routing.StateReceipt.Entries[0].Hash = strings.Repeat("11", 32)
	})
	if err == nil {
		t.Fatal("a routing proof whose receipt was altered was accepted")
	}
}

// A 2.0 document carries none of the 2.1 members; 2.1 members on a 2.0 document are refused rather than silently ignored.
func TestX20DocumentWithTwoOneMembersIsRefused(t *testing.T) {
	b, err := xworld.Build(xworld.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b.Evidence.Version = proofv2.Version
	if _, err := proofv2.VerifyFromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin); err == nil || !strings.Contains(err.Error(), "2.0") {
		t.Fatalf("a 2.0 document with 2.1 members: %v", err)
	}
}

// Consensus and the execution check call Verify, VerifyFromGenesis and VerifyFromSpine. They refuse 2.1 by version exactly as
// before, so a 2.1 document is accepted nowhere until the rules switch that activates it: no consensus verdict changes.
func TestX21IsRefusedByEveryEntryPointConsensusCalls(t *testing.T) {
	b, err := xworld.Build(xworld.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proofv2.VerifyFromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("VerifyFromGenesis on 2.1: %v", err)
	}
	if _, err := proofv2.VerifyFromSpine(b.Evidence, nil, b.Pin); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("VerifyFromSpine on 2.1: %v", err)
	}
	if _, err := proofv2.Verify(b.Evidence, b.Archive, nil, b.Pin); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("Verify on 2.1: %v", err)
	}
	// And the 2.1 entry point refuses a 2.0 document.
	b.Evidence.Version = proofv2.Version
	if _, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin); err == nil {
		t.Fatal("Verify21FromGenesis accepted a 2.0 document")
	}
}
