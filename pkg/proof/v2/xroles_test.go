// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func verifyCase(t *testing.T, c xworld.Case) (*proofv2.Report, error) {
	t.Helper()
	_, p, err := c.Document()
	if err != nil {
		t.Fatal(err)
	}
	return proofv2.VerifyPortable(p)
}

// header-authority was a declared role: a page could record it and the verifier listed it without a reason. With the transaction
// carried it is derived from the header, so a page that records it when the header names no authority is refused by name.
func TestRoleHeaderAuthorityClaimedWithoutAHeaderIsRefused(t *testing.T) {
	_, err := verifyCase(t, xworld.Case{Opts: xworld.Options{Timeline: &xworld.Timeline{}},
		Mutate: func(ev *proofv2.Evidence) {
			p := &ev.Pages[1]
			for i := range ev.Pages {
				if strings.EqualFold(ev.Pages[i].URL, xworld.BankPage2) {
					p = &ev.Pages[i]
				}
			}
			p.Roles = append(p.Roles, proofv2.RoleHeaderAuthority)
		}})
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateRoleMismatch || ns.Partition != "BVN2" || ns.Block != xworld.BlockBVN2 {
		t.Fatalf("a header-authority role the carried transaction does not justify: %v", err)
	}
}

// The initiating signature is among the carried signatures: the role is proven (no Declared entry, no unproven state for it), and a
// page that records it without being the payer or a delegator is refused.
func TestRoleInitiatorSignerIsDerivedFromTheInitiatingSignature(t *testing.T) {
	var c xworld.Case
	for _, k := range xworld.Cases3b() {
		if k.Name == "roles-initiator-derived" {
			c = k
		}
	}
	rep, err := verifyCase(t, c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range rep.Proven {
		if strings.EqualFold(g.URL, xworld.BankPage1) {
			found = true
			has := false
			for _, r := range g.Roles {
				has = has || r == proofv2.RoleInitiatorSigner
			}
			if !has || len(g.Declared) != 0 {
				t.Fatalf("%s: roles %v declared %v: initiator-signer must be a proven role", g.URL, g.Roles, g.Declared)
			}
		}
	}
	if !found {
		t.Fatal("BankPage1 is not among the proven pages")
	}
	for _, u := range rep.Unproven {
		if u.Code == proofv2.StateInitiatorSignatureNotCarried {
			t.Fatalf("the initiating signature is carried, yet the report says %v", u)
		}
	}
}

// With the header naming the authority that voted, header-authority is derived for its book and every page, and when no initiating
// signature is carried the recorded initiator-signer is a declared fact the report names.
func TestRoleDeclaredOnlyWhenTheEvidenceCannotDeriveIt(t *testing.T) {
	var c xworld.Case
	for _, k := range xworld.Cases3b() {
		if k.Name == "roles-initiator-signature-not-carried" {
			c = k
		}
	}
	rep, err := verifyCase(t, c)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, u := range rep.Unproven {
		named = named || u.Code == proofv2.StateInitiatorSignatureNotCarried
	}
	if !named {
		t.Fatalf("the report does not name the undeclared initiator: %v", rep.Unproven)
	}
	for _, g := range rep.Proven {
		if strings.EqualFold(g.URL, xworld.BankPage2) && (len(g.Declared) != 1 || g.Declared[0] != proofv2.RoleInitiatorSigner) {
			t.Fatalf("%s: declared %v", g.URL, g.Declared)
		}
	}
}

// One comparison of two key pages, for the timeline and the shadow cross-check (RB9-C1b-1-F3).
func TestAuthorityDiffIsOneComparison(t *testing.T) {
	mk := func() *protocol.KeyPage {
		return &protocol.KeyPage{Url: url.MustParse("acc://a.acme/book/1"), Version: 1, AcceptThreshold: 1,
			Keys: []*protocol.KeySpec{{PublicKeyHash: []byte{1}}, {PublicKeyHash: []byte{2}}}}
	}
	a, b := mk(), mk()
	if d := proofv2.AuthorityDiff(a, b); d != "" {
		t.Fatalf("equal pages differ: %q", d)
	}
	b.TransactionBlacklist = new(protocol.AllowedTransactions)
	bit, _ := protocol.TransactionTypeWriteData.AllowedTransactionBit()
	b.TransactionBlacklist.Set(bit)
	if d := proofv2.AuthorityDiff(a, b); d != "transaction blacklist" {
		t.Fatalf("blacklist: %q", d)
	}
	b = mk()
	b.Keys[1].Delegate = url.MustParse("acc://d.acme/book")
	b.Keys = b.Keys[:2]
	if d := proofv2.AuthorityDiff(a, b); d != "keys[1].delegate" {
		t.Fatalf("delegate: %q", d)
	}
	b = mk()
	b.Version = 2
	b.AcceptThreshold = 2
	got := proofv2.AuthorityFieldDiffs(a, b)
	if len(got) != 2 || got[0].Field != "version" || got[1].Field != "acceptThreshold" || proofv2.AuthorityDiff(a, b) != "version 1 vs 2" {
		t.Fatalf("diffs %+v", got)
	}
}
