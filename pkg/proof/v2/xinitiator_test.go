// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// DAX-1G (G-83): a transaction initiated by a page that is not a voting authority, the signature carried in Evidence.InitiatingSignature and
// proven by the verifier. Every document of the suite xworld.Cases7 (the shared vectors of testdata/xpartition7 are generated from the same
// cases) gets the verdict the case names: a verified document with exactly the unproven states it lists, a refusal by the named state at the
// partition and block it was judged at.
func TestInitiatorSuiteCases(t *testing.T) {
	cases := xworld.Cases7()
	if len(cases) != 15 {
		t.Fatalf("the suite holds %d cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			rep, err := verifyCase(t, c)
			switch c.Expect {
			case "refused":
				if err == nil {
					t.Fatalf("accepted; want %s{%s,%d}", c.State, c.Partition, c.Block)
				}
				if c.State == "" {
					var ns *proofv2.NamedState
					if errors.As(err, &ns) {
						t.Fatalf("refused with the named state %v, the case names none", ns)
					}
					return
				}
				named(t, err, c.State, c.Partition, c.Block)
			case "verified":
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				var got []string
				for _, u := range rep.Unproven {
					got = append(got, u.Code)
				}
				if strings.Join(got, ",") != strings.Join(c.Unproven, ",") {
					t.Fatalf("unproven %v, the case lists %v", got, c.Unproven)
				}
			default:
				t.Fatalf("expect %q", c.Expect)
			}
		})
	}
}

func provenPage(t *testing.T, rep *proofv2.Report, page string) proofv2.ProvenPage {
	t.Helper()
	for _, g := range rep.Proven {
		if strings.EqualFold(g.URL, page) {
			return g
		}
	}
	t.Fatalf("%s is not among the proven pages", page)
	return proofv2.ProvenPage{}
}

func hasRole(roles []proofv2.PageRole, r proofv2.PageRole) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

// The role is PROVEN, not declared: initiator-signer is in the page's Roles and nowhere in Declared (certified-key-page is the one role that is
// declared, as in every document), for the payer and, for a delegated initiating signature, its delegator.
func TestInitiatorMemberMakesTheRoleProvenNotDeclared(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pages  []string
		cosign bool
	}{
		{"initiator-nonvoting-carried", []string{xworld.ErpPage1}, false},
		{"initiator-nonvoting-key-removed-after-arrival", []string{xworld.ErpPage1}, false},
		{"initiator-nonvoting-delegated-carried", []string{xworld.ErpPage1, xworld.DelePage1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c xworld.Case
			for _, k := range xworld.Cases7() {
				if k.Name == tc.name {
					c = k
				}
			}
			rep, err := verifyCase(t, c)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range tc.pages {
				g := provenPage(t, rep, p)
				if !hasRole(g.Roles, proofv2.RoleInitiatorSigner) || hasRole(g.Declared, proofv2.RoleInitiatorSigner) {
					t.Fatalf("%s: roles %v declared %v: initiator-signer must be proven, not declared", p, g.Roles, g.Declared)
				}
			}
			for _, u := range rep.Unproven {
				t.Fatalf("the report leaves %v unproven", u)
			}
		})
	}
}
