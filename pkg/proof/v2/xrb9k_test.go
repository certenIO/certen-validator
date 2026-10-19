package proofv2_test

import (
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-K defect 2 (verifier round VR): UpdateAccountAuth is the one modelled type that rewrites the authority set the verifier reads. The
// principal is proven at the anchor block, so its set is the set AFTER the transaction; the executor required the set BEFORE it. Each
// operation kind is modelled (Add, Enable, Disable: the requirement before equals the requirement the verifier derives) or refused by name
// (Remove, and the first authorities of an inheriting account); xoverride.go has the audit. These tests drive the real xworld with
// operations (no earlier test used any).

func authOps(ops ...protocol.AccountAuthOperation) *protocol.UpdateAccountAuth {
	return &protocol.UpdateAccountAuth{Operations: ops}
}

func addOp(book string) protocol.AccountAuthOperation {
	return &protocol.AddAccountAuthorityOperation{Authority: url.MustParse(book)}
}
func removeOp(book string) protocol.AccountAuthOperation {
	return &protocol.RemoveAccountAuthorityOperation{Authority: url.MustParse(book)}
}
func enableOp(book string) protocol.AccountAuthOperation {
	return &protocol.EnableAccountAuthOperation{Authority: url.MustParse(book)}
}
func disableOp(book string) protocol.AccountAuthOperation {
	return &protocol.DisableAccountAuthOperation{Authority: url.MustParse(book)}
}

// A RemoveAccountAuthorityOperation: the authority required before is absent after, and the Disabled flag of its entry is lost. Whatever
// the votes say, the document is refused by name before the vote is re-evaluated - including an honest document that the old reading
// refused as g1_vote_not_reproduced, and one that omits the removed authority's vote and verified under the weaker after-set.
func TestRB9KUpdateAccountAuthWithARemoveOperationIsRefusedByName(t *testing.T) {
	for name, s := range map[string]xworld.Timeline{
		"remove an authority that did not vote (the after-set is the voter alone: verified under the weaker requirement)": {
			Body: authOps(removeOp(xworld.DeleBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}},
		"remove the voter's book (the after-set no longer lists the voter)": {
			Body: authOps(removeOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.DeleBook}}},
		"remove beside an add": {
			Body: authOps(addOp(xworld.DeleBook), removeOp(xworld.DeleBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, s, nil)
			refusedWith(t, err, proofv2.StateExecutorOverrideUnsupported, "BVN1", xworld.BlockBVN1)
		})
	}
}

// The first authorities of an account that listed none: the after-set is exactly the added authorities, the executor required the
// authorities inherited from the parent.
func TestRB9KUpdateAccountAuthAddingTheFirstAuthoritiesIsRefusedByName(t *testing.T) {
	_, err := tl(t, xworld.Timeline{Body: authOps(addOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}}, nil)
	refusedWith(t, err, proofv2.StateExecutorOverrideUnsupported, "BVN1", xworld.BlockBVN1)
}

// Enable and Disable change only the flag, which RequireAuthorization makes irrelevant to the requirement: modelled, the flag is not read.
func TestRB9KUpdateAccountAuthEnableAndDisableAreModelled(t *testing.T) {
	for name, s := range map[string]xworld.Timeline{
		"disable the voter's book":        {Body: authOps(disableOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook, Disabled: true}}},
		"enable the voter's book":         {Body: authOps(enableOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}},
		"disable and enable, both listed": {Body: authOps(disableOp(xworld.BankBook), enableOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}},
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := tl(t, s, nil)
			if err != nil {
				t.Fatal(err)
			}
			if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired {
				t.Fatalf("mode %q", rep.AuthorizationMode)
			}
		})
	}
}

// An authority the transaction disables or adds is still required (the executor required it before - the disabled one enabled, and
// RequireAuthorization requires the disabled; the added one by GetAdditionalAuthorities): it did not vote, so the transaction was not ready.
func TestRB9KUpdateAccountAuthDisabledAndAddedAuthoritiesThatDidNotVoteAreNotReady(t *testing.T) {
	for name, c := range map[string]struct {
		s   xworld.Timeline
		mut func(ev *proofv2.Evidence)
	}{
		"disable an authority that did not vote": {xworld.Timeline{Body: authOps(disableOp(xworld.DeleBook)),
			PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}, {Book: xworld.DeleBook, Disabled: true}}},
			func(ev *proofv2.Evidence) { xworld.SetAuthorityRoles(ev, xworld.DeleBook, xworld.DelePage1) }},
		"add an authority that did not vote": {xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)),
			PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}, {Book: xworld.DeleBook}}},
			func(ev *proofv2.Evidence) {
				xworld.SetRoles(ev, xworld.DeleBook, proofv2.RoleAuthorityBook, proofv2.RoleHeaderAuthority)
				xworld.SetRoles(ev, xworld.DelePage1, proofv2.RoleAuthorityPage, proofv2.RoleHeaderAuthority)
			}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, c.s, c.mut)
			refusedWith(t, err, proofv2.StateAuthorityNotReady, "BVN1", xworld.BlockBVN1)
		})
	}
}
