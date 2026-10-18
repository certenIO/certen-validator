// Copyright 2026 Certen Protocol

package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Cases5 is the suite of RB9-K (verifier round VR, defect 2): UpdateAccountAuth with operations. The principal is proven at the anchor block,
// so its authority set is the set AFTER the transaction; the executor required the set BEFORE it. The operation kinds the document's body
// lets the verifier invert are modelled (Add, Enable, Disable) and the rest are refused by name (xoverride.go has the audit). The world
// has one voter (BankBook); a vector in which an authority the transaction adds also votes needs a second voter and is not in this suite.
func Cases5() []Case {
	held := proofv2.StateVoteHeld
	ops := func(o ...protocol.AccountAuthOperation) *protocol.UpdateAccountAuth {
		return &protocol.UpdateAccountAuth{Operations: o}
	}
	add := func(b string) protocol.AccountAuthOperation {
		return &protocol.AddAccountAuthorityOperation{Authority: url.MustParse(b)}
	}
	remove := func(b string) protocol.AccountAuthOperation {
		return &protocol.RemoveAccountAuthorityOperation{Authority: url.MustParse(b)}
	}
	enable := func(b string) protocol.AccountAuthOperation {
		return &protocol.EnableAccountAuthOperation{Authority: url.MustParse(b)}
	}
	disable := func(b string) protocol.AccountAuthOperation {
		return &protocol.DisableAccountAuthOperation{Authority: url.MustParse(b)}
	}
	deleAuthority := func(ev *proofv2.Evidence) { SetAuthorityRoles(ev, DeleBook, DelePage1) }
	deleAdded := func(ev *proofv2.Evidence) {
		SetRoles(ev, DeleBook, proofv2.RoleAuthorityBook, proofv2.RoleHeaderAuthority)
		SetRoles(ev, DelePage1, proofv2.RoleAuthorityPage, proofv2.RoleHeaderAuthority)
	}
	return []Case{
		{Name: "update-account-auth-remove-op-that-leaves-the-voter", Description: "an UpdateAccountAuth removes the delegate book from the principal's list; the principal proven after the transaction lists the voter alone, so the set the executor required (both books) cannot be derived: refused by name before the vote is re-evaluated", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(remove(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}}}}},
		{Name: "update-account-auth-remove-op-of-the-voters-book", Description: "an UpdateAccountAuth removes the voter's own book; the principal proven after it lists another book: refused by name", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(remove(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: DeleBook}}}}},
		{Name: "update-account-auth-add-op-first-authorities-of-an-inheriting-account", Description: "an UpdateAccountAuth adds the voter's book to an account that listed none: the principal proven after it lists exactly the added book, the executor required the authorities it inherited from its parent, which the document does not carry: refused by name", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(add(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}}}}},
		{Name: "update-account-auth-add-op-authority-did-not-vote", Description: "an UpdateAccountAuth adds the delegate book to a principal that listed the voter's book: the added authority is required (GetAdditionalAuthorities) and never voted", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}, {Book: DeleBook}}}}, Mutate: deleAdded},
		{Name: "update-account-auth-disable-op-voted", Description: "an UpdateAccountAuth disables the voter's own book: a disabled authority is still required by this type, the voter accepted, the mode is authorities_required", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Body: ops(disable(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}}}}},
		{Name: "update-account-auth-enable-op-voted", Description: "an UpdateAccountAuth enables the voter's book (it was disabled before): required before and after alike, the voter accepted", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Body: ops(enable(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}}}}},
		{Name: "update-account-auth-disable-op-authority-did-not-vote", Description: "an UpdateAccountAuth disables the delegate book, which never voted: it was required before (enabled) and is required after (disabled, by RequireAuthorization)", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(disable(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}, {Book: DeleBook, Disabled: true}}}}, Mutate: deleAuthority},
		{Name: "update-account-auth-enable-op-authority-did-not-vote", Description: "an UpdateAccountAuth enables the delegate book, which never voted: it was required before (disabled, by RequireAuthorization) and after", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: ops(enable(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}, {Book: DeleBook}}}}, Mutate: deleAuthority},
	}
}
