// Copyright 2026 Certen Protocol

package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// addRoles adds roles to a page of the document (canonical order).
func addRoles(ev *proofv2.Evidence, page string, roles ...proofv2.PageRole) {
	p := &ev.Pages[idx(ev, page)]
	rs, err := proofv2.CanonicalRoles(append(append([]proofv2.PageRole{}, p.Roles...), roles...))
	if err != nil {
		panic(err)
	}
	p.Roles = rs
}

// Cases3b is the suite of RB9 Phase C1b-2 that needs the timeline world (testdata/xpartition3b; the first two suites and the Directory
// suite are untouched): the roles the carried transaction proves (header-authority, initiator-signer; xroles.go), the executor version
// the evidence proves, and the evidence budget. A verified document lists the codes its report must carry; a refusal names the state
// with the partition and block it was judged at.
func Cases3b() []Case {
	held := proofv2.StateVoteHeld
	notCarried := proofv2.StateInitiatorSignatureNotCarried
	headerAll := func(ev *proofv2.Evidence) {
		addRoles(ev, BankBook, proofv2.RoleHeaderAuthority)
		addRoles(ev, BankPage1, proofv2.RoleHeaderAuthority)
		addRoles(ev, BankPage2, proofv2.RoleHeaderAuthority)
	}
	cases := []Case{
		{Name: "roles-header-authority-derived", Description: "the transaction's header names the authority book that voted: its book and both pages are header-authority pages, derived from the carried transaction and equal to the recorded roles (proven, not declared)", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{HeaderAuthority: BankBook}}, Mutate: headerAll},
		{Name: "roles-header-authority-not-recorded", Description: "the header names the authority book but the document does not record header-authority on its pages: justified by the carried transaction, not recorded", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{HeaderAuthority: BankBook}}},
		{Name: "roles-header-authority-claimed", Description: "the carried transaction names no header authority but a page records header-authority: claimed, not justified (a declared role before C1b-2)", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) { addRoles(ev, BankPage2, proofv2.RoleHeaderAuthority) }},
		{Name: "roles-header-authority-without-pages", Description: "the header names an authority whose pages are not among the proven pages", Expect: refused,
			State: proofv2.StateHeaderAuthorityMissing, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{HeaderAuthority: "acc://pv2-nobody-5.acme/book"}}},
		{Name: "roles-initiator-derived", Description: "the last carried key signature initiated the transaction (Header.Initiator is its metadata hash): its signer page is an initiator-signer, derived and equal to the recorded role", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Initiate: true}},
			Mutate: func(ev *proofv2.Evidence) { addRoles(ev, BankPage1, proofv2.RoleInitiatorSigner) }},
		{Name: "roles-initiator-not-recorded", Description: "the carried signature initiated the transaction but its page does not record initiator-signer", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{Initiate: true}}},
		{Name: "roles-initiator-claimed-elsewhere", Description: "the carried signature initiated the transaction on BankPage1, and BankPage2 also records initiator-signer: claimed, not justified", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{Initiate: true}},
			Mutate: func(ev *proofv2.Evidence) {
				addRoles(ev, BankPage1, proofv2.RoleInitiatorSigner)
				addRoles(ev, BankPage2, proofv2.RoleInitiatorSigner)
			}},
		{Name: "roles-initiator-signature-altered", Description: "the signature that initiated the transaction is not the message its signature-chain entry holds", Expect: refused,
			State: proofv2.StateSignatureInvalid, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{Initiate: true}},
			Mutate: func(ev *proofv2.Evidence) {
				addRoles(ev, BankPage1, proofv2.RoleInitiatorSigner)
				h := &ev.Votes[0].Hops[0]
				b := []byte(h.Signature)
				// flip the last nibble of the encoded signature bytes (still a decodable signature, no longer the recorded message)
				if b[len(b)-1] == '0' {
					b[len(b)-1] = '1'
				} else {
					b[len(b)-1] = '0'
				}
				h.Signature = string(b)
			}},
		{Name: "roles-initiator-signature-not-carried", Description: "a page records initiator-signer but the evidence carries no signature that initiated the transaction (the payer may be a page that signed nothing a vote needed): a declared role, named in the report, never a proven one", Expect: verified,
			Unproven: []string{notCarried, held}, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) { addRoles(ev, BankPage2, proofv2.RoleInitiatorSigner) }},

		{Name: "executor-version-baikonur-proven", Description: "the transaction partition's system ledger is proven at its block and holds executor version 6 (Baikonur): the version the re-evaluation's rules are for is proven, not assumed", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{LedgerVersion: 6}}},
		{Name: "executor-version-kourou-proven", Description: "executor version 9 (Kourou), a later version than the rules need", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{LedgerVersion: 9}}},
		{Name: "executor-version-before-baikonur", Description: "the proven system ledger holds executor version 5 (V2, before Baikonur): authority sets were copied at creation and the delegation path differs, so the document is refused by name", Expect: refused,
			State: proofv2.StateExecutorVersionUnsupported, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{LedgerVersion: 5}}},
	}
	return cases
}
