// Copyright 2026 Certen Protocol

package xworld

import (
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Cases6 is the suite of RB9-K-F1 (testdata/xpartition6): UpdateAccountAuth with TWO voters. The world holds a second authority, DeleBook
// through DelePage1 on BVN3, beside BankBook through BankPage1 on BVN2, so the vector xpartition5 could not hold - an Add operation whose
// added authority votes - is a document, with the verdicts that sit beside it.
//
// What the executor does (Accumulate e1d1db9eb, internal/core/execute/v2; identical on main):
//
//   - Admitting a vote. A signature by an authority is admitted when the authority is one the transaction ADDS (chain/utils.go:20-31
//     additionalAuthorities.AuthorityIsAccepted, reached through update_account_auth.go:26-38), whether or not the principal lists it
//     yet. Any other authority is admitted only if the principal, as it is BEFORE the transaction, lists it - disabled or not - because
//     the all-authorities-disabled escape does not apply to a type with RequireAuthorization (block/sig_common.go:348-371,
//     protocol/access_control.go:13-20).
//   - Readiness. Every added authority must have voted accept (chain/utils.go:34-67, update_account_auth.go:40-57), then the default
//     rule requires a vote and every authority of the principal as it is before the transaction, the disabled included
//     (block/transaction.go:207-221 ignoreDisabled := RequireAuthorization). A vote that is not accept rejects the transaction.
//   - After. The operations run (update_account_auth.go:95-170): Add appends the authority (a duplicate fails), Enable and Disable flip
//     the entry's Disabled flag. The verifier reads the principal after the transaction, so the requirement it derives is the after-set
//     plus the added authorities, which for these operation kinds is exactly the requirement the executor applied (xoverride.go).
//
// The authority a vote is for, and the page that cast it, are what the vote model re-evaluates on each page's certified timeline; this
// suite adds nothing to that, it adds a world in which two books vote.
func Cases6() []Case {
	held := proofv2.StateVoteHeld
	both := []AuthSpec{{Book: BankBook}, {Book: DeleBook}}
	ops := func(o ...protocol.AccountAuthOperation) *protocol.UpdateAccountAuth {
		return &protocol.UpdateAccountAuth{Operations: o}
	}
	add := func(b string) protocol.AccountAuthOperation {
		return &protocol.AddAccountAuthorityOperation{Authority: url.MustParse(b)}
	}
	enable := func(b string) protocol.AccountAuthOperation {
		return &protocol.EnableAccountAuthOperation{Authority: url.MustParse(b)}
	}
	disable := func(b string) protocol.AccountAuthOperation {
		return &protocol.DisableAccountAuthOperation{Authority: url.MustParse(b)}
	}
	addDele := func(second *Timeline) Timeline {
		return Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, Second: second}
	}
	twoKeys := func(sigs ...SigEvent) *Timeline {
		return &Timeline{Genesis: []string{"K2", "K3"}, Events: []PageEvent{{Block: 20, Threshold: 2}}, Sigs: sigs}
	}
	withHistory := &Timeline{Events: []PageEvent{{Block: 40, Add: []string{"K3"}}, {Block: 50, Credits: true}}, Sigs: []SigEvent{{Key: "K2", Version: 2, Block: SecondSigBlock}}}
	withOpts := func(t Timeline) Options { return Options{Timeline: &t} }
	twoHeld := []string{held, held} // neither vote's production is carried: one named state per vote, at the partition that produced it
	return []Case{
		{Name: "add-op-added-authority-voted", Description: "an UpdateAccountAuth adds the delegate book to a principal that listed the voter's book; both books vote accept: the added book's signature is admitted although the principal does not list it yet, the transaction is ready when the added book and the book of the set before it have voted. Each key signature's arrival is derived on its own partition (BankPage1 on BVN2 in block 65, DelePage1 on BVN3 in block 66) and each vote's production is proven in its partition's synthetic ledger and bound to its SequencedMessage: nothing is left unproven", Expect: verified,
			Opts: withOpts(Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, ProduceBlock: 66, BindSequenced: true,
				Second: &Timeline{ProduceBlock: 68, BindSequenced: true}})},
		{Name: "add-op-added-authority-voted-first", Description: "the added authority's vote is delivered to the principal before the voter's: its key signature arrives in block 60, it is first in the principal's signature chain and in the document. The executor finds the transaction ready when the last required vote arrives, whichever it is", Expect: verified,
			Unproven: twoHeld, Opts: withOpts(Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, SecondFirst: true,
				Second: &Timeline{Sigs: []SigEvent{{Key: "K2", Version: 1, Block: 60}}}})},
		{Name: "add-op-votes-listed-in-the-other-order", Description: "the principal's signature chain holds the voter's vote and then the added authority's, the document lists them the other way round: the verifier reads no order into the list", Expect: verified,
			Unproven: twoHeld, Opts: withOpts(Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, SwapDocumentOrder: true, Second: &Timeline{}})},
		{Name: "add-op-added-authority-page-threshold-two-voted", Description: "the added authority's page holds two keys and a threshold of 2 (version 2 after the threshold was set in block 20): both keys signed, in blocks 62 and 66, and the page's vote is the book's vote; all three key signatures' arrivals are derived", Expect: verified,
			Unproven: twoHeld, Opts: withOpts(addDele(twoKeys(SigEvent{Key: "K2", Version: 2, Block: 62}, SigEvent{Key: "K3", Version: 2, Block: 66})))},
		{Name: "enable-op-both-authorities-voted", Description: "an UpdateAccountAuth enables the delegate book, which was disabled before: RequireAuthorization makes a disabled authority as required as an enabled one, and both books voted", Expect: verified,
			Unproven: twoHeld, Opts: withOpts(Timeline{Body: ops(enable(DeleBook)), PrincipalAuthorities: both, Second: &Timeline{}})},
		{Name: "disable-op-both-authorities-voted", Description: "an UpdateAccountAuth disables the delegate book: it was required before (enabled) and is required after (disabled, by RequireAuthorization), and both books voted", Expect: verified,
			Unproven: twoHeld, Opts: withOpts(Timeline{Body: ops(disable(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}, {Book: DeleBook, Disabled: true}}, Second: &Timeline{}})},

		{Name: "add-op-only-the-added-authority-voted", Description: "the added authority voted and the voter's book, which the principal listed before the transaction, did not: the default rule still requires every authority of the set before it", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, NoFirstVote: true, Second: &Timeline{}})},
		{Name: "add-op-added-authority-voted-reject", Description: "the added authority voted reject: a vote that is not accept rejects the transaction (utils.go:57), so it was not ready", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(addDele(&Timeline{Sigs: []SigEvent{{Key: "K2", Version: 1, Block: SecondSigBlock, Vote: protocol.VoteTypeReject}}}))},
		{Name: "add-op-added-authority-page-below-threshold", Description: "the added authority's page holds two keys and a threshold of 2 and one signature is recorded with a vote of accept: the page did not vote, the recorded vote cannot be reproduced", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(addDele(twoKeys(SigEvent{Key: "K3", Version: 2, Block: 66})))},
		{Name: "update-account-auth-voter-neither-listed-nor-added", Description: "the delegate book votes on an UpdateAccountAuth that enables the voter's book: the principal lists only the voter's book and the transaction adds nothing, so the executor refused the delegate book's signature (sig_common.go:348-371) and the recorded vote cannot be a vote", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(Timeline{Body: ops(enable(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook}}, Second: &Timeline{}})},
		{Name: "disable-op-every-authority-disabled-one-voted", Description: "an UpdateAccountAuth disables both books and only the delegate book voted: every listed authority is disabled afterwards, but this type requires authorization, so the all-authorities-disabled rule (any one vote suffices) does not apply and the voter's book was still required", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(Timeline{Body: ops(disable(BankBook), disable(DeleBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}, {Book: DeleBook, Disabled: true}},
				NoFirstVote: true, Second: &Timeline{}})},
		{Name: "disable-op-voter-outside-the-list-every-authority-disabled", Description: "the delegate book votes on an UpdateAccountAuth that disables the voter's only book: every listed authority is disabled afterwards, and for a type that did not require authorization any authority's vote would then be accepted (sig_common.go:368), but this type does, so the executor refused the signature of a book neither listed nor added and the recorded vote cannot be a vote", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(Timeline{Body: ops(disable(BankBook)), PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}}, Second: &Timeline{}})},
		{Name: "add-op-first-authorities-both-added-both-voted", Description: "an UpdateAccountAuth adds both books to an account that listed none and both voted: the principal proven after it lists exactly the added books, the executor required the authorities it inherited from its parent as well, which the document does not carry: refused by name whatever the votes", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(Timeline{Body: ops(add(BankBook), add(DeleBook)), PrincipalAuthorities: both, Second: &Timeline{}})},
		{Name: "add-op-second-voter-page-at-another-block", Description: "the added authority's page is proven at another BVN3 block (a valid receipt to a different state root): refused at BVN3 and its block, not at the principal's", Expect: refused,
			State: proofv2.StatePageBlockMismatch, Partition: "BVN3", Block: BlockBVN3,
			Opts: Options{Timeline: &Timeline{Body: ops(add(DeleBook)), PrincipalAuthorities: both, Second: &Timeline{}}, AltBlockPage: DelePage1}},
		{Name: "add-op-second-voter-history-tampered", Description: "a history entry of the added authority's page replaced by another valid transaction: the entries do not fold to the main chain root proven at BVN3's block", Expect: refused,
			State: proofv2.StateHistoryFoldMismatch, Partition: "BVN3", Block: BlockBVN3, Opts: withOpts(addDele(withHistory)),
			Mutate: func(ev *proofv2.Evidence) {
				h := ev.Pages[idx(ev, DelePage1)].History
				h.Entries[2] = h.Entries[1]
			}},
		{Name: "add-op-second-voter-key-added-after-arrival", Description: "the added authority's signing key was added to its page in block 68, after its signature claimed to arrive in block 66: it must not count although the page proven at BVN3's block holds it", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1,
			Opts: withOpts(addDele(&Timeline{Events: []PageEvent{{Block: 68, Add: []string{"K3"}}}, Sigs: []SigEvent{{Key: "K3", Version: 1, Block: SecondSigBlock}}}))},
		{Name: "add-op-second-vote-not-in-the-principal-chain", Description: "the added authority's vote is not a member of the principal's signature chain at the transaction's block", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN1", Block: BlockBVN1, Opts: withOpts(addDele(&Timeline{})),
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[1].Message = strings.Repeat("cd", 32) }},
	}
}
