// Copyright 2026 Certen Protocol

package xworld

import (
	"encoding/hex"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// setRoles replaces the recorded roles of a page (canonical order).
func setRoles(ev *proofv2.Evidence, page string, roles ...proofv2.PageRole) {
	p := &ev.Pages[idx(ev, page)]
	rs, err := proofv2.CanonicalRoles(roles)
	if err != nil {
		panic(err)
	}
	p.Roles = rs
}

// RelabelAnchorWrapper changes only the SequencedMessage wrapper's Source of the partition anchor held under key (the anchor
// transaction, header and body, is untouched, so its receipt still proves it into the certified root) and every claim that names the
// partition with it: the anchors key and the pages' partition.
func RelabelAnchorWrapper(ev *proofv2.Evidence, key, to string) {
	a := ev.Anchors[key]
	seq := decodeSeq(a.Message)
	seq.Source = url.MustParse(to)
	a.Message = hex.EncodeToString(must(seq.MarshalBinary()))
	delete(ev.Anchors, key)
	ev.Anchors[to] = a
	for i := range ev.Pages {
		if ev.Pages[i].Partition == key {
			ev.Pages[i].Partition = to
		}
	}
}

func decodeSeq(msgHex string) *messaging.SequencedMessage {
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(must(hex.DecodeString(msgHex))); err != nil {
		panic(err)
	}
	return seq
}

// repointSequenced edits the SequencedMessage a vote's production carries and points the synthetic ledger entry (the production's Message)
// at the edited message's hash, so only the binding of the message to the vote can refuse it.
func repointSequenced(ev *proofv2.Evidence, edit func(*messaging.SequencedMessage)) {
	pr := ev.Votes[0].Produced
	seq := decodeSeq(pr.Sequenced)
	edit(seq)
	pr.Sequenced = hex.EncodeToString(must(seq.MarshalBinary()))
	h := seq.Hash()
	pr.Message = hex.EncodeToString(h[:])
}

// Cases4 is the suite of the RB9 verifier round VA fixes (testdata/xpartition4; the earlier suites are untouched): the executor-override
// body-type gate (DEF-1), the partition derived from the committed anchor body (DEF-2), the verifier-level core semantics of the
// authority sets (DEF-3: readiness, the all-authorities-disabled mode and its disclosure, a voter outside an enabled list, a mismatching
// transaction), the binding of a sequenced vote's production to the vote (DEF-4) and the held-vote name.
func Cases4() []Case {
	held := proofv2.StateVoteHeld
	updAuth := &protocol.UpdateAccountAuth{}
	createBook := &protocol.CreateKeyBook{}
	netMaint := &protocol.NetworkMaintenance{}
	headerDele := func(ev *proofv2.Evidence) {
		setRoles(ev, DeleBook, proofv2.RoleHeaderAuthority)
		setRoles(ev, DelePage1, proofv2.RoleHeaderAuthority)
	}
	// every listed authority is disabled (DeleBook) and BankBook, outside the list, voted: any authority's vote is accepted then.
	outsideVoterRoles := func(ev *proofv2.Evidence) {
		setRoles(ev, DeleBook, proofv2.RoleAuthorityBook)
		setRoles(ev, DelePage1, proofv2.RoleAuthorityPage)
		setRoles(ev, BankBook, proofv2.RoleVoter)
		setRoles(ev, BankPage1, proofv2.RoleVoter)
		setRoles(ev, BankPage2, proofv2.RoleVoter)
	}
	return []Case{
		{Name: "override-create-key-book", Description: "the transaction is a CreateKeyBook, whose executor extends the authorization rule (create_key_book.go:23-38): refused by name before the vote is re-evaluated", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{Body: createBook}}},
		{Name: "override-network-maintenance", Description: "the transaction is a NetworkMaintenance, whose executor lets dn.acme/operators authorize a partition ADI's transaction (network_maintenance.go:21-70)", Expect: refused,
			State: proofv2.StateExecutorOverrideUnsupported, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{Body: netMaint}}},
		{Name: "override-update-account-auth-is-modelled", Description: "an UpdateAccountAuth is the default rule plus the authorities its operations add and RequireAuthorization, which the verifier implements: it is not refused", Expect: verified, Unproven: []string{held},
			Opts: Options{Timeline: &Timeline{Body: updAuth}}},

		{Name: "anchor-wrapper-source-altered", Description: "the SequencedMessage wrapper of BVN3's anchor names acc://bvn-BVN4.acme and the anchors key and the pages' partition follow it: every receipt still verifies (the receipt covers the anchor transaction, not the wrapper) but the committed body names BVN3", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN3", Block: BlockBVN3, Opts: Options{NoRouting: true},
			Mutate: func(ev *proofv2.Evidence) { RelabelAnchorWrapper(ev, PartBVN3, "acc://bvn-BVN4.acme") }},

		{Name: "production-sequenced-bound", Description: "the vote's production carries the SequencedMessage: its hash is the synthetic ledger entry, it wraps the vote's signature message and names the vote's transport", Expect: verified,
			Opts: Options{Timeline: &Timeline{ProduceBlock: 66, BindSequenced: true}}},
		{Name: "production-sequenced-number-altered", Description: "the carried SequencedMessage has another Number than the vote's transport (the ledger entry is its hash)", Expect: refused,
			State: proofv2.StateArrivalUnproven, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{ProduceBlock: 66, BindSequenced: true}},
			Mutate: func(ev *proofv2.Evidence) { repointSequenced(ev, func(s *messaging.SequencedMessage) { s.Number++ }) }},
		{Name: "production-sequenced-wraps-another-vote", Description: "the carried SequencedMessage wraps a signature message that is not the vote", Expect: refused,
			State: proofv2.StateArrivalUnproven, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Timeline: &Timeline{ProduceBlock: 66, BindSequenced: true}},
			Mutate: func(ev *proofv2.Evidence) {
				repointSequenced(ev, func(s *messaging.SequencedMessage) {
					sm := s.Message.(*messaging.SignatureMessage)
					as := *sm.Signature.(*protocol.AuthoritySignature)
					as.Vote = protocol.VoteTypeReject
					s.Message = &messaging.SignatureMessage{Signature: &as, TxID: sm.TxID}
				})
			}},
		{Name: "production-sequenced-message-not-carried", Description: "a document made before the production carried its message: it keeps its verdict and the report discloses the production as unbound", Expect: verified, Disclosures: []string{proofv2.StateVoteProductionUnbound},
			Opts: Options{Timeline: &Timeline{ProduceBlock: 66}}},

		{Name: "held-transaction-vote-without-production", Description: "the transaction is held (HoldUntil) and the vote carries no production proof: a release may have produced it later than its signature arrived", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{HoldUntil: 60}},
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Produced = nil }},
		{Name: "inline-vote-without-production-not-held", Description: "an inline vote on a transaction that is not held needs no production to be placed: nothing is unproven", Expect: verified,
			Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) {
				ev.Votes[0].Transport = proofv2.VoteTransport{Kind: proofv2.TransportInline}
			}},

		{Name: "authority-not-ready-header-authority-without-a-vote", Description: "the header names the delegate book as a required authority; it never voted", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{HeaderAuthority: DeleBook}}, Mutate: headerDele},
		{Name: "all-authorities-disabled-outside-voter", Description: "the principal lists only the delegate book and it is disabled: any authority's vote suffices, the voter (BankBook) is outside the list and the report discloses it", Expect: verified, Disclosures: []string{proofv2.StateAuthorityVoterOutsideList}, Unproven: []string{held},
			Opts: Options{Timeline: &Timeline{PrincipalAuthorities: []AuthSpec{{Book: DeleBook, Disabled: true}}}}, Mutate: outsideVoterRoles},
		{Name: "enabled-listed-authority-outside-voter", Description: "the principal lists the delegate book, enabled; the vote is BankBook's, outside the list while another authority is enabled: it is not a vote the executor counts", Expect: refused,
			State: proofv2.StateVoteNotReproduced, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{PrincipalAuthorities: []AuthSpec{{Book: DeleBook}}}},
			Mutate: func(ev *proofv2.Evidence) {
				setRoles(ev, DeleBook, proofv2.RoleAuthorityBook)
				setRoles(ev, DelePage1, proofv2.RoleAuthorityPage)
				drop(ev, BankBook, BankPage2)
				setRoles(ev, BankPage1, proofv2.RoleVoter)
			}},
		{Name: "write-data-all-listed-disabled-listed-voter", Description: "the principal lists BankBook and it is disabled, and BankBook voted: the executor needs one vote and nothing more, so the mode is all_authorities_disabled", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}}}}},
		{Name: "update-account-auth-requires-the-disabled-listed-authority", Description: "the same principal, but the transaction is an UpdateAccountAuth, which always requires its authorities (RequireAuthorization): BankBook voted accept, so it is ready, and the mode is authorities_required", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Body: updAuth, PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}}}}},
		{Name: "update-account-auth-requires-another-disabled-authority", Description: "an UpdateAccountAuth on a principal listing two disabled books, BankBook (voted) and the delegate book (did not): the disabled authority is still required", Expect: refused,
			State: proofv2.StateAuthorityNotReady, Partition: "BVN1", Block: BlockBVN1,
			Opts: Options{Timeline: &Timeline{Body: updAuth, PrincipalAuthorities: []AuthSpec{{Book: BankBook, Disabled: true}, {Book: DeleBook, Disabled: true}}}},
			Mutate: func(ev *proofv2.Evidence) {
				setRoles(ev, DeleBook, proofv2.RoleAuthorityBook)
				setRoles(ev, DelePage1, proofv2.RoleAuthorityPage)
			}},
		{Name: "delegation-path-of-21-recorded", Description: "the key signature of the delegated vote is recorded as passing through 21 delegators, one more than protocol.DelegationDepthLimit", Expect: refused,
			State: proofv2.StateDelegationDepthExceeded, Opts: Options{Timeline: &Timeline{Delegated: true}},
			Mutate: func(ev *proofv2.Evidence) {
				h := &ev.Votes[0].Hops[len(ev.Votes[0].Hops)-1]
				sig, err := protocol.UnmarshalSignature(must(hex.DecodeString(h.Signature)))
				if err != nil {
					panic(err)
				}
				for i := 0; i < protocol.DelegationDepthLimit+1-1; i++ {
					sig = &protocol.DelegatedSignature{Signature: sig, Delegator: url.MustParse(BankPage2)}
				}
				h.Signature = hex.EncodeToString(must(sig.MarshalBinary()))
			}},
		{Name: "delegation-chain-depth-2", Description: "the vote is cast through two delegations: BankPage2 delegates to book 1, whose page delegates to the delegate book; the key signature is wrapped in two delegated signatures and each hop's authority signature is recorded on the page that delegated", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true, DelegateDepth: 2}}},
		{Name: "delegation-chain-depth-20", Description: "the vote is cast through 20 delegations, the limit (protocol.DelegationDepthLimit): 21 pages on two partitions, every hop's arrival derived", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true, DelegateDepth: 20}}},
		{Name: "delegation-chain-depth-21", Description: "the key signature is wrapped in 21 delegated signatures, one more than the limit: the executor refuses it, so the document is refused by name", Expect: refused,
			State: proofv2.StateDelegationDepthExceeded, Opts: Options{Timeline: &Timeline{Delegated: true, DelegateDepth: 21}}},
		{Name: "delegation-cycle-between-the-books", Description: "the delegate book's page delegates back to the authority book that delegates to it: the governing set contains a cycle, each book is expanded once and the vote, cast through the first delegation, verifies", Expect: verified,
			Unproven: []string{held}, Opts: Options{Timeline: &Timeline{Delegated: true, DelegateCycle: true}}},
		{Name: "transaction-other-than-the-evidence-names", Description: "the carried transaction is another transaction than TxHash names", Expect: refused,
			State: proofv2.StateTransactionMismatch, Partition: "BVN1", Block: BlockBVN1, Opts: Options{Timeline: &Timeline{}},
			Mutate: func(ev *proofv2.Evidence) {
				txn := new(protocol.Transaction)
				if err := txn.UnmarshalBinary(must(hex.DecodeString(ev.Transaction))); err != nil {
					panic(err)
				}
				txn.Header.Memo = "another transaction"
				ev.Transaction = hex.EncodeToString(must(txn.MarshalBinary()))
			}},
	}
}
