// Copyright 2026 Certen Protocol
//
// The second voter of the timeline world (RB9-K-F1; docs/proof/G1_CROSS_PARTITION.md D3). The world of timeline.go has one voter: BankBook
// through BankPage1 on BVN2. A transaction that needs two authorities to vote - an UpdateAccountAuth that ADDS an authority, whose
// requirement is the added authority and every authority of the set before it (Accumulate internal/core/execute/v2/chain/utils.go
// additionalAuthorities, update_account_auth.go:26-57, block/transaction.go userTransactionIsReady) - needs a second one. The second
// voter is DelePage1 of DeleBook on BVN3: a second timelineWorld (the same page script, signature chain, index chains and synthetic
// ledger, built over the same transaction, with its own seeds), so its page is proven at BVN3's own block through BVN3's own anchor and
// its vote reaches the principal on BVN1 as a SequencedMessage of its own. The principal's signature chain holds the votes that
// voted, in the order they were delivered.
package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// secondVoterRoles are the roles a document records for DeleBook and DelePage1 as the second voter's: what the verifier derives from the
// proven states. A book the principal lists, or the transaction names (Header.Authorities, or the authorities its body adds), is an
// authority - and a header authority in the second case; a book neither is reached only through BankPage2's delegate entry, unless
// every listed authority is disabled for a type that does not require authorization (then the authority of a counted vote is a voter).
func secondVoterRoles(txn *protocol.Transaction, auths []protocol.AuthorityEntry) (book, page []proofv2.PageRole) {
	dele := mustURL(DeleBook)
	listed, allDisabled := false, true
	for _, a := range auths {
		if a.Url.Equal(dele) {
			listed = true
		}
		if !a.Disabled {
			allDisabled = false
		}
	}
	allDisabled = allDisabled && !txn.Body.Type().RequireAuthorization()
	header := false
	for _, u := range append(append([]*url.URL{}, txn.Header.Authorities...), txn.GetAdditionalAuthorities()...) {
		if u.Equal(dele) {
			header = true
		}
	}
	switch {
	case listed || header:
		book, page = []proofv2.PageRole{proofv2.RoleAuthorityBook}, []proofv2.PageRole{proofv2.RoleAuthorityPage, proofv2.RoleVoter}
		if header {
			book, page = append(book, proofv2.RoleHeaderAuthority), append(page, proofv2.RoleHeaderAuthority)
		}
	case allDisabled:
		book, page = []proofv2.PageRole{proofv2.RoleVoter}, []proofv2.PageRole{proofv2.RoleVoter}
	default:
		book, page = []proofv2.PageRole{proofv2.RoleDelegateBook}, []proofv2.PageRole{proofv2.RoleDelegatePage, proofv2.RoleVoter}
	}
	return book, page
}

// twoVotes are the document's votes of a world with two voters: the first voter's (vote1, built by the caller) with its receipt into the
// principal's signature chain of all the votes, and the second's. chainVotes lists the voters that voted (1 and 2) in the order the
// principal's signature chain holds their votes; sigEntries is that chain (the entry before the votes first). The document lists them in
// that order, or the reverse with SwapDocumentOrder.
func twoVotes(tw, tw2 *timelineWorld, destination string, vote1 proofv2.Vote, voteMsgs map[int][]byte, chainVotes []int, sigEntries [][]byte) []proofv2.Vote {
	receipt := func(n int) string {
		for i, m := range chainVotes {
			if m == n {
				return rcptHex(entryReceipt(sigEntries, i+1))
			}
		}
		return ""
	}
	vote1.Receipt = receipt(1)
	hop, counted := tw2.hops()
	vote2 := proofv2.Vote{
		Authority: tw2.id.book, Origin: tw2.id.page, Vote: tw2.voteType().String(),
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportSequenced, Source: tw2.id.partSrc, Destination: destination, Number: tw2.id.number},
		Message:   hexs(voteMsgs[2]), Receipt: receipt(2),
		Hops: []proofv2.VoteHop{hop}, Counted: counted, Produced: tw2.production(),
	}
	byVoter := map[int]proofv2.Vote{1: vote1, 2: vote2}
	order := append([]int{}, chainVotes...)
	if tw.t.SwapDocumentOrder {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	var out []proofv2.Vote
	for _, n := range order {
		out = append(out, byVoter[n])
	}
	return out
}
