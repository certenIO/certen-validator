// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-K-F1: the two-voter world. An UpdateAccountAuth that ADDS an authority is the one transaction whose authorization needs two books to
// vote: the executor admits the added book's signature although the principal does not list it yet (chain/utils.go additionalAuthorities.
// AuthorityIsAccepted, update_account_auth.go:26), and finds the transaction ready only when every added book and then every book of the
// set BEFORE the transaction - disabled ones too, RequireAuthorization - has voted accept (utils.go TransactionIsReady, block/transaction.go
// userTransactionIsReady:207). The verifier reads the principal AFTER the transaction (before-set plus the added books), which is the
// same requirement. These tests drive the real xworld with a second voter (DeleBook through DelePage1 on BVN3) and pin the verdicts the
// executor semantics define, with the fields the verified ones must report.

func bothBooks() []xworld.AuthSpec {
	return []xworld.AuthSpec{{Book: xworld.BankBook}, {Book: xworld.DeleBook}}
}

// The added authority's roles in a document: it is a listed authority and a header authority (GetAdditionalAuthorities), its page votes.
func TestRB9K2AddOpAddedAuthorityVotedIsVerified(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{
		Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(),
		ProduceBlock: 66, BindSequenced: true,
		Second: &xworld.Timeline{ProduceBlock: 68, BindSequenced: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired {
		t.Fatalf("mode %q", rep.AuthorizationMode)
	}
	if len(rep.Unproven) != 0 || len(rep.Disclosures) != 0 {
		t.Fatalf("unproven %v disclosures %v: both votes are produced and bound, nothing is left unproven", codes(rep), rep.Disclosures)
	}
	// The vote model derived each key signature's arrival from its own page's signature-index chain (BankPage1 on BVN2, DelePage1 on BVN3),
	// then each production from its partition's synthetic ledger.
	want := []proofv2.ArrivalReport{
		{Kind: "signature", Account: xworld.BankPage1, Block: 65},
		{Kind: "signature", Account: xworld.DelePage1, Block: 66},
		{Kind: "produced", Account: "acc://bvn-BVN2.acme/synthetic", Block: 66},
		{Kind: "produced", Account: "acc://bvn-BVN3.acme/synthetic", Block: 68},
	}
	if len(rep.Arrivals) != len(want) {
		t.Fatalf("arrivals %+v, want %d", rep.Arrivals, len(want))
	}
	for i, w := range want {
		if g := rep.Arrivals[i]; g.Kind != w.Kind || g.Account != w.Account || g.Block != w.Block {
			t.Fatalf("arrival %d is %+v, want %+v", i, g, w)
		}
	}
	roles := map[string]string{}
	for _, p := range rep.Proven {
		var rs []string
		for _, r := range p.Roles {
			rs = append(rs, string(r))
		}
		roles[p.URL+"@"+p.Partition] = strings.Join(rs, ",")
	}
	for page, w := range map[string]string{
		xworld.DeleBook + "@" + xworld.PartBVN3:  "authority-book,header-authority",
		xworld.DelePage1 + "@" + xworld.PartBVN3: "authority-page,header-authority,voter",
		xworld.BankPage1 + "@" + xworld.PartBVN2: "authority-page,voter",
	} {
		if g := roles[page]; g != w {
			t.Fatalf("%s has roles %q, want %q (all: %v)", page, g, w, roles)
		}
	}
}

// Both orders of the two votes are the same authorization: the executor finds the transaction ready when the last required vote arrives,
// whichever it is, and the verifier reads no order into the votes (neither their order in the document nor in the principal's chain).
func TestRB9K2AddOpTheOrderOfTheVotesDoesNotMatter(t *testing.T) {
	for name, c := range map[string]struct {
		s    xworld.Timeline
		want []string // the accounts of the signature arrivals, in the document's vote order
	}{
		"the added authority's vote is delivered first": {
			xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), SecondFirst: true,
				Second: &xworld.Timeline{Sigs: []xworld.SigEvent{{Key: "K2", Version: 1, Block: 60}}}},
			[]string{xworld.DelePage1, xworld.BankPage1}},
		"the votes are delivered in one order and listed in the other": {
			xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), SwapDocumentOrder: true,
				Second: &xworld.Timeline{}},
			[]string{xworld.DelePage1, xworld.BankPage1}},
		"the before-set authority's vote is delivered first": {
			xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &xworld.Timeline{}},
			[]string{xworld.BankPage1, xworld.DelePage1}},
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := tl(t, c.s, nil)
			if err != nil {
				t.Fatal(err)
			}
			if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired || len(rep.Arrivals) != 2 {
				t.Fatalf("mode %q, arrivals %+v", rep.AuthorizationMode, rep.Arrivals)
			}
			for i, a := range c.want {
				if rep.Arrivals[i].Account != a {
					t.Fatalf("arrival %d is %s, want %s", i, rep.Arrivals[i].Account, a)
				}
			}
		})
	}
}

// The added authority's page needs two keys: the threshold of the page that votes is part of the vote the authority casts.
func TestRB9K2AddOpAddedAuthorityPageWithThresholdTwo(t *testing.T) {
	two := xworld.Timeline{Genesis: []string{"K2", "K3"}, Events: []xworld.PageEvent{{Block: 20, Threshold: 2}},
		Sigs: []xworld.SigEvent{{Key: "K2", Version: 2, Block: 62}, {Key: "K3", Version: 2, Block: 66}}}
	s := xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &two}
	rep, err := tl(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Arrivals) != 3 || rep.Arrivals[1].Account != xworld.DelePage1 || rep.Arrivals[1].Block != 66 || rep.Arrivals[2].Block != 62 {
		t.Fatalf("arrivals %+v: the cause signature (block 66) and the other counted one (block 62) are both derived on DelePage1", rep.Arrivals)
	}
	// One of the two signatures is not a vote of a threshold-2 page: the recorded vote cannot be reproduced.
	one := two
	one.Sigs = []xworld.SigEvent{{Key: "K3", Version: 2, Block: 66}}
	s.Second = &one
	_, err = tl(t, s, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
}

// Enable and Disable with two books: a disabled authority is still required by this transaction type, so its vote is counted and the
// other's is not enough alone.
func TestRB9K2EnableAndDisableWithTwoVoters(t *testing.T) {
	for name, s := range map[string]xworld.Timeline{
		"enable the delegate book, which had been disabled, both voted": {Body: authOps(enableOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &xworld.Timeline{}},
		"disable the delegate book, both voted": {Body: authOps(disableOp(xworld.DeleBook)),
			PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}, {Book: xworld.DeleBook, Disabled: true}}, Second: &xworld.Timeline{}},
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
	// Every listed authority disabled after the transaction: the all-authorities-disabled shortcut (any one vote suffices) is not the rule of
	// this type, which needs every book, and one of the two did not vote.
	_, err := tl(t, xworld.Timeline{Body: authOps(disableOp(xworld.BankBook), disableOp(xworld.DeleBook)),
		PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook, Disabled: true}, {Book: xworld.DeleBook, Disabled: true}},
		NoFirstVote:          true, Second: &xworld.Timeline{}}, nil)
	refusedWith(t, err, proofv2.StateAuthorityNotReady, "BVN1", xworld.BlockBVN1)
}

// The refusals the executor semantics define for an Add: a required book did not vote, a book rejected, a book that is neither listed nor
// added voted, and the one case the document cannot judge (the first authorities of an account that inherited its set).
func TestRB9K2AddOpAdverseVerdicts(t *testing.T) {
	for name, c := range map[string]struct {
		s    xworld.Timeline
		code string
	}{
		"only the added authority voted: the before-set's book did not": {
			xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), NoFirstVote: true, Second: &xworld.Timeline{}},
			proofv2.StateAuthorityNotReady},
		"the added authority voted reject": {
			xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(),
				Second: &xworld.Timeline{Sigs: []xworld.SigEvent{{Key: "K2", Version: 1, Block: 66, Vote: protocol.VoteTypeReject}}}},
			proofv2.StateAuthorityNotReady},
		"a book neither listed nor added voted beside the listed one": {
			xworld.Timeline{Body: authOps(enableOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook}}, Second: &xworld.Timeline{}},
			proofv2.StateVoteNotReproduced},
		"a book neither listed nor added voted although every listed authority is disabled: the any-vote shortcut is not this type's rule": {
			xworld.Timeline{Body: authOps(disableOp(xworld.BankBook)), PrincipalAuthorities: []xworld.AuthSpec{{Book: xworld.BankBook, Disabled: true}}, Second: &xworld.Timeline{}},
			proofv2.StateVoteNotReproduced},
		"the first authorities of an inheriting account, both voted": {
			xworld.Timeline{Body: authOps(addOp(xworld.BankBook), addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &xworld.Timeline{}},
			proofv2.StateExecutorOverrideUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tl(t, c.s, nil)
			refusedWith(t, err, c.code, "BVN1", xworld.BlockBVN1)
		})
	}
}

// The second voter's page is proven on ITS partition, at ITS partition's block: a page at another BVN3 block, and a tampered history, are
// refused at BVN3 and its block, not at the principal's.
func TestRB9K2TheSecondVotersPageIsJudgedAtItsOwnPartition(t *testing.T) {
	s := xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &xworld.Timeline{}}
	_, err := runX(t, xworld.Options{Timeline: &s, AltBlockPage: xworld.DelePage1}, nil)
	refusedWith(t, err, proofv2.StatePageBlockMismatch, "BVN3", xworld.BlockBVN3)

	s.Second = &xworld.Timeline{Events: []xworld.PageEvent{{Block: 40, Add: []string{"K3"}}, {Block: 50, Credits: true}}, Sigs: []xworld.SigEvent{{Key: "K2", Version: 2, Block: 66}}}
	if _, err := tl(t, s, nil); err != nil {
		t.Fatalf("the untampered world must verify: %v", err)
	}
	_, err = tl(t, s, func(ev *proofv2.Evidence) {
		h := ev.Pages[at(t, ev, xworld.DelePage1)].History
		h.Entries[2] = h.Entries[1]
	})
	refusedWith(t, err, proofv2.StateHistoryFoldMismatch, "BVN3", xworld.BlockBVN3)

	// A key added to DelePage1 after its signature arrived does not count, although the page proven at B_Y holds it.
	s.Second = &xworld.Timeline{Events: []xworld.PageEvent{{Block: 68, Add: []string{"K3"}}}, Sigs: []xworld.SigEvent{{Key: "K3", Version: 1, Block: 66}}}
	_, err = tl(t, s, nil)
	refusedWith(t, err, proofv2.StateVoteNotReproduced, "BVN1", xworld.BlockBVN1)
}

// The second vote is a member of the principal's signature chain like the first: one that is not is refused at the principal's block.
func TestRB9K2TheSecondVoteMustBeInThePrincipalsSignatureChain(t *testing.T) {
	s := xworld.Timeline{Body: authOps(addOp(xworld.DeleBook)), PrincipalAuthorities: bothBooks(), Second: &xworld.Timeline{}}
	_, err := tl(t, s, func(ev *proofv2.Evidence) { ev.Votes[1].Message = strings.Repeat("cd", 32) })
	refusedWith(t, err, proofv2.StateBlockBeforeArrival, "BVN1", xworld.BlockBVN1)
}

// A second voter does not combine with the delegated world (the vote there is cast through the delegation), and its own description
// carries only what describes its page and its vote: a field the world would silently ignore is refused.
func TestRB9K2TheSecondVoterDoesNotCombineWithOtherWorlds(t *testing.T) {
	for name, o := range map[string]xworld.Options{
		"delegated":                         {Timeline: &xworld.Timeline{Delegated: true, Second: &xworld.Timeline{}}},
		"a second voter's own second voter": {Timeline: &xworld.Timeline{Second: &xworld.Timeline{Second: &xworld.Timeline{}}}},
		"a second voter with a body":        {Timeline: &xworld.Timeline{Second: &xworld.Timeline{Body: authOps(addOp(xworld.DeleBook))}}},
		"a second voter that is delegated":  {Timeline: &xworld.Timeline{Second: &xworld.Timeline{Delegated: true}}},
		"no voter at all":                   {Timeline: &xworld.Timeline{NoFirstVote: true}},
		"an order without a second voter":   {Timeline: &xworld.Timeline{SecondFirst: true}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := xworld.Build(o); err == nil {
				t.Fatal("built")
			}
		})
	}
}
