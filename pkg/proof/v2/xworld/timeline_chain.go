// Copyright 2026 Certen Protocol
//
// The delegation-chain variant of the delegated timeline world (RB9 verifier round VA, DEF-3: delegate chains of depth 2 and 20 verified,
// 21 refused). Timeline.DelegateDepth = N > 1 puts N delegations between the authority book and the key: BankPage2 (P0, BVN2) holds a
// delegate entry to book 1, the page of book k (Pk, BVN3) holds a delegate entry to book k+1, and PN (DelePage1 of DeleBook) holds the key.
// The key signature is wrapped in N delegated signatures (P0 outermost); the authority signature of book k (Origin Pk, Delegator
// [P(k-1) .. P0]) is recorded on P(k-1), in blocks that ascend toward P0: the block of Pk is 66-k. Depth 1 is newDelegatedWorld, unchanged.
package xworld

import (
	"fmt"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// midPage is the page and book of an intermediate delegation (1 <= k < N).
type midPage struct {
	book, pageURL string
	page          scriptedPage
	hop           proofv2.VoteHop // the authority signature recorded ON this page
}

func midBookURL(k int) string { return fmt.Sprintf("acc://pv2-dele-5.acme/mid%d", k) }

// chainURLs returns the pages P0..PN and the books of P1..PN.
func chainURLs(n int) (pages, books []string) {
	pages = append(pages, BankPage2)
	books = append(books, BankBook)
	for k := 1; k < n; k++ {
		books = append(books, midBookURL(k))
		pages = append(pages, midBookURL(k)+"/1")
	}
	books = append(books, DeleBook)
	pages = append(pages, DelePage1)
	return
}

func newChainDelegatedWorld(t Timeline, txn *protocol.Transaction, txHash []byte) *delegatedWorld {
	n := t.DelegateDepth
	pages, books := chainURLs(n)
	d := &delegatedWorld{authBlock: 66, keyBlock: uint64(66 - n)}
	blockOf := func(k int) uint64 { return uint64(66 - k) }

	// The key signature: K2 on PN, delegated through P(N-1) ... P0 (P0 outermost).
	b := new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(mustURL(pages[n])).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(keyOf("K2").priv)
	for k := 0; k < n; k++ {
		b = b.AddDelegator(mustURL(pages[k]))
	}
	keySig := must(b.Sign(txHash))
	if got := delegatorPages(keySig); len(got) != n || got[0].String() != pages[0] {
		// the builder lists the first delegator added innermost: add them the other way round
		b = new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(mustURL(pages[n])).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(keyOf("K2").priv)
		for k := n - 1; k >= 0; k-- {
			b = b.AddDelegator(mustURL(pages[k]))
		}
		keySig = must(b.Sign(txHash))
		if got := delegatorPages(keySig); len(got) != n || got[0].String() != pages[0] {
			panic("xworld: cannot build the delegated key signature with the outermost delegator first")
		}
	}
	keyMsg := (&messaging.SignatureMessage{Signature: keySig, TxID: txn.ID()}).Hash()

	// auth[k], k = N..1: the vote of book k, cast by Pk, recorded on P(k-1).
	auth := make([]*protocol.AuthoritySignature, n+1)
	msg := make([][32]byte, n+1)
	prev := keyMsg
	for k := n; k >= 1; k-- {
		var del []*url.URL
		for j := k - 1; j >= 0; j-- {
			del = append(del, mustURL(pages[j])) // innermost first: [P(k-1) .. P0]
		}
		auth[k] = &protocol.AuthoritySignature{Origin: mustURL(pages[k]), Authority: mustURL(books[k]), Vote: protocol.VoteTypeAccept, TxID: txn.ID(),
			Cause: mustURL(pages[k]).WithTxID(prev), Delegator: del}
		msg[k] = (&messaging.SignatureMessage{Signature: auth[k], TxID: txn.ID()}).Hash()
		prev = msg[k]
	}

	// The pages: P(k) holds a delegate entry to book k+1 and the message of auth[k+1] in its signature chain; PN holds the key.
	d.p3 = scriptPage(DelePage1, DeleBook, []entry{{key: "K2"}}, nil, keyMsg[:], blockOf(n), "dele")
	d.p2 = scriptPage(BankPage2, BankBook, []entry{{delegate: books[1]}}, t.DelegatorEvents, msg[1][:], blockOf(0), "bank2")
	d.hopAuth = d.p2.hop(BankPage2, auth[1], blockOf(0))
	d.hopKey = d.p3.hop(DelePage1, keySig, blockOf(n))
	for k := 1; k < n; k++ {
		mp := midPage{book: books[k], pageURL: pages[k]}
		mp.page = scriptPage(pages[k], books[k], []entry{{delegate: books[k+1]}}, nil, msg[k+1][:], blockOf(k), fmt.Sprintf("mid%d", k))
		mp.hop = mp.page.hop(pages[k], auth[k+1], blockOf(k))
		d.mids = append(d.mids, mp)
	}
	return d
}

// midHistory is the scripted history of an intermediate page of a chain, nil for any other URL.
func midHistory(dw *delegatedWorld, u string) *proofv2.PageHistory {
	for _, mp := range dw.mids {
		if mp.pageURL == u {
			return mp.page.history
		}
	}
	return nil
}

// delegatorPages returns the delegator pages a signature is wrapped in, outermost first.
func delegatorPages(sig protocol.Signature) []*url.URL {
	var out []*url.URL
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			return out
		}
		out = append(out, d.Delegator)
		sig = d.Signature
	}
}
