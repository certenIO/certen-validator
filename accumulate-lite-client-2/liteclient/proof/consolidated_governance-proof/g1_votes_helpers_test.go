// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The vote model is govvote's and its own tests are there. These are the helpers the CLI's remaining vote tests -
// the authority set, the Kermit corpus, the verdict - use: page timelines of the CLI's own type, and facts.

type memTimelines map[string]*pageTimeline

func (m memTimelines) Timeline(_ context.Context, page string) (govvote.Timeline, error) {
	tl, ok := m[normalizeAccURL(page)]
	if !ok {
		return nil, fmt.Errorf("no history for %s", page)
	}
	return tl, nil
}

// vPage is a page state: keys by name, delegates by book, thresholds.
type vPage struct {
	version, accept, reject, response uint64
	keys                              []string
	delegates                         []string
	deny                              []protocol.TransactionType
}

func (p vPage) build(t *testing.T, url string) *protocol.KeyPage {
	t.Helper()
	kp := &protocol.KeyPage{Url: mustURL(t, url), Version: p.version, AcceptThreshold: p.accept,
		RejectThreshold: p.reject, ResponseThreshold: p.response}
	for _, k := range p.keys {
		kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: keyHash(k)})
	}
	for _, d := range p.delegates {
		kp.AddKeySpec(&protocol.KeySpec{Delegate: mustURL(t, d)})
	}
	for _, typ := range p.deny {
		bit, _ := typ.AllowedTransactionBit()
		if kp.TransactionBlacklist == nil {
			kp.TransactionBlacklist = new(protocol.AllowedTransactions)
		}
		kp.TransactionBlacklist.Set(bit)
	}
	return kp
}

// timeline builds a page's history: states[i] begins at blocks[i].
func timeline(t *testing.T, url string, blocks []int64, states ...vPage) *pageTimeline {
	t.Helper()
	tl := &pageTimeline{Page: normalizeAccURL(url)}
	for i, s := range states {
		tl.States = append(tl.States, timedState{Block: blocks[i], Page: s.build(t, url)})
	}
	return tl
}

func kh(name string) string { return strings.ToLower(fmt.Sprintf("%x", keyHash(name))) }

func sig(signer, key string, version uint64, block int64, path ...string) sigFact {
	return sigFact{ID: fmt.Sprintf("sig-%s-%s-%d", key, signer, block), Signer: normalizeAccURL(signer),
		Path: normPath(path), Version: version, KeyHash: kh(key), Vote: protocol.VoteTypeAccept, Block: block}
}

func normPath(p []string) []string {
	out := make([]string, len(p))
	for i, s := range p {
		out[i] = normalizeAccURL(s)
	}
	return out
}

func recorded(book, origin string, block int64) recordedVote {
	return recordedVote{ID: "vote-" + origin, Authority: normalizeAccURL(book), Origin: normalizeAccURL(origin),
		Vote: protocol.VoteTypeAccept, Block: block}
}

func requireSatisfied(t *testing.T, av *AccountVote, err error, want bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if av.Satisfied != want {
		t.Fatalf("satisfied = %v, want %v: %+v", av.Satisfied, want, av)
	}
}

func requireUnevaluable(t *testing.T, err error) {
	t.Helper()
	var u *VoteUnevaluable
	if !errors.As(err, &u) {
		t.Fatalf("want an unevaluable vote, got %v", err)
	}
	t.Logf("unevaluable: %v", err)
}
