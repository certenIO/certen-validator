// Copyright 2026 Certen Protocol
//
// THE AUTHORITY VOTE, AS ACCUMULATE-CORE COUNTS IT.
//
// # WHAT WAS WRONG
//
// Resolution counted distinct entries of the principal's page satisfied by any
// signature, however it arrived. That is not how the network decides, and it
// accepted authorizations the network would not have:
//
//   - A delegate page's own threshold was never applied. One signature from a
//     2-of-2 delegate page satisfied the principal's delegate entry, although
//     the delegate votes - and forwards its vote - only when its own threshold
//     is met (g1_delegate_threshold_test.go).
//   - A signature's vote was never read, so a key that voted REJECT counted as
//     an acceptance.
//   - Every page was judged at the principal's execution block, in the
//     principal's partition's block numbers, although each page is judged when
//     the message reaches it, on its own partition.
//
// # WHAT ACCUMULATE-CORE DOES (internal/core/execute/v2/block)
//
//	sig_user.go verifySigner       a signature is checked against its signer page
//	                               AS IT STANDS WHEN THE SIGNATURE IS PROCESSED:
//	                               version, key membership, blacklist. It reaches
//	                               the page's signature chain only if it passes.
//	sig_common.go addSignature     a page's signature set for a transaction holds
//	                               ONE version; a signature at a newer version
//	                               replaces the set.
//	transaction.go SignerWillVote  votes are tallied PER DELEGATION PATH; a page
//	                               votes on a path once its votes there reach the
//	                               response threshold and then the accept (or
//	                               reject) threshold, or it abstains when neither
//	                               can be reached.
//	sig_authority.go               a delegate's vote reaches the delegator page as
//	                               an authority signature, is checked against that
//	                               page's delegate entry when it arrives, and is
//	                               recorded there with Path = the delegators
//	                               beyond it (Baikonur) - so at the outermost page
//	                               delegated votes and direct signatures share a
//	                               path and combine.
//	AuthorityWillVote              a book votes with the first of its pages that
//	                               votes.
//	userTransactionIsReady         every required authority of the principal, AS
//	                               OF EXECUTION, must vote accept.
//
// # HOW THIS MIRRORS IT
//
// Every fact here is one the chain recorded: a signature or a delegated vote on
// the signature chain of the page that received it, with the block it was
// recorded in (on that page's own partition). Each page is judged in the states
// it could have held during that block; the signer version, which core required
// to match, picks among them.
//
// A recorded fact that this model cannot reconcile with the page's replayed
// history is NOT a rejection. The network accepted it, so the disagreement is
// ours - the proof reports the vote as unevaluable. Where more than one state
// is possible within a block and the choice could change a vote, the vote is
// unevaluable too; where it cannot, the vote stands.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// sigFact is one user signature, as the chain recorded it on its signer page.
type sigFact struct {
	ID      string
	Signer  string   // the signing page, normalised
	Path    []string // delegators, outermost first, normalised
	Version uint64
	KeyHash string // lower hex
	Vote    protocol.VoteType
	Block   int64 // on the signer page's partition
}

// arrivalFact is one delegated vote, as the chain recorded it on the delegator
// page that received it.
type arrivalFact struct {
	ID        string
	Page      string   // the delegator page, normalised
	Authority string   // the delegate book that voted, normalised
	Path      []string // delegators beyond Page, outermost first
	Block     int64    // on Page's partition
}

// voteFacts is what the model reads.
type voteFacts struct {
	TxType   protocol.TransactionType
	Sigs     []sigFact
	Arrivals []arrivalFact
}

// timelineSource supplies page timelines (authority_history.go).
type timelineSource interface {
	Timeline(ctx context.Context, page string) (*pageTimeline, error)
}

// VoteUnevaluable reports a vote the chain records but this model could not
// re-establish. It is never a governance verdict.
type VoteUnevaluable struct {
	Page   string
	Reason string
}

func (e *VoteUnevaluable) Error() string {
	return fmt.Sprintf("the vote of %s could not be evaluated: %s", e.Page, e.Reason)
}

// PageVote is one page's vote on one delegation path, with its evidence.
type PageVote struct {
	Page      string            `json:"page"`
	Path      []string          `json:"path,omitempty"`
	Voted     bool              `json:"voted"`
	Vote      string            `json:"vote,omitempty"`
	Version   uint64            `json:"version,omitempty"`
	Threshold uint64            `json:"threshold,omitempty"`
	Counted   []CountedEntry    `json:"counted,omitempty"`
	Excluded  []ExcludedMessage `json:"excluded,omitempty"`

	vote protocol.VoteType
}

// CountedEntry is one entry of a page and the vote it cast.
type CountedEntry struct {
	Entry string `json:"entry"`
	Vote  string `json:"vote"`
	By    string `json:"by"`
}

// ExcludedMessage is a recorded signature or vote that did not count, and why.
type ExcludedMessage struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
}

// BookVote is a book's vote: the vote of its first page that voted.
type BookVote struct {
	Book  string     `json:"book"`
	Voted bool       `json:"voted"`
	Vote  string     `json:"vote,omitempty"`
	By    string     `json:"by,omitempty"`
	Pages []PageVote `json:"pages,omitempty"`

	vote protocol.VoteType
}

type voteModel struct {
	facts voteFacts
	src   timelineSource

	pages map[string]*PageVote
	books map[string]*BookVote
}

func newVoteModel(facts voteFacts, src timelineSource) *voteModel {
	return &voteModel{facts: facts, src: src, pages: map[string]*PageVote{}, books: map[string]*BookVote{}}
}

// contribution is one fact's effect on a page's tally.
type contribution struct {
	entry     string
	vote      protocol.VoteType
	by        string
	block     int64
	ambiguous bool // true when a state that would exclude it was possible
}

// bookVote returns a book's vote on a delegation path.
func (m *voteModel) bookVote(ctx context.Context, book string, path []string, depth int) (*BookVote, error) {
	book = normalizeAccURL(book)
	key := book + "|" + strings.Join(path, ",")
	if bv, ok := m.books[key]; ok {
		return bv, nil
	}

	// The pages of this book that could have voted on this path are the ones a
	// fact names. A page with nothing recorded does not vote.
	seen := map[string]bool{}
	for _, s := range m.facts.Sigs {
		if bookOfPage(s.Signer) == book && pathEqual(s.Path, path) {
			seen[s.Signer] = true
		}
	}
	for _, a := range m.facts.Arrivals {
		if bookOfPage(a.Page) == book && pathEqual(a.Path, path) {
			seen[a.Page] = true
		}
	}
	pages := make([]string, 0, len(seen))
	for p := range seen {
		pages = append(pages, p)
	}
	sort.Slice(pages, func(i, j int) bool { return pageIndex(pages[i]) < pageIndex(pages[j]) })

	bv := &BookVote{Book: book}
	for _, p := range pages {
		pv, err := m.pageVote(ctx, p, path, depth)
		if err != nil {
			return nil, err
		}
		bv.Pages = append(bv.Pages, *pv)
		if pv.Voted {
			bv.Voted, bv.Vote, bv.By, bv.vote = true, pv.Vote, p, pv.vote
			break
		}
	}
	m.books[key] = bv
	return bv, nil
}

// pageVote returns a page's vote on a delegation path.
func (m *voteModel) pageVote(ctx context.Context, page string, path []string, depth int) (*PageVote, error) {
	page = normalizeAccURL(page)
	key := page + "|" + strings.Join(path, ",")
	if pv, ok := m.pages[key]; ok {
		return pv, nil
	}
	if depth > protocol.DelegationDepthLimit {
		return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
			"delegation deeper than Accumulate's limit of %d", protocol.DelegationDepthLimit)}
	}

	pv := &PageVote{Page: page, Path: path}
	var direct []sigFact
	for _, s := range m.facts.Sigs {
		if s.Signer == page && pathEqual(s.Path, path) {
			direct = append(direct, s)
		}
	}
	var arrived []arrivalFact
	for _, a := range m.facts.Arrivals {
		if a.Page == page && pathEqual(a.Path, path) {
			arrived = append(arrived, a)
		}
	}
	if len(direct) == 0 && len(arrived) == 0 {
		m.pages[key] = pv
		return pv, nil
	}

	tl, err := m.src.Timeline(ctx, page)
	if err != nil {
		return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf("its history could not be replayed: %v", err)}
	}

	// The version the page's signature set stood at. A signature at a newer
	// version replaces the set, so the newest version recorded is the one that
	// voted, and anything recorded at an older one was discarded.
	var v uint64
	for _, s := range direct {
		if s.Version > v {
			v = s.Version
		}
	}
	arrivalVersions := make([]map[uint64]bool, len(arrived))
	for i, a := range arrived {
		arrivalVersions[i] = map[uint64]bool{}
		for _, c := range tl.CandidatesDuring(a.Block) {
			arrivalVersions[i][c.Version] = true
		}
		if len(arrivalVersions[i]) == 0 {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"the delegated vote %s was recorded at block %d, before the page existed", short(a.ID), a.Block)}
		}
		if len(direct) == 0 {
			for ver := range arrivalVersions[i] {
				if ver > v {
					v = ver
				}
			}
		}
	}

	state, ok := tl.OfVersion(v)
	if !ok {
		return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
			"the chain records messages at version %d, a version its replayed history never reached", v)}
	}
	pv.Version = v

	var contribs []contribution
	for _, s := range direct {
		if s.Version < v {
			pv.Excluded = append(pv.Excluded, ExcludedMessage{By: s.ID, Reason: fmt.Sprintf(
				"made at version %d; a signature at version %d replaced the page's signature set", s.Version, v)})
			continue
		}
		cands := ofVersion(tl.CandidatesDuring(s.Block), v)
		if len(cands) == 0 {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"signature %s is recorded at block %d at version %d, which the page did not hold during that block",
				short(s.ID), s.Block, v)}
		}
		kh, err := decodeHash(s.KeyHash)
		if err != nil {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf("signature %s: %v", short(s.ID), err)}
		}
		holding := 0
		for _, c := range cands {
			if blacklisted(c, m.facts.TxType) {
				continue
			}
			if _, _, ok := c.EntryByKeyHash(kh); ok {
				holding++
			}
		}
		if holding == 0 {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"signature %s is recorded, but no state of the page at version %d during block %d both holds "+
					"its key and allows a %v - the network accepted what the replay cannot",
				short(s.ID), v, s.Block, m.facts.TxType)}
		}
		contribs = append(contribs, contribution{
			entry: "key:" + strings.ToLower(s.KeyHash), vote: s.Vote, by: s.ID, block: s.Block,
			ambiguous: holding < len(cands),
		})
	}

	for i, a := range arrived {
		if !arrivalVersions[i][v] {
			pv.Excluded = append(pv.Excluded, ExcludedMessage{By: a.ID, Reason: fmt.Sprintf(
				"recorded while the page was not at version %d; a newer signature set replaced it", v)})
			continue
		}
		authority, err := url.Parse(a.Authority)
		if err != nil {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf("delegated vote %s names %q", short(a.ID), a.Authority)}
		}
		holding := 0
		cands := ofVersion(tl.CandidatesDuring(a.Block), v)
		for _, c := range cands {
			if blacklisted(c, m.facts.TxType) {
				continue
			}
			if _, _, ok := c.EntryByDelegate(authority); ok {
				holding++
			}
		}
		if holding == 0 {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"the delegated vote of %s is recorded at block %d, but the page at version %d then carries no "+
					"entry delegating to it", a.Authority, a.Block, v)}
		}

		// The delegate's vote, recomputed from its own signatures rather than
		// taken from the record that it was cast.
		inner := append(append([]string{}, path...), page)
		dv, err := m.bookVote(ctx, a.Authority, inner, depth+1)
		if err != nil {
			return nil, err
		}
		if !dv.Voted {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"the chain records a vote by %s, but its own signatures do not reach a vote", a.Authority)}
		}
		contribs = append(contribs, contribution{
			entry: "delegate:" + normalizeAccURL(a.Authority), vote: dv.vote, by: a.ID, block: a.Block,
			ambiguous: holding < len(cands),
		})
	}

	// Decide with every ambiguous contribution counted and with none. If the
	// two agree the vote stands; if they do not, which state the page was in
	// decides the vote and it is not ours to guess.
	all := tally(contribs, true)
	definite := tally(contribs, false)
	withAll, votedAll := decideVote(state, all)
	withNone, votedNone := decideVote(state, definite)
	if votedAll != votedNone || (votedAll && withAll != withNone) {
		return nil, &VoteUnevaluable{Page: page, Reason: "within one block the page held states that " +
			"decide its vote differently, and which one each message saw is not recorded"}
	}

	pv.Threshold = acceptThreshold(state)
	for _, c := range sortedEntries(all) {
		pv.Counted = append(pv.Counted, CountedEntry{Entry: c.entry, Vote: c.vote.String(), By: c.by})
	}
	if votedAll {
		pv.Voted, pv.Vote, pv.vote = true, withAll.String(), withAll
	}
	m.pages[key] = pv
	return pv, nil
}

// tally reduces contributions to one vote per entry: a later contribution for
// the same entry overwrites an earlier one, as the signature set does.
func tally(contribs []contribution, includeAmbiguous bool) map[string]contribution {
	out := map[string]contribution{}
	for _, c := range contribs {
		if c.ambiguous && !includeAmbiguous {
			continue
		}
		if prev, ok := out[c.entry]; ok && prev.block > c.block {
			continue
		}
		out[c.entry] = c
	}
	return out
}

// decideVote mirrors SignerWillVote for one path.
func decideVote(page *protocol.KeyPage, entries map[string]contribution) (protocol.VoteType, bool) {
	votes := map[protocol.VoteType]uint64{}
	var all uint64
	for _, c := range entries {
		votes[c.vote]++
		all++
	}
	tAccept := acceptThreshold(page)
	tReject := page.RejectThreshold
	if tReject == 0 {
		tReject = tAccept
	}
	if all < page.ResponseThreshold {
		return 0, false
	}
	if votes[protocol.VoteTypeAccept] >= tAccept {
		return protocol.VoteTypeAccept, true
	}
	if votes[protocol.VoteTypeReject] >= tReject {
		return protocol.VoteTypeReject, true
	}
	undecided := uint64(len(page.Keys)) - all
	couldAccept := votes[protocol.VoteTypeAccept]+undecided >= tAccept
	couldReject := votes[protocol.VoteTypeReject]+undecided >= tReject
	if !couldAccept && !couldReject {
		return protocol.VoteTypeAbstain, true
	}
	return 0, false
}

// acceptThreshold is GetSignatureThreshold: an unset threshold means one.
func acceptThreshold(p *protocol.KeyPage) uint64 {
	if p.AcceptThreshold == 0 {
		return 1
	}
	return p.AcceptThreshold
}

func blacklisted(p *protocol.KeyPage, typ protocol.TransactionType) bool {
	bit, ok := typ.AllowedTransactionBit()
	return ok && p.TransactionBlacklist.IsSet(bit)
}

func ofVersion(states []*protocol.KeyPage, v uint64) []*protocol.KeyPage {
	var out []*protocol.KeyPage
	for _, s := range states {
		if s.Version == v {
			out = append(out, s)
		}
	}
	return out
}

func sortedEntries(m map[string]contribution) []contribution {
	out := make([]contribution, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].entry < out[j].entry })
	return out
}

func decodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) == 0 || len(b) > 32 {
		return nil, fmt.Errorf("key hash %q is not a hash", s)
	}
	return b, nil
}

func pathEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalizeAccURL(a[i]) != normalizeAccURL(b[i]) {
			return false
		}
	}
	return true
}

// pageIndex is a page's number within its book: acc://x.acme/book/2 -> 2.
func pageIndex(page string) uint64 {
	i := strings.LastIndex(page, "/")
	n, err := strconv.ParseUint(page[i+1:], 10, 64)
	if err != nil {
		return ^uint64(0)
	}
	return n
}

// AuthorityVote is one required authority's vote.
type AuthorityVote struct {
	Authority string   `json:"authority"`
	Disabled  bool     `json:"disabled,omitempty"`
	Extra     bool     `json:"extra,omitempty"`
	Vote      BookVote `json:"vote"`
}

// AccountVote answers what G1 asks: did every authority that had to vote,
// vote to accept?
type AccountVote struct {
	Account     string          `json:"account"`
	Authorities []AuthorityVote `json:"authorities"`
	Satisfied   bool            `json:"satisfied"`
}

// accountVote mirrors userTransactionIsReady. The authority set is the
// principal's AS OF EXECUTION; a disabled authority is skipped unless the
// transaction type requires authorization; authorities the transaction itself
// names are always required.
func (m *voteModel) accountVote(ctx context.Context, account string, authorities []AccountAuthority,
	extra []string, ignoreDisabled bool) (*AccountVote, error) {

	out := &AccountVote{Account: normalizeAccURL(account), Satisfied: true}
	seen := map[string]bool{}
	require := func(a AccountAuthority, isExtra bool) error {
		u := normalizeAccURL(a.URL)
		if seen[u] {
			return nil
		}
		seen[u] = true
		bv, err := m.bookVote(ctx, u, nil, 0)
		if err != nil {
			return err
		}
		out.Authorities = append(out.Authorities, AuthorityVote{Authority: u, Disabled: a.Disabled, Extra: isExtra, Vote: *bv})
		if !bv.Voted || bv.vote != protocol.VoteTypeAccept {
			out.Satisfied = false
		}
		return nil
	}

	if len(authorities) == 0 {
		return nil, fmt.Errorf("%s has no authority set at execution, so there is nothing that could have "+
			"authorized it", out.Account)
	}
	for _, a := range authorities {
		if a.Disabled && !ignoreDisabled {
			continue
		}
		if err := require(a, false); err != nil {
			return nil, err
		}
	}
	for _, e := range extra {
		if err := require(AccountAuthority{URL: e}, true); err != nil {
			return nil, err
		}
	}
	if len(out.Authorities) == 0 {
		// Every authority is disabled and the type does not require
		// authorization: core still requires one signature at least
		// (voters non-empty), which the caller checks against the recorded
		// votes. A verdict here would be a guess.
		return nil, fmt.Errorf("every authority of %s is disabled; which signature satisfied it is not "+
			"something this model decides", out.Account)
	}
	return out, nil
}
