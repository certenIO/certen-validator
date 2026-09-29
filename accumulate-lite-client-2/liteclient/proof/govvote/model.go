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
package govvote

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
type SigFact struct {
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
type ArrivalFact struct {
	ID        string
	Page      string   // the delegator page, normalised
	Authority string   // the delegate book that voted, normalised
	Path      []string // delegators beyond Page, outermost first
	Block     int64    // on Page's partition
	// Origin is the delegate's page that cast the vote, and Vote the vote, as the network recorded them.
	Origin string
	Vote   protocol.VoteType
}

// recordedVote is one authority's vote on the transaction as the network recorded it on the principal: the
// authority signature core produced when the book voted, naming the page that cast it.
type RecordedVote struct {
	ID        string
	Authority string // the book, normalised
	Origin    string // the page that cast the book's vote, normalised
	Vote      protocol.VoteType
	Block     int64 // on the principal's partition
}

// voteFacts is what the model reads.
type Facts struct {
	TxType   protocol.TransactionType
	Sigs     []SigFact
	Arrivals []ArrivalFact
	// Votes are the authorities' votes recorded on the principal.
	Votes []RecordedVote
}

// timelineSource supplies page timelines (authority_history.go).
type TimelineSource interface {
	Timeline(ctx context.Context, page string) (Timeline, error)
}

// Timeline is what the model reads of a page's history: the states it may have been in during a block, and a state
// at a version. The CLI's timeline is read from the network; the verifier's is replayed from stored evidence (States).
type Timeline interface {
	CandidatesDuring(block int64) []*protocol.KeyPage
	OfVersion(v uint64) (*protocol.KeyPage, bool)
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
	Page      string   `json:"page"`
	Path      []string `json:"path,omitempty"`
	Voted     bool     `json:"voted"`
	Vote      string   `json:"vote,omitempty"`
	Version   uint64   `json:"version,omitempty"`
	Threshold uint64   `json:"threshold,omitempty"`
	// RejectThreshold and ResponseThreshold decide the vote as much as Threshold (the accept threshold) does.
	RejectThreshold   uint64 `json:"rejectThreshold,omitempty"`
	ResponseThreshold uint64 `json:"responseThreshold,omitempty"`
	// DecidedAt is the block, on the page's own partition, in which its signature set first reached the vote -
	// the moment Accumulate's page voted. Records after it are not part of the decision (RB4-F67).
	DecidedAt int64             `json:"decidedAt,omitempty"`
	Counted   []CountedEntry    `json:"counted,omitempty"`
	Excluded  []ExcludedMessage `json:"excluded,omitempty"`

	// Delegates are the votes of the delegate books this page counted,
	// recomputed from their own signatures.
	Delegates []BookVote `json:"delegates,omitempty"`

	vote protocol.VoteType
}

// CountedEntry is one entry of a page and the vote it cast.
type CountedEntry struct {
	Entry string `json:"entry"`
	Vote  string `json:"vote"`
	By    string `json:"by"`
	// Block is where the counted message was recorded, on the page's partition.
	Block int64 `json:"block"`
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
	facts Facts
	src   TimelineSource

	pages map[string]*PageVote
	books map[string]*BookVote
}

func newVoteModel(facts Facts, src TimelineSource) *voteModel {
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
//
// A book votes with whichever of its pages decides first: core asks each page, in order, at the moment a signature
// is processed (AuthorityWillVote), and records the page that answered as the origin of the authority signature it
// produces - on the principal for the account's own authorities, on the delegator page for a delegate. So the page
// is not chosen here. It is the one the network names, and it is checked: replaying that page must reach the recorded
// vote, and no page of the book may have decided in an earlier block, or the replay and the network disagree and
// the vote is not evaluated. A book the network records no vote for did not vote; if the replay finds that one of
// its pages did, that too is a disagreement (RB4-F67).
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
		if BookOfPage(s.Signer) == book && pathEqual(s.Path, path) {
			seen[s.Signer] = true
		}
	}
	for _, a := range m.facts.Arrivals {
		if BookOfPage(a.Page) == book && pathEqual(a.Path, path) {
			seen[a.Page] = true
		}
	}
	pages := make([]string, 0, len(seen))
	for p := range seen {
		pages = append(pages, p)
	}
	sort.Slice(pages, func(i, j int) bool { return pageIndex(pages[i]) < pageIndex(pages[j]) })

	rec, err := m.recordedBookVote(book, path)
	if err != nil {
		return nil, err
	}
	bv := &BookVote{Book: book}

	if rec == nil {
		// No vote recorded: the book did not vote. Every page with records is evaluated so the evidence says what
		// each recorded, and none of them may have decided.
		for _, p := range pages {
			pv, err := m.pageVote(ctx, p, path, depth)
			if err != nil {
				return nil, err
			}
			if pv.Voted {
				return nil, &VoteUnevaluable{Page: p, Reason: fmt.Sprintf(
					"its signatures decide %s's vote (%s at block %d), but the network records no vote by %s",
					book, pv.Vote, pv.DecidedAt, book)}
			}
			bv.Pages = append(bv.Pages, *pv)
		}
		m.books[key] = bv
		return bv, nil
	}

	if BookOfPage(rec.origin) != book {
		return nil, &VoteUnevaluable{Page: rec.origin, Reason: fmt.Sprintf(
			"the network records %s's vote as cast by %s, which is not one of its pages", book, rec.origin)}
	}
	pv, err := m.pageVote(ctx, rec.origin, path, depth)
	if err != nil {
		return nil, err
	}
	if !pv.Voted || pv.vote != rec.vote {
		got := "no vote"
		if pv.Voted {
			got = pv.Vote
		}
		return nil, &VoteUnevaluable{Page: rec.origin, Reason: fmt.Sprintf(
			"the network records %s's vote as %s cast by this page (%s), but replaying its signatures reaches %s",
			book, rec.vote, rec.id, got)}
	}
	for _, p := range pages {
		if p == rec.origin {
			continue
		}
		earlier, at, err := m.pageDecidedBefore(ctx, p, path, depth, pv.DecidedAt)
		if err != nil {
			return nil, err
		}
		if earlier {
			return nil, &VoteUnevaluable{Page: p, Reason: fmt.Sprintf(
				"its signatures decide %s's vote at block %d, before %s decided it at block %d, yet the network "+
					"records %s as the page that cast it", book, at, rec.origin, pv.DecidedAt, rec.origin)}
		}
	}
	bv.Pages = append(bv.Pages, *pv)
	bv.Voted, bv.Vote, bv.By, bv.vote = true, pv.Vote, rec.origin, pv.vote
	m.books[key] = bv
	return bv, nil
}

// bookRecord is the network's record of a book's vote on one path.
type bookRecord struct {
	id     string
	origin string
	vote   protocol.VoteType
}

// recordedBookVote is the vote the network recorded for book on path: for the account's own authorities (an empty
// path) the authority signature on the principal, for a delegate the delegated vote recorded on the page it was
// delegated from. More than one record naming different pages or votes is not a record of one vote.
func (m *voteModel) recordedBookVote(book string, path []string) (*bookRecord, error) {
	var recs []bookRecord
	if len(path) == 0 {
		for _, v := range m.facts.Votes {
			if normalizeAccURL(v.Authority) == book {
				recs = append(recs, bookRecord{id: v.ID, origin: normalizeAccURL(v.Origin), vote: v.Vote})
			}
		}
	} else {
		at, beyond := path[len(path)-1], path[:len(path)-1]
		for _, a := range m.facts.Arrivals {
			if normalizeAccURL(a.Authority) == book && a.Page == at && pathEqual(a.Path, beyond) {
				if a.Origin == "" {
					return nil, &VoteUnevaluable{Page: at, Reason: fmt.Sprintf(
						"the delegated vote %s by %s names no originating page", short(a.ID), book)}
				}
				recs = append(recs, bookRecord{id: a.ID, origin: normalizeAccURL(a.Origin), vote: a.Vote})
			}
		}
	}
	if len(recs) == 0 {
		return nil, nil
	}
	for _, r := range recs[1:] {
		if r.origin != recs[0].origin || r.vote != recs[0].vote {
			return nil, &VoteUnevaluable{Page: book, Reason: fmt.Sprintf(
				"the network records more than one vote by %s (%s from %s, %s from %s)",
				book, short(recs[0].id), recs[0].origin, short(r.id), r.origin)}
		}
	}
	return &recs[0], nil
}

// pageDecidedBefore reports whether page's records, on path, decide a vote in a block before b, and in which.
func (m *voteModel) pageDecidedBefore(ctx context.Context, page string, path []string, depth int, b int64) (bool, int64, error) {
	var direct []SigFact
	for _, s := range m.facts.Sigs {
		if s.Signer == page && pathEqual(s.Path, path) && s.Block < b {
			direct = append(direct, s)
		}
	}
	var arrived []ArrivalFact
	for _, a := range m.facts.Arrivals {
		if a.Page == page && pathEqual(a.Path, path) && a.Block < b {
			arrived = append(arrived, a)
		}
	}
	if len(direct) == 0 && len(arrived) == 0 {
		return false, 0, nil
	}
	tl, err := m.src.Timeline(ctx, page)
	if err != nil {
		return false, 0, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf("its history could not be replayed: %v", err)}
	}
	eval := &pageEvaluation{m: m, page: page, path: path, depth: depth, tl: tl,
		direct: direct, arrived: arrived, holding: map[string]int{}, cands: map[string]int{}}
	for _, blk := range recordBlocks(direct, arrived) {
		d, err := eval.decideThrough(ctx, blk)
		if err != nil {
			return false, 0, err
		}
		if d.voted {
			return true, blk, nil
		}
	}
	return false, 0, nil
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
	var direct []SigFact
	for _, s := range m.facts.Sigs {
		if s.Signer == page && pathEqual(s.Path, path) {
			direct = append(direct, s)
		}
	}
	var arrived []ArrivalFact
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

	// The page votes the way Accumulate's page does: at the first block in which its active signature set reaches a
	// decision (SignerWillVote), the set being replaced whenever an entry at a newer version arrives (addSignature).
	// So the records are walked in block order and the vote is decided on each prefix. What was recorded after the
	// deciding block is not part of the decision: Accumulate records signatures on a transaction that has already
	// executed, and on another partition nothing else filters them (RB4-F67).
	eval := &pageEvaluation{m: m, page: page, path: path, depth: depth, tl: tl,
		direct: direct, arrived: arrived, holding: map[string]int{}, cands: map[string]int{}}
	var d *pageDecision
	for _, b := range recordBlocks(direct, arrived) {
		d, err = eval.decideThrough(ctx, b)
		if err != nil {
			return nil, err
		}
		if d.voted {
			break
		}
	}

	pv.Version = d.version
	pv.Threshold = acceptThreshold(d.state)
	pv.RejectThreshold = d.state.RejectThreshold
	pv.ResponseThreshold = d.state.ResponseThreshold
	pv.Excluded = append(pv.Excluded, d.excluded...)
	for _, c := range sortedEntries(d.counted) {
		pv.Counted = append(pv.Counted, CountedEntry{Entry: c.entry, Vote: c.vote.String(), By: c.by, Block: c.block})
	}
	pv.Delegates = d.delegates
	if d.voted {
		pv.Voted, pv.Vote, pv.vote, pv.DecidedAt = true, d.vote.String(), d.vote, d.through
		after := func(id string, block int64) {
			pv.Excluded = append(pv.Excluded, ExcludedMessage{By: id, Reason: fmt.Sprintf(
				"recorded at block %d, after the page's vote was decided at block %d; not part of the decision",
				block, d.through)})
		}
		for _, s := range direct {
			if s.Block > d.through {
				after(s.ID, s.Block)
			}
		}
		for _, a := range arrived {
			if a.Block > d.through {
				after(a.ID, a.Block)
			}
		}
	}
	m.pages[key] = pv
	return pv, nil
}

// recordBlocks is every block a page's records were recorded in, ascending.
func recordBlocks(direct []SigFact, arrived []ArrivalFact) []int64 {
	seen := map[int64]bool{}
	for _, s := range direct {
		seen[s.Block] = true
	}
	for _, a := range arrived {
		seen[a.Block] = true
	}
	out := make([]int64, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// pageEvaluation is one page's records on one delegation path, decided prefix by prefix.
type pageEvaluation struct {
	m       *voteModel
	page    string
	path    []string
	depth   int
	tl      Timeline
	direct  []SigFact
	arrived []ArrivalFact
	// holding and cands cache, per record and version, how many states of the page during the record's block held
	// its entry, and how many states at that version there were.
	holding map[string]int
	cands   map[string]int
}

// pageDecision is the page's signature set through one block, and what it decided.
type pageDecision struct {
	through   int64
	version   uint64
	state     *protocol.KeyPage
	counted   map[string]contribution
	excluded  []ExcludedMessage
	delegates []BookVote
	voted     bool
	vote      protocol.VoteType
}

// decideThrough decides the page's vote on the records up to and including block b.
func (e *pageEvaluation) decideThrough(ctx context.Context, b int64) (*pageDecision, error) {
	page, tl := e.page, e.tl
	var direct []SigFact
	for _, s := range e.direct {
		if s.Block <= b {
			direct = append(direct, s)
		}
	}
	var arrived []ArrivalFact
	for _, a := range e.arrived {
		if a.Block <= b {
			arrived = append(arrived, a)
		}
	}

	// The version the page's signature set stood at. A signature at a newer version replaces the set, so the newest
	// version recorded so far is the one the set held, and anything recorded at an older one was discarded.
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
	d := &pageDecision{through: b, version: v, state: state}

	var contribs []contribution
	for _, s := range direct {
		if s.Version < v {
			d.excluded = append(d.excluded, ExcludedMessage{By: s.ID, Reason: fmt.Sprintf(
				"made at version %d; a signature at version %d replaced the page's signature set", s.Version, v)})
			continue
		}
		holding, cands, err := e.keyHolding(s, v)
		if err != nil {
			return nil, err
		}
		contribs = append(contribs, contribution{
			entry: "key:" + strings.ToLower(s.KeyHash), vote: s.Vote, by: s.ID, block: s.Block,
			ambiguous: holding < cands,
		})
	}

	for i, a := range arrived {
		if !arrivalVersions[i][v] {
			d.excluded = append(d.excluded, ExcludedMessage{By: a.ID, Reason: fmt.Sprintf(
				"recorded while the page was not at version %d; a newer signature set replaced it", v)})
			continue
		}
		holding, cands, err := e.delegateHolding(a, v)
		if err != nil {
			return nil, err
		}

		// The delegate's vote, recomputed from its own signatures rather than
		// taken from the record that it was cast.
		inner := append(append([]string{}, e.path...), page)
		dv, err := e.m.bookVote(ctx, a.Authority, inner, e.depth+1)
		if err != nil {
			return nil, err
		}
		if !dv.Voted {
			return nil, &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"the chain records a vote by %s, but its own signatures do not reach a vote", a.Authority)}
		}
		contribs = append(contribs, contribution{
			entry: "delegate:" + normalizeAccURL(a.Authority), vote: dv.vote, by: a.ID, block: a.Block,
			ambiguous: holding < cands,
		})
		d.delegates = append(d.delegates, *dv)
	}

	if err := sameBlockConflict(page, contribs); err != nil {
		return nil, err
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
	d.counted = all
	d.voted, d.vote = votedAll, withAll
	return d, nil
}

// keyHolding is how many states of the page at version v during s's block held s's key and allowed the transaction,
// and how many states at v there were. A signature the page could not have accepted stops the vote.
func (e *pageEvaluation) keyHolding(s SigFact, v uint64) (int, int, error) {
	ck := fmt.Sprintf("%s|%d", s.ID, v)
	if h, ok := e.holding[ck]; ok {
		return h, e.cands[ck], nil
	}
	cands := ofVersion(e.tl.CandidatesDuring(s.Block), v)
	if len(cands) == 0 {
		return 0, 0, &VoteUnevaluable{Page: e.page, Reason: fmt.Sprintf(
			"signature %s is recorded at block %d at version %d, which the page did not hold during that block",
			short(s.ID), s.Block, v)}
	}
	kh, err := decodeHash(s.KeyHash)
	if err != nil {
		return 0, 0, &VoteUnevaluable{Page: e.page, Reason: fmt.Sprintf("signature %s: %v", short(s.ID), err)}
	}
	holding := 0
	for _, c := range cands {
		if blacklisted(c, e.m.facts.TxType) {
			continue
		}
		if _, _, ok := c.EntryByKeyHash(kh); ok {
			holding++
		}
	}
	if holding == 0 {
		return 0, 0, &VoteUnevaluable{Page: e.page, Reason: fmt.Sprintf(
			"signature %s is recorded, but no state of the page at version %d during block %d both holds "+
				"its key and allows a %v - the network accepted what the replay cannot",
			short(s.ID), v, s.Block, e.m.facts.TxType)}
	}
	e.holding[ck], e.cands[ck] = holding, len(cands)
	return holding, len(cands), nil
}

// delegateHolding is keyHolding for a delegated vote: the states that carried an entry delegating to its authority.
func (e *pageEvaluation) delegateHolding(a ArrivalFact, v uint64) (int, int, error) {
	ck := fmt.Sprintf("%s|%d", a.ID, v)
	if h, ok := e.holding[ck]; ok {
		return h, e.cands[ck], nil
	}
	authority, err := url.Parse(a.Authority)
	if err != nil {
		return 0, 0, &VoteUnevaluable{Page: e.page, Reason: fmt.Sprintf("delegated vote %s names %q", short(a.ID), a.Authority)}
	}
	holding := 0
	cands := ofVersion(e.tl.CandidatesDuring(a.Block), v)
	for _, c := range cands {
		if blacklisted(c, e.m.facts.TxType) {
			continue
		}
		if _, _, ok := c.EntryByDelegate(authority); ok {
			holding++
		}
	}
	if holding == 0 {
		return 0, 0, &VoteUnevaluable{Page: e.page, Reason: fmt.Sprintf(
			"the delegated vote of %s is recorded at block %d, but the page at version %d then carries no "+
				"entry delegating to it", a.Authority, a.Block, v)}
	}
	e.holding[ck], e.cands[ck] = holding, len(cands)
	return holding, len(cands), nil
}

// tally reduces contributions to one vote per entry: a later contribution for
// the same entry overwrites an earlier one, as the signature set does.
func tally(contribs []contribution, includeAmbiguous bool) map[string]contribution {
	out := map[string]contribution{}
	for _, c := range contribs {
		if c.ambiguous && !includeAmbiguous {
			continue
		}
		if prev, ok := out[c.entry]; ok && (prev.block > c.block || (prev.block == c.block && prev.by < c.by)) {
			// A later block's contribution replaces an earlier one, as the signature set does. Within one block
			// the order core processed them in is not recorded; when they agree (sameBlockConflict refuses the
			// case where they do not) the lowest message id is credited, so the record does not depend on the
			// order it was read in.
			continue
		}
		out[c.entry] = c
	}
	return out
}

// sameBlockConflict refuses one entry recorded with different votes in the same block: the set keeps whichever core
// processed last, and that order is not recorded, so the entry's vote - and the page's - is not known.
func sameBlockConflict(page string, contribs []contribution) error {
	type slot struct {
		entry string
		block int64
	}
	seen := map[slot]contribution{}
	for _, c := range contribs {
		k := slot{c.entry, c.block}
		if prev, ok := seen[k]; ok && prev.vote != c.vote {
			return &VoteUnevaluable{Page: page, Reason: fmt.Sprintf(
				"%s voted %s (%s) and %s (%s) in the same block %d; which one the page's set kept is not recorded",
				c.entry, prev.vote, short(prev.by), c.vote, short(c.by), c.block)}
		}
		seen[k] = c
	}
	return nil
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

	// Unused are recorded signatures that reached no authority this
	// transaction required - a delegation chain that leads nowhere the account
	// is governed from, or a page no required book owns. Reported, not dropped:
	// a signature that did not count must say why.
	Unused []ExcludedMessage `json:"unused,omitempty"`
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
	for _, s := range m.facts.Sigs {
		if _, evaluated := m.pages[s.Signer+"|"+strings.Join(s.Path, ",")]; evaluated {
			continue
		}
		reason := fmt.Sprintf("signed on %s", s.Signer)
		if len(s.Path) > 0 {
			reason += " for " + strings.Join(s.Path, " -> ")
		}
		out.Unused = append(out.Unused, ExcludedMessage{By: s.ID,
			Reason: reason + ", which reaches no authority this transaction required"})
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

// AcceptingKeys counts the distinct keys whose acceptance was counted by a page
// that voted, across every authority and every delegate that voted for one -
// the "unique valid keys" G1 reports.
func (av *AccountVote) AcceptingKeys() int {
	keys := map[string]bool{}
	var walk func(bv BookVote)
	walk = func(bv BookVote) {
		for _, pv := range bv.Pages {
			if !pv.Voted {
				continue
			}
			for _, c := range pv.Counted {
				if c.Vote == protocol.VoteTypeAccept.String() && strings.HasPrefix(c.Entry, "key:") {
					keys[c.Entry] = true
				}
			}
			// The keys that signed through delegation are on the delegate
			// books' pages, and count as much as the principal's own.
			for _, d := range pv.Delegates {
				if d.Voted && d.vote == protocol.VoteTypeAccept {
					walk(d)
				}
			}
		}
	}
	for _, a := range av.Authorities {
		walk(a.Vote)
	}
	return len(keys)
}

// Describe names each required authority, how it voted and which page decided.
func (av *AccountVote) Describe() string {
	parts := make([]string, 0, len(av.Authorities))
	for _, a := range av.Authorities {
		switch {
		case a.Vote.Voted:
			parts = append(parts, fmt.Sprintf("%s: %s (by %s)", a.Authority, a.Vote.Vote, a.Vote.By))
		case len(a.Vote.Pages) == 0:
			parts = append(parts, fmt.Sprintf("%s: no page recorded a vote", a.Authority))
		default:
			var pages []string
			for _, pv := range a.Vote.Pages {
				pages = append(pages, fmt.Sprintf("%s v%d %d/%d", pv.Page, pv.Version, countAccepts(pv), pv.Threshold))
			}
			parts = append(parts, fmt.Sprintf("%s: did not vote (%s)", a.Authority, strings.Join(pages, ", ")))
		}
	}
	return strings.Join(parts, "; ")
}

func countAccepts(pv PageVote) int {
	n := 0
	for _, c := range pv.Counted {
		if c.Vote == protocol.VoteTypeAccept.String() {
			n++
		}
	}
	return n
}

// AccountAuthority is one entry of an account's authority set.
type AccountAuthority struct {
	URL string `json:"url"`

	// Disabled means auth checks are skipped for this authority unless the
	// transaction type requires authorization (Body.Type().RequireAuthorization()),
	// which is the caller's to decide, so it is carried rather than filtered.
	Disabled bool `json:"disabled,omitempty"`
}

// bookOfPage returns the key book a page belongs to: acc://foo.acme/book/1 ->
// acc://foo.acme/book.
func BookOfPage(page string) string {
	p := normalizeAccURL(page)
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// SignerPages lists, in canonical order, every page whose counted signatures
// made up the vote - through delegates as well. It is every signer account the
// proof of this vote needs an inclusion leg for.
func (av *AccountVote) SignerPages() []string {
	seen := map[string]bool{}
	var walk func(bv BookVote)
	walk = func(bv BookVote) {
		for _, pv := range bv.Pages {
			if !pv.Voted {
				continue
			}
			for _, c := range pv.Counted {
				if strings.HasPrefix(c.Entry, "key:") {
					seen[pv.Page] = true
				}
			}
			for _, d := range pv.Delegates {
				walk(d)
			}
		}
	}
	for _, a := range av.Authorities {
		walk(a.Vote)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Evaluate is the authority vote on a transaction: every authority account required (authorities, plus extra the
// transaction itself names; disabled authorities count only when ignoreDisabled), each decided from facts - the
// signatures, delegated votes and recorded votes - over the page histories src supplies.
func Evaluate(ctx context.Context, facts Facts, src TimelineSource, account string, authorities []AccountAuthority,
	extra []string, ignoreDisabled bool) (*AccountVote, error) {
	return newVoteModel(facts, src).accountVote(ctx, account, authorities, extra, ignoreDisabled)
}

// EvaluatePage is one page's vote on one delegation path, decided from facts over the page histories src supplies.
func EvaluatePage(ctx context.Context, facts Facts, src TimelineSource, page string, path []string) (*PageVote, error) {
	return newVoteModel(facts, src).pageVote(ctx, page, path, 0)
}
