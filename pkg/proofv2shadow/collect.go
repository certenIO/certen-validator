// Copyright 2026 Certen Protocol
//
// Capturing every governing page of an intent at its own partition's block (docs/proof/G1_CROSS_PARTITION.md D2, D6).
//
// The transaction's partition X keeps its block B. Every other partition Y that holds a governing account is read as of one
// block B_Y, chosen from the Directory's record of Y's anchors (proofv2.SelectPartitionBlock) and confirmed by the anchor the
// Directory executed for it; each page's receipt must pass through that anchor's state root. The governing set itself is
// derived from the proven pages as they are read, so it is the set at the proven block, not at discovery.

package proofv2shadow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	acerrors "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// CaptureVersion names the stored layout of a capture. A row stored before it is a bare JSON array of pages (version 1).
const CaptureVersion = "capture/2"

// CapturedPage is a captured page and the partition block it was read at. Block is a capture-time record: the verifier
// derives the block from the partition's anchor and never reads it.
type CapturedPage struct {
	proofv2.PageState
	Block uint64 `json:"block,omitempty"`
}

// PartitionCapture is where one partition's pages were read: its block, and the anchor the Directory executed for it.
type PartitionCapture struct {
	Partition string `json:"partition"` // the partition ID as the routing table spells it
	Block     uint64 `json:"block"`
	Index     uint64 `json:"index,omitempty"`   // the anchor's position in the Directory's anchor(<partition>)-root chain (0 for the transaction's own partition)
	DNBlock   uint64 `json:"dnBlock,omitempty"` // the Directory block that executed the anchor
	StateRoot string `json:"stateRoot"`         // hex32: the partition's state tree root at Block, which every page passes through
	RootChain string `json:"rootChain,omitempty"`
	AnchorTx  string `json:"anchorTx,omitempty"` // hex32: the anchor transaction the Directory executed (foreign partitions)
}

// Capture is everything captured at discovery for one intent.
type Capture struct {
	Version    string                      `json:"version"`
	Principal  string                      `json:"principal"`
	Partition  string                      `json:"partition"` // the transaction's partition X
	Block      uint64                      `json:"block"`     // B
	Partitions map[string]PartitionCapture `json:"partitions"`
	Pages      []CapturedPage              `json:"pages"`
	Votes      []proofv2.Vote              `json:"votes,omitempty"` // the counted votes, without their receipts (added when the evidence is built)
	Notes      []string                    `json:"notes,omitempty"` // named states that did not stop the capture

	// Absent are the authorities the principal lists (or a vote names) that do not exist at the block they were read at, each with the
	// partition and block the absence was judged at (g1_authority_missing). The executor allows a disabled one, so a 2.0 document is
	// built exactly as before; no receipt proves an account absent, so evidence 2.1 - whose verifier and binding require every listed
	// authority to be a proven book - is refused by name from them (Assembly) instead of failing later at the binding (RB9-C2-F1).
	Absent []proofv2.NamedState `json:"absentAuthorities,omitempty"`

	// Transaction is the governed transaction (binary, hex) and Sequenced maps each sequenced vote's message to the hash of the
	// SequencedMessage its source partition recorded in its synthetic ledger: what the timeline members of evidence 2.1 are built from
	// (RB9 Phase C1b-2). A capture without a Transaction is a capture made before them; its votes cannot be re-evaluated.
	Transaction string            `json:"transaction,omitempty"`
	Sequenced   map[string]string `json:"sequenced,omitempty"`
}

// DecodeCapture reads a stored capture: this version's object, or a version 1 bare array of pages captured on the
// transaction's partition alone.
func DecodeCapture(raw []byte) (*Capture, error) {
	t := strings.TrimSpace(string(raw))
	if strings.HasPrefix(t, "[") {
		var pages []*proofv2.PageState
		if err := json.Unmarshal(raw, &pages); err != nil {
			return nil, err
		}
		c := &Capture{Version: "capture/1"}
		for _, p := range pages {
			c.Pages = append(c.Pages, CapturedPage{PageState: *p})
		}
		return c, nil
	}
	c := new(Capture)
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if c.Version != CaptureVersion {
		return nil, fmt.Errorf("capture version %q is not %q", c.Version, CaptureVersion)
	}
	return c, nil
}

// Collector captures one intent. Its members are the network, so a test can stand a partitioned network behind them.
type Collector struct {
	// Route names the partition (ID as the routing table spells it) an account lives on.
	Route func(ctx context.Context, account string) (string, error)
	// Block is the transaction's own block B, available as soon as the transaction executed.
	Block func(ctx context.Context, account, tx string) (uint64, error)
	// Position is B with the Directory block that executed the partition's anchor for it and the partition's state root at B;
	// it is available once the Directory has recorded that anchor, so it is asked until then.
	Position func(ctx context.Context, account, tx, partitionLabel string) (*proofv2.TxPosition, error)
	// Facts reads who approved the transaction.
	Facts func(ctx context.Context, account, tx string) (*TxFacts, error)
	// Log is the Directory's record of each partition's anchors.
	Log proofv2.AnchorLog
	// Page reads an account as of a block on its partition, waiting within the partition's retention for it to be servable.
	Page func(ctx context.Context, account, partition string, block uint64) (*proofv2.PageState, error)
	// Anchor confirms the Directory executed the partition's anchor for the selected block and returns its transaction hash.
	Anchor func(ctx context.Context, pb *proofv2.PartitionBlock) ([32]byte, error)
	// Arrival is the block of the account's partition at which the signature message arrived.
	Arrival func(ctx context.Context, id *url.TxID) (partition string, block uint64, err error)
	// Trace follows a vote's cause back through each delegating page to the key signature: the signature message of each hop,
	// on its page, with the block it arrived in, and the Delegator pages of the key signature (nearest the key page first).
	Trace func(ctx context.Context, cause *url.TxID) (hops []Hop, delegators []*url.URL, err error)
	// Certified resolves the key page the intent certificate names, as ResolveSigningKeyPage does; nil when the caller has no
	// declared key book or page to resolve from (the certified page is then unproven by name).
	Certified func(ctx context.Context, account, tx string) (*url.URL, error)
	// Chains reads the chains the timeline members are built from: a page's main chain as transactions (its history). Nil: no history is
	// captured and the evidence says so by name (g1_completeness_unproven).
	Chains proofv2.ChainSource

	// PositionWait bounds the wait for Position; Poll is the interval.
	PositionWait time.Duration
	Poll         time.Duration
}

type binding struct {
	partition string
	block     uint64
	stateRoot [32]byte
	rootChain [32]byte
	pb        *proofv2.PartitionBlock // nil for the transaction's own partition
	anchorTx  [32]byte
}

type captured struct {
	page  *proofv2.PageState
	block uint64
}

// runState is what a capture holds while it runs, so a capture that stops keeps the pages it read.
type runState struct {
	cache     map[string]*captured
	bindings  map[string]*binding
	x         string
	b         uint64
	principal string
}

// partial is the pages read so far, for a capture that stopped: they were read while their blocks were servable and are
// kept (the repository never replaces a capture that holds pages). No roles are claimed for them.
func (s *runState) partial() *Capture {
	if len(s.cache) == 0 {
		return nil
	}
	out := &Capture{Version: CaptureVersion, Principal: s.principal, Partition: s.x, Block: s.b, Partitions: map[string]PartitionCapture{}}
	for p, bd := range s.bindings {
		out.Partitions[p] = PartitionCapture{Partition: p, Block: bd.block, StateRoot: hex.EncodeToString(bd.stateRoot[:])}
	}
	var urls []string
	for k := range s.cache {
		urls = append(urls, k)
	}
	sort.Strings(urls)
	for _, k := range urls {
		out.Pages = append(out.Pages, CapturedPage{PageState: *s.cache[k].page, Block: s.cache[k].block})
	}
	return out
}

// Collect captures the governing pages of the intent transaction tx on account. On an error it returns, with the error, the
// pages read so far.
func (c *Collector) Collect(ctx context.Context, account, tx string) (*Capture, error) {
	st := &runState{cache: map[string]*captured{}, bindings: map[string]*binding{}, principal: account}
	out, err := c.collect(ctx, st, account, tx)
	if err != nil && out == nil {
		return st.partial(), err
	}
	return out, err
}

func (c *Collector) collect(ctx context.Context, st *runState, account, tx string) (*Capture, error) {
	x, err := c.Route(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("route %s: %w", account, err)
	}
	// A principal on the Directory (design D2c) is captured like any other: the Directory is a partition whose anchor is the
	// DirectoryAnchor it executed for its own block (collect_directory.go).
	b, err := c.Block(ctx, account, tx)
	if err != nil {
		return nil, fmt.Errorf("transaction block: %w", err)
	}
	facts, err := c.Facts(ctx, account, tx)
	if err != nil {
		return nil, fmt.Errorf("transaction facts: %w", err)
	}

	st.x, st.b = x, b
	bindings := st.bindings
	bindings[x] = &binding{partition: x, block: b}

	// The certified key page, exactly as the intent certificate resolves it. A page that cannot be resolved does not stop the
	// capture of the rest; it is the named state the capture ends with.
	var softErr error
	if executorOverrides[facts.Type] {
		// These body types decide who may sign by an executor override (chain/utils.go, chain/update_key.go,
		// chain/update_account_auth.go), not by the default rule the proof re-evaluates (design D6).
		softErr = &proofv2.NamedState{Code: proofv2.StateExecutorOverrideUnsupported, Partition: x, Block: b,
			Detail: fmt.Sprintf("%v has an executor override of who may sign; the default rule is not what judged it", facts.Type)}
	}
	if c.Certified != nil {
		if cp, err := c.Certified(ctx, account, tx); err != nil {
			if softErr == nil {
				softErr = &proofv2.NamedState{Code: proofv2.StateCertifiedPageUnproven, Partition: x, Block: b, Detail: err.Error()}
			}
		} else {
			facts.Certified = cp
		}
	}
	if facts.Held && softErr == nil && c.Chains == nil {
		// A vote released by HoldUntil was produced in a later block than its signature arrived in. With the chains readable the
		// production of each vote is proven from the synthetic ledger or the principal's signature chain (evidence 2.1 Vote.Produced);
		// without them the block is not established, so the capture names the state (design D6) after capturing everything else.
		softErr = &proofv2.NamedState{Code: proofv2.StateVoteHeld, Partition: x, Block: b,
			Detail: "the transaction is held (HoldUntil) and the chains are not readable: the block that released each vote is not established"}
	}

	// Follow every vote's cause back to its key signature: the pages of the chain, and the block each message arrived in on
	// its page's partition. Together with the arrival of the certified and initiating pages' signatures they bound from below
	// the block each partition's pages are read at (design D2).
	type arrival struct {
		page  string
		block uint64
		what  string
	}
	var arrivals []arrival
	bounds := map[string]uint64{}
	needHist := map[string]bool{} // key pages a counted signature was recorded on: their history is captured
	routeOf := func(u *url.URL) (string, error) {
		p, err := c.Route(ctx, u.String())
		if err != nil {
			return "", fmt.Errorf("route %v: %w", u, err)
		}
		return p, nil // the Directory included (design D2b): its block is chosen from its own anchors like any partition's
	}
	record := func(page *url.URL, block uint64, what string) error {
		p, err := routeOf(page)
		if err != nil {
			return err
		}
		if block > bounds[p] {
			bounds[p] = block
		}
		arrivals = append(arrivals, arrival{page.String(), block, what})
		return nil
	}
	for i := range facts.Votes {
		v := &facts.Votes[i]
		if v.Cause == nil {
			return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Detail: fmt.Sprintf("the vote of %v records no causing signature", v.Authority)}
		}
		hops, dels, err := c.Trace(ctx, v.Cause)
		if err != nil {
			return nil, fmt.Errorf("the cause chain of the vote of %v: %w", v.Authority, err)
		}
		if len(dels) > DelegationDepthLimit {
			return nil, &proofv2.NamedState{Code: proofv2.StateDelegationDepthExceeded,
				Detail: fmt.Sprintf("the vote of %v was signed through %d delegators, the limit is %d", v.Authority, len(dels), DelegationDepthLimit)}
		}
		v.Hops, v.Delegators = hops, dels
		for _, h := range hops {
			needHist[key(h.Page)] = true
			if err := record(h.Page, h.Block, "the vote of "+v.Authority.String()); err != nil {
				return nil, err
			}
		}
		// The other signatures the pages on the cause chain recorded for the transaction: a threshold above 1 counts them too, and each
		// bounds from below the block its page's partition is read at.
		inHops := map[string]bool{}
		for _, h := range hops {
			inHops[hashHex(h.ID)] = true
		}
		for _, h := range hops {
			for _, sr := range facts.PageSigs[key(h.Page)] {
				hx := hashHex(sr.ID)
				if inHops[hx] {
					continue
				}
				inHops[hx] = true
				_, blk, err := c.Arrival(ctx, sr.ID)
				if err != nil {
					return nil, fmt.Errorf("arrival of %v: %w", sr.ID, err)
				}
				v.Counted = append(v.Counted, Hop{Page: h.Page, ID: sr.ID, Block: blk, Sig: sr.Sig})
				if err := record(h.Page, blk, "a counted signature of the vote of "+v.Authority.String()); err != nil {
					return nil, err
				}
			}
		}
	}
	var sigPages []*url.URL
	if facts.Certified != nil {
		sigPages = append(sigPages, facts.Certified)
	}
	sigPages = append(sigPages, facts.Initiators...)
	sigPages = append(sigPages, facts.InitiatorPath...)
	seenSig := map[string]bool{}
	for _, p := range sigPages {
		for _, id := range facts.KeySigs[key(p)] {
			if seenSig[id.String()] {
				continue
			}
			seenSig[id.String()] = true
			_, blk, err := c.Arrival(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("arrival of %v: %w", id, err)
			}
			if err := record(id.Account(), blk, "the signature "+id.String()); err != nil {
				return nil, err
			}
		}
	}

	var pos *proofv2.TxPosition
	position := func() (*proofv2.TxPosition, error) {
		if pos != nil {
			return pos, nil
		}
		wait, poll := c.PositionWait, c.Poll
		if wait == 0 {
			wait = 10 * time.Minute
		}
		if poll == 0 {
			poll = 2 * time.Second
		}
		pctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		for {
			p, err := c.Position(pctx, account, tx, strings.ToLower(x))
			if err == nil {
				pos = p
				return p, nil
			}
			if pctx.Err() != nil {
				return nil, &proofv2.NamedState{Code: proofv2.StatePartitionAnchorUnavailable, Partition: x, Block: b,
					Detail: fmt.Sprintf("the Directory has not recorded the partition's anchor for the transaction's block: %v", err)}
			}
			select {
			case <-pctx.Done():
			case <-time.After(poll):
			}
		}
	}
	bindFrom := func(pb *proofv2.PartitionBlock) (*binding, error) {
		h, err := c.Anchor(ctx, pb)
		if err != nil {
			return nil, err
		}
		return &binding{partition: pb.Partition, block: pb.Block, stateRoot: pb.Anchor.StateTreeAnchor, rootChain: pb.Anchor.RootChainAnchor, pb: pb, anchorTx: h}, nil
	}
	bindingFor := func(p string) (*binding, error) {
		if bd, ok := bindings[p]; ok {
			return bd, nil
		}
		px, err := position()
		if err != nil {
			return nil, err
		}
		pb, err := proofv2.SelectPartitionBlock(ctx, c.Log, p, px.DNBlock, bounds[p])
		if err != nil {
			return nil, err
		}
		bd, err := bindFrom(pb)
		if err != nil {
			return nil, err
		}
		bindings[p] = bd
		return bd, nil
	}
	// advance moves a partition to its next admissible anchor when the block chosen has left its retention before any page was
	// read at it: "the smallest servable anchor-bearing block" (design D2).
	advance := func(p string, cause error) (*binding, error) {
		old := bindings[p]
		if old == nil || old.pb == nil {
			return nil, cause
		}
		for _, cp := range st.cache {
			if cp.page.Partition == protocol.PartitionUrl(p).String() {
				return nil, cause // pages are already read at this block, so it is retained: the refusal is about something else
			}
		}
		next, err := proofv2.NextPartitionBlock(ctx, c.Log, old.pb)
		if err != nil {
			return nil, cause
		}
		bd, err := bindFrom(next)
		if err != nil {
			return nil, err
		}
		bindings[p] = bd
		return bd, nil
	}

	cache := st.cache
	histDelegates := map[string][]*url.URL{}
	get := func(ctx context.Context, u *url.URL) (protocol.Account, error) {
		k := key(u)
		if cp, ok := cache[k]; ok {
			return decodeAccount(cp.page, u)
		}
		p, err := routeOf(u)
		if err != nil {
			return nil, err
		}
		bd, err := bindingFor(p)
		if err != nil {
			return nil, err
		}
		var ps *proofv2.PageState
		for {
			ps, err = c.Page(ctx, u.String(), p, bd.block)
			var ns *proofv2.NamedState
			if err != nil && errors.As(err, &ns) && ns.Code == proofv2.StateHistoricalUnavailable {
				if nb, aerr := advance(p, err); aerr == nil {
					bd = nb
					continue
				}
			}
			break
		}
		if err != nil {
			if isMissing(err) {
				return nil, &AccountMissingError{Partition: p, Block: bd.block, Cause: err}
			}
			return nil, err
		}
		if bd.pb != nil {
			// Foreign pages are bound now, while the block is inside retention: a page that does not pass through the anchor's
			// state root was not read at that block, and the block cannot be read again later.
			if ps, err = proofv2.BindToAnchor(ps, p, bd.block, bd.stateRoot); err != nil {
				return nil, err
			}
		}
		acct, err := decodeAccount(ps, u)
		if err != nil {
			return nil, err
		}
		ps.Partition = protocol.PartitionUrl(p).String()
		// A page a counted signature was recorded on carries its history, so the verifier can judge the signature against the page as it
		// stood when it arrived; the delegate books its earlier states named are part of the governing set.
		if _, isPage := acct.(*protocol.KeyPage); isPage && needHist[k] && c.Chains != nil {
			if herr := proofv2.AttachHistory(ctx, c.Chains, ps); herr != nil {
				softErr = firstState(softErr, &proofv2.NamedState{Code: proofv2.StateHistoryUnavailable, Partition: p, Block: bd.block, Detail: herr.Error()})
			} else if states, herr := proofv2.HistoryStates(ps, p, bd.block); herr != nil {
				return nil, herr
			} else {
				for _, st := range states {
					for _, ks := range st.Page.Keys {
						if ks.Delegate != nil {
							histDelegates[k] = append(histDelegates[k], ks.Delegate)
						}
					}
				}
			}
		}
		cache[k] = &captured{page: ps, block: bd.block}
		return acct, nil
	}

	cl, err := governingWith(ctx, facts, get, func(page *url.URL) []*url.URL { return histDelegates[key(page)] })
	if err != nil {
		return nil, err
	}
	// The executor version in force at each partition's block is proven by that partition's system ledger (proofv2 xexecutor.go): read as
	// of the block the partition's other pages are read at. A version before Baikonur is the named state the capture ends with, after the
	// rest is captured; a ledger that cannot be read is a note, never an assumed version.
	if vErr := c.captureLedgers(ctx, st, cl, get); vErr != nil && softErr == nil {
		softErr = vErr
	}

	// The transaction's own partition's pages are bound to its state root once the Directory has recorded the anchor.
	px, err := position()
	if err != nil {
		return nil, err
	}
	bindings[x].stateRoot, bindings[x].rootChain = px.StateRoot, px.RootChain
	if px.Block != b {
		return nil, fmt.Errorf("the transaction's block is %d, its position says %d", b, px.Block)
	}
	for k, cp := range cache {
		if cp.page.Partition != protocol.PartitionUrl(x).String() {
			continue
		}
		t, err := proofv2.BindToAnchor(cp.page, x, b, px.StateRoot)
		if err != nil {
			return nil, err
		}
		t.Partition = cp.page.Partition
		cache[k].page = t
	}

	// Every book's proven PageCount must be exactly the pages captured for it: the closure was derived from the proven books,
	// and a book whose pages are missing is refused.
	for _, gp := range cl.Pages {
		cp, ok := cache[strings.ToLower(gp.URL)]
		if !ok {
			return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Detail: fmt.Sprintf("%s is in the governing set but was not captured", gp.URL)}
		}
		acct, err := decodeAccount(cp.page, mustURL(gp.URL))
		if err != nil {
			return nil, err
		}
		if bk, ok := acct.(*protocol.KeyBook); ok {
			for i := uint64(0); i < bk.PageCount; i++ {
				pu := protocol.FormatKeyPageUrl(bk.Url, i)
				if _, ok := cache[key(pu)]; !ok {
					return nil, &proofv2.NamedState{Code: proofv2.StateBookPageCountUnproven, Partition: cp.page.Partition, Block: cp.block,
						Detail: fmt.Sprintf("%v proves PageCount %d but page %v was not captured", bk.Url, bk.PageCount, pu)}
				}
			}
		}
	}

	// The block each partition's pages were read at must not precede the arrival of any signature that was counted on it.
	for _, a := range arrivals {
		p, err := routeOf(mustURL(a.page))
		if err != nil {
			return nil, err
		}
		bd := bindings[p]
		if bd == nil {
			if bd, err = bindingFor(p); err != nil {
				return nil, err
			}
		}
		if bd.block < a.block {
			return nil, &proofv2.NamedState{Code: proofv2.StateBlockBeforeArrival, Partition: p, Block: bd.block,
				Detail: fmt.Sprintf("%s arrived at block %d of %s, after the block its pages are read at", a.what, a.block, p)}
		}
	}
	if facts.Certified != nil {
		if _, ok := cache[key(facts.Certified)]; !ok {
			return nil, &proofv2.NamedState{Code: proofv2.StateCertifiedPageUnproven, Detail: fmt.Sprintf("%v was not captured", facts.Certified)}
		}
	}

	out := &Capture{Version: CaptureVersion, Principal: facts.Principal.String(), Partition: x, Block: b, Partitions: map[string]PartitionCapture{}}
	for p, bd := range bindings {
		pc := PartitionCapture{Partition: p, Block: bd.block, StateRoot: hex.EncodeToString(bd.stateRoot[:]), RootChain: hex.EncodeToString(bd.rootChain[:])}
		if bd.pb != nil {
			pc.Index, pc.DNBlock, pc.AnchorTx = bd.pb.Index, bd.pb.DNBlock, hex.EncodeToString(bd.anchorTx[:])
		} else {
			pc.DNBlock = px.DNBlock
		}
		out.Partitions[p] = pc
	}
	for _, gp := range cl.Pages {
		cp := cache[strings.ToLower(gp.URL)]
		ps := *cp.page
		ps.Roles = gp.Roles
		out.Pages = append(out.Pages, CapturedPage{PageState: ps, Block: cp.block})
	}
	for _, v := range cl.Counted {
		out.Votes = append(out.Votes, voteOf(v))
		if v.Sequenced {
			if out.Sequenced == nil {
				out.Sequenced = map[string]string{}
			}
			out.Sequenced[hex.EncodeToString(v.Message[:])] = hex.EncodeToString(v.SeqHash[:])
		}
	}
	if facts.Txn != nil {
		raw, err := facts.Txn.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("the governed transaction: %w", err)
		}
		out.Transaction = hex.EncodeToString(raw)
	}
	for _, n := range cl.Notes {
		out.Notes = append(out.Notes, n.Error())
	}
	for _, n := range cl.Absent {
		out.Absent = append(out.Absent, *n)
	}
	// A capture with pages on other partitions is a 2.1 document whatever the rules in force: the absence is its refusal now.
	if len(out.Absent) > 0 && out.HasForeignPages() {
		softErr = firstState(softErr, &out.Absent[0])
	}
	// The evidence travels in one consensus transaction: a closure whose pages and votes cannot fit the budget is a named state, after the
	// capture is kept (proofv2 xbudget.go).
	if softErr == nil {
		pages := make([]proofv2.PageState, len(out.Pages))
		for i := range out.Pages {
			pages[i] = out.Pages[i].PageState
		}
		softErr = proofv2.CheckClosureBudget(pages, out.Votes, x, b)
	}
	return out, softErr
}

// executorOverrides are the transaction types whose executor decides who may sign itself (SignerValidator and the
// AuthorityWillVote / TransactionIsReady overrides in internal/core/execute/v2/chain); only WriteData and the other types
// without an override follow the default rule the proof re-evaluates.
var executorOverrides = map[protocol.TransactionType]bool{
	protocol.TransactionTypeCreateDataAccount:      true,
	protocol.TransactionTypeCreateIdentity:         true,
	protocol.TransactionTypeCreateKeyBook:          true,
	protocol.TransactionTypeCreateLiteTokenAccount: true,
	protocol.TransactionTypeCreateToken:            true,
	protocol.TransactionTypeCreateTokenAccount:     true,
	protocol.TransactionTypeReleaseLockedOperation: true,
	protocol.TransactionTypeUpdateAccountAuth:      true,
	protocol.TransactionTypeUpdateKey:              true,
	protocol.TransactionTypeUpdateKeyPage:          true,
}

func isDirectory(partition string) bool { return strings.EqualFold(partition, protocol.Directory) }

func voteOf(v VoteFact) proofv2.Vote {
	pv := proofv2.Vote{Authority: v.Authority.String(), Vote: v.Vote.String(), Message: hex.EncodeToString(v.Message[:])}
	if v.Origin != nil {
		pv.Origin = v.Origin.String()
	}
	// The hops are recorded by page, message, signature and arrival block; their receipts and arrival proofs are added when the evidence
	// is built (proofv2.Assembly.ProveMembers).
	hopOf := func(h Hop) proofv2.VoteHop {
		hp := proofv2.VoteHop{Page: h.Page.String(), Block: h.Block}
		if h.ID != nil {
			hash := h.ID.Hash()
			hp.Message = hex.EncodeToString(hash[:])
		}
		if h.Sig != nil {
			if sb, err := h.Sig.MarshalBinary(); err == nil {
				hp.Signature = hex.EncodeToString(sb)
			}
		}
		return hp
	}
	for _, h := range v.Hops {
		pv.Hops = append(pv.Hops, hopOf(h))
	}
	for _, h := range v.Counted {
		pv.Counted = append(pv.Counted, hopOf(h))
	}
	if v.Cause != nil {
		pv.Cause = v.Cause.String()
	}
	if v.Sequenced {
		pv.Transport = proofv2.VoteTransport{Kind: proofv2.TransportSequenced, Number: v.Number}
		if v.Source != nil {
			pv.Transport.Source = v.Source.String()
		}
		if v.Destination != nil {
			pv.Transport.Destination = v.Destination.String()
		}
	} else {
		pv.Transport = proofv2.VoteTransport{Kind: proofv2.TransportInline}
	}
	return pv
}

func decodeAccount(p *proofv2.PageState, want *url.URL) (protocol.Account, error) {
	raw, err := hex.DecodeString(p.State)
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.URL, err)
	}
	if !acct.GetUrl().Equal(want) {
		return nil, fmt.Errorf("the proven state is %v, not %v", acct.GetUrl(), want)
	}
	return acct, nil
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// isMissing says an error means the account does not exist as of the block.
func isMissing(err error) bool {
	if errors.Is(err, ErrAccountMissing) || acerrors.Is(err, acerrors.NotFound) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "not found") && !strings.Contains(s, "retained")
}

// ReadTxFacts reads the transaction record on its principal and returns who approved it: the authorities it names, the
// authority votes recorded on the principal, and the pages that initiated and paid for it.
func ReadTxFacts(ctx context.Context, net api.Querier, principal, txHash string) (*TxFacts, error) {
	pu, err := url.Parse(principal)
	if err != nil {
		return nil, err
	}
	id, err := url.ParseTxID(fmt.Sprintf("acc://%s@%s%s", strings.TrimPrefix(txHash, "0x"), pu.Authority, pu.Path))
	if err != nil {
		return nil, err
	}
	r, err := net.Query(ctx, id.AsUrl(), &api.DefaultQuery{})
	if err != nil {
		return nil, fmt.Errorf("transaction %s on %s: %w", txHash, principal, err)
	}
	mr, ok := r.(*api.MessageRecord[messaging.Message])
	if !ok {
		return nil, fmt.Errorf("transaction %s on %s: got %T", txHash, principal, r)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		return nil, fmt.Errorf("%s is %T, not a transaction", txHash, mr.Message)
	}
	txn := tm.Transaction
	f := &TxFacts{Principal: pu, Type: txn.Body.Type(), Held: txn.Header.HoldUntil != nil, Txn: txn, PageSigs: map[string][]SigRecord{}}
	seen := map[string]bool{}
	for _, a := range append(append([]*url.URL(nil), txn.Header.Authorities...), txn.GetAdditionalAuthorities()...) {
		if !seen[key(a)] {
			seen[key(a)] = true
			f.HeaderAuthorities = append(f.HeaderAuthorities, a)
		}
	}
	if mr.Signatures == nil {
		return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Detail: "the transaction record carries no signature sets"}
	}
	if uint64(len(mr.Signatures.Records)) != mr.Signatures.Total {
		return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven,
			Detail: fmt.Sprintf("the transaction record lists %d of %d signature sets", len(mr.Signatures.Records), mr.Signatures.Total)}
	}
	initiators := map[string]bool{}
	f.KeySigs = map[string][]*url.TxID{}
	for _, set := range mr.Signatures.Records {
		if set.Signatures == nil {
			continue
		}
		if uint64(len(set.Signatures.Records)) != set.Signatures.Total {
			return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven,
				Detail: fmt.Sprintf("the signature set of %v lists %d of %d messages", set.Account.GetUrl(), len(set.Signatures.Records), set.Signatures.Total)}
		}
		for _, rec := range set.Signatures.Records {
			switch m := rec.Message.(type) {
			case *messaging.CreditPayment:
				if m.Initiator && m.Payer != nil && !initiators[key(m.Payer)] {
					initiators[key(m.Payer)] = true
					f.Initiators = append(f.Initiators, m.Payer)
				}
			case *messaging.SignatureMessage:
				if as, ok := m.Signature.(*protocol.AuthoritySignature); ok {
					if set.Account.GetUrl().Equal(pu) {
						f.Votes = append(f.Votes, voteFact(as, rec))
						continue
					}
					// A delegating page's authority signature is recorded in that page's set and counted by its threshold.
					if rec.ID != nil {
						f.PageSigs[key(set.Account.GetUrl())] = append(f.PageSigs[key(set.Account.GetUrl())], SigRecord{ID: rec.ID, Sig: m.Signature})
					}
					continue
				}
				if rec.ID != nil {
					f.PageSigs[key(set.Account.GetUrl())] = append(f.PageSigs[key(set.Account.GetUrl())], SigRecord{ID: rec.ID, Sig: m.Signature})
				}
				if rec.ID != nil {
					// The signature message, at the page whose set holds it: its arrival bounds the block that page's partition is read at.
					f.KeySigs[key(rec.ID.Account())] = append(f.KeySigs[key(rec.ID.Account())], rec.ID)
				}
				if didInit, _ := protocol.SignatureDidInitiate(m.Signature, txn.Header.Initiator[:], nil); didInit {
					if p := initiatorPayer(m.Signature); p != nil && !initiators[key(p)] {
						initiators[key(p)] = true
						f.Initiators = append(f.Initiators, p)
					}
					for _, d := range delegatorPath(m.Signature) {
						f.InitiatorPath = append(f.InitiatorPath, d)
					}
				}
			}
		}
	}
	return f, nil
}

// initiatorPayer is the page a signature that initiated a transaction pays from: its signer, a lite token address paying as
// its lite identity (the account core's initiating credit payment names).
func initiatorPayer(sig protocol.Signature) *url.URL {
	signer := sig.GetSigner()
	if signer == nil {
		return nil
	}
	if key, _ := protocol.ParseLiteIdentity(signer); key == nil {
		if key, _, _ := protocol.ParseLiteTokenAddress(signer); key != nil {
			return signer.RootIdentity()
		}
	}
	return signer
}

func voteFact(as *protocol.AuthoritySignature, rec *api.MessageRecord[messaging.Message]) VoteFact {
	v := VoteFact{Authority: as.Authority, Origin: as.Origin, Vote: as.Vote, Delegators: as.Delegator, Cause: as.Cause}
	if rec.ID != nil {
		v.Message = rec.ID.Hash()
	}
	if rec.Sequence != nil && rec.Sequence.Source != nil {
		v.Sequenced = true
		v.Source, v.Destination, v.Number = rec.Sequence.Source, rec.Sequence.Destination, rec.Sequence.Number
		// The SequencedMessage the source partition recorded in its synthetic ledger (synthetic.go: chain.AddEntry(seq.Hash())).
		v.SeqHash = (&messaging.SequencedMessage{Message: rec.Message, Source: rec.Sequence.Source, Destination: rec.Sequence.Destination, Number: rec.Sequence.Number}).Hash()
	}
	return v
}

// evidencePages are the captured pages a 2.0 evidence document carries: those of the transaction's own partition, as 2.0 holds them.
// A capture that holds pages of other partitions is built as evidence 2.1 (planBuild); handing one to this function is a caller's error,
// reported as such rather than answered with a document that proves fewer pages than the governing set.
func evidencePages(cp *Capture) ([]*proofv2.PageState, error) {
	own := ""
	if cp.Partition != "" {
		own = protocol.PartitionUrl(cp.Partition).String()
	}
	var out []*proofv2.PageState
	var foreign []string
	for i := range cp.Pages {
		p := cp.Pages[i].PageState
		if p.Partition != "" && !strings.EqualFold(p.Partition, own) {
			foreign = append(foreign, fmt.Sprintf("%s on %s", p.URL, p.Partition))
			continue
		}
		out = append(out, &proofv2.PageState{URL: p.URL, State: p.State, Receipt: p.Receipt, Chains: p.Chains, PendingHash: p.PendingHash, ChainError: p.ChainError})
	}
	if len(foreign) > 0 {
		return nil, fmt.Errorf("evidence 2.0 cannot carry pages on other partitions (%s): build evidence 2.1 (planBuild)", strings.Join(foreign, ", "))
	}
	return out, nil
}

// delegatorPath returns the delegator pages of a signature, outermost first as DelegatedSignature nests them, and none for a
// signature that is not delegated. (The executor reverses this list so that delegators[0] is nearest the key page; membership
// is what the capture needs.)
func delegatorPath(sig protocol.Signature) []*url.URL {
	var out []*url.URL
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			return out
		}
		if d.Delegator != nil {
			out = append(out, d.Delegator)
		}
		sig = d.Signature
	}
}

// TraceCause follows a vote's cause back to its key signature through net: each hop is a signature message recorded on a page's
// own signature chain, and the block of that page's partition the message arrived in is the receipt's block. An authority
// signature leads to its own cause; the key signature ends the chain, and its Delegator list is the delegation path.
func TraceCause(ctx context.Context, net api.Querier, cause *url.TxID) ([]Hop, []*url.URL, error) {
	var hops []Hop
	id := cause
	for n := 0; n <= DelegationDepthLimit+2; n++ {
		r, err := net.Query(ctx, id.AsUrl(), &api.DefaultQuery{})
		if err != nil {
			return nil, nil, fmt.Errorf("signature %v: %w", id, err)
		}
		mr, ok := r.(*api.MessageRecord[messaging.Message])
		if !ok {
			return nil, nil, fmt.Errorf("signature %v: got %T", id, r)
		}
		sm, ok := mr.Message.(*messaging.SignatureMessage)
		if !ok {
			return nil, nil, fmt.Errorf("%v is %T, not a signature", id, mr.Message)
		}
		blk, err := proofv2.ChainEntryBlock(ctx, net, id.Account(), "signature", id.Hash())
		if err != nil {
			return nil, nil, err
		}
		hops = append(hops, Hop{Page: id.Account(), ID: id, Block: blk, Sig: sm.Signature})
		if as, ok := sm.Signature.(*protocol.AuthoritySignature); ok {
			if as.Cause == nil {
				return nil, nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Detail: fmt.Sprintf("the authority signature %v records no cause", id)}
			}
			id = as.Cause
			continue
		}
		return hops, delegatorPath(sm.Signature), nil
	}
	return nil, nil, &proofv2.NamedState{Code: proofv2.StateDelegationDepthExceeded,
		Detail: fmt.Sprintf("the cause chain of %v is longer than %d hops", cause, DelegationDepthLimit+2)}
}

func hashHex(id *url.TxID) string {
	h := id.Hash()
	return hex.EncodeToString(h[:])
}

// firstState keeps the first named state a capture met that did not stop it.
func firstState(prior error, s *proofv2.NamedState) error {
	if prior != nil {
		return prior
	}
	return s
}

// HasForeignPages says the capture holds pages on partitions other than the transaction's own: a 2.0 document cannot carry them.
func (cp *Capture) HasForeignPages() bool {
	own := ""
	if cp.Partition != "" {
		own = protocol.PartitionUrl(cp.Partition).String()
	}
	for i := range cp.Pages {
		if p := cp.Pages[i].Partition; p != "" && !strings.EqualFold(p, own) {
			return true
		}
	}
	return false
}

// Assembly converts a capture into the input of proofv2.Builder.Build21: every page with its partition, roles and history, the state
// root of each partition, the anchors of the partitions other than the transaction's, and the votes and transaction the timeline needs.
func (cp *Capture) Assembly(ctx context.Context, log proofv2.AnchorLog, src proofv2.ChainSource) (*proofv2.Assembly, error) {
	if len(cp.Absent) > 0 {
		n := cp.Absent[0]
		return nil, &n
	}
	a := &proofv2.Assembly{Roots: map[string][32]byte{}, Votes: cp.Votes, Sequenced: cp.Sequenced, Transaction: cp.Transaction, Source: src}
	for i := range cp.Pages {
		p := cp.Pages[i].PageState
		a.Pages = append(a.Pages, &p)
	}
	var names []string
	for n := range cp.Partitions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		pc := cp.Partitions[n]
		raw, err := hex.DecodeString(pc.StateRoot)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("the state root of %s is not 32 bytes of hex", n)
		}
		var root [32]byte
		copy(root[:], raw)
		a.Roots[protocol.PartitionUrl(n).String()] = root
		if strings.EqualFold(n, cp.Partition) {
			continue
		}
		pb, err := proofv2.LoadPartitionBlock(ctx, log, n, pc.Index)
		if err != nil {
			return nil, fmt.Errorf("the anchor of %s block %d: %w", n, pc.Block, err)
		}
		if pb.Block != pc.Block || pb.Anchor.StateTreeAnchor != root {
			return nil, &proofv2.NamedState{Code: proofv2.StateChainMoved, Partition: n, Block: pc.Block,
				Detail: fmt.Sprintf("the Directory's anchor %d of %s is for block %d with state root %x, the capture was made at block %d with %x", pc.Index, n, pb.Block, pb.Anchor.StateTreeAnchor, pc.Block, root)}
		}
		a.Foreign = append(a.Foreign, pb)
	}
	return a, nil
}
