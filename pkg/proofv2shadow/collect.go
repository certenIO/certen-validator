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
	if isDirectory(x) {
		return nil, &proofv2.NamedState{Code: proofv2.StateDirectoryPartitionUnsupported, Partition: x,
			Detail: fmt.Sprintf("the principal %s is on the Directory: evidence for a Directory transaction is not built (design D2c)", account)}
	}
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
	if c.Certified != nil {
		if cp, err := c.Certified(ctx, account, tx); err != nil {
			softErr = &proofv2.NamedState{Code: proofv2.StateCertifiedPageUnproven, Partition: x, Block: b, Detail: err.Error()}
		} else {
			facts.Certified = cp
		}
	}
	if facts.Held && softErr == nil {
		// A vote released by HoldUntil was produced in a later block than its signature arrived in; this build does not establish
		// that block, so it names the state (design D6) after capturing everything else.
		softErr = &proofv2.NamedState{Code: proofv2.StateVoteHeld, Partition: x, Block: b,
			Detail: "the transaction is held (HoldUntil): the block that released each vote is not established by this build"}
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
	routeOf := func(u *url.URL) (string, error) {
		p, err := c.Route(ctx, u.String())
		if err != nil {
			return "", fmt.Errorf("route %v: %w", u, err)
		}
		if isDirectory(p) {
			return "", &proofv2.NamedState{Code: proofv2.StateDirectoryPartitionUnsupported, Partition: p,
				Detail: fmt.Sprintf("%v is on the Directory: capture of a Directory page is not built (design D2b)", u)}
		}
		return p, nil
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
			if err := record(h.Page, h.Block, "the vote of "+v.Authority.String()); err != nil {
				return nil, err
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
				return nil, fmt.Errorf("%w: %v", ErrAccountMissing, err)
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
		cache[k] = &captured{page: ps, block: bd.block}
		return acct, nil
	}

	cl, err := governing(ctx, facts, get)
	if err != nil {
		return nil, err
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
	}
	for _, n := range cl.Notes {
		out.Notes = append(out.Notes, n.Error())
	}
	return out, softErr
}

func isDirectory(partition string) bool { return strings.EqualFold(partition, protocol.Directory) }

func voteOf(v VoteFact) proofv2.Vote {
	pv := proofv2.Vote{Authority: v.Authority.String(), Vote: v.Vote.String(), Message: hex.EncodeToString(v.Message[:])}
	if v.Origin != nil {
		pv.Origin = v.Origin.String()
	}
	// The hops are recorded by page, message and arrival block; their signatures and receipts are added when the evidence is built.
	for _, h := range v.Hops {
		hp := proofv2.VoteHop{Page: h.Page.String(), Block: h.Block}
		if h.ID != nil {
			hash := h.ID.Hash()
			hp.Message = hex.EncodeToString(hash[:])
		}
		pv.Hops = append(pv.Hops, hp)
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
	f := &TxFacts{Principal: pu, Type: txn.Body.Type(), Held: txn.Header.HoldUntil != nil}
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
					}
					continue
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
	}
	return v
}

// evidencePages are the captured pages a 2.0 evidence document carries: those of the transaction's own partition, as 2.0 holds
// them. A capture that holds pages of other partitions needs evidence 2.1, which this build does not yet produce or verify
// (RB9 Phase C); it is refused by name rather than built as a 2.0 document that proves fewer pages than the governing set.
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
		return nil, &proofv2.NamedState{Code: proofv2.StateEvidence21Required, Block: cp.Block,
			Detail: fmt.Sprintf("pages on other partitions are captured (%s) and need evidence 2.1, which is built and verified by RB9 Phase C", strings.Join(foreign, ", "))}
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
		hops = append(hops, Hop{Page: id.Account(), ID: id, Block: blk})
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
