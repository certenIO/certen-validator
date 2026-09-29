// Copyright 2026 Certen Protocol
//
// THE FACTS G1'S AUTHORIZATION VERDICT IS COMPUTED FROM, AND HOW EACH IS BOUND.
//
// The vote model (g1_votes.go) decides; this file gathers what it decides
// from. Every fact is something the chain recorded, and each is bound before it
// is used:
//
//   - A SIGNATURE counts at the block its signer page recorded it, read from its
//     receipt on that page's signature chain. The receipt must start at the
//     signature message and recompute to its anchor (evaluateCandidate); a
//     block from an unchecked receipt is a number the endpoint chose.
//   - A DELEGATED VOTE is an authority signature on the delegator page's
//     signature chain, read from the governed transaction's own signature sets
//     and bound the same way.
//   - A PAGE's states come from its replayed history (authority_history.go),
//     which must reach the page the network holds.
//   - The principal's AUTHORITY SET is the one at execution, replayed from the
//     account's own main chain - its creation and every UpdateAccountAuth -
//     and required to reach the set the network holds (g1_account_auth.go).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"strings"
	"sync"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// authorizationEvaluator decides whether a transaction's signatures authorized
// it. One is built per proof: it is true of one transaction and one execution.
type authorizationEvaluator interface {
	Evaluate(ctx context.Context, sigs []ValidatedSignature, extra ExtraAuthorities) (*AccountVote, error)
}

// timelineCache serves page timelines for one proof, replaying each page once.
type timelineCache struct {
	builder *AuthorityBuilder

	mu     sync.Mutex
	pages  map[string]*pageTimeline
	failed map[string]error
}

func newTimelineCache(builder *AuthorityBuilder) *timelineCache {
	return &timelineCache{builder: builder, pages: map[string]*pageTimeline{}, failed: map[string]error{}}
}

func (c *timelineCache) Timeline(ctx context.Context, page string) (govvote.Timeline, error) {
	key := normalizeAccURL(page)
	c.mu.Lock()
	if tl, ok := c.pages[key]; ok {
		c.mu.Unlock()
		return tl, nil
	}
	if err, ok := c.failed[key]; ok {
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Unlock()

	tl, err := c.builder.BuildPageTimeline(ctx, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.failed[key] = err
		return nil, err
	}
	c.pages[key] = tl
	return tl, nil
}

// g1Authorization is the evaluator for one governed transaction.
type g1Authorization struct {
	g1        *G1Layer
	txID      string // acc://<hash>@<principal>
	principal string // the principal account
	txHash    string // the executed transaction's hash, as G0 proved it
	execMBI   int64  // on the principal's partition
	txType    protocol.TransactionType
	timelines *timelineCache

	// evidence is what the last Evaluate read, verified to reproduce its vote (g1_vote_evidence.go).
	evidence *govvote.Evidence
}

func (a *g1Authorization) Evaluate(ctx context.Context, sigs []ValidatedSignature, extra ExtraAuthorities) (*AccountVote, error) {
	facts := voteFacts{TxType: a.txType}
	for _, v := range sigs {
		f, isVote, err := sigFactOf(v)
		if err != nil {
			return nil, err
		}
		if isVote {
			facts.Sigs = append(facts.Sigs, f)
		}
	}
	arrivals, votes, recorded, err := a.g1.collectRecordedVotes(ctx, a.txID, a.principal)
	if err != nil {
		return nil, err
	}
	facts.Arrivals, facts.Votes = arrivals, votes

	histories := newAccountHistories()
	authorities, err := a.g1.authoritySetAtExec(ctx, a.principal, a.execMBI, histories)
	if err != nil {
		return nil, err
	}
	vote, err := govvote.Evaluate(ctx, facts, a.timelines, a.principal, authorities, extra.URLs, extra.IgnoreDisabled)
	if err != nil {
		return nil, err
	}
	a.evidence, err = a.buildVoteEvidence(ctx, facts, sigs, recorded, authorities, histories, extra, vote)
	if err != nil {
		return nil, err
	}
	return vote, nil
}

// sigFactOf turns a validated signature into the fact the model reads. A
// suggestion is recorded on the chain but is not a vote (sig_user.go: added to
// the chain only), and is reported as not one.
func sigFactOf(v ValidatedSignature) (sigFact, bool, error) {
	s := v.Signature
	vote := protocol.VoteTypeAccept
	if s.Vote != "" {
		parsed, ok := protocol.VoteTypeByName(s.Vote)
		if !ok {
			return sigFact{}, false, fmt.Errorf("signature %s casts %q, which is not a vote", SafeTruncate(v.MessageID, 24), s.Vote)
		}
		vote = parsed
	}
	if vote == protocol.VoteTypeSuggest {
		return sigFact{}, false, nil
	}
	if v.Receipt.LocalBlock <= 0 {
		return sigFact{}, false, fmt.Errorf("signature %s has no recorded block", SafeTruncate(v.MessageID, 24))
	}
	sv := SignatureVerifier{}
	kh, err := sv.ComputeKeyHash(s.PublicKey)
	if err != nil {
		return sigFact{}, false, fmt.Errorf("signature %s: key hash: %w", SafeTruncate(v.MessageID, 24), err)
	}
	return sigFact{
		ID:      v.MessageID,
		Signer:  normalizeAccURL(s.Signer),
		Path:    normalizedChain(s.DelegatorChain()),
		Version: uint64(s.SignerVersion),
		KeyHash: strings.ToLower(kh),
		Vote:    vote,
		Block:   v.Receipt.LocalBlock,
	}, true, nil
}

func normalizedChain(chain []string) []string {
	out := make([]string, len(chain))
	for i, c := range chain {
		out[i] = normalizeAccURL(c)
	}
	return out
}

// collectRecordedVotes reads every authority vote the network recorded for the transaction, each bound to the block
// its signature chain recorded it in.
//
// Each signature set for the transaction carries, beside user signatures, the authority signatures core produced
// when a book voted. One with a delegator is a delegated vote arriving at delegator[0], on that page's set; the rest
// of the delegator list is the path beyond it, innermost first on the wire. One without is the vote of one of the
// principal's own authorities, on the principal's set. Both name the page that cast them (origin) and the vote.
//
// Each vote's signature bytes and bound receipt are returned beside the facts, by message id: the vote's evidence
// (RB4-F66).
func (g1 *G1Layer) collectRecordedVotes(ctx context.Context, txID, principal string) ([]arrivalFact, []recordedVote,
	map[string]recordedMessage, error) {
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "g1_arrivals_tx", g1.client, txID,
		map[string]interface{}{"queryType": "default"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read the signature sets of %s: %w", txID, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read the signature sets of %s: %w", txID, err)
	}
	arrivals, votes, binaries, err := recordedVotesWithBytes(result, principal)
	if err != nil {
		return nil, nil, nil, err
	}
	recorded := map[string]recordedMessage{}
	for i := range arrivals {
		a := &arrivals[i]
		receipt, err := g1.recordedReceipt(ctx, a.Page, a.ID, "g1_arrival_")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the delegated vote %s on %s: %w", SafeTruncate(a.ID, 24), a.Page, err)
		}
		a.Block = receipt.LocalBlock
		recorded[strings.ToLower(a.ID)] = recordedMessage{Binary: binaries[strings.ToLower(a.ID)], Receipt: receipt}
	}
	for i := range votes {
		v := &votes[i]
		receipt, err := g1.recordedReceipt(ctx, normalizeAccURL(principal), v.ID, "g1_vote_")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the recorded vote %s of %s: %w", SafeTruncate(v.ID, 24), v.Authority, err)
		}
		v.Block = receipt.LocalBlock
		recorded[strings.ToLower(v.ID)] = recordedMessage{Binary: binaries[strings.ToLower(v.ID)], Receipt: receipt}
	}
	return arrivals, votes, recorded, nil
}

// recordedMessage is a recorded vote as the chain holds it: its signature bytes (hex) and its bound receipt.
type recordedMessage struct {
	Binary  string
	Receipt ReceiptData
}

// recordedReceipt is the bound receipt of a recorded message (by its id) on account's signature chain.
func (g1 *G1Layer) recordedReceipt(ctx context.Context, account, id, label string) (ReceiptData, error) {
	hash, err := URLUtils{}.ParseAccURLHash(id)
	if err != nil || len(hash) != 64 {
		return ReceiptData{}, fmt.Errorf("%q has no message hash", id)
	}
	return g1.boundSignatureChainReceipt(ctx, account, hash, label+SafeTruncate(hash, 16))
}

// recordedVotesWithBytes is recordedVotesOf with each vote's signature in Accumulate's binary encoding, by id.
func recordedVotesWithBytes(result map[string]interface{}, principal string) ([]arrivalFact, []recordedVote,
	map[string]string, error) {
	arrivals, votes, err := recordedVotesOf(result, principal)
	if err != nil {
		return nil, nil, nil, err
	}
	want := map[string]bool{}
	for _, a := range arrivals {
		want[strings.ToLower(a.ID)] = true
	}
	for _, v := range votes {
		want[strings.ToLower(v.ID)] = true
	}
	binaries := map[string]string{}
	pu := ProofUtilities{}
	sets, _ := pu.CaseInsensitiveGet(result, "signatures").(map[string]interface{})
	setRecords, _ := pu.CaseInsensitiveGet(sets, "records").([]interface{})
	for _, sr := range setRecords {
		set, _ := sr.(map[string]interface{})
		sigs, _ := pu.CaseInsensitiveGet(set, "signatures").(map[string]interface{})
		records, _ := pu.CaseInsensitiveGet(sigs, "records").([]interface{})
		for _, r := range records {
			rec, _ := r.(map[string]interface{})
			id, _ := pu.CaseInsensitiveGet(rec, "id").(string)
			if !want[strings.ToLower(id)] {
				continue
			}
			b, err := signatureBytes(pu.CaseInsensitiveGet(rec, "message"))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("the authority vote %s: %w", SafeTruncate(id, 24), err)
			}
			if prev, dup := binaries[strings.ToLower(id)]; dup && prev != b {
				return nil, nil, nil, fmt.Errorf("the authority vote %s is recorded twice with different bytes",
					SafeTruncate(id, 24))
			}
			binaries[strings.ToLower(id)] = b
		}
	}
	for id := range want {
		if binaries[id] == "" {
			return nil, nil, nil, fmt.Errorf("the authority vote %s carries no signature bytes", SafeTruncate(id, 24))
		}
	}
	return arrivals, votes, binaries, nil
}

// recordedVotesOf reads the authority votes out of a transaction's signature sets (see collectRecordedVotes). Blocks
// are not in the sets; the caller binds them.
func recordedVotesOf(result map[string]interface{}, principal string) ([]arrivalFact, []recordedVote, error) {
	pu := ProofUtilities{}
	principal = normalizeAccURL(principal)
	var arrivals []arrivalFact
	var votes []recordedVote
	sets, _ := pu.CaseInsensitiveGet(result, "signatures").(map[string]interface{})
	setRecords, _ := pu.CaseInsensitiveGet(sets, "records").([]interface{})
	for _, sr := range setRecords {
		set, _ := sr.(map[string]interface{})
		acct, _ := pu.CaseInsensitiveGet(set, "account").(map[string]interface{})
		page, _ := pu.CaseInsensitiveGet(acct, "url").(string)
		page = normalizeAccURL(page)
		sigs, _ := pu.CaseInsensitiveGet(set, "signatures").(map[string]interface{})
		records, _ := pu.CaseInsensitiveGet(sigs, "records").([]interface{})
		for _, r := range records {
			rec, _ := r.(map[string]interface{})
			id, _ := pu.CaseInsensitiveGet(rec, "id").(string)
			msg, _ := pu.CaseInsensitiveGet(rec, "message").(map[string]interface{})
			if t, _ := pu.CaseInsensitiveGet(msg, "type").(string); !strings.EqualFold(t, "signature") {
				continue
			}
			sig, _ := pu.CaseInsensitiveGet(msg, "signature").(map[string]interface{})
			if t, _ := pu.CaseInsensitiveGet(sig, "type").(string); !strings.EqualFold(t, "authority") {
				continue
			}
			authority, _ := pu.CaseInsensitiveGet(sig, "authority").(string)
			if authority == "" {
				return nil, nil, fmt.Errorf("the authority vote %s names no authority", SafeTruncate(id, 24))
			}
			origin, _ := pu.CaseInsensitiveGet(sig, "origin").(string)
			if origin == "" {
				return nil, nil, fmt.Errorf("the authority vote %s by %s names no originating page, so which page "+
					"cast it is not recorded", SafeTruncate(id, 24), authority)
			}
			vote := protocol.VoteTypeAccept
			if name, _ := pu.CaseInsensitiveGet(sig, "vote").(string); name != "" {
				parsed, ok := protocol.VoteTypeByName(name)
				if !ok {
					return nil, nil, fmt.Errorf("the authority vote %s casts %q, which is not a vote", SafeTruncate(id, 24), name)
				}
				vote = parsed
			}

			rawDelegators, _ := pu.CaseInsensitiveGet(sig, "delegator").([]interface{})
			if len(rawDelegators) == 0 {
				// The vote of one of the principal's own authorities: recorded on the principal, nowhere else.
				if page != principal {
					return nil, nil, fmt.Errorf("the authority vote %s by %s is recorded on %s, not on the principal %s",
						SafeTruncate(id, 24), authority, page, principal)
				}
				votes = append(votes, recordedVote{ID: id, Authority: normalizeAccURL(authority),
					Origin: normalizeAccURL(origin), Vote: vote})
				continue
			}
			delegators := make([]string, 0, len(rawDelegators))
			for _, d := range rawDelegators {
				ds, _ := d.(string)
				delegators = append(delegators, normalizeAccURL(ds))
			}
			if delegators[0] != page {
				return nil, nil, fmt.Errorf("the delegated vote %s is recorded on %s but names %s as its delegator",
					SafeTruncate(id, 24), page, delegators[0])
			}

			// On the wire the path beyond delegator[0] is innermost first; the
			// model's paths are outermost first, like a signature's chain.
			beyond := delegators[1:]
			path := make([]string, len(beyond))
			for i := range beyond {
				path[i] = beyond[len(beyond)-1-i]
			}
			arrivals = append(arrivals, arrivalFact{ID: id, Page: page, Authority: normalizeAccURL(authority), Path: path,
				Origin: normalizeAccURL(origin), Vote: vote})
		}
	}
	return arrivals, votes, nil
}

// boundSignatureChainReceipt returns the receipt that records a message on a
// page's signature chain - its block is the block the message was recorded in -
// requiring it to start at the message and recompute to its anchor.
func (g1 *G1Layer) boundSignatureChainReceipt(ctx context.Context, page, messageHash, label string) (ReceiptData, error) {
	query := g1.queryBuilder.BuildNormativeChainQuery("signature", messageHash, true)
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, label, g1.client, page, query)
	if err != nil {
		return ReceiptData{}, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return ReceiptData{}, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	receipt, err := pu.ExtractReceiptFromChainEntry(result)
	if err != nil {
		return ReceiptData{}, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	if err := requireBoundReceipt(receipt, messageHash); err != nil {
		return ReceiptData{}, err
	}
	return receipt, nil
}

// requireBoundReceipt requires a receipt to start at the message it is for and
// to recompute to its own anchor.
func requireBoundReceipt(r ReceiptData, messageHash string) error {
	if !strings.EqualFold(r.Start, messageHash) {
		return ValidationError{Msg: fmt.Sprintf("its receipt starts at %s, not at the message %s",
			SafeTruncate(r.Start, 16), SafeTruncate(messageHash, 16))}
	}
	if err := VerifyReceiptMerkle(r, "signature chain receipt"); err != nil {
		return err
	}
	if r.LocalBlock <= 0 {
		return ValidationError{Msg: "its receipt names no block"}
	}
	return nil
}

// authoritySetAtExec returns the authority set that governed the principal
// when the transaction executed.
//
// An account created without authorities has none of its own and is governed
// by its nearest ancestor identity that has some, evaluated when used
// (chain/create_utils.go setInitialAuthorities, V2Baikonur). So the walk climbs
// from the principal, and at each account requires that its own set did not
// change after the execution block.
func (g1 *G1Layer) authoritySetAtExec(ctx context.Context, account string, execMBI int64,
	rec *accountHistories) ([]AccountAuthority, error) {
	u, err := url.Parse(normalizeAccURL(account))
	if err != nil {
		return nil, fmt.Errorf("principal %q: %w", account, err)
	}
	// Each step removes one path element, so the walk ends within the URL's
	// own depth; the bound only guards a malformed URL.
	for step := 0; step <= strings.Count(u.String(), "/"); step++ {
		// This account's own set as of execution, replayed from its chain
		// (g1_account_auth.go).
		auth, err := g1.accountAuthAt(ctx, u, execMBI, rec)
		if err != nil {
			return nil, err
		}
		if len(auth.Authorities) > 0 {
			out := make([]AccountAuthority, 0, len(auth.Authorities))
			for _, e := range auth.Authorities {
				out = append(out, AccountAuthority{URL: normalizeAccURL(e.Url.String()), Disabled: e.Disabled})
			}
			return out, nil
		}
		if u.IsRootIdentity() {
			return nil, ValidationError{Msg: fmt.Sprintf("%v and every identity above it have no authorities", account)}
		}
		// The next identity up, as core climbs (create_utils.go).
		u = u.Identity()
	}
	return nil, ValidationError{Msg: fmt.Sprintf("cannot climb from %v to an identity with authorities", account)}
}

// liveAccountAuth reads an account's own authority set as the network holds it.
func (g1 *G1Layer) liveAccountAuth(ctx context.Context, u *url.URL) (*protocol.AccountAuth, error) {
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "g1_account_auth_"+sanitizeLabel(u.String()), g1.client,
		u.String(), map[string]interface{}{"queryType": "default"})
	if err != nil {
		return nil, fmt.Errorf("read %v: %w", u, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("read %v: %w", u, err)
	}
	b, err := json.Marshal(pu.CaseInsensitiveGet(result, "account"))
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccountJSON(b)
	if err != nil {
		return nil, fmt.Errorf("decode %v: %w", u, err)
	}
	full, ok := acct.(protocol.FullAccount)
	if !ok {
		return nil, ValidationError{Msg: fmt.Sprintf("%v is a %v, which has no authority set of its own", u, acct.Type())}
	}
	return full.GetAuth(), nil
}

// lastMainIndexAtOrBefore returns the last main chain position written at or
// before a block, or -1 if the chain was empty then.
func (g1 *G1Layer) lastMainIndexAtOrBefore(ctx context.Context, scope string, block int64) (int, error) {
	pu := ProofUtilities{}
	indexCount := 0
	{
		resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "g1_main_index_count_"+sanitizeLabel(scope), g1.client, scope,
			map[string]interface{}{"queryType": "chain", "name": "main-index"})
		if err != nil {
			return 0, fmt.Errorf("read %s's main-index chain: %w", scope, err)
		}
		result, err := pu.ExpectResult(resp)
		if err != nil {
			return 0, err
		}
		c, ok := pu.CaseInsensitiveGet(result, "count").(float64)
		if !ok {
			return 0, fmt.Errorf("%s's main-index chain reports no count", scope)
		}
		indexCount = int(c)
	}

	type indexEntry struct {
		source int
		block  int64
	}
	read := func(i int) (indexEntry, error) {
		resp, err := g1.artifactManager.SaveRPCArtifact(ctx, fmt.Sprintf("g1_main_index_%s_%d", sanitizeLabel(scope), i),
			g1.client, scope, map[string]interface{}{
				"queryType": "chain", "name": "main-index",
				"range": map[string]interface{}{"start": i, "count": 1, "expand": true},
			})
		if err != nil {
			return indexEntry{}, err
		}
		result, err := pu.ExpectResult(resp)
		if err != nil {
			return indexEntry{}, err
		}
		records, _ := pu.CaseInsensitiveGet(result, "records").([]interface{})
		if len(records) != 1 {
			return indexEntry{}, fmt.Errorf("main-index entry %d of %s is missing", i, scope)
		}
		rec, _ := records[0].(map[string]interface{})
		value, _ := pu.CaseInsensitiveGet(rec, "value").(map[string]interface{})
		inner, _ := pu.CaseInsensitiveGet(value, "value").(map[string]interface{})
		b, ok := pu.CaseInsensitiveGet(inner, "blockIndex").(float64)
		if !ok {
			return indexEntry{}, fmt.Errorf("main-index entry %d of %s names no block", i, scope)
		}
		src, _ := pu.CaseInsensitiveGet(inner, "source").(float64) // omitted when zero
		return indexEntry{source: int(src), block: int64(b)}, nil
	}

	// The largest index entry at or before the block, by binary search: index
	// entries are appended in block order.
	lo, hi, found := 0, indexCount-1, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		e, err := read(mid)
		if err != nil {
			return 0, err
		}
		if e.block <= block {
			found = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if found < 0 {
		return -1, nil
	}
	e, err := read(found)
	if err != nil {
		return 0, err
	}
	return e.source, nil
}
