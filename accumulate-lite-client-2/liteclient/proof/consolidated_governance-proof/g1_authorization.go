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

func (c *timelineCache) Timeline(ctx context.Context, page string) (*pageTimeline, error) {
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
	execMBI   int64  // on the principal's partition
	txType    protocol.TransactionType
	timelines *timelineCache
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
	arrivals, err := a.g1.collectArrivals(ctx, a.txID)
	if err != nil {
		return nil, err
	}
	facts.Arrivals = arrivals

	authorities, err := a.g1.authoritySetAtExec(ctx, a.principal, a.execMBI)
	if err != nil {
		return nil, err
	}
	return newVoteModel(facts, a.timelines).accountVote(ctx, a.principal, authorities, extra.URLs, extra.IgnoreDisabled)
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

// collectArrivals reads every delegated vote recorded for the transaction.
//
// Each key page's signature set for the transaction carries, beside user
// signatures, the authority signatures it received. One with a delegator is a
// delegated vote arriving at delegator[0]; the rest of the delegator list is
// the path beyond it, innermost first on the wire.
func (g1 *G1Layer) collectArrivals(ctx context.Context, txID string) ([]arrivalFact, error) {
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "g1_arrivals_tx", g1.client, txID,
		map[string]interface{}{"queryType": "default"})
	if err != nil {
		return nil, fmt.Errorf("read the signature sets of %s: %w", txID, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("read the signature sets of %s: %w", txID, err)
	}

	var out []arrivalFact
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
			rawDelegators, _ := pu.CaseInsensitiveGet(sig, "delegator").([]interface{})
			if len(rawDelegators) == 0 {
				continue // a direct authority vote, recorded for the transaction itself
			}
			delegators := make([]string, 0, len(rawDelegators))
			for _, d := range rawDelegators {
				ds, _ := d.(string)
				delegators = append(delegators, normalizeAccURL(ds))
			}
			if delegators[0] != page {
				return nil, fmt.Errorf("the delegated vote %s is recorded on %s but names %s as its delegator",
					SafeTruncate(id, 24), page, delegators[0])
			}
			authority, _ := pu.CaseInsensitiveGet(sig, "authority").(string)
			if authority == "" {
				return nil, fmt.Errorf("the delegated vote %s names no authority", SafeTruncate(id, 24))
			}

			hash, err := URLUtils{}.ParseAccURLHash(id)
			if err != nil || len(hash) != 64 {
				return nil, fmt.Errorf("the delegated vote %q has no message hash", id)
			}
			block, err := g1.boundSignatureChainBlock(ctx, page, hash, "g1_arrival_"+SafeTruncate(hash, 16))
			if err != nil {
				return nil, fmt.Errorf("the delegated vote %s on %s: %w", SafeTruncate(id, 24), page, err)
			}

			// On the wire the path beyond delegator[0] is innermost first; the
			// model's paths are outermost first, like a signature's chain.
			beyond := delegators[1:]
			path := make([]string, len(beyond))
			for i := range beyond {
				path[i] = beyond[len(beyond)-1-i]
			}
			out = append(out, arrivalFact{ID: id, Page: page, Authority: normalizeAccURL(authority), Path: path, Block: block})
		}
	}
	return out, nil
}

// boundSignatureChainBlock returns the block a message was recorded in on a
// page's signature chain, from a receipt that starts at the message and
// recomputes to its anchor.
func (g1 *G1Layer) boundSignatureChainBlock(ctx context.Context, page, messageHash, label string) (int64, error) {
	query := g1.queryBuilder.BuildNormativeChainQuery("signature", messageHash, true, false)
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, label, g1.client, page, query)
	if err != nil {
		return 0, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return 0, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	receipt, err := pu.ExtractReceiptFromChainEntry(result)
	if err != nil {
		return 0, fmt.Errorf("read its signature chain receipt: %w", err)
	}
	if err := requireBoundReceipt(receipt, messageHash); err != nil {
		return 0, err
	}
	return receipt.LocalBlock, nil
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
func (g1 *G1Layer) authoritySetAtExec(ctx context.Context, account string, execMBI int64) ([]AccountAuthority, error) {
	u, err := url.Parse(normalizeAccURL(account))
	if err != nil {
		return nil, fmt.Errorf("principal %q: %w", account, err)
	}
	// Each step removes one path element, so the walk ends within the URL's
	// own depth; the bound only guards a malformed URL.
	for step := 0; step <= strings.Count(u.String(), "/"); step++ {
		// This account's own set as of execution, replayed from its chain
		// (g1_account_auth.go).
		auth, err := g1.accountAuthAt(ctx, u, execMBI)
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
