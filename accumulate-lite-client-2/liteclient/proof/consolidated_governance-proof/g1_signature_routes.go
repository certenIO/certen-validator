// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// The two independent routes to a transaction's counted signatures.
//
//	routeSignatureSet - query the TRANSACTION message, pick the signatureSet
//	                    for the key page, resolve each message ID.
//	routeEnumeration  - query the KEY PAGE's own P#signature chain by range,
//	                    resolve each entry, filter to this transaction.
//
// Spec section 4.1 required artifact 5 requires "Enumeration of P#signature
// entries and single-entry resolution for each counted candidate". Only the
// first route existed in the live path, so resolution happened and enumeration
// never did. Both now run.
//
// The routes have genuinely different failure surfaces: one depends on the
// transaction message and its signatureSet layout, the other on the key page's
// chain. Running both buys spec compliance and an independent check for free.

const (
	routeSignatureSet = "signatureSet"
	routeEnumeration  = "enumeration"

	// enumerationPageSize is the paging window for the P#signature chain.
	enumerationPageSize = 50

	// enumerationMaxEntries bounds how much of a key page's signature chain
	// the enumeration route will read. A key page that has signed a very large
	// number of transactions would otherwise make every proof O(chain).
	//
	// Exceeding it does NOT silently truncate: the route reports itself
	// bounded, is excluded from being the sole basis of a verdict, and the
	// reason is recorded. Silent truncation reads as "covered everything" when
	// it did not.
	enumerationMaxEntries = 2000

	// Retry policy. Retry is only ever applied to SigUnavailable candidates -
	// retrying a governance rejection would be wrong, and before the outcome
	// classification existed the two were the same value.
	sigRetryAttempts = 3
	sigRetryBase     = 150 * time.Millisecond
	sigRetryMax      = 2 * time.Second
)

// sigCandidate is one candidate signature in flight through a route.
type sigCandidate struct {
	MessageID   string
	MessageHash string

	// Page is the key page whose signature chain carries this message.
	//
	// It is per-candidate because under delegation the candidates do NOT all
	// live on one page: the delegated signer's user signature is on the
	// innermost page, and looking its receipt up on the principal's chain
	// returns "ElementIndex not found" - which the classifier correctly calls an
	// outage, so the whole route goes unavailable and falls back to one that
	// only sees the principal's page. Observed live on Kermit for corpus case D.
	//
	// Empty means "the route's own page", which is every non-delegated case.
	Page string
}

// pageFor returns the page a candidate's receipt should be read from.
func (c sigCandidate) pageFor(fallback string) string {
	if c.Page != "" {
		return c.Page
	}
	return fallback
}

// evalResult is the outcome of evaluating one candidate.
type evalResult struct {
	Outcome   SigOutcome
	Validated ValidatedSignature
	Stage     string
	Reason    string
}

// ---------------------------------------------------------------------------
// Route 1: signature set
// ---------------------------------------------------------------------------

// collectViaSignatureSet resolves every message ID in the transaction's
// signatureSet for this key page.
//
// This replaces the previous validateSignaturesFromTransaction, in which all
// ten failure branches were a bare `continue`. An RPC timeout and a signature
// belonging to a different transaction were dropped identically, so N timeouts
// under load meant N fewer signatures and a false governance rejection.
func (g1 *G1Layer) collectViaSignatureSet(ctx context.Context, sigData *SignatureSetData,
	snapshot AuthoritySnapshot, txHash string) (*SignatureEvidence, error) {

	ev := &SignatureEvidence{Route: routeSignatureSet, Candidates: len(sigData.MessageIDs)}
	if len(sigData.MessageIDs) == 0 {
		return nil, &SignatureEvidenceIncomplete{
			Route:     routeSignatureSet,
			Requested: 0,
			Unavailable: []UnavailableSignature{{
				Stage: "signatureSet",
				Err:   "the transaction's signatureSet for this key page is empty or could not be read",
			}},
		}
	}

	var unavailable []UnavailableSignature
	uu := URLUtils{}

	for i, messageID := range sigData.MessageIDs {
		msgHash, err := uu.ParseAccURLHash(messageID)
		if err != nil {
			// A malformed message ID is an extraction failure, not a
			// governance rejection: we never got to evaluate the signature.
			unavailable = append(unavailable, UnavailableSignature{
				MessageID: messageID, Stage: "parse-message-id", Err: err.Error(),
			})
			continue
		}

		// The page comes from the message ID itself - acc://<hash>@<page> - so a
		// delegated signature's receipt is read from the chain that actually
		// holds it. Under delegation the candidates span several pages, and
		// using the route's page for all of them turns the delegated ones into
		// not-found outages.
		res := g1.evaluateCandidateWithRetry(ctx, sigCandidate{
			MessageID: messageID, MessageHash: msgHash, Page: pageOfMessageID(messageID),
		}, sigData.KeyPage, snapshot, txHash, fmt.Sprintf("g1_sigset_%d", i))

		switch res.Outcome {
		case SigUnavailable:
			unavailable = append(unavailable, UnavailableSignature{
				MessageID: messageID, Stage: res.Stage, Err: res.Reason,
			})
		case SigCounted:
			ev.Counted = append(ev.Counted, res.Validated)
		case SigRejected:
			ev.Rejected = append(ev.Rejected, RejectedSignature{MessageID: messageID, Reason: res.Reason})
		default:
			// SigNotEvaluated must never escape evaluateCandidate. Treat it as
			// an outage rather than letting a zero value pass for a verdict.
			unavailable = append(unavailable, UnavailableSignature{
				MessageID: messageID, Stage: "classify",
				Err: "candidate returned no outcome (internal error)",
			})
		}
	}

	if len(unavailable) > 0 {
		return nil, &SignatureEvidenceIncomplete{
			Route:       routeSignatureSet,
			Requested:   len(sigData.MessageIDs),
			Evaluated:   len(sigData.MessageIDs) - len(unavailable),
			Unavailable: unavailable,
		}
	}
	return ev, nil
}

// ---------------------------------------------------------------------------
// Route 2: enumeration of the key page's P#signature chain
// ---------------------------------------------------------------------------

// collectViaEnumeration enumerates the key page's P#signature chain and
// resolves every entry.
//
// This replaces validateSignaturesDirectFromTransaction, which returned
// `[]ValidatedSignature{}, nil` - success with zero signatures - and was
// reached whenever signatureSet extraction failed.
//
// It enumerates the KEY PAGE. The previously dead enumeration code used
// extractPrincipal(keyPage), which yields the ADI root, a different account
// whose signature chain does not hold the key page's signatures (verified
// live: acc://<adi>.acme has 3 entries, acc://<adi>.acme/book/1 has 9, and
// only the latter carries the ed25519 signature messages).
//
// Every entry passes through single-entry resolution, which returns a receipt;
// timing is validated against that receipt. This is not extraction from
// expanded JSON, which section 2.2 forbids as evidence - it is receipt-bound
// throughout.
func (g1 *G1Layer) collectViaEnumeration(ctx context.Context, keyPage string,
	snapshot AuthoritySnapshot, txHash string) (*SignatureEvidence, error) {

	ev := &SignatureEvidence{Route: routeEnumeration}

	// The principal's page AND every page its delegate entries lead to.
	//
	// Enumerating only the principal's chain misses the delegated signer's
	// signature entirely, and the two routes then disagree - correctly, and
	// fatally, because a disagreement is a fail-closed condition. Both routes
	// must cover the same ground.
	//
	// They discover it from DIFFERENT sources, which is the point of having two:
	// the signatureSet route follows the authority signatures on the
	// transaction, this one follows the delegate entries on the key pages
	// themselves. Two independent paths to the same set of signer accounts.
	pages, pageErr := g1.enumerateDelegatePages(ctx, keyPage, snapshot)
	if pageErr != nil {
		return nil, &SignatureEvidenceIncomplete{
			Route:     routeEnumeration,
			Requested: 0,
			Unavailable: []UnavailableSignature{{
				MessageID: keyPage, Stage: "enumerate-delegate-pages", Err: pageErr.Error(),
			}},
		}
	}

	fmt.Printf("[G1] [ENUMERATION] signer pages: %v\n", pages)

	var unavailable []UnavailableSignature
	for _, page := range pages {
		total, err := g1.signatureChainCount(ctx, page)
		if err != nil {
			return nil, &SignatureEvidenceIncomplete{
				Route:     routeEnumeration,
				Requested: 0,
				Unavailable: []UnavailableSignature{{
					MessageID: page, Stage: "chain-count", Err: err.Error(),
				}},
			}
		}
		if total == 0 {
			if page != keyPage {
				// A delegate page with no signature chain simply did not sign.
				// That is not an outage.
				continue
			}
			return nil, &SignatureEvidenceIncomplete{
				Route:     routeEnumeration,
				Requested: 0,
				Unavailable: []UnavailableSignature{{
					MessageID: page, Stage: "chain-count",
					Err: "key page P#signature chain is empty; the transaction's signatures cannot be enumerated",
				}},
			}
		}

		// Read the most recent window. Signatures are appended, so a
		// transaction's signatures sit at or before its execution point, near
		// the tail for any recent transaction.
		start := 0
		if total > enumerationMaxEntries {
			start = total - enumerationMaxEntries
			ev.Bounded = true
			ev.BoundedReason = fmt.Sprintf("read the most recent %d of %d P#signature entries on %s",
				enumerationMaxEntries, total, page)
		}

		entries, err := g1.enumerateSignatureEntryHashes(ctx, page, start, total)
		if err != nil {
			return nil, &SignatureEvidenceIncomplete{
				Route:     routeEnumeration,
				Requested: total - start,
				Unavailable: []UnavailableSignature{{
					MessageID: page, Stage: "enumerate", Err: err.Error(),
				}},
			}
		}
		ev.Candidates += len(entries)

		for i, entryHash := range entries {
			messageID := fmt.Sprintf("acc://%s@%s", entryHash, strings.TrimPrefix(page, "acc://"))
			res := g1.evaluateCandidateWithRetry(ctx, sigCandidate{
				MessageID: messageID, MessageHash: entryHash, Page: page,
			}, page, snapshot, txHash, fmt.Sprintf("g1_enum_%s_%d", sanitizeLabel(page), i))

			switch res.Outcome {
			case SigUnavailable:
				unavailable = append(unavailable, UnavailableSignature{
					MessageID: messageID, Stage: res.Stage, Err: res.Reason,
				})
			case SigCounted:
				ev.Counted = append(ev.Counted, res.Validated)
			case SigRejected:
				ev.Rejected = append(ev.Rejected, RejectedSignature{MessageID: messageID, Reason: res.Reason})
			default:
				unavailable = append(unavailable, UnavailableSignature{
					MessageID: messageID, Stage: "classify",
					Err: "candidate returned no outcome (internal error)",
				})
			}
		}
	}

	if len(unavailable) > 0 {
		return nil, &SignatureEvidenceIncomplete{
			Route:       routeEnumeration,
			Requested:   ev.Candidates,
			Evaluated:   ev.Candidates - len(unavailable),
			Unavailable: unavailable,
		}
	}
	return ev, nil
}

// enumerateDelegatePages walks the key pages reachable from the principal's
// through delegate entries, breadth first, and returns them in canonical order.
//
// This is the enumeration route's OWN discovery of the signer accounts: it reads
// the key pages, where the signatureSet route reads the transaction. Two sources
// that must agree is the whole value of running both.
//
// The visited set is what makes it terminate: a delegation graph may cycle, and
// corpus case H is one Kermit executes transactions over. The hop bound is
// Accumulate's own depth limit, because a chain deeper than the protocol allows
// cannot have produced a valid signature.
func (g1 *G1Layer) enumerateDelegatePages(ctx context.Context, keyPage string,
	snapshot AuthoritySnapshot) ([]string, error) {

	uu := URLUtils{}
	start := uu.NormalizeURL(keyPage)

	source := newLivePageSource(g1.client, g1.authorityBuilder)
	visited := map[string]bool{start: true}
	order := []string{start}

	// The principal's own state comes from the KPSW-EXEC snapshot, which is
	// replayed from genesis; pages reached through delegation are queried. The
	// difference is recorded on resolution links rather than smoothed over here.
	frontier := delegateBooksOf(snapshot.StateExec.EntrySet())
	fmt.Printf("[G1] [ENUMERATION] principal entries=%d delegate books=%v\n",
		len(snapshot.StateExec.EntrySet()), frontier)

	for hop := 0; hop < delegationEnumerationMaxHops && len(frontier) > 0; hop++ {
		var next []string
		for _, book := range frontier {
			page := uu.NormalizeURL(book + "/1")
			if visited[page] {
				continue
			}
			state, err := source.PageState(ctx, page)
			if err != nil {
				// NOT skipped silently. A delegate page we cannot read is a
				// signer account we cannot enumerate, and dropping it makes the
				// counted set smaller than the authority - which surfaces as a
				// threshold shortfall and reads as "the institution did not
				// authorize this".
				//
				// This was a silent `continue` for one iteration of this code and
				// it hid exactly that: every corpus delegate book reports no
				// accept threshold field, the parse failed, the page was skipped,
				// and the delegated signature became invisible.
				return nil, fmt.Errorf("delegate page %s could not be read, so the signer "+
					"accounts cannot be fully enumerated: %w", page, err)
			}
			visited[page] = true
			order = append(order, page)
			next = append(next, delegateBooksOf(state.EntrySet())...)
		}
		frontier = next
	}

	if len(order) > 1 {
		sort.Strings(order[1:])
	}
	return order, nil
}

// delegateBooksOf returns the delegate book URLs among a page's entries.
func delegateBooksOf(entries []KeyPageEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Delegate != "" {
			out = append(out, e.Delegate)
		}
	}
	return out
}

func (g1 *G1Layer) signatureChainCount(ctx context.Context, keyPage string) (int, error) {
	query := g1.queryBuilder.BuildSignatureChainQuery(nil, 0, 0)
	response, err := g1.artifactManager.SaveRPCArtifact(ctx,
		fmt.Sprintf("signature_chain_count_%s", sanitizeLabel(keyPage)), g1.client, keyPage, query)
	if err != nil {
		return 0, fmt.Errorf("query signature chain count: %w", err)
	}

	pu := ProofUtilities{}
	data := pu.CaseInsensitiveGet(response, "result")
	if data == nil {
		data = pu.CaseInsensitiveGet(response, "data")
	}
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return 0, ValidationError{Msg: "invalid signature chain count response: missing result object"}
	}
	count := pu.CaseInsensitiveGet(dataMap, "count")
	countFloat, ok := count.(float64)
	if !ok {
		return 0, ValidationError{Msg: "invalid signature chain count response: count is not a number"}
	}
	return int(countFloat), nil
}

// enumerateSignatureEntryHashes pages through [start,total) and returns the
// entry hashes. A short page is an error, never a silent truncation.
func (g1 *G1Layer) enumerateSignatureEntryHashes(ctx context.Context, keyPage string, start, total int) ([]string, error) {
	var out []string
	pu := ProofUtilities{}

	for s := start; s < total; s += enumerationPageSize {
		count := enumerationPageSize
		if s+count > total {
			count = total - s
		}
		query := g1.queryBuilder.BuildSignatureChainRangeQuery(s, count)
		response, err := g1.artifactManager.SaveRPCArtifact(ctx,
			fmt.Sprintf("signature_entries_%s_%d_%d", sanitizeLabel(keyPage), s, count),
			g1.client, keyPage, query)
		if err != nil {
			return nil, fmt.Errorf("enumerate P#signature [%d:%d]: %w", s, s+count, err)
		}

		data := pu.CaseInsensitiveGet(response, "result")
		if data == nil {
			data = pu.CaseInsensitiveGet(response, "data")
		}
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("enumerate P#signature [%d:%d]: response has no result object", s, s+count)
		}
		records, ok := pu.CaseInsensitiveGet(dataMap, "records").([]interface{})
		if !ok {
			return nil, fmt.Errorf("enumerate P#signature [%d:%d]: response has no records array", s, s+count)
		}

		before := len(out)
		for _, rec := range records {
			recMap, ok := rec.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("enumerate P#signature [%d:%d]: malformed record", s, s+count)
			}
			entry, _ := pu.CaseInsensitiveGet(recMap, "entry").(string)
			if entry == "" {
				// Some records nest the chain entry.
				if ceMap, ok := pu.CaseInsensitiveGet(recMap, "chainEntry").(map[string]interface{}); ok {
					entry, _ = pu.CaseInsensitiveGet(ceMap, "entry").(string)
				}
			}
			if entry == "" {
				return nil, fmt.Errorf("enumerate P#signature [%d:%d]: record has no entry hash", s, s+count)
			}
			out = append(out, entry)
		}
		if got := len(out) - before; got != count {
			return nil, fmt.Errorf("enumerate P#signature [%d:%d]: expected %d entries, got %d", s, s+count, count, got)
		}
	}
	if len(out) != total-start {
		return nil, fmt.Errorf("enumerate P#signature: expected %d entries, got %d", total-start, len(out))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Candidate evaluation, shared by both routes
// ---------------------------------------------------------------------------

// evaluateCandidateWithRetry evaluates a candidate, retrying ONLY when the
// outcome is SigUnavailable.
//
// Retry is safe only once unavailable and rejected are distinguishable.
// Retrying a governance rejection would be wrong; retrying a timeout is
// correct. Before the classification existed they were the same value, which
// is why retry could not be added first.
func (g1 *G1Layer) evaluateCandidateWithRetry(ctx context.Context, cand sigCandidate, keyPage string,
	snapshot AuthoritySnapshot, txHash, label string) evalResult {

	var res evalResult
	delay := sigRetryBase

	for attempt := 1; attempt <= sigRetryAttempts; attempt++ {
		res = g1.evaluateCandidate(ctx, cand, keyPage, snapshot, txHash, fmt.Sprintf("%s_a%d", label, attempt))
		if res.Outcome != SigUnavailable {
			return res
		}
		if attempt == sigRetryAttempts {
			break
		}
		if ctx.Err() != nil {
			res.Reason = fmt.Sprintf("%s (context ended during retry: %v)", res.Reason, ctx.Err())
			return res
		}
		// Jittered exponential backoff.
		jitter := time.Duration(rand.Int63n(int64(delay/2) + 1))
		select {
		case <-ctx.Done():
			res.Reason = fmt.Sprintf("%s (context ended during retry: %v)", res.Reason, ctx.Err())
			return res
		case <-time.After(delay + jitter):
		}
		if delay *= 2; delay > sigRetryMax {
			delay = sigRetryMax
		}
		fmt.Printf("[G1] [EVIDENCE] retry %d/%d for %s after %s: %s\n",
			attempt+1, sigRetryAttempts, SafeTruncate(cand.MessageID, 32), res.Stage, res.Reason)
	}

	// Retries exhausted. Still unavailable - never downgrade to a verdict.
	res.Reason = fmt.Sprintf("%s (after %d attempts)", res.Reason, sigRetryAttempts)
	return res
}

// evaluateCandidate performs one full evaluation of a candidate signature.
//
// Every failure is classified. Infrastructure failures - anything that stopped
// us from reaching a conclusion - are SigUnavailable. Only a conclusion that
// the signature does not count is SigRejected.
func (g1 *G1Layer) evaluateCandidate(ctx context.Context, cand sigCandidate, keyPage string,
	snapshot AuthoritySnapshot, txHash, label string) evalResult {

	pu := ProofUtilities{}

	// --- fetch the signature message -------------------------------------
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, label+"_msg", g1.client, cand.MessageID, g1.queryBuilder.BuildMsgIDQuery())
	if err != nil {
		return evalResult{Outcome: SigUnavailable, Stage: "query-signature-message", Reason: err.Error()}
	}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return evalResult{Outcome: SigUnavailable, Stage: "extract-message-result", Reason: err.Error()}
	}
	signature, err := g1.signatureVerifier.ExtractSignatureFromMessageResult(result)
	if err != nil {
		// The chain holds several message kinds (signatureRequest,
		// creditPayment, ...). Those are not ed25519 signatures and are a
		// legitimate rejection, not an outage. Anything else is an outage.
		if isNotASignatureMessage(err) {
			return evalResult{Outcome: SigRejected, Stage: "extract-signature", Reason: "not an ed25519 signature message"}
		}
		return evalResult{Outcome: SigUnavailable, Stage: "extract-signature", Reason: err.Error()}
	}

	// --- does it belong to this transaction? (section 7.1) ----------------
	if !g1.signatureVerifier.ValidateTransactionHash(signature, txHash) {
		return evalResult{Outcome: SigRejected, Stage: "transaction-hash",
			Reason: fmt.Sprintf("signature covers %s, not %s",
				SafeTruncate(signature.TransactionHash, 16), SafeTruncate(txHash, 16))}
	}

	// --- receipt, for timing (section 6.2 / 7.1) --------------------------
	receiptQuery := g1.queryBuilder.BuildNormativeChainQuery("signature", cand.MessageHash, true, false)
	// The candidate's OWN page, not the route's. A delegated signature lives on
	// the innermost signer's chain, and asking the principal's chain for it
	// returns not-found - an outage, not a rejection, which takes the whole
	// route down with it.
	receiptResp, err := g1.artifactManager.SaveRPCArtifact(ctx, label+"_receipt", g1.client,
		cand.pageFor(keyPage), receiptQuery)
	if err != nil {
		return evalResult{Outcome: SigUnavailable, Stage: "query-receipt", Reason: err.Error()}
	}
	receiptResult, err := pu.ExpectResult(receiptResp)
	if err != nil {
		return evalResult{Outcome: SigUnavailable, Stage: "extract-receipt-result", Reason: err.Error()}
	}
	receipt, err := pu.ExtractReceiptFromChainEntry(receiptResult)
	if err != nil {
		return evalResult{Outcome: SigUnavailable, Stage: "extract-receipt", Reason: err.Error()}
	}

	timingVerified := g1.signatureVerifier.ValidateSignatureTiming(receipt, snapshot.ExecTerms.MBI)
	if !timingVerified {
		return evalResult{Outcome: SigRejected, Stage: "timing",
			Reason: fmt.Sprintf("signed after execution: receipt.localBlock=%d > execMBI=%d",
				receipt.LocalBlock, snapshot.ExecTerms.MBI)}
	}

	validated := ValidatedSignature{
		MessageID:               cand.MessageID,
		MessageHash:             cand.MessageHash,
		Signature:               signature,
		Receipt:                 receipt,
		TimingVerified:          true,
		TransactionHashVerified: true,
	}

	// --- ed25519 + key-page membership (section 8.5) ----------------------
	form, err := g1.signatureVerifier.ValidateSignature(ctx, validated, snapshot.StateExec, txHash)
	if err != nil {
		if isInfrastructureDigestFailure(err) {
			return evalResult{Outcome: SigUnavailable, Stage: "compute-digest", Reason: err.Error()}
		}
		// A capability limit is UNAVAILABLE, not REJECTED, and the difference is
		// the whole of runbook rule 7.
		//
		// An unsupported key type is a real vote by a real key that really did
		// authorize the transaction - corpus case K is one Kermit DELIVERED - and
		// we cannot check it. Recording that as a rejection lets the threshold be
		// computed over the remainder, which is a silent skip: the count comes up
		// short and reads as "the institution did not authorize this". A false
		// governance rejection is worse than an error, so this is an error.
		// SigUnavailable is exactly that: not evidence, and no threshold may be
		// computed while one is outstanding.
		//
		// The same holds for a delegation we have not resolved.
		if u, ok := IsUnsupportedSignatureType(err); ok {
			return evalResult{Outcome: SigUnavailable, Stage: u.Reason(), Reason: err.Error()}
		}
		if d, ok := err.(DelegationNotResolved); ok {
			return evalResult{Outcome: SigUnavailable, Stage: d.Reason(), Reason: err.Error()}
		}
		return evalResult{Outcome: SigRejected, Stage: "validate-signature", Reason: err.Error()}
	}
	validated.Signature.DigestForm = form
	validated.CryptographicallyVerified = true

	return evalResult{Outcome: SigCounted, Validated: validated, Stage: "counted"}
}

// isNotASignatureMessage reports whether an extraction error means the entry
// simply is not an ed25519 signature over a transaction, as opposed to the
// extraction itself failing.
//
// A key page's P#signature chain legitimately carries several message kinds -
// signatureRequest, creditPayment, authority signatures, and so on. Those are
// not validator-style ed25519 votes and are a correct REJECTION, not an
// outage. Verified live on Kermit: enumerating
// acc://carp-buyer-62431.acme/book/1 yields an entry of type "authority",
// which produced "Not an ed25519 signature (type: authority)".
//
// The strings below are matched against the exact messages
// ExtractSignatureFromMessageResult produces (signature_verifier.go:401-439).
// Getting this wrong is the same defect class this package exists to close,
// just pointed the other way: it turns a routine rejection into a fake outage,
// which then costs the cross-check and burns retries on a permanent condition.
func isNotASignatureMessage(err error) bool {
	// The typed refusal first. It replaced the "not an ed25519 signature"
	// string, and matching on prose is what made this a maintenance hazard: an
	// error message was reworded in Phase 7 and every authority-type chain entry
	// silently changed class. The string cases below remain for the errors that
	// are still only prose.
	//
	// Note which refusal is here and which is NOT. NotAKeySignature is routine.
	// UnsupportedSignatureType is deliberately absent: a btc or eth signature IS
	// a vote, and treating it as "not a signature message" would skip it
	// silently - the exact thing runbook rule 7 forbids.
	if _, ok := err.(NotAKeySignature); ok {
		return true
	}

	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "not a signature message"): // wrong message type
		return true
	case strings.Contains(s, "not an ed25519 signature"): // wrong signature type
		return true
	case strings.Contains(s, "missing message.signature"): // no signature payload
		return true
	case strings.Contains(s, "signature.type missing"):
		return true
	case strings.Contains(s, "signature is not an object"):
		return true
	}
	return false
}

// isInfrastructureDigestFailure reports whether a ValidateSignature error came
// from being unable to compute the digest at all, rather than from the
// signature being invalid.
//
// ComputeAccumulateDigest can fail on hex decoding, URL parsing, or - when an
// external sigbytes tool is configured - on process execution. None of those
// are governance rejections, and counting them as such is the same defect
// class this file exists to remove.
func isInfrastructureDigestFailure(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "failed to compute signature digest") ||
		strings.Contains(s, "failed to compute key hash") ||
		strings.Contains(s, "sigbytes")
}

func sanitizeLabel(s string) string {
	r := strings.NewReplacer("://", "_", "/", "_", "@", "_", ":", "_")
	out := r.Replace(s)
	return SafeTruncate(out, 48)
}
