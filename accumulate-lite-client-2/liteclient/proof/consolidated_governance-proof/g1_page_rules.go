// Copyright 2026 Certen Protocol
//
// THE RULES A PAGE CARRIES THAT THIS PROOF DID NOT RE-DERIVE.
//
// # WHAT WAS MISSING
//
// A key page carries four thresholds. KeyPageState modelled one:
//
//	acceptThreshold     how many accept votes make the authority vote ACCEPT
//	rejectThreshold     how many reject votes make it vote REJECT
//	responseThreshold   how many votes of ANY kind before it votes at all
//	blockThreshold      (see below - the protocol does not enforce this one)
//
// The other three were dropped at parse. For a page that leaves them unset -
// every page in the Phase 7/8 corpus and every page in production - that is
// complete, because Accumulate omits a zero threshold and zero means "no extra
// rule". For a page that SETS one, G1's claim of "threshold satisfaction" is
// narrower than the page's own rules, and nothing said so.
//
// # WHAT THE PROTOCOL ACTUALLY DOES, FROM accumulate-core
//
// internal/core/execute/v2/block/transaction.go, SignerWillVote - quoted from
// the executor, not inferred from what a page reports:
//
//	tReject = page.RejectThreshold; if tReject == 0 { tReject = tAccept }
//	tResponse = page.ResponseThreshold
//	...
//	if allVotes < tResponse            { continue }           // no vote yet
//	if votes[Accept] >= tAccept        { return Accept }      // accept wins
//	if votes[Reject] >= tReject        { return Reject }
//
// and blockThresholdIsMet, which despite the name reads
// transaction.Header.HoldUntil and never reads page.BlockThreshold at all,
// under an explicit TODO saying page-level minimum thresholds do not exist yet.
//
// # THE DECISION: RECORD, DO NOT RE-DERIVE - AND WHY, PER RULE
//
// The runbook requires this be decided explicitly rather than left silent.
// These proofs are about transactions that ALREADY EXECUTED, and G0 proves the
// execution, so the question for each rule is whether re-deriving it could
// change the answer:
//
//	rejectThreshold    CANNOT change the outcome of an executed transaction.
//	                   Accept is tested BEFORE reject in the executor, and the
//	                   transaction executed - so the accept branch is the one
//	                   that was taken. Re-deriving the reject threshold would
//	                   compute a number that could not alter the verdict.
//
//	responseThreshold  COULD change it, and is the reason this evidence exists.
//	                   It gates on allVotes - accepts, rejects and abstains
//	                   together, per delegation path. A G1 proof enumerates the
//	                   signatures it could validate as accepts; it cannot claim
//	                   to have counted votes it did not enumerate. Since the
//	                   transaction executed, the network's own SignerWillVote
//	                   found the threshold met - that fact is inherited from
//	                   execution, not re-derived here, and that is exactly the
//	                   weaker basis this file records.
//
//	blockThreshold     is not enforced against the page by accumulate-core.
//	                   Claiming to verify it would claim more than the protocol
//	                   implements, so it is recorded as present and unenforced.
//
// Silently ignoring all three - the state before this file - was the one option
// the runbook rules out.
//
// # WHY IT TRAVELS BESIDE THE HASHED SHAPE
//
// KeyPageState is reachable from G1Result (AuthoritySnapshot.StateExec), and
// G1Result is what the validator hashes into the govRoot via SetG1FromJSON.
// Adding these thresholds to KeyPageState would widen the preimage and move
// every govRoot ever signed.
//
// So this travels in its own top-level array on the emitted G1 document,
// exactly where SignatureTimingBasis and GovReceiptEvidence travel and for the
// same reason. The validator's own G1Result has no such field, so it is dropped
// on the way into the hash and the preimage is byte-identical with or without
// it.
package main

import (
	"fmt"
	"sort"
)

// Reason codes, so a reader distinguishes the three cases without parsing
// prose. They are part of the cross-binary contract and are pinned by test.
const (
	// PageRuleUnverifiedResponse is the one that could have changed the answer.
	PageRuleUnverifiedResponse = "response-threshold-not-recounted"
	// PageRuleMootReject cannot change an executed transaction's outcome.
	PageRuleMootReject = "reject-threshold-moot-after-execution"
	// PageRuleUnenforcedBlock is not enforced against the page by the protocol.
	PageRuleUnenforcedBlock = "block-threshold-not-enforced-by-protocol"
)

// PageRuleNote records ONE rule that one page carries and this proof did not
// re-derive.
//
// Value is carried so a reader can see what the page actually demands rather
// than only that it demands something.
type PageRuleNote struct {
	Page   string `json:"page"`
	Rule   string `json:"rule"`
	Value  uint64 `json:"value"`
	Reason string `json:"reason"`
	// Explanation is the sentence an operator reads. It says which of the three
	// cases this is, because "not evaluated" alone would leave a moot rule and
	// a load-bearing one looking identical.
	Explanation string `json:"explanation"`
}

// pageThresholds is what a page reports beyond its accept threshold.
//
// Deliberately NOT part of KeyPageState: see the file comment. This is read at
// the same moment and kept beside it.
type pageThresholds struct {
	Reject   uint64
	Response uint64
	Block    uint64
}

// any reports whether the page carries a rule beyond accept.
func (t pageThresholds) any() bool {
	return t.Reject != 0 || t.Response != 0 || t.Block != 0
}

// parsePageThresholds reads the three unmodelled thresholds from a key page
// definition.
//
// Absent is zero, and zero is what Accumulate means by "no extra rule" - it
// omits a zero threshold rather than writing it. That is the same convention
// acceptThreshold already relies on, and it is why a page with none of these
// produces no evidence and behaves exactly as it did before.
func parsePageThresholds(def map[string]interface{}) pageThresholds {
	pu := ProofUtilities{}
	read := func(name string) uint64 {
		v := pu.CaseInsensitiveGet(def, name)
		if v == nil {
			return 0
		}
		switch n := v.(type) {
		case float64:
			if n <= 0 {
				return 0
			}
			return uint64(n)
		case int:
			if n <= 0 {
				return 0
			}
			return uint64(n)
		case int64:
			if n <= 0 {
				return 0
			}
			return uint64(n)
		case uint64:
			return n
		}
		return 0
	}
	return pageThresholds{
		Reject:   read("rejectThreshold"),
		Response: read("responseThreshold"),
		Block:    read("blockThreshold"),
	}
}

// pageRuleNotes turns one page's thresholds into the notes it earns.
//
// A page that sets nothing earns none, which is why every proof in the corpus
// and in production carries an empty array and is byte-identical to before.
func pageRuleNotes(page string, t pageThresholds) []PageRuleNote {
	var out []PageRuleNote

	if t.Response != 0 {
		out = append(out, PageRuleNote{
			Page:   page,
			Rule:   "responseThreshold",
			Value:  t.Response,
			Reason: PageRuleUnverifiedResponse,
			Explanation: fmt.Sprintf("this page does not vote until %d votes of ANY kind have been "+
				"cast on a delegation path. That count includes rejects and abstains, which this "+
				"proof does not enumerate, so the rule was NOT recounted here: it is inherited from "+
				"the fact that the transaction executed, which is a weaker basis than the accept "+
				"threshold, which was re-derived", t.Response),
		})
	}

	if t.Reject != 0 {
		out = append(out, PageRuleNote{
			Page:   page,
			Rule:   "rejectThreshold",
			Value:  t.Reject,
			Reason: PageRuleMootReject,
			Explanation: fmt.Sprintf("this page votes REJECT at %d reject votes. The executor tests "+
				"accept BEFORE reject and the transaction executed, so the accept branch is the one "+
				"that was taken and this threshold could not have changed the outcome. Recorded "+
				"because the page carries it, not because it is in doubt", t.Reject),
		})
	}

	if t.Block != 0 {
		out = append(out, PageRuleNote{
			Page:   page,
			Rule:   "blockThreshold",
			Value:  t.Block,
			Reason: PageRuleUnenforcedBlock,
			Explanation: fmt.Sprintf("this page carries a block threshold of %d, and accumulate-core "+
				"does not enforce it: blockThresholdIsMet reads the transaction's HoldUntil header "+
				"and never reads the page's blockThreshold, under a TODO saying page-level minimum "+
				"thresholds do not exist. Verifying it would claim more than the protocol "+
				"implements", t.Block),
		})
	}

	return out
}

// sortPageRuleNotes puts the notes in a canonical order.
//
// Discovery order is not stable - pages are reached by concurrent queries - and
// two validators reading identical chain data must produce identical bytes.
// Rule 12: unordered anything is how that stops being true.
func sortPageRuleNotes(notes []PageRuleNote) {
	sort.SliceStable(notes, func(i, j int) bool {
		if notes[i].Page != notes[j].Page {
			return notes[i].Page < notes[j].Page
		}
		return notes[i].Rule < notes[j].Rule
	})
}
