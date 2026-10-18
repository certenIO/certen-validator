// Copyright 2026 Certen Protocol
//
// The shadow cross-check (docs/proof/PROOF_V2.md §5.2): the page v1 replayed from the page's own main-chain history must equal
// the page v2 captured from the network at the partition block it was proven at, for EVERY page both read - the principal's
// own, foreign books', delegates', voters' - and a page v1 evaluated that v2 did not capture is a gap in v2's closure. Any
// disagreement is stop-the-line: it means one of the two replays of Accumulate's rules is wrong.

package proofv2shadow

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// PageDisagreement is one difference between v1's replayed page and v2's captured page.
type PageDisagreement struct {
	URL       string
	Partition string // the partition v2 read the page on
	Block     uint64 // the partition block v2 read it at
	Field     string // what differs; "uncaptured" for a page v1 evaluated that v2 did not capture
	V1, V2    string
}

func (d PageDisagreement) String() string {
	return fmt.Sprintf("%s (%s, block %d): %s: v1 %q, v2 %q", d.URL, d.Partition, d.Block, d.Field, d.V1, d.V2)
}

// CrossCheckResult is what the comparison established.
type CrossCheckResult struct {
	Compared      int // pages both v1 and v2 read, which were compared
	Disagreements []PageDisagreement
}

// OK says v1 and v2 agree on every page.
func (r *CrossCheckResult) OK() bool { return len(r.Disagreements) == 0 }

func (r *CrossCheckResult) String() string {
	if r.OK() {
		return fmt.Sprintf("%d pages compared, v1 and v2 agree", r.Compared)
	}
	var parts []string
	for _, d := range r.Disagreements {
		parts = append(parts, d.String())
	}
	return fmt.Sprintf("%d pages compared, %d disagreements: %s", r.Compared, len(r.Disagreements), strings.Join(parts, "; "))
}

// CrossCheckPages compares v1's replayed key pages with the pages a capture holds. v1 maps each page, in its canonical
// spelling, to the states its replay passed through. A page is compared as of the block v2 read it at: the last state v1's
// replay reached at or before that block of the page's own partition.
func CrossCheckPages(v1 map[string]govvote.States, c *Capture) *CrossCheckResult {
	res := &CrossCheckResult{}
	seen := map[string]bool{}
	for _, p := range c.Pages {
		k := govvote.CanonicalAccSpelling(p.URL)
		states, ok := v1[k]
		if !ok {
			continue // v1 read no history for it: nothing to compare (an account, a book, a page v1 had no reason to evaluate)
		}
		seen[k] = true
		acct, err := decodeAccount(&p.PageState, mustURL(p.URL))
		if err != nil {
			res.Disagreements = append(res.Disagreements, PageDisagreement{URL: p.URL, Partition: p.Partition, Block: p.Block, Field: "state", V2: err.Error()})
			continue
		}
		v2, ok := acct.(*protocol.KeyPage)
		if !ok {
			res.Disagreements = append(res.Disagreements, PageDisagreement{URL: p.URL, Partition: p.Partition, Block: p.Block, Field: "type", V1: "keyPage", V2: fmt.Sprintf("%T", acct)})
			continue
		}
		var at *protocol.KeyPage
		for _, st := range states {
			if st.Block >= 0 && uint64(st.Block) <= p.Block {
				at = st.Page
			}
		}
		res.Compared++
		if at == nil {
			res.Disagreements = append(res.Disagreements, PageDisagreement{URL: p.URL, Partition: p.Partition, Block: p.Block, Field: "history", V1: "page not yet created", V2: "page exists"})
			continue
		}
		for _, f := range pageDifferences(at, v2) {
			f.URL, f.Partition, f.Block = p.URL, p.Partition, p.Block
			res.Disagreements = append(res.Disagreements, f)
		}
	}
	// A page v1 evaluated that v2 did not capture is a gap in v2's closure.
	var missing []string
	for k := range v1 {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		res.Disagreements = append(res.Disagreements, PageDisagreement{URL: k, Field: "uncaptured", V1: "evaluated by v1", V2: "not in v2's capture"})
	}
	return res
}

// pageDifferences lists what differs between two key pages in what decides who may sign. It is the shared comparison of the
// verifier's certified timeline (proofv2.AuthorityFieldDiffs, RB9-C1b-1-F3): the version, the thresholds, the transaction blacklist and
// each entry's key hash and delegate. (LastUsedOn and the credit balance change without changing who may sign.)
func pageDifferences(v1, v2 *protocol.KeyPage) []PageDisagreement {
	var out []PageDisagreement
	for _, d := range proofv2.AuthorityFieldDiffs(v1, v2) {
		out = append(out, PageDisagreement{Field: d.Field, V1: d.A, V2: d.B})
	}
	return out
}

func delegateOf(k *protocol.KeySpec) string {
	if k.Delegate == nil {
		return ""
	}
	return strings.ToLower(k.Delegate.String())
}

// CrossCheck compares the pages v1's vote evidence replayed with the capture stored for the intent, once the capture is
// recorded, and reports the result: a disagreement is logged by name and counted, and must be zero before the shadow exits
// (PROOF_V2 §11). It never delays or fails an intent.
func (s *Shadow) CrossCheck(intentID string, ev *govvote.Evidence) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), captureWait+5*time.Minute)
		defer cancel()
		res, err := s.crossCheck(ctx, intentID, ev)
		switch {
		case err != nil:
			shadowResults.WithLabelValues("crosscheck", "unavailable").Inc()
			s.logf("[PROOF-V2-SHADOW] cross-check %s unavailable: %v", intentID, err)
		case !res.OK():
			shadowResults.WithLabelValues("crosscheck", "disagree").Inc()
			s.logf("[PROOF-V2-SHADOW] CROSS-CHECK DISAGREEMENT (stop the line) %s: %s", intentID, res)
		default:
			shadowResults.WithLabelValues("crosscheck", "agree").Inc()
			s.logf("[PROOF-V2-SHADOW] cross-check %s: %s", intentID, res)
		}
	}()
}

func (s *Shadow) crossCheck(ctx context.Context, intentID string, ev *govvote.Evidence) (*CrossCheckResult, error) {
	if ev == nil {
		return nil, fmt.Errorf("v1 recorded no vote evidence for the intent")
	}
	v1, err := govvote.ReplayPageHistories(ev)
	if err != nil {
		return nil, fmt.Errorf("v1's page histories do not replay: %w", err)
	}
	for {
		raw, _, done, err := s.repo.CaptureResult(ctx, intentID)
		if err != nil {
			return nil, err
		}
		if done {
			if raw == nil {
				return nil, fmt.Errorf("no pages were captured")
			}
			c, err := DecodeCapture(raw)
			if err != nil {
				return nil, err
			}
			return CrossCheckPages(v1, c), nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// CrossCheck implements intent.ProofV2CrossChecker.
func (l *Lazy) CrossCheck(intentID string, ev *govvote.Evidence) {
	if s := l.p.Load(); s != nil {
		s.CrossCheck(intentID, ev)
	}
}
