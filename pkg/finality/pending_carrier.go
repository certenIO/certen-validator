// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"sort"
)

// PendingCarrier is an error that is itself a pending answer: a light-client source whose ledger is too far behind the head returns one
// (runtime.LedgerIncompleteError), and the builder that asked must report that pending state, not the generic unavailability of the source
// (RB12 OPS-A2 item 6).
type PendingCarrier interface{ PendingState() *PendingState }

// PendingOf returns the pending state an error carries, or nil.
func PendingOf(err error) *PendingState {
	var c PendingCarrier
	if errors.As(err, &c) {
		return c.PendingState()
	}
	return nil
}

// JudgedPairs is the judged values of a pending state as alternating key, value arguments in key order, the form the builders' pending
// helpers take.
func (p *PendingState) JudgedPairs() []any {
	keys := make([]string, 0, len(p.Judged))
	for k := range p.Judged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, 2*len(keys))
	for _, k := range keys {
		out = append(out, k, p.Judged[k])
	}
	return out
}
