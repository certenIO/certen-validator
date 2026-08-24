// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Signature evidence: distinguishing "invalid" from "unavailable".
//
// Every observed G1 failure has the same shape:
//
//	{"threshold_m":1,"threshold_n":1,"attestation_count":1,"threshold_met":false}
//
// One signature expected, one found, zero validated, threshold recorded as
// unmet. Arithmetically 1 >= 1. The count fell to zero because a signature
// could not be *evaluated* - an RPC timeout, a failed extraction - and the
// code treated that identically to a signature that was evaluated and
// rejected. It then computed a threshold verdict over what was left.
//
// A threshold verdict computed over an incomplete evidence set is not a
// verdict. These types make the distinction explicit so it cannot collapse
// again.

// SigOutcome classifies why a candidate signature was not counted.
type SigOutcome int

const (
	// SigNotEvaluated is the zero value. A candidate must never reach a
	// verdict while still carrying it: "never evaluated" must not be able to
	// read as "evaluated and rejected" simply because it is the default.
	SigNotEvaluated SigOutcome = iota

	// SigCounted: the signature was evaluated and counts toward the threshold.
	SigCounted

	// SigRejected: the signature was evaluated and is genuinely not a valid
	// counted signature for this transaction. This IS evidence, and the
	// threshold may be evaluated over a set containing rejections.
	SigRejected

	// SigUnavailable: the signature could not be evaluated at all. This is
	// NOT evidence. A threshold must never be computed while any candidate is
	// unavailable.
	SigUnavailable
)

func (o SigOutcome) String() string {
	switch o {
	case SigCounted:
		return "counted"
	case SigRejected:
		return "rejected"
	case SigUnavailable:
		return "unavailable"
	default:
		return "not-evaluated"
	}
}

// UnavailableSignature records one candidate that could not be evaluated,
// with enough detail to retry it or to diagnose the outage.
type UnavailableSignature struct {
	MessageID string `json:"messageID"`
	Stage     string `json:"stage"`
	Err       string `json:"error"`
}

// RejectedSignature records one candidate that was evaluated and not counted.
type RejectedSignature struct {
	MessageID string `json:"messageID"`
	Reason    string `json:"reason"`
}

// SignatureEvidenceIncomplete is returned when at least one candidate
// signature could not be evaluated. It is deliberately an error and not a
// result: the caller must not turn it into a threshold verdict.
type SignatureEvidenceIncomplete struct {
	Route       string
	Requested   int
	Evaluated   int
	Unavailable []UnavailableSignature
}

func (e *SignatureEvidenceIncomplete) Error() string {
	var b strings.Builder
	if e.Requested == 0 {
		// The route failed before it could enumerate candidates at all, so
		// "n of 0" would be nonsense. Say what actually happened.
		fmt.Fprintf(&b, "signature evidence incomplete on route %q: the route could not be started", e.Route)
	} else {
		fmt.Fprintf(&b, "signature evidence incomplete on route %q: %d of %d candidates could not be evaluated",
			e.Route, len(e.Unavailable), e.Requested)
	}
	for i, u := range e.Unavailable {
		if i >= 5 {
			fmt.Fprintf(&b, "; (+%d more)", len(e.Unavailable)-i)
			break
		}
		fmt.Fprintf(&b, "; [%s at %s: %s]", SafeTruncate(u.MessageID, 24), u.Stage, u.Err)
	}
	b.WriteString(" - this is an infrastructure failure, NOT a governance rejection")
	return b.String()
}

// IsEvidenceIncomplete reports whether err is a SignatureEvidenceIncomplete.
// Callers use it to avoid recording an infrastructure outage as an unmet
// threshold.
func IsEvidenceIncomplete(err error) (*SignatureEvidenceIncomplete, bool) {
	var e *SignatureEvidenceIncomplete
	if err == nil {
		return nil, false
	}
	if x, ok := err.(*SignatureEvidenceIncomplete); ok {
		e = x
		return e, true
	}
	return nil, false
}

// SignatureEvidence is the outcome of one extraction route.
type SignatureEvidence struct {
	Route string `json:"route"`

	// Counted signatures, fully validated and receipt-bound.
	Counted []ValidatedSignature `json:"-"`

	// Rejected candidates. Retained as evidence: a proof that says "three
	// candidates, one counted, two rejected because they belong to another
	// transaction" is stronger than one that says "one counted".
	Rejected []RejectedSignature `json:"rejected"`

	// Candidates considered. For the signatureSet route this is the number of
	// message IDs in the set; for the enumeration route, the number of
	// P#signature entries examined.
	Candidates int `json:"candidates"`

	// Bounded is set when the route deliberately did not examine everything.
	// It is never silent: a bounded route is reported and is not allowed to
	// stand alone as the basis for a threshold verdict.
	Bounded       bool   `json:"bounded"`
	BoundedReason string `json:"boundedReason,omitempty"`
}

// countedKey identifies a counted signature independently of which route
// found it. Routes reach the same signature by different queries and may
// format the message ID differently, so the identity is the content:
// which signature message, over which transaction, by which key.
type countedKey struct {
	MessageHash     string
	TransactionHash string
	PublicKey       string
}

func (e *SignatureEvidence) countedKeys() map[countedKey]struct{} {
	out := make(map[countedKey]struct{}, len(e.Counted))
	for _, s := range e.Counted {
		out[countedKey{
			MessageHash:     strings.ToLower(strings.TrimPrefix(s.MessageHash, "0x")),
			TransactionHash: strings.ToLower(strings.TrimPrefix(s.Signature.TransactionHash, "0x")),
			PublicKey:       strings.ToLower(strings.TrimPrefix(s.Signature.PublicKey, "0x")),
		}] = struct{}{}
	}
	return out
}

// RouteDisagreement reports that two independent routes to the same evidence
// produced different counted sets.
//
// This is a finding, not something to average or to resolve by preferring one
// route. Two routes disagreeing about which signatures authorised a
// transaction means at least one of them is wrong, and a proof must not be
// issued while that is true.
type RouteDisagreement struct {
	RouteA, RouteB string
	OnlyInA        []string
	OnlyInB        []string
}

func (e *RouteDisagreement) Error() string {
	return fmt.Sprintf(
		"signature routes disagree: %q found %d signature(s) %q did not (%s); %q found %d %q did not (%s)",
		e.RouteA, len(e.OnlyInA), e.RouteB, strings.Join(truncateEach(e.OnlyInA, 3), ", "),
		e.RouteB, len(e.OnlyInB), e.RouteA, strings.Join(truncateEach(e.OnlyInB, 3), ", "))
}

func truncateEach(in []string, n int) []string {
	if len(in) > n {
		in = append(append([]string{}, in[:n]...), fmt.Sprintf("+%d more", len(in)-n))
	}
	return in
}

// CrossCheckRoutes compares the counted sets of two routes.
//
// Comparison is on the set of (messageHash, transactionHash, publicKey)
// triples, not on raw counts - two different sets can have the same size.
func CrossCheckRoutes(a, b *SignatureEvidence) error {
	ka, kb := a.countedKeys(), b.countedKeys()

	var onlyA, onlyB []string
	for k := range ka {
		if _, ok := kb[k]; !ok {
			onlyA = append(onlyA, describeKey(k))
		}
	}
	for k := range kb {
		if _, ok := ka[k]; !ok {
			onlyB = append(onlyB, describeKey(k))
		}
	}
	if len(onlyA) == 0 && len(onlyB) == 0 {
		return nil
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return &RouteDisagreement{RouteA: a.Route, RouteB: b.Route, OnlyInA: onlyA, OnlyInB: onlyB}
}

func describeKey(k countedKey) string {
	return fmt.Sprintf("msg=%s key=%s", SafeTruncate(k.MessageHash, 16), SafeTruncate(k.PublicKey, 16))
}

// ResolveRoutes decides what to do given both routes' outcomes.
//
//	both succeed, sets agree        -> proceed, record both artifacts
//	both succeed, sets disagree     -> FAIL CLOSED, report the diff
//	one succeeds, other unavailable -> proceed on the successful one
//	both unavailable                -> FAIL as SignatureEvidenceIncomplete
//
// Degradation is never silent: whenever a route did not contribute, the
// returned RouteStatus says so, and the caller records it.
type RouteStatus struct {
	PrimaryRoute   string   `json:"primaryRoute"`
	RoutesAgreed   bool     `json:"routesAgreed"`
	Degraded       bool     `json:"degraded"`
	DegradedReason string   `json:"degradedReason,omitempty"`
	Artifacts      []string `json:"artifacts"`
}

func ResolveRoutes(a, aErr error, primary *SignatureEvidence, secondary *SignatureEvidence, secErr error) (
	*SignatureEvidence, *RouteStatus, error) {
	_ = a

	status := &RouteStatus{}

	switch {
	case aErr != nil && secErr != nil:
		// Both routes failed. If either failure is an evidence outage, the
		// combined outcome is an outage, not a rejection.
		if inc, ok := IsEvidenceIncomplete(aErr); ok {
			return nil, nil, inc
		}
		if inc, ok := IsEvidenceIncomplete(secErr); ok {
			return nil, nil, inc
		}
		return nil, nil, fmt.Errorf("both signature routes failed: primary: %v; secondary: %v", aErr, secErr)

	case aErr != nil:
		status.PrimaryRoute = secondary.Route
		status.Degraded = true
		status.DegradedReason = fmt.Sprintf("primary route unavailable: %v", aErr)
		status.Artifacts = []string{secondary.Route}
		return secondary, status, nil

	case secErr != nil:
		status.PrimaryRoute = primary.Route
		status.Degraded = true
		status.DegradedReason = fmt.Sprintf("secondary route unavailable: %v", secErr)
		status.Artifacts = []string{primary.Route}
		return primary, status, nil
	}

	// Both routes succeeded.
	if err := CrossCheckRoutes(primary, secondary); err != nil {
		return nil, nil, err
	}
	status.PrimaryRoute = primary.Route
	status.RoutesAgreed = true
	status.Artifacts = []string{primary.Route, secondary.Route}

	// A bounded route that agrees is fine, but say so.
	if primary.Bounded || secondary.Bounded {
		status.Degraded = true
		reasons := []string{}
		if primary.Bounded {
			reasons = append(reasons, primary.Route+": "+primary.BoundedReason)
		}
		if secondary.Bounded {
			reasons = append(reasons, secondary.Route+": "+secondary.BoundedReason)
		}
		status.DegradedReason = "coverage bounded (" + strings.Join(reasons, "; ") + ")"
	}
	return primary, status, nil
}
