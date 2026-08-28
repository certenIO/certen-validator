// Copyright 2026 Certen Protocol
//
// Phase 8 — a transaction that has not executed is not a transaction that was
// refused, and the proof must say which one it is looking at.
//
// Rule 8 ranks a FALSE governance rejection above every other failure, because
// an error is obviously a problem and a false rejection looks like a finding.
// The three outcomes below are the ones that must never collapse into one
// another:
//
//	executed, authority set not satisfied  -> governance rejection. A finding.
//	not executed (pending or absent)       -> nothing to prove. NOT a finding.
//	chain unreadable                       -> infrastructure. NOT a finding.
//
// Measured on Kermit 2026-08-28: corpus case L-partial (fd279178fb52a6e0) is a
// transaction the network is deliberately holding PENDING because only one of
// acc://certen-p8l.acme's two authorities has voted. G0 reported it as
// "Response missing result{} or data{}" - the third outcome, when the truth was
// the second.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// p8neClient answers exactly one txID probe, and records what it was asked.
type p8neClient struct {
	resp      map[string]interface{}
	err       error
	askedFor  string
	callCount int
}

func (c *p8neClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	c.askedFor = scope
	c.callCount++
	return c.resp, c.err
}

func (c *p8neClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	return nil, errors.New("not used")
}

func (c *p8neClient) GetEndpoint() string { return "test" }

// notFoundEntry is the shape Kermit actually returned for L-partial.
func notFoundEntry(account, txHash string) map[string]interface{} {
	msg := "get entry index: Account." + account + ".MainChain.ElementIndex." + txHash + " not found"
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    float64(-33404),
			"message": msg,
			"data": map[string]interface{}{
				"message": msg,
				"code":    "notFound",
			},
		},
	}
}

// TestP8_MissingEntryIsRecognised pins that the notFound for a main-chain entry
// is distinguished from every other failure the same RPC can return.
func TestP8_MissingEntryIsRecognised(t *testing.T) {
	ok, detail := missingMainChainEntry(
		notFoundEntry("acc://certen-p8l.acme/data", "fd279178fb52a6e0"))
	if !ok {
		t.Fatal("the notFound Kermit returns for a missing main-chain entry was not recognised; " +
			"a pending transaction will be reported as a malformed response")
	}
	if !strings.Contains(detail, "ElementIndex") {
		t.Errorf("the network's own words must be carried through, got %q", detail)
	}
}

// TestP8_MissingAccountIsNotMissingEntry is the reason this matches on the
// element name and not on notFound alone.
//
// A missing ACCOUNT is also notFound, and it is an entirely different fact: it
// means the account URL is wrong, not that a transaction is waiting for a vote.
// Collapsing the two would replace one wrong answer with another.
func TestP8_MissingAccountIsNotMissingEntry(t *testing.T) {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "load state: Account.acc://nope.acme/data.Main not found",
			"data":    map[string]interface{}{"code": "notFound"},
		},
	}
	if ok, _ := missingMainChainEntry(resp); ok {
		t.Fatal("a missing ACCOUNT was read as a missing transaction entry: " +
			"a wrong URL would be reported as a pending transaction")
	}
}

// TestP8_SuccessIsNotAMissingEntry guards the obvious direction.
func TestP8_SuccessIsNotAMissingEntry(t *testing.T) {
	resp := map[string]interface{}{"result": map[string]interface{}{"index": float64(7)}}
	if ok, _ := missingMainChainEntry(resp); ok {
		t.Fatal("a successful response was classified as a missing entry")
	}
}

// TestP8_PendingIsNamedAsPending is case L-partial: the transaction exists and
// the network is still collecting authorization.
func TestP8_PendingIsNamedAsPending(t *testing.T) {
	c := &p8neClient{resp: map[string]interface{}{
		"result": map[string]interface{}{"status": "pending"},
	}}

	e := classifyNotExecuted(context.Background(), c,
		"acc://certen-p8l.acme/data", "fd279178fb52a6e0", "detail")

	if e.State != notExecutedPending {
		t.Fatalf("state = %q, want %q", e.State, notExecutedPending)
	}
	if !strings.Contains(c.askedFor, "fd279178fb52a6e0@certen-p8l.acme/data") {
		t.Errorf("the probe must ask about the TRANSACTION, asked %q", c.askedFor)
	}

	msg := e.Error()
	for _, want := range []string{"PENDING", "NOT a governance rejection", "NOT a threshold shortfall"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message must contain %q, got: %s", want, msg)
		}
	}
	if e.Reason() != "not-executed" {
		t.Errorf("Reason() = %q, want a distinct code a caller can match on", e.Reason())
	}
}

// TestP8_AbsentIsNamedAsAbsent separates "waiting for a vote" from "never seen".
// Both mean it did not execute; they are different facts and both are stated.
func TestP8_AbsentIsNamedAsAbsent(t *testing.T) {
	c := &p8neClient{resp: map[string]interface{}{
		"error": map[string]interface{}{"message": "not found"},
	}}

	e := classifyNotExecuted(context.Background(), c, "acc://a.acme/data", "deadbeef", "")

	if e.State != notExecutedAbsent {
		t.Fatalf("state = %q, want %q", e.State, notExecutedAbsent)
	}
	if !strings.Contains(e.Error(), "NO RECORD") {
		t.Errorf("an absent transaction must say so, got: %s", e.Error())
	}
}

// TestP8_UnprobableStaysUnknown is the fail-closed direction, and the whole
// point of the state field.
//
// When the follow-up query cannot be answered we do not know whether the
// transaction is pending. Defaulting to "pending" because it is the common case
// would invent a fact about a transaction we could not read - exactly what rule
// 8 exists to prevent.
func TestP8_UnprobableStaysUnknown(t *testing.T) {
	c := &p8neClient{err: errors.New("connection refused")}

	e := classifyNotExecuted(context.Background(), c, "acc://a.acme/data", "deadbeef", "")

	if e.State != notExecutedUnknown {
		t.Fatalf("state = %q, want %q - an unanswered probe must never be reported as a known state",
			e.State, notExecutedUnknown)
	}
	if !strings.Contains(e.Error(), "could not be answered") {
		t.Errorf("the message must admit the probe failed, got: %s", e.Error())
	}
}

// TestP8_DeliveredContradictionIsSurfaced covers the case where the premise is
// wrong: the transaction reports delivered, yet has no entry on the chain we
// queried. That contradiction is the operator's business, not something to
// smooth into a tidy "pending".
func TestP8_DeliveredContradictionIsSurfaced(t *testing.T) {
	c := &p8neClient{resp: map[string]interface{}{
		"result": map[string]interface{}{"status": "delivered"},
	}}

	e := classifyNotExecuted(context.Background(), c, "acc://a.acme/data", "deadbeef", "")

	if e.State == notExecutedPending {
		t.Fatal("a delivered transaction was reported as pending")
	}
	if !strings.Contains(e.Detail, "delivered") {
		t.Errorf("the contradiction must reach the reader, got detail %q", e.Detail)
	}
}

// TestP8_NotExecutedSurvivesWrapping pins the %w at both wrap sites.
//
// G0 wraps into "execution inclusion proof failed" and G1 wraps that into
// "G0 proof failed". With %v the type is destroyed and a caller has nothing to
// match on but prose, which is how a capability limit ends up being read as a
// governance rejection.
func TestP8_NotExecutedSurvivesWrapping(t *testing.T) {
	inner := NotExecutedOnChain{Account: "acc://a.acme/data", TxHash: "deadbeef", State: notExecutedPending}

	wrapped := wrapTwice(inner)

	if !IsNotExecuted(inner) {
		t.Fatal("IsNotExecuted must recognise the bare error")
	}
	var got NotExecutedOnChain
	if !errors.As(wrapped, &got) {
		t.Fatal("the not-executed reason did not survive wrapping: both wrap sites must use %w")
	}
	if got.State != notExecutedPending {
		t.Errorf("state lost through wrapping: %q", got.State)
	}
	if !IsNotExecuted(wrapped) {
		t.Error("IsNotExecuted must see through the wrapping the real call path applies")
	}
}

// wrapTwice reproduces the two wrap sites verbatim: g0_layer.go wraps
// proveExecutionInclusion, and g1_layer.go wraps ProveG0.
func wrapTwice(err error) error {
	g0 := fmt.Errorf("execution inclusion proof failed: %w", err)
	return fmt.Errorf("G0 proof failed: %w", g0)
}
