// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Gate 4A.6 - fault injection.
//
// The defect this phase exists to remove is that an infrastructure failure and
// a governance rejection were the same value. Every observed G1 failure looked
// like this:
//
//	{"threshold_m":1,"threshold_n":1,"attestation_count":1,"threshold_met":false}
//
// One signature expected, one found, zero validated. The signature could not be
// EVALUATED, and that was recorded as a governance verdict.
//
// Reading the code cannot prove this is fixed. These tests wrap the REAL Kermit
// client, fail selected calls, and assert on what comes out. They run against
// live data so the only thing synthetic is the fault.

const faultV3Endpoint = "https://kermit.accumulatenetwork.io/v3"

// faultyClient wraps a real RPC client and fails calls matching a predicate.
type faultyClient struct {
	inner RPCClientInterface
	mu    sync.Mutex
	// failOn decides whether this call fails. It receives the scope and the
	// query, and the number of times it has already been consulted.
	failOn func(scope string, query map[string]interface{}, n int) bool
	calls  int
	failed int
}

func (f *faultyClient) shouldFail(scope string, q map[string]interface{}) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failOn != nil && f.failOn(scope, q, f.calls) {
		f.failed++
		return true
	}
	return false
}

func (f *faultyClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	if f.shouldFail(scope, query) {
		return nil, fmt.Errorf("injected fault: connection reset by peer")
	}
	return f.inner.Query(ctx, scope, query)
}

func (f *faultyClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	if f.shouldFail(scope, query) {
		return nil, fmt.Errorf("injected fault: connection reset by peer")
	}
	return f.inner.QueryRaw(ctx, scope, query)
}

func (f *faultyClient) GetEndpoint() string { return f.inner.GetEndpoint() }

func (f *faultyClient) stats() (calls, failed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.failed
}

// The live fixture: a real transaction whose G1 proof succeeds unfaulted.
const (
	faultAccount = "acc://carp-buyer-62431.acme/data"
	faultTxHash  = "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0"
	faultKeyPage = "acc://carp-buyer-62431.acme/book/1"
)

func newFaultG1(t *testing.T, failOn func(string, map[string]interface{}, int) bool) (*G1Layer, *faultyClient) {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = faultV3Endpoint
	}
	real := NewRPCClient(RPCConfig{
		Endpoint: ep,
		Timeout:  60 * time.Second,
		Backend:  "http",
		UseHTTP:  true,
	})
	fc := &faultyClient{inner: real, failOn: failOn}
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatalf("artifact manager: %v", err)
	}
	return NewG1Layer(fc, am, ""), fc
}

func faultG1Request() G1Request {
	return G1Request{
		G0Request: G0Request{Account: faultAccount, TxHash: faultTxHash, Chain: "main"},
		KeyPage:   faultKeyPage,
	}
}

// Control: with no faults injected, G1 must succeed. Without this, a test that
// "correctly rejects" proves nothing - it might reject everything.
func TestPhase4A_FaultInjection_ControlSucceeds(t *testing.T) {
	g1, fc := newFaultG1(t, nil)
	res, err := g1.ProveG1(context.Background(), faultG1Request())
	if err != nil {
		t.Fatalf("unfaulted G1 must succeed, got: %v", err)
	}
	if !res.ThresholdSatisfied {
		t.Fatal("unfaulted G1 must satisfy the threshold")
	}
	if res.SignatureRouteStatus == nil {
		t.Fatal("route status must be recorded")
	}
	if !res.SignatureRouteStatus.RoutesAgreed {
		t.Fatalf("both routes must run and agree, got: %+v", res.SignatureRouteStatus)
	}
	calls, _ := fc.stats()
	t.Logf("control passed: %d RPC calls, routes agreed, unique keys=%d threshold=%d",
		calls, res.UniqueValidKeys, res.RequiredThreshold)
}

// The core gate: an RPC error on a signature's message query MUST surface as
// SignatureEvidenceIncomplete and MUST NEVER become a threshold verdict.
func TestPhase4A_FaultInjection_RPCErrorIsNeverAThresholdVerdict(t *testing.T) {
	// Fail every query whose scope looks like a signature message ID, i.e. the
	// per-signature resolution both routes depend on.
	isSigMessageQuery := func(scope string, q map[string]interface{}, _ int) bool {
		if !strings.Contains(scope, "@") {
			return false
		}
		// The message-ID query has no chain name; receipt queries do.
		_, hasName := q["name"]
		return !hasName
	}

	g1, fc := newFaultG1(t, isSigMessageQuery)
	res, err := g1.ProveG1(context.Background(), faultG1Request())

	if err == nil {
		t.Fatalf("CRITICAL DEFECT: G1 succeeded while every signature was unreachable "+
			"(unique keys=%d, threshold satisfied=%t)", res.UniqueValidKeys, res.ThresholdSatisfied)
	}

	inc, ok := IsEvidenceIncomplete(err)
	if !ok {
		t.Fatalf("CRITICAL DEFECT: an RPC outage produced %T instead of SignatureEvidenceIncomplete.\n"+
			"This is the exact confusion that recorded nine healthy proofs as governance failures.\nerror: %v",
			err, err)
	}
	if len(inc.Unavailable) == 0 {
		t.Fatal("SignatureEvidenceIncomplete must name the unavailable candidates")
	}

	// The message must not read as a governance rejection.
	msg := strings.ToLower(inc.Error())
	for _, forbidden := range []string{"threshold not satisfied", "threshold_met"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("CRITICAL DEFECT: an outage was reported as a threshold verdict: %s", inc.Error())
		}
	}
	if !strings.Contains(msg, "infrastructure") {
		t.Fatalf("the outage must say what it is, got: %s", inc.Error())
	}

	calls, failed := fc.stats()
	t.Logf("rejected correctly: %d/%d calls faulted", failed, calls)
	t.Logf("  requested=%d evaluated=%d unavailable=%d", inc.Requested, inc.Evaluated, len(inc.Unavailable))
	t.Logf("  %s", SafeTruncate(inc.Error(), 320))
}

// Retry must apply to unavailable candidates - and only to them. A transient
// fault that clears must not fail the proof.
func TestPhase4A_FaultInjection_TransientFaultIsRetried(t *testing.T) {
	var once sync.Once
	var tripped bool
	failFirstSigQuery := func(scope string, q map[string]interface{}, _ int) bool {
		if !strings.Contains(scope, "@") {
			return false
		}
		if _, hasName := q["name"]; hasName {
			return false
		}
		fail := false
		once.Do(func() { fail = true; tripped = true })
		return fail
	}

	g1, fc := newFaultG1(t, failFirstSigQuery)
	res, err := g1.ProveG1(context.Background(), faultG1Request())
	if !tripped {
		t.Fatal("test setup: the fault never fired")
	}
	if err != nil {
		t.Fatalf("a single transient fault must be retried, not fatal: %v", err)
	}
	if !res.ThresholdSatisfied {
		t.Fatal("threshold must still be satisfied after a retried transient fault")
	}
	calls, failed := fc.stats()
	t.Logf("recovered from a transient fault: %d/%d calls faulted, threshold satisfied", failed, calls)
}

// A receipt-query outage is also an outage, not a timing rejection. Timing
// failures and receipt-unavailability used to be the same `continue`.
func TestPhase4A_FaultInjection_ReceiptOutageIsNotATimingRejection(t *testing.T) {
	failReceiptQueries := func(scope string, q map[string]interface{}, _ int) bool {
		name, _ := q["name"].(string)
		return name == "signature" && q["entry"] != nil
	}

	g1, _ := newFaultG1(t, failReceiptQueries)
	_, err := g1.ProveG1(context.Background(), faultG1Request())
	if err == nil {
		t.Fatal("CRITICAL DEFECT: G1 succeeded while no signature receipt could be fetched")
	}
	inc, ok := IsEvidenceIncomplete(err)
	if !ok {
		t.Fatalf("CRITICAL DEFECT: a receipt outage produced %T, not SignatureEvidenceIncomplete: %v", err, err)
	}
	sawReceiptStage := false
	for _, u := range inc.Unavailable {
		if strings.Contains(u.Stage, "receipt") {
			sawReceiptStage = true
		}
		if strings.Contains(strings.ToLower(u.Stage), "timing") {
			t.Fatalf("CRITICAL DEFECT: a receipt outage was classified as a timing rejection: %+v", u)
		}
	}
	if !sawReceiptStage {
		t.Fatalf("expected a receipt-stage outage, got: %+v", inc.Unavailable)
	}
	t.Logf("rejected correctly at the receipt stage: %s", SafeTruncate(inc.Error(), 240))
}

// Route disagreement must fail closed with a diff, never be averaged or
// resolved by preferring one route.
func TestPhase4A_RouteDisagreementFailsClosed(t *testing.T) {
	mk := func(route string, sigs ...ValidatedSignature) *SignatureEvidence {
		return &SignatureEvidence{Route: route, Counted: sigs}
	}
	sig := func(msg, tx, pk string) ValidatedSignature {
		return ValidatedSignature{
			MessageHash: msg,
			Signature:   SignatureData{TransactionHash: tx, PublicKey: pk},
		}
	}
	a := sig("aa11", "tx1", "pk1")
	b := sig("bb22", "tx1", "pk2")

	t.Run("identical sets agree", func(t *testing.T) {
		if err := CrossCheckRoutes(mk("A", a, b), mk("B", b, a)); err != nil {
			t.Fatalf("order must not matter: %v", err)
		}
	})

	t.Run("extra signature in one route is a disagreement", func(t *testing.T) {
		err := CrossCheckRoutes(mk("A", a, b), mk("B", a))
		if err == nil {
			t.Fatal("CRITICAL DEFECT: routes with different sets were accepted")
		}
		if _, ok := err.(*RouteDisagreement); !ok {
			t.Fatalf("expected RouteDisagreement, got %T", err)
		}
		t.Logf("%v", err)
	})

	t.Run("same count, different keys is a disagreement", func(t *testing.T) {
		// Raw counts coincide; the sets do not. Comparing counts would pass.
		c := sig("cc33", "tx1", "pk3")
		if err := CrossCheckRoutes(mk("A", a, b), mk("B", a, c)); err == nil {
			t.Fatal("CRITICAL DEFECT: equal-sized but different sets were accepted")
		}
	})

	t.Run("same key over a different transaction is a disagreement", func(t *testing.T) {
		d := sig("aa11", "tx2", "pk1")
		if err := CrossCheckRoutes(mk("A", a), mk("B", d)); err == nil {
			t.Fatal("CRITICAL DEFECT: signatures over different transactions were treated as equal")
		}
	})

	t.Run("ResolveRoutes fails closed on disagreement", func(t *testing.T) {
		_, status, err := ResolveRoutes(nil, nil, mk("A", a, b), mk("B", a), nil)
		if err == nil {
			t.Fatal("CRITICAL DEFECT: ResolveRoutes accepted disagreeing routes")
		}
		if status != nil {
			t.Fatal("no route status may be produced for a disagreement")
		}
	})

	t.Run("one route unavailable proceeds but is marked degraded", func(t *testing.T) {
		outage := &SignatureEvidenceIncomplete{Route: "B", Requested: 1}
		ev, status, err := ResolveRoutes(nil, nil, mk("A", a), nil, outage)
		if err != nil {
			t.Fatalf("a single-route outage must not fail the proof: %v", err)
		}
		if ev == nil || status == nil {
			t.Fatal("expected evidence and status")
		}
		if !status.Degraded || status.DegradedReason == "" {
			t.Fatal("CRITICAL DEFECT: degradation was silent")
		}
		if status.RoutesAgreed {
			t.Fatal("routes cannot have agreed when one did not run")
		}
	})

	t.Run("both routes unavailable is an evidence outage", func(t *testing.T) {
		oa := &SignatureEvidenceIncomplete{Route: "A", Requested: 1}
		ob := &SignatureEvidenceIncomplete{Route: "B", Requested: 1}
		_, _, err := ResolveRoutes(nil, oa, nil, nil, ob)
		if _, ok := IsEvidenceIncomplete(err); !ok {
			t.Fatalf("expected SignatureEvidenceIncomplete, got %T: %v", err, err)
		}
	})
}
