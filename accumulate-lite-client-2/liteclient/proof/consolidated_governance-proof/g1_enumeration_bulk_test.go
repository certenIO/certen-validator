// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The enumeration route read every P#signature entry with its own message query, so its cost grew
// with everything the key page had ever signed. On 2026-09-26 acc://certen-kermit-12.acme/book/1
// carried 362 entries, G1 needed about 5m45s against a 115s budget, and every intent that page
// signed failed G1 as an infrastructure timeout.
//
// The fix reads the message bodies with the range itself (RangeOptions.Expand) and settles, from
// that body and with the same functions evaluateCandidate uses, only the two outcomes that need
// nothing else: "not a signature message" and "covers another transaction". Everything else is
// evaluated exactly as before. These tests run against live Kermit data; only the wrapper is
// synthetic.

// The e2e intent whose G1 timed out, and the page that signed it.
const (
	bulkAccount = "acc://certen-kermit-12.acme/data"
	bulkTxHash  = "77303959333f11820dbb33bc48360e1230c15fa41958e3ce385d8f1b48d8001d"
	bulkKeyPage = "acc://certen-kermit-12.acme/book/1"
)

var perMessageScope = regexp.MustCompile(`^acc://[0-9a-fA-F]{64}@`)

// bulkClient wraps the real client, counts per-message queries per page, and can rewrite the
// records of signature-chain range responses.
type bulkClient struct {
	inner     RPCClientInterface
	mu        sync.Mutex
	perMsg    map[string]int // page (without acc://) -> message queries
	rewrite   func(rec map[string]interface{})
	failRange bool
}

func (b *bulkClient) note(scope string, query map[string]interface{}) {
	if qt, _ := query["queryType"].(string); qt != "default" || !perMessageScope.MatchString(scope) {
		return
	}
	page := scope[strings.Index(scope, "@")+1:]
	b.mu.Lock()
	b.perMsg[page]++
	b.mu.Unlock()
}

func isSignatureRange(query map[string]interface{}) bool {
	_, hasRange := query["range"]
	name, _ := query["name"].(string)
	return hasRange && name == "signature"
}

func (b *bulkClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	raw, err := b.QueryRaw(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *bulkClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	b.note(scope, query)
	if isSignatureRange(query) && b.failRange {
		return nil, fmt.Errorf("injected fault: connection reset by peer")
	}
	raw, err := b.inner.QueryRaw(ctx, scope, query)
	if err != nil || b.rewrite == nil || !isSignatureRange(query) {
		return raw, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return raw, nil
	}
	if res, ok := resp["result"].(map[string]interface{}); ok {
		if recs, ok := res["records"].([]interface{}); ok {
			for _, r := range recs {
				if m, ok := r.(map[string]interface{}); ok {
					b.rewrite(m)
				}
			}
		}
	}
	return json.Marshal(resp)
}

func (b *bulkClient) GetEndpoint() string { return b.inner.GetEndpoint() }

func (b *bulkClient) messages(page string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.perMsg[strings.TrimPrefix(page, "acc://")]
}

func newBulkG1(t *testing.T, bc *bulkClient) *G1Layer {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = faultV3Endpoint
	}
	bc.inner = NewRPCClient(RPCConfig{Endpoint: ep, Timeout: 60 * time.Second, Backend: "http", UseHTTP: true})
	bc.perMsg = map[string]int{}
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatalf("artifact manager: %v", err)
	}
	return NewG1Layer(bc, am, "")
}

func bulkRequest() G1Request {
	return G1Request{G0Request: G0Request{Account: bulkAccount, TxHash: bulkTxHash, Chain: "main"}, KeyPage: bulkKeyPage}
}

// Fails on the pre-fix code: it issued one message query per P#signature entry (362 on this page).
func TestG1Enumeration_CostDoesNotGrowWithPageHistory(t *testing.T) {
	bc := &bulkClient{}
	g1 := newBulkG1(t, bc)
	start := time.Now()
	res, err := g1.ProveG1(context.Background(), bulkRequest())
	if err != nil {
		t.Fatalf("G1 must succeed for the e2e intent: %v", err)
	}
	if !res.ThresholdSatisfied || res.SignatureRouteStatus == nil || !res.SignatureRouteStatus.RoutesAgreed || res.SignatureRouteStatus.Degraded {
		t.Fatalf("both routes must run, agree and not degrade: satisfied=%v status=%+v", res.ThresholdSatisfied, res.SignatureRouteStatus)
	}
	// Route 1 resolves this transaction's one signature, route 2 fully evaluates only entries it
	// cannot settle from the body: the same one signature, plus retries at most.
	if n := bc.messages(bulkKeyPage); n > 6 {
		t.Fatalf("%d per-message queries on %s: the enumeration route still reads every entry one by one", n, bulkKeyPage)
	}
	t.Logf("G1 in %s, per-message queries on the signer page: %d", time.Since(start).Round(time.Millisecond), bc.messages(bulkKeyPage))
}

// A range record without a body must be evaluated in full, never skipped: stripping every body
// has to give the same verdict as the unmodified run, at the old cost.
func TestG1Enumeration_MissingBodyIsEvaluatedNotSkipped(t *testing.T) {
	bc := &bulkClient{rewrite: func(rec map[string]interface{}) { delete(rec, "value") }}
	g1 := newBulkG1(t, bc)
	res, err := g1.ProveG1(context.Background(), bulkRequest())
	if err != nil {
		t.Fatalf("G1 must still succeed when the range carries no bodies: %v", err)
	}
	if !res.ThresholdSatisfied || !res.SignatureRouteStatus.RoutesAgreed {
		t.Fatalf("routes must agree: %+v", res.SignatureRouteStatus)
	}
	if n := bc.messages(bulkKeyPage); n < 300 {
		t.Fatalf("only %d per-message queries: bodiless entries were skipped instead of evaluated", n)
	}
}

// A body that lies about which transaction it covers can at most HIDE a signature from route 2 -
// exactly what omitting it from the range already could. Route 1 still finds it, so the routes
// disagree and G1 fails closed; it never yields a verdict over a smaller set.
func TestG1Enumeration_TamperedBodyFailsClosed(t *testing.T) {
	bc := &bulkClient{rewrite: func(rec map[string]interface{}) {
		v, _ := rec["value"].(map[string]interface{})
		m, _ := v["message"].(map[string]interface{})
		s, _ := m["signature"].(map[string]interface{})
		if h, _ := s["transactionHash"].(string); strings.EqualFold(h, bulkTxHash) {
			s["transactionHash"] = strings.Repeat("ab", 32)
		}
	}}
	g1 := newBulkG1(t, bc)
	_, err := g1.ProveG1(context.Background(), bulkRequest())
	if err == nil {
		t.Fatal("a route-2 body hiding the counted signature must make G1 fail, not pass")
	}
	var dis *RouteDisagreement
	if !asRouteDisagreement(err, &dis) {
		t.Fatalf("expected a fail-closed route disagreement, got: %v", err)
	}
}

// A failed bulk read is an outage of route 2, never a rejection: G1 continues on route 1 and says
// it is degraded.
func TestG1Enumeration_RangeOutageDegradesNeverRejects(t *testing.T) {
	bc := &bulkClient{failRange: true}
	g1 := newBulkG1(t, bc)
	res, err := g1.ProveG1(context.Background(), bulkRequest())
	if err != nil {
		t.Fatalf("route-2 outage must degrade to route 1, got: %v", err)
	}
	if !res.ThresholdSatisfied || res.SignatureRouteStatus == nil || !res.SignatureRouteStatus.Degraded {
		t.Fatalf("expected a satisfied, DEGRADED verdict: %+v", res.SignatureRouteStatus)
	}
}

func asRouteDisagreement(err error, out **RouteDisagreement) bool { return errors.As(err, out) }
