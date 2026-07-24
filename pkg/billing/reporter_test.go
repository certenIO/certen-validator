package billing

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The reporter's promise is narrow and absolute: a cost that was measured is
// never lost, and reporting can never fail a proof cycle. These tests attack
// both halves.

func testReporter(t *testing.T, gatewayURL string) *Reporter {
	t.Helper()
	r := NewReporter(ReporterConfig{
		GatewayURL:         gatewayURL,
		ServiceTokenSecret: "test-secret",
		WALDir:             t.TempDir(),
		MaxAttempts:        3,
		RetryBase:          10 * time.Millisecond,
		Logger:             log.New(io.Discard, "", 0),
	})
	if r == nil {
		t.Fatal("reporter should be enabled with a URL and secret")
	}
	return r
}

func sampleCost(chain, tx, leg string) *ChainCost {
	c := &ChainCost{
		Chain: chain, Leg: leg, TxHash: tx, NativeSymbol: "ETH",
		WeiPerNative: new(big.Int).Set(wei), ObservedAt: time.Now(),
		Breakdown: map[string]string{},
	}
	c.setGas(369000, big.NewInt(15000000000))
	return c
}

func TestReporterDisabledWithoutConfig(t *testing.T) {
	// A nil reporter must be safe to use, so callers never need a branch and
	// can never accidentally make cost reporting mandatory.
	if r := NewReporter(ReporterConfig{Logger: log.New(io.Discard, "", 0)}); r != nil {
		t.Fatal("expected nil reporter when unconfigured")
	}
	var nilReporter *Reporter
	nilReporter.Report(&CostEvent{})
	nilReporter.Start(context.Background())
	nilReporter.Stop(time.Millisecond)
	nilReporter.ObserveAndReport(context.Background(), ProbeConfig{}, "i", "o", "t", nil)
	if stats := nilReporter.Stats(); stats["enabled"] != false {
		t.Fatal("nil reporter stats should report disabled")
	}
}

func TestReportWritesWALBeforeDelivery(t *testing.T) {
	// Durability: the event must be on disk the instant Report returns, before
	// any network call. A crash in between otherwise loses a cost the chain
	// already charged us for.
	r := testReporter(t, "http://127.0.0.1:1") // unreachable on purpose
	event, err := NewCostEvent("intent-1", "", sampleCost("base", "0xaaa", LegAnchor), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Report(event)

	entries, _ := os.ReadDir(r.cfg.WALDir)
	found := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("expected 1 WAL entry, found %d", found)
	}
	if r.pendingCount() != 1 {
		t.Fatalf("pendingCount = %d", r.pendingCount())
	}
}

func TestDeliverySucceedsAndClearsWAL(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&received, 1)
		if req.Header.Get("X-Certen-Service-Token") == "" {
			t.Error("request is missing the service token")
		}
		var body CostEvent
		_ = json.NewDecoder(req.Body).Decode(&body)
		if body.IdempotencyKey == "" {
			t.Error("event has no idempotency key")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	defer srv.Close()

	r := testReporter(t, srv.URL)
	event, _ := NewCostEvent("intent-2", "", sampleCost("base", "0xbbb", LegVerify), nil)
	r.Report(event)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop(2 * time.Second)

	waitFor(t, 3*time.Second, func() bool { return r.pendingCount() == 0 })
	if atomic.LoadInt32(&received) != 1 {
		t.Fatalf("gateway received %d events, want 1", received)
	}
}

func TestDuplicateReportIsIdempotent(t *testing.T) {
	// Same (chain, tx, leg) reported twice must occupy ONE WAL slot, or a
	// retry loop would deliver the same cost repeatedly and inflate COGS.
	r := testReporter(t, "http://127.0.0.1:1")
	cost := sampleCost("base", "0xccc", LegAnchor)
	e1, _ := NewCostEvent("i", "", cost, nil)
	e2, _ := NewCostEvent("i", "", cost, nil)
	if e1.IdempotencyKey != e2.IdempotencyKey {
		t.Fatalf("idempotency keys differ: %s vs %s", e1.IdempotencyKey, e2.IdempotencyKey)
	}
	r.Report(e1)
	r.Report(e2)
	if r.pendingCount() != 1 {
		t.Fatalf("expected 1 WAL entry after a duplicate report, got %d", r.pendingCount())
	}
}

func TestWALSurvivesRestart(t *testing.T) {
	// The whole point of the WAL: a process that dies before delivering still
	// delivers after a restart.
	dir := t.TempDir()

	first := NewReporter(ReporterConfig{
		GatewayURL: "http://127.0.0.1:1", ServiceTokenSecret: "s",
		WALDir: dir, Logger: log.New(io.Discard, "", 0),
	})
	event, _ := NewCostEvent("intent-3", "", sampleCost("solana", "sig123", LegAnchor), nil)
	first.Report(event)
	if first.pendingCount() != 1 {
		t.Fatal("event should be on disk")
	}
	// No Stop(): simulate a hard crash.

	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	second := NewReporter(ReporterConfig{
		GatewayURL: srv.URL, ServiceTokenSecret: "s", WALDir: dir,
		MaxAttempts: 3, RetryBase: 10 * time.Millisecond,
		Logger: log.New(io.Discard, "", 0),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	second.Start(ctx)
	defer second.Stop(2 * time.Second)

	waitFor(t, 3*time.Second, func() bool { return atomic.LoadInt32(&received) == 1 })
	waitFor(t, 2*time.Second, func() bool { return second.pendingCount() == 0 })
}

func TestGatewayAcceptedAsIdempotentReplayClearsWAL(t *testing.T) {
	// 200 means "already recorded" and is as final as 201. Treating it as a
	// failure would retry forever against a gateway that already has the data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"recorded":false}`))
	}))
	defer srv.Close()

	r := testReporter(t, srv.URL)
	event, _ := NewCostEvent("i", "", sampleCost("base", "0xddd", LegAnchor), nil)
	r.Report(event)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop(2 * time.Second)

	waitFor(t, 3*time.Second, func() bool { return r.pendingCount() == 0 })
}

func TestAuthRejectionParksInsteadOfRetryingForever(t *testing.T) {
	// A wrong shared secret will not fix itself. Burning retries would hide
	// the real problem behind noise.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid service token"}`))
	}))
	defer srv.Close()

	r := testReporter(t, srv.URL)
	event, _ := NewCostEvent("i", "", sampleCost("base", "0xeee", LegAnchor), nil)
	r.Report(event)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)
	defer r.Stop(2 * time.Second)

	parked := filepath.Join(r.cfg.WALDir, "parked")
	waitFor(t, 3*time.Second, func() bool {
		entries, err := os.ReadDir(parked)
		return err == nil && len(entries) == 1
	})
	// Parked, never deleted: the event is the only record that we spent money.
	if r.pendingCount() != 0 {
		t.Fatalf("parked event should leave the active queue, pending = %d", r.pendingCount())
	}
}

func TestReportNeverBlocksWhenQueueIsFull(t *testing.T) {
	// Cost reporting must never be able to stall a proof cycle.
	r := NewReporter(ReporterConfig{
		GatewayURL: "http://127.0.0.1:1", ServiceTokenSecret: "s",
		WALDir: t.TempDir(), QueueSize: 1, Logger: log.New(io.Discard, "", 0),
	})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			c := sampleCost("base", "0x"+string(rune('a'+i%26))+string(rune('a'+i/26)), LegAnchor)
			e, _ := NewCostEvent("i", "", c, nil)
			r.Report(e)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Report blocked when the queue was full — it must never block the executor")
	}
	// Overflow still reaches disk, so nothing is lost; the sweep picks it up.
	if r.pendingCount() == 0 {
		t.Fatal("overflowed events must still be durable in the WAL")
	}
}

func TestNewCostEventRejectsUnattributableCost(t *testing.T) {
	// A cost with no intent cannot be reconciled or billed; recording it would
	// create an orphan that inflates COGS with no matching charge.
	if _, err := NewCostEvent("", "", sampleCost("base", "0xf", LegAnchor), nil); err == nil {
		t.Fatal("expected rejection of a cost event without an intent id")
	}
}

func TestCostEventCarriesFactsNotPrices(t *testing.T) {
	// The validator must never send a USD amount: pricing belongs to the
	// gateway, using its own signed FX observation.
	event, err := NewCostEvent("i", "org", sampleCost("base", "0x1", LegVaultExecute), nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(event)
	for _, forbidden := range []string{"usd", "cost_microusd", "price_microusd"} {
		if containsFold(string(blob), forbidden) {
			t.Fatalf("cost event must not carry a price field (%q): %s", forbidden, blob)
		}
	}
	if event.GasUsed != "369000" || event.EffectiveGasPriceWei != "15000000000" {
		t.Fatalf("chain facts not carried verbatim: %s / %s", event.GasUsed, event.EffectiveGasPriceWei)
	}
	if event.WeiPerNative != "1000000000000000000" {
		t.Fatalf("denominator must travel with the event, got %s", event.WeiPerNative)
	}
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) > len(h) {
		return false
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}
