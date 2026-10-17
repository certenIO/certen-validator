// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

var registerOnce sync.Once

func reader(t *testing.T, ps ...*ethprooftest.Provider) *ethrpc.AgreeingReader {
	t.Helper()
	r, err := ethrpc.NewAgreeingReader(context.Background(), ps[0].F.ChainID, ethprooftest.URLs(t, ps...), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// retype restates the first full transaction of every served block as type typ - a type no encoder knows.
func retype(typ string) func(string, []json.RawMessage, json.RawMessage) json.RawMessage {
	return func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getBlockByHash" && method != "eth_getBlockByNumber" {
			return res
		}
		var b map[string]json.RawMessage
		if json.Unmarshal(res, &b) != nil {
			return res
		}
		var txs []map[string]json.RawMessage
		if json.Unmarshal(b["transactions"], &txs) != nil || len(txs) == 0 {
			return res
		}
		txs[0]["type"] = json.RawMessage(`"` + typ + `"`)
		b["transactions"], _ = json.Marshal(txs)
		out, _ := json.Marshal(b)
		return out
	}
}

func number(t *testing.T, f *ethprooftest.Fixture) uint64 { return f.Header(t).Number.Uint64() }

// Range mode: a proven block exits 0, an unprovable one exits 1 naming it, an unread one exits 3.
func TestRangeExitCodesNameWhatWasEstablished(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.ArbitrumRedeem)
	n := number(t, f)
	cases := []struct {
		name string
		ps   []*ethprooftest.Provider
		want int
	}{
		{"proven", []*ethprooftest.Provider{{F: f}, {F: f, NoBlockReceipts: true}}, exitProven},
		{"cannot be proven", []*ethprooftest.Provider{{F: f, Mutate: retype("0x7d")}, {F: f, Mutate: retype("0x7d")}}, exitRefused},
		{"not read", []*ethprooftest.Provider{{F: f}, {F: f, Down: true}}, exitUnread},
	}
	for _, c := range cases {
		rs := checkAll(context.Background(), reader(t, c.ps...), []uint64{n}, 1, 2, time.Millisecond, nil)
		s := summarize(rs)
		if s.exitCode() != c.want {
			t.Fatalf("%s: exit %d, want %d (%+v)", c.name, s.exitCode(), c.want, rs[0].err)
		}
		if c.want == exitProven && (s.proven != 1 || s.types[0x68] != 1 || s.types[0x2] == 0) {
			t.Fatalf("%s: summary %+v", c.name, s)
		}
		if c.want == exitRefused && !strings.Contains(s.refusals[0].err.Error(), "0x7d") {
			t.Fatalf("%s: refusal not named: %v", c.name, s.refusals[0].err)
		}
	}
}

// Follow mode: the finalized block is proven and counted; an unprovable one is counted as refused and logged; an unread
// one stays pending and is asked again on the next cycle, never skipped.
func TestFollowCountsProvenRefusedAndKeepsUnreadPending(t *testing.T) {
	registerOnce.Do(func() { registerMetrics(prometheus.NewRegistry()) })
	f := ethprooftest.Load(t, ethprooftest.BaseSepolia)
	chain := "84532"
	var logged []string
	logf := func(format string, args ...interface{}) {
		logged = append(logged, strings.TrimSpace(fmt.Sprintf(format, args...)))
	}

	proven0 := testutil.ToFloat64(mBlocksProven.WithLabelValues(chain))
	fl := &follower{chainID: f.ChainID, src: reader(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f}), workers: 1, attempts: 1,
		backoff: time.Millisecond, maxBatch: 10, logf: logf}
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(mBlocksProven.WithLabelValues(chain)) - proven0; got != 1 || len(fl.pending) != 0 {
		t.Fatalf("proven %v, pending %d", got, len(fl.pending))
	}
	if testutil.ToFloat64(mProvenThrough.WithLabelValues(chain)) != float64(number(t, f)) {
		t.Fatal("proven_through_block is not the finalized block")
	}

	refused0 := testutil.ToFloat64(mRefused.WithLabelValues(chain))
	fl = &follower{chainID: f.ChainID, src: reader(t, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")},
		&ethprooftest.Provider{F: f, Mutate: retype("0x7d")}), workers: 1, attempts: 1, backoff: time.Millisecond, maxBatch: 10, logf: logf}
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(mRefused.WithLabelValues(chain))-refused0 != 1 || len(fl.pending) != 0 {
		t.Fatal("an unprovable block was not counted as refused")
	}
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], "CANNOT be proven") || !strings.Contains(logged[len(logged)-1], "0x7d") {
		t.Fatalf("the refusal was not logged by name: %v", logged)
	}

	down := &ethprooftest.Provider{F: f, Mutate: func(method string, p []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method == "eth_getBlockReceipts" {
			return json.RawMessage("null")
		}
		return res
	}}
	fl = &follower{chainID: f.ChainID, src: reader(t, &ethprooftest.Provider{F: f}, down), workers: 1, attempts: 1,
		backoff: time.Millisecond, maxBatch: 10, logf: logf}
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fl.pending) != 1 || testutil.ToFloat64(mPending.WithLabelValues(chain)) != 1 {
		t.Fatalf("an unread block is not pending: %d", len(fl.pending))
	}
	if testutil.ToFloat64(mProvenThrough.WithLabelValues(chain)) != float64(number(t, f)-1) {
		t.Fatal("proven_through_block passed a pending block")
	}
	// The provider recovers: the pending block is asked again and proven.
	fl.src = reader(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f})
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fl.pending) != 0 || testutil.ToFloat64(mProvenThrough.WithLabelValues(chain)) != float64(number(t, f)) {
		t.Fatalf("the pending block was not proven on the next cycle: %d pending", len(fl.pending))
	}
}

// The monitor reads each block from ONE provider and confirms a refusal through the agreeing providers: one provider
// serving an unprovable block is overruled (proven, and named); every provider serving it is a refusal.
func TestFollowReadsOneProviderAndConfirmsARefusal(t *testing.T) {
	registerOnce.Do(func() { registerMetrics(prometheus.NewRegistry()) })
	f := ethprooftest.Load(t, ethprooftest.ArbitrumRedeem)
	chain := "421614"
	dial := func(p *ethprooftest.Provider) *rpc.Client {
		c, err := rpc.Dial(ethprooftest.URLs(t, p)[0])
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var logged []string
	logf := func(format string, args ...interface{}) { logged = append(logged, fmt.Sprintf(format, args...)) }

	liar := &ethprooftest.Provider{F: f, Mutate: retype("0x7d")}
	proven0 := testutil.ToFloat64(mBlocksProven.WithLabelValues(chain))
	fl := &follower{chainID: f.ChainID, src: reader(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f}),
		one: []*rpc.Client{dial(liar)}, workers: 1, attempts: 1, backoff: time.Millisecond, maxBatch: 10, logf: logf}
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(mBlocksProven.WithLabelValues(chain))-proven0 != 1 {
		t.Fatal("THE regression: one provider's unprovable bodies were counted as an unprovable block")
	}
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], "that provider is wrong") {
		t.Fatalf("the wrong provider was not named: %v", logged)
	}

	refused0 := testutil.ToFloat64(mRefused.WithLabelValues(chain))
	fl = &follower{chainID: f.ChainID, src: reader(t, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")}, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")}),
		one: []*rpc.Client{dial(liar)}, workers: 1, attempts: 1, backoff: time.Millisecond, maxBatch: 10, logf: logf}
	if _, err := fl.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(mRefused.WithLabelValues(chain))-refused0 != 1 {
		t.Fatal("a block every provider serves unprovable was not counted refused")
	}
}
