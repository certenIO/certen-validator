// Copyright 2026 Certen Protocol

package capture_test

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// TestAT9ArbitrumAttestationCaptureWindowUnderLoad is the AT-9 load test of WP-S8-3b under the replay clock: seven validators capture the
// same Arbitrum attestation at once, four captures per chain at a time (the gate), against providers whose latency per call follows the
// MEASURED table of the check-in (2026-10-24, Arbitrum Sepolia public endpoints: one slot 100-300 ms, 81 slots 100-800 ms, +about 50 ms for
// the first call). Every capture runs on its own virtual clock, so a provider call costs exactly its modelled latency and the calls of one
// capture are summed: with Parallel = 1 this is an UPPER bound of the wall-clock time (the production setting overlaps the calls of a pass).
// The captures that wait for a gate slot start one finished capture later. AT-9 accepts p95 <= 15 s inside the 25 s window.
func TestAT9ArbitrumAttestationCaptureWindowUnderLoad(t *testing.T) {
	fc := newFakeChain(t, 421614, "h0")
	gate := capture.NewGate(4)
	type latency struct{ base, perSlot time.Duration }
	models := []latency{{280 * time.Millisecond, 6 * time.Millisecond}, {100 * time.Millisecond, 0}, {60 * time.Millisecond, 0}} // zan, arbitrum rollup, publicnode
	const captures = 7
	durations := make([]time.Duration, captures)
	calls := make([]int, captures)
	var wg sync.WaitGroup
	errs := make([]error, captures)
	perFirst := map[string]int{}
	for i := 0; i < captures; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			clk := ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0))
			src := &fakeSource{fc: fc}
			for j, m := range models {
				m := m
				src.providers = append(src.providers, &fakeProvider{name: fmt.Sprintf("https://p%d.example", j), fc: fc, mode: honest,
					lat: func(slots int) { clk.Sleep(context.Background(), m.base+time.Duration(slots)*m.perSlot) }})
			}
			cfg := fc.config(src)
			cfg.Clock, cfg.Gate, cfg.Budget = clk, gate, 20*time.Second
			start := clk.Now()
			res, err := capture.CaptureAttest(context.Background(), cfg, capture.AttestRequest{TxHash: fc.attTx})
			if err == nil && res.Stated != nil {
				err = fmt.Errorf("Stated %s", res.Stated.Reason)
			}
			errs[i], durations[i] = err, clk.Now().Sub(start)
			for _, p := range src.providers {
				fp := p.(*fakeProvider)
				calls[i] += fp.count()
				if i == 0 {
					fp.mu.Lock()
					for k, n := range fp.asked {
						perFirst[k[:8]+k[len(k)-9:]] += n
					}
					fp.mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
	}
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// the captures beyond the gate's four slots start when the fastest of the first wave is done
	withWait := make([]time.Duration, 0, captures)
	for i, d := range sorted {
		if i < 4 {
			withWait = append(withWait, d)
		} else {
			withWait = append(withWait, sorted[0]+d)
		}
	}
	p95 := withWait[len(withWait)-1] // 7 samples: the largest is the p95
	var per []string
	for k, n := range perFirst {
		per = append(per, fmt.Sprintf("%s:%d", k, n))
	}
	sort.Strings(per)
	fmt.Printf("AT-9 eth_getProof requests of capture 0 by contract@block: %v\n", per)
	fmt.Printf("AT-9 model: calls per capture %v, capture time (sum of call latencies) min %v max %v, with the gate wait max %v (p95), window 25s, budget 20s\n",
		calls, sorted[0], sorted[len(sorted)-1], p95)
	if p95 > 15*time.Second {
		t.Fatalf("p95 %v exceeds the AT-9 threshold of 15 s", p95)
	}
	if gate.InUse() != 0 {
		t.Fatal("the gate leaked a slot")
	}
	for _, n := range calls {
		if n != 21 { // pinned: 10 proof calls per station for the anchor at 5 rounds, 4 for the verifier, 1+1 for the others, 3 codes
			t.Fatalf("a capture made %d provider calls, the plan needs exactly 21", n)
		}
	}
}
