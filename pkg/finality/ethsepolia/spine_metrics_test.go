// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// scraped is the value of the series name{labels} in the default registry (what /metrics serves), and whether it is exposed at all.
func scraped(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
	next:
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					continue next
				}
			}
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue(), true
			}
		}
	}
	return 0, false
}

// Class 9: the gauges are non-zero at the moment they should be, and the recommended alert can fire. A leg whose provider is down keeps no
// new chunk: after three such attempts certen_finality_spine_stalled_attempts_max is 3 (the alert threshold of pr/rb11-alerts.md) and the leg
// is counted as awaiting; when the spine completes both fall back to 0 and the fetched headers are counted.
func TestSpineMetricsAreNonZeroWhenALegStallsAndZeroWhenItCompletes(t *testing.T) {
	metrics.RegisterMetrics()
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	src := ch.model(clk, 0)
	down := true
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		if down {
			return nil, errors.New("provider down")
		}
		return out, nil
	}
	store := finality.NewMemCaptureStore()
	p := spineProver(src, store, clk, 0)

	errBefore, _ := scraped(t, "certen_finality_spine_attempts_total", map[string]string{"outcome": "error"})
	for i := 1; i <= 3; i++ {
		if _, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend == nil {
			t.Fatalf("attempt %d: %v %v", i, pend, err)
		}
		stalled, ok := scraped(t, "certen_finality_spine_stalled_attempts_max", nil)
		awaiting, ok2 := scraped(t, "certen_finality_spine_legs_awaiting", nil)
		if !ok || !ok2 || stalled != float64(i) || awaiting != 1 {
			t.Fatalf("after %d attempts without progress: stalled_attempts_max %v (%v) legs_awaiting %v (%v), want %d and 1", i, stalled, ok, awaiting, ok2, i)
		}
	}
	if n, _ := scraped(t, "certen_finality_spine_attempts_total", map[string]string{"outcome": "error"}); n != errBefore+3 {
		t.Fatalf("error attempts %v, want %v", n, errBefore+3)
	}

	down = false
	fetchedBefore, _ := scraped(t, "certen_finality_spine_headers_total", map[string]string{"outcome": "fetched"})
	completeBefore, _ := scraped(t, "certen_finality_spine_attempts_total", map[string]string{"outcome": "complete"})
	if sp, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend != nil || len(sp) == 0 {
		t.Fatalf("the healed provider: %v %v", pend, err)
	}
	if stalled, _ := scraped(t, "certen_finality_spine_stalled_attempts_max", nil); stalled != 0 {
		t.Fatalf("stalled_attempts_max %v after the spine completed", stalled)
	}
	if awaiting, _ := scraped(t, "certen_finality_spine_legs_awaiting", nil); awaiting != 0 {
		t.Fatalf("legs_awaiting %v after the spine completed", awaiting)
	}
	if n, _ := scraped(t, "certen_finality_spine_headers_total", map[string]string{"outcome": "fetched"}); n != fetchedBefore+float64(ch.top()-legN) {
		t.Fatalf("fetched headers %v, want %v more than %v", n, ch.top()-legN, fetchedBefore)
	}
	if n, _ := scraped(t, "certen_finality_spine_attempts_total", map[string]string{"outcome": "complete"}); n != completeBefore+1 {
		t.Fatalf("complete attempts %v, want %v", n, completeBefore+1)
	}
}

// A kept row that is not what its key says is counted by reason when it is found.
func TestSpineMetricsCountAWrongKeptRowByReason(t *testing.T) {
	metrics.RegisterMetrics()
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	spans := PlanSpans(legN, ch.top()-1)
	target := spans[2]
	k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: target.End, L1Hash: ch.hashOf(target.End), Item: SpineItem(target.Count())}
	store := replaced(t, filledStore(t, ch, legN), k, encodeSpan(ch.hs[:target.Count()-1])) // one header short
	before, _ := scraped(t, "certen_finality_spine_rows_invalid_total", map[string]string{"reason": SpineRowMalformed})
	clk := newClock()
	p := spineProver(ch.model(clk, 0), store, clk, 0)
	if _, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend != nil {
		t.Fatalf("%v %v", pend, err)
	}
	if n, ok := scraped(t, "certen_finality_spine_rows_invalid_total", map[string]string{"reason": SpineRowMalformed}); !ok || n != before+1 {
		t.Fatalf("rows_invalid_total{reason=%s} = %v (%v), want %v", SpineRowMalformed, n, ok, before+1)
	}
}
