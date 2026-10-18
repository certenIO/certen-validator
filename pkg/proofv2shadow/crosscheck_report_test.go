// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// C5-D2: the cross-check is the instrument of the shadow-exit rule (PROOF_V2 section 11), so what it found must be readable without a
// log search. Every outcome is one count of certen_proof_v2_shadow_results_total{stage="crosscheck",result=agree|disagree|unavailable}
// and one "[PROOF-V2-SHADOW] cross-check ..." log line, and the series exist (at 0) from the moment the process starts.

// capDriver is a database/sql driver that answers the one query CaptureResult makes, with the row it is given.
type capDriver struct {
	raw        []byte
	captureErr string
	done       bool
	absent     bool
}

func (d *capDriver) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *capDriver) Driver() driver.Driver                        { return d }
func (d *capDriver) Open(string) (driver.Conn, error)             { return d, nil }
func (d *capDriver) Prepare(string) (driver.Stmt, error)          { return d, nil }
func (d *capDriver) Close() error                                 { return nil }
func (d *capDriver) Begin() (driver.Tx, error)                    { return nil, fmt.Errorf("no transactions") }
func (d *capDriver) NumInput() int                                { return -1 }
func (d *capDriver) Exec([]driver.Value) (driver.Result, error)   { return nil, fmt.Errorf("no writes") }
func (d *capDriver) Query([]driver.Value) (driver.Rows, error)    { return &capRows{d: d}, nil }

type capRows struct {
	d    *capDriver
	sent bool
}

func (r *capRows) Columns() []string { return []string{"captured", "capture_error", "recorded"} }
func (r *capRows) Close() error      { return nil }
func (r *capRows) Next(dest []driver.Value) error {
	if r.sent || r.d.absent {
		return io.EOF
	}
	r.sent = true
	dest[0], dest[1], dest[2] = r.d.raw, r.d.captureErr, r.d.done
	return nil
}

// logSink collects the shadow's log lines.
type logSink chan string

func (l logSink) logf(f string, a ...any) { l <- fmt.Sprintf(f, a...) }

func (l logSink) next(t *testing.T) string {
	t.Helper()
	select {
	case s := <-l:
		return s
	case <-time.After(30 * time.Second):
		t.Fatal("no cross-check line was logged")
		return ""
	}
}

func crossCount(result string) float64 {
	return testutil.ToFloat64(shadowResults.WithLabelValues("crosscheck", result))
}

// v1 evidence of a real live intent (the RB4 Phase C intent, recorded by the validator and verified by govvote's own tests), and the key
// pages its replay reached.
func liveEvidence(t *testing.T) (*govvote.Evidence, map[string]govvote.States) {
	t.Helper()
	raw, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/govvote/testdata/evidence_phasec_98e40472.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Evidence govvote.Evidence `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	pages, err := govvote.ReplayPageHistories(&f.Evidence)
	if err != nil || len(pages) == 0 {
		t.Fatalf("the live evidence replays to %d pages: %v", len(pages), err)
	}
	return &f.Evidence, pages
}

func shadowWith(t *testing.T, d *capDriver, sink logSink) *Shadow {
	t.Helper()
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	return &Shadow{repo: database.NewProofV2ShadowRepository(database.NewClientFromDB(db)), logf: sink.logf}
}

// capturedFrom is a capture of the pages v1's replay reached, each at its last state (as of a block after every change), edited by edit.
func capturedFrom(t *testing.T, pages map[string]govvote.States, edit func(*protocol.KeyPage)) []byte {
	t.Helper()
	c := &Capture{Version: CaptureVersion, Principal: "acc://rb4-phase-c-09282125.acme/data", Partition: "acc://bvn-BVN1.acme", Block: 1 << 40}
	for _, st := range pages {
		p := st[len(st)-1].Page.Copy()
		if edit != nil {
			edit(p)
		}
		c.Pages = append(c.Pages, capturedPage(t, p, "acc://bvn-BVN1.acme", 1<<40))
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCrossCheckReportsAgreementDisagreementAndUnavailabilityByName(t *testing.T) {
	ev, pages := liveEvidence(t)
	n := len(pages)

	t.Run("agree", func(t *testing.T) {
		sink := make(logSink, 4)
		s := shadowWith(t, &capDriver{raw: capturedFrom(t, pages, nil), done: true}, sink)
		before := crossCount("agree")
		s.CrossCheck("intent-agree", ev)
		line := sink.next(t)
		want := fmt.Sprintf("[PROOF-V2-SHADOW] cross-check intent-agree: %d pages compared, v1 and v2 agree", n)
		if line != want {
			t.Fatalf("logged %q, want %q", line, want)
		}
		if got := crossCount("agree") - before; got != 1 {
			t.Fatalf("the agree count moved by %v", got)
		}
	})

	t.Run("disagree", func(t *testing.T) {
		sink := make(logSink, 4)
		s := shadowWith(t, &capDriver{raw: capturedFrom(t, pages, func(p *protocol.KeyPage) { p.AcceptThreshold += 7 }), done: true}, sink)
		before := crossCount("disagree")
		s.CrossCheck("intent-disagree", ev)
		line := sink.next(t)
		if !strings.HasPrefix(line, "[PROOF-V2-SHADOW] CROSS-CHECK DISAGREEMENT (stop the line) intent-disagree: ") ||
			!strings.Contains(line, fmt.Sprintf("%d pages compared, ", n)) || !strings.Contains(line, "acceptThreshold") {
			t.Fatalf("logged %q", line)
		}
		if got := crossCount("disagree") - before; got != 1 {
			t.Fatalf("the disagree count moved by %v", got)
		}
	})

	t.Run("a page v1 evaluated that v2 did not capture is a disagreement", func(t *testing.T) {
		sink := make(logSink, 4)
		s := shadowWith(t, &capDriver{raw: capturedFrom(t, map[string]govvote.States{}, nil), done: true}, sink)
		before := crossCount("disagree")
		s.CrossCheck("intent-uncaptured", ev)
		if line := sink.next(t); !strings.Contains(line, "CROSS-CHECK DISAGREEMENT (stop the line) intent-uncaptured") || !strings.Contains(line, "uncaptured") {
			t.Fatalf("logged %q", line)
		}
		if got := crossCount("disagree") - before; got != 1 {
			t.Fatalf("the disagree count moved by %v", got)
		}
	})

	t.Run("no vote evidence", func(t *testing.T) {
		sink := make(logSink, 4)
		s := shadowWith(t, &capDriver{done: true}, sink)
		before := crossCount("unavailable")
		s.CrossCheck("intent-noev", nil)
		if line := sink.next(t); line != "[PROOF-V2-SHADOW] cross-check intent-noev unavailable: v1 recorded no vote evidence for the intent" {
			t.Fatalf("logged %q", line)
		}
		if got := crossCount("unavailable") - before; got != 1 {
			t.Fatalf("the unavailable count moved by %v", got)
		}
	})

	t.Run("no pages were captured", func(t *testing.T) {
		sink := make(logSink, 4)
		s := shadowWith(t, &capDriver{done: true, captureErr: "g1_authority_missing"}, sink)
		before := crossCount("unavailable")
		s.CrossCheck("intent-nocap", ev)
		if line := sink.next(t); line != "[PROOF-V2-SHADOW] cross-check intent-nocap unavailable: no pages were captured" {
			t.Fatalf("logged %q", line)
		}
		if got := crossCount("unavailable") - before; got != 1 {
			t.Fatalf("the unavailable count moved by %v", got)
		}
	})
}

// A cross-check asked of a shadow that has not finished starting is not silent: nothing was captured to compare, and that is counted and
// logged by name. The other entry points of Lazy record the same moment (notReady); this one used to return without a trace.
func TestLazyCrossCheckBeforeTheShadowIsReadyIsCountedAndNamed(t *testing.T) {
	sink := make(logSink, 4)
	l := NewLazy(nil, sink.logf)
	before := crossCount("unavailable")
	l.CrossCheck("intent-early", &govvote.Evidence{})
	if got := crossCount("unavailable") - before; got != 1 {
		t.Fatalf("the unavailable count moved by %v; a cross-check asked before the shadow is ready is lost without a trace", got)
	}
	line := sink.next(t)
	if !strings.HasPrefix(line, "[PROOF-V2-SHADOW] cross-check intent-early unavailable: ") || !strings.Contains(line, "not ready") {
		t.Fatalf("logged %q", line)
	}
}

// The comparison runs in a goroutine of its own, so a panic in it would end the validator process, not just the comparison: whatever goes
// wrong inside is reported as an unavailable cross-check, by name, and the process goes on.
func TestCrossCheckContainsAPanicInsideTheComparison(t *testing.T) {
	sink := make(logSink, 4)
	s := &Shadow{logf: sink.logf} // no repository: reading the capture dereferences nil
	before := crossCount("unavailable")
	s.CrossCheck("intent-panic", &govvote.Evidence{})
	line := sink.next(t)
	if !strings.HasPrefix(line, "[PROOF-V2-SHADOW] cross-check intent-panic unavailable: ") || !strings.Contains(line, "panic") {
		t.Fatalf("logged %q", line)
	}
	if got := crossCount("unavailable") - before; got != 1 {
		t.Fatalf("the unavailable count moved by %v", got)
	}
}

// The cross-check's series are exported at 0 from the start: an operator reading the metric sees "wired, nothing found" as 0, never as no
// series at all, which is also what a build without the cross-check shows.
func TestCrossCheckSeriesAreExportedFromStart(t *testing.T) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range families {
		if f.GetName() != "certen_proof_v2_shadow_results_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["stage"] == "crosscheck" {
				seen[labels["result"]] = true
			}
		}
	}
	for _, r := range []string{"agree", "disagree", "unavailable"} {
		if !seen[r] {
			t.Errorf("certen_proof_v2_shadow_results_total{stage=\"crosscheck\",result=%q} is not exported until the first cross-check", r)
		}
	}
}
