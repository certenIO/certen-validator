// Copyright 2026 Certen Protocol

package build

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2 item 11 (same mislabel class as F5): a capture row that cannot be kept, an assertion log that does not decode and (not
// reachable by a test double, see the comment at the site) a trie proof that cannot be built are faults of the BUILDER, not verdicts of the
// verifier: they are finality_builder_error{stage: build}, never finality_verifier_failed, and the cause is kept (redacted).
func wantBuilderErrorAtBuild(t *testing.T, add *finality.Addendum, pend *finality.PendingState, err error, cause string) {
	t.Helper()
	if add != nil || pend != nil {
		t.Fatalf("add %v pend %v", add != nil, pend)
	}
	if s, named := finality.AsNamed(err); named {
		t.Fatalf("a named verdict %v: the fault is the builder's", s.Code)
	}
	st := finality.BuilderStatusOf("proof", finality.ChainArbitrumSepolia, finality.LevelFinalized, finality.LevelIncluded, nil, err, false, time.Unix(0, 0))
	if st.State == nil || st.State.Code != finality.CodeBuilderError || st.State.Fields["stage"] != finality.StageBuild || !strings.Contains(fmt.Sprint(st.State.Fields["cause"]), cause) {
		t.Fatalf("status %+v", st.State)
	}
}

func TestACaptureThatCannotBeKeptIsABuilderErrorAtTheBuildStageNotAVerifierFailure(t *testing.T) {
	for _, c := range []struct {
		name, prefix string
		world        func(*testing.T) *world
	}{
		{"wallet", captureItemWallet, func(t *testing.T) *world { return newWorldWith(t, provenWallet()) }},
		{"state", captureItemState, newWorld},
		{"confirmation", captureItemConf, newWorld},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := c.world(t)
			w.p.Store = failingStore{CaptureStore: NewMemStore(), prefix: c.prefix}
			add, pend, err := w.build(t)
			wantBuilderErrorAtBuild(t, add, pend, err, "disk full")
		})
	}
}

func TestAnAssertionLogThatDoesNotDecodeIsABuilderErrorAtTheBuildStage(t *testing.T) {
	w := newWorld(t)
	for i := range w.l1.logs {
		w.l1.logs[i].Data = []byte{1, 2, 3}
	}
	add, pend, err := w.build(t)
	wantBuilderErrorAtBuild(t, add, pend, err, "")
}
