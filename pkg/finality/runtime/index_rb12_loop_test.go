// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// rtIndexer is a finality.CaptureIndexer that records how the capture loop drives it.
type rtIndexer struct {
	mu     sync.Mutex
	upTo   []uint64
	budget []*finality.MemoryBudget
	err    error
}

func (r *rtIndexer) Chain() uint64  { return finality.ChainBaseSepolia }
func (r *rtIndexer) Family() string { return "bi" }
func (r *rtIndexer) Step(ctx context.Context, upTo uint64) (finality.StepReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upTo = append(r.upTo, upTo)
	r.budget = append(r.budget, finality.MemoryBudgetOf(ctx))
	return finality.StepReport{Target: upTo, Through: upTo}, r.err
}
func (r *rtIndexer) SelfCheck(context.Context, int) error { return nil }

// RB12-INDEX-A: the capture index is stepped after every capture tick, towards the capture cursor, under the process memory budget, also on
// a tick that finds nothing new (a backfill must progress while the capture is caught up); it never stops the capture, and a named
// inconsistency it reports is recorded in the status table under the chain's capture pseudo id.
func TestRTBaseLoopStepsTheCaptureIndexAfterEveryTickTowardsTheCursorUnderTheMemoryBudget(t *testing.T) {
	l1 := &rtBaseL1{head: 100}
	loop, _, _ := rtBaseLoop(t, l1, nil)
	idx := &rtIndexer{}
	budget := finality.NewMemoryBudget(0)
	loop.Index, loop.Memory = idx, budget
	ctx := context.Background()
	if err := loop.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := loop.Tick(ctx, 2); err != nil { // the head has not moved: nothing to capture, the index still steps
		t.Fatal(err)
	}
	l1.head = 120
	if err := loop.Tick(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if got := idx.upTo; len(got) != 3 || got[0] != 100 || got[1] != 100 || got[2] != 120 {
		t.Fatalf("the index was stepped towards %v, want [100 100 120]", got)
	}
	for i, b := range idx.budget {
		if b != budget {
			t.Fatalf("step %d did not carry the process memory budget", i)
		}
	}
}

func TestRTBaseLoopRecordsTheIndexInconsistencyAndKeepsCapturing(t *testing.T) {
	l1 := &rtBaseL1{head: 100}
	st := &rtStatus{}
	loop, mem, lg := rtBaseLoop(t, l1, st)
	idx := &rtIndexer{err: finality.IndexInconsistent(finality.ChainBaseSepolia, "bi", finality.IndexSelfCheckMismatch, "item", "idx/g1/bi/c/1/2/00", "l1_block", uint64(7))}
	loop.Index = idx
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatalf("an index failure must not fail the capture tick: %v", err)
	}
	row, ok := st.row(CaptureStatusProofID(finality.ChainBaseSepolia), finality.LevelL1Posted)
	if !ok || row.State == nil || row.State.Code != finality.CodeIndexInconsistent || row.State.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("the named inconsistency is a status row of the capture pseudo proof: %+v", row)
	}
	if !lg.has("index bi: step to L1 block 100") {
		t.Fatal("the failed step was not logged")
	}
	if cur, ok, _ := readCursor(context.Background(), mem, finality.ChainBaseSepolia); !ok || cur != 100 {
		t.Fatalf("the capture cursor still advanced: %d %v", cur, ok)
	}
	// an unnamed failure is logged and not recorded as a state the registry does not name
	st2 := &rtStatus{}
	loop2, _, lg2 := rtBaseLoop(t, &rtBaseL1{head: 50}, st2)
	loop2.Index = &rtIndexer{err: errors.New("database is down")}
	if err := loop2.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if st2.n != 0 || !lg2.has("database is down") {
		t.Fatalf("unnamed failure: %d status writes, logged %v", st2.n, lg2.has("database is down"))
	}
	// a cancelled context does not step
	loop3, _, _ := rtBaseLoop(t, &rtBaseL1{head: 50}, nil)
	idx3 := &rtIndexer{}
	loop3.Index = idx3
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	loop3.runIndex(cctx, statusSink{}, 50)
	if len(idx3.upTo) != 0 {
		t.Fatal("a cancelled context must not step the index")
	}
}

func TestRTConfigReadsTheIndexSettingsAndRefusesBadOnes(t *testing.T) {
	t.Setenv(EnvBaseIndex, "")
	t.Setenv(finality.EnvIndexGeneration, "")
	c, err := ConfigFromEnv()
	if err != nil || !c.BaseIndex || c.IndexGeneration != 1 || c.IndexBlocks != 128 || c.IndexStep.Seconds() != 15 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	t.Setenv(EnvBaseIndex, "false")
	t.Setenv(finality.EnvIndexGeneration, "3")
	t.Setenv(EnvIndexBlocks, "16")
	if c, err = ConfigFromEnv(); err != nil || c.BaseIndex || c.IndexGeneration != 3 || c.IndexBlocks != 16 {
		t.Fatalf("set: %+v %v", c, err)
	}
	// a bad setting is a named disabled state of the index and the validator keeps running (TestRTBadIndexSettings... pins every class)
	t.Setenv(finality.EnvIndexGeneration, "0")
	if c, err = ConfigFromEnv(); err != nil || c.BaseIndex || c.IndexDisabled == nil || c.IndexDisabled.Code != "finality_index_disabled" || c.IndexDisabled.Fields["variable"] != finality.EnvIndexGeneration {
		t.Fatalf("generation 0 is the named disabled state, not a fatal startup: %+v %v", c.IndexDisabled, err)
	}
	t.Setenv(finality.EnvIndexGeneration, "1")
	t.Setenv(EnvBaseIndex, "maybe")
	if c, err = ConfigFromEnv(); err != nil || c.BaseIndex || c.IndexDisabled == nil || c.IndexDisabled.Fields["variable"] != EnvBaseIndex {
		t.Fatalf("a switch that is not a boolean is the named disabled state, not a fatal startup: %+v %v", c.IndexDisabled, err)
	}
}
