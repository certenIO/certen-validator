// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-B at the runtime: the settings, the wiring, the loop and the on-demand self-check of the Arbitrum batch index.

// A bad Arbitrum index setting is a named disabled state of THAT chain's index and never a fatal startup; a setting both indexes share switches
// both off, each with its own state.
func TestRTBadArbIndexSettingsAreANamedDisabledStateNotAFatalStartup(t *testing.T) {
	for _, c := range []struct {
		key, val, reason, refused string
		both                      bool
	}{
		{EnvArbIndex, "maybe", "switch_invalid", "", false},
		{EnvArbIndexGeneration, "0", "setting_invalid", "out_of_range", false},
		{EnvArbIndexGeneration, "-3", "setting_invalid", "out_of_range", false},
		{EnvArbIndexGeneration, "4294967296", "setting_invalid", "out_of_range", false},
		{EnvArbIndexGeneration, "4294967297", "setting_invalid", "out_of_range", false},
		{EnvArbIndexGeneration, "one", "setting_invalid", "not_an_integer", false},
		{EnvIndexBlocks, "0", "setting_invalid", "out_of_range", true},
		{EnvIndexStepSecond, "soon", "setting_invalid", "not_an_integer", true},
	} {
		t.Run(c.key+"="+c.val, func(t *testing.T) {
			t.Setenv(c.key, c.val)
			cfg, err := ConfigFromEnv()
			if err != nil {
				t.Fatalf("a bad index setting must not stop the validator: %v", err)
			}
			if cfg.ArbIndex {
				t.Fatal("the Arbitrum index must be off while a setting is bad")
			}
			if c.both == cfg.BaseIndex {
				t.Fatalf("shared setting %v: Base index on = %v", c.both, cfg.BaseIndex)
			}
			d, ok := cfg.Describe()["arb_index_disabled"].(string)
			if !ok || !strings.Contains(d, "finality_index_disabled") || !strings.Contains(d, c.key) || !strings.Contains(d, c.reason) || !strings.Contains(d, c.refused) || !strings.Contains(d, "421614") {
				t.Fatalf("the description names the state, the key, the reason and the chain: %v", cfg.Describe()["arb_index_disabled"])
			}
			if strings.Contains(d, c.val) && len(c.val) > 3 {
				t.Fatalf("the state must not echo the value: %s", d)
			}
		})
	}
	// the defaults
	for _, k := range []string{EnvArbIndex, EnvArbIndexGeneration} {
		t.Setenv(k, "")
	}
	if cfg, err := ConfigFromEnv(); err != nil || !cfg.ArbIndex || cfg.ArbIndexGeneration != 1 || cfg.ArbIndexDisabled != nil {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
}

func TestRTBadArbIndexSettingIsAnnouncedAndWiresNoIndexWhileTheArbChainStillRuns(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(EnvArbIndexGeneration, "4294967297")
	w, reg, logs := rtWire(t)
	if w.Disabled[finality.ChainArbitrumSepolia] != nil {
		t.Fatalf("the Arbitrum chain keeps running: %v", w.Disabled[finality.ChainArbitrumSepolia])
	}
	if !strings.Contains(logs.String(), "finality_index_disabled") {
		t.Fatalf("the disabled state is logged: %s", logs.String())
	}
	assertArbIndexWiring(t, reg, false)
	assertBaseIndexWiring(t, reg, true) // an Arbitrum-only setting leaves the Base index alone
	chains, _ := metrics.FinalityHealth()["chains"].(map[string]any)
	c, _ := chains["421614"].(map[string]any)
	if r, _ := c["index_disabled_reason"].(string); !strings.Contains(r, "finality_index_disabled") || !strings.Contains(r, "421614") {
		t.Fatalf("/health/detailed names the disabled index of the chain: %v", c)
	}
}

func TestRTArbIndexOffLeavesNoIndexerAndNoReaderAndOnWiresBoth(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(EnvArbIndex, "off")
	_, reg, _ := rtWire(t)
	assertArbIndexWiring(t, reg, false)
	t.Setenv(EnvArbIndex, "")
	_, reg, _ = rtWire(t)
	assertArbIndexWiring(t, reg, true)
}

func assertArbIndexWiring(t *testing.T, reg *finality.Registry, want bool) {
	t.Helper()
	var loops, builders int
	for _, c := range reg.Capturers() {
		if l, ok := c.(*ArbPostedLoop); ok {
			loops++
			if (l.Index != nil) != want {
				t.Errorf("the Arbitrum capture loop has an indexer: %v, want %v", l.Index != nil, want)
			}
			if want && l.Memory == nil {
				t.Error("the indexer runs without the process memory budget")
			}
		}
	}
	for _, p := range reg.Provers(finality.ChainArbitrumSepolia) {
		if b, ok := p.(*arbposted.Builder); ok {
			builders++
			if (b.Index != nil) != want {
				t.Errorf("the Arbitrum l1_posted builder has an index reader: %v, want %v", b.Index != nil, want)
			}
		}
	}
	if loops != 1 || builders != 1 {
		t.Fatalf("expected one Arbitrum capture loop and one l1_posted builder, got %d and %d", loops, builders)
	}
}

// rtArbIndexer records how the Arbitrum capture loop drives the index.
type rtArbIndexer struct {
	mu     sync.Mutex
	upTo   []uint64
	budget []*finality.MemoryBudget
	notes  []uint64
	err    error
}

func (r *rtArbIndexer) Chain() uint64  { return finality.ChainArbitrumSepolia }
func (r *rtArbIndexer) Family() string { return "arb" }
func (r *rtArbIndexer) Step(ctx context.Context, upTo uint64) (finality.StepReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upTo = append(r.upTo, upTo)
	r.budget = append(r.budget, finality.MemoryBudgetOf(ctx))
	return finality.StepReport{Target: upTo, Through: upTo}, r.err
}
func (r *rtArbIndexer) SelfCheck(context.Context, int) error { return nil }
func (r *rtArbIndexer) NoteLate(b uint64)                    { r.mu.Lock(); r.notes = append(r.notes, b); r.mu.Unlock() }

// The batch index is stepped after every capture tick, towards the capture cursor, under the process memory budget, also on a tick that finds
// nothing new; a named inconsistency it reports is recorded in the status table and never stops the capture.
func TestRTArbLoopStepsTheBatchIndexAfterEveryTickUnderTheMemoryBudget(t *testing.T) {
	l1 := &rtArbL1{head: 100}
	st := &rtStatus{}
	loop, lg := rtArbLoop(t, l1, st)
	idx := &rtArbIndexer{err: finality.IndexInconsistent(finality.ChainArbitrumSepolia, "arb", finality.IndexSelfCheckMismatch, "item", "idx/g1/arb/e/1/2/3", "l1_block", uint64(7))}
	budget := finality.NewMemoryBudget(0)
	loop.Index, loop.Memory = idx, budget
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc := &rtScript{stopAfter: 3, cancel: cancel}
	loop.Clock = loopClock{After: sc.After}
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := idx.upTo; len(got) != 3 || got[0] != 100 || got[1] != 100 || got[2] != 100 {
		t.Fatalf("the index was stepped towards %v, want the capture cursor three times", got)
	}
	for i, b := range idx.budget {
		if b != budget {
			t.Fatalf("step %d did not carry the process memory budget", i)
		}
	}
	row, ok := st.row(CaptureStatusProofID(finality.ChainArbitrumSepolia), finality.LevelL1Posted)
	if !ok || row.State == nil || row.State.Code != finality.CodeIndexInconsistent || row.State.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("the named inconsistency is a status row of the capture pseudo proof: %+v", row)
	}
	if !lg.has("index arb: step to L1 block 100") {
		t.Fatal("the failed step was not logged")
	}
	// an unnamed failure is logged and not recorded as a state the registry does not name
	st2 := &rtStatus{}
	loop2, lg2 := rtArbLoop(t, &rtArbL1{head: 50}, st2)
	loop2.Index = &rtArbIndexer{err: errors.New("database is down")}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	loop2.Clock = loopClock{After: (&rtScript{stopAfter: 1, cancel: cancel2}).After}
	_ = loop2.Run(ctx2)
	if st2.n != 0 || !lg2.has("database is down") {
		t.Fatalf("unnamed failure: %d status writes, logged %v", st2.n, lg2.has("database is down"))
	}
	// a cancelled context does not step
	loop3, _ := rtArbLoop(t, &rtArbL1{head: 50}, nil)
	idx3 := &rtArbIndexer{}
	loop3.Index = idx3
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	loop3.runIndex(cctx, statusSink{})
	if len(idx3.upTo) != 0 {
		t.Fatal("a cancelled context must not step the index")
	}
}

// The blocks whose blob rows were all stored this tick are noted to the index, which may have passed them while they were incomplete.
func TestRTArbLoopNotesTheBlocksWhoseBlobsArrived(t *testing.T) {
	loop, _ := rtArbLoop(t, &rtArbL1{head: 100}, nil)
	idx := &rtArbIndexer{}
	loop.Index = idx
	loop.noteBlobs(capture.Report{BlobBlocks: []uint64{11, 13}})
	if len(idx.notes) != 2 || idx.notes[0] != 11 || idx.notes[1] != 13 {
		t.Fatalf("notes %v", idx.notes)
	}
	var _ finality.LateBlockNoter = (*arbposted.Indexer)(nil) // the real indexer takes the same notes (the archive backfill's prefix scan calls the same interface)
}

type fakeArbSelfChecker struct {
	res arbposted.SelfCheckResult
	err error
}

func (f fakeArbSelfChecker) SelfCheckReport(context.Context, int) (arbposted.SelfCheckResult, error) {
	return f.res, f.err
}

func TestRTArbIndexSelfCheckOnDemandNamesItsResult(t *testing.T) {
	on := Config{ArbIndex: true}
	for _, c := range []struct {
		name string
		cfg  Config
		ix   ArbIndexSelfChecker
		code int
		want string
	}{
		{"ok", on, fakeArbSelfChecker{res: arbposted.SelfCheckResult{Generation: 1, Entries: 4, Digests: 4}}, IndexSelfCheckOK, "finality-arb-index-selfcheck: ok generation=1"},
		{"a mismatch counted", on, fakeArbSelfChecker{res: arbposted.SelfCheckResult{Generation: 1, Entries: 4, Mismatches: 1}}, IndexSelfCheckMismatch, "MISMATCH"},
		{"a mismatch named", on, fakeArbSelfChecker{err: finality.IndexInconsistent(421614, "arb", finality.IndexSelfCheckMismatch, "item", "idx/g1/arb/e/1/2/3")}, IndexSelfCheckMismatch, "self_check_mismatch"},
		{"checks skipped", on, fakeArbSelfChecker{res: arbposted.SelfCheckResult{Generation: 1, Entries: 1, Skipped: 2}}, IndexSelfCheckIncomplete, "INCOMPLETE generation=1 around_l1_block=0 entries=1 digests=0 skipped=2"},
		{"the store failed", on, fakeArbSelfChecker{err: errors.New("store down")}, IndexSelfCheckFailed, "FAILED"},
		{"index off", Config{}, fakeArbSelfChecker{}, IndexSelfCheckNotRunning, "switched off"},
		{"no indexer", on, nil, IndexSelfCheckNotRunning, "switched off"},
		{"a bad setting", Config{ArbIndexDisabled: finality.IndexDisabledState(421614, EnvArbIndex, finality.IndexSettingSwitchInvalid, "")}, fakeArbSelfChecker{}, IndexSelfCheckNotRunning, "finality_index_disabled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			code := RunArbIndexSelfCheck(context.Background(), &out, c.cfg, c.ix, 16)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("code %d (want %d), output %q (want it to contain %q)", code, c.code, out.String(), c.want)
			}
		})
	}
}
