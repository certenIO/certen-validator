// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
	var loops, indexLoops, builders int
	for _, c := range reg.Capturers() {
		if l, ok := c.(*ArbPostedLoop); ok {
			loops++
			if (l.Notes != nil) != want {
				t.Errorf("the Arbitrum capture loop notes blobs to an indexer: %v, want %v", l.Notes != nil, want)
			}
		}
		if l, ok := c.(*ArbIndexLoop); ok {
			indexLoops++
			if l.Index == nil || l.Memory == nil {
				t.Error("the index loop runs without its indexer or the process memory budget")
			}
		}
	}
	if (indexLoops == 1) != want || indexLoops > 1 {
		t.Errorf("%d index loops registered, want one: %v", indexLoops, want)
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

// The batch index runs in its OWN loop: it is stepped on every tick of that loop towards the capture cursor under the process memory budget, whatever
// the capture does; a named inconsistency it reports is recorded in the status table and never stops the loop.
func TestRTArbIndexLoopStepsTheBatchIndexTowardsTheCaptureCursorUnderTheMemoryBudget(t *testing.T) {
	l1 := &rtArbL1{head: 100}
	st := &rtStatus{}
	capLoop, lg := rtArbLoop(t, l1, st)
	ctx0 := context.Background()
	if _, err := capLoop.Cap.Tick(ctx0); err != nil { // the capture writes its cursor row
		t.Fatal(err)
	}
	idx := &rtArbIndexer{err: finality.IndexInconsistent(finality.ChainArbitrumSepolia, "arb", finality.IndexSelfCheckMismatch, "item", "idx/g1/arb/e/1/2/3", "l1_block", uint64(7))}
	budget := finality.NewMemoryBudget(0)
	loop := &ArbIndexLoop{Index: idx, Store: capLoop.Cap.Store, Memory: budget, Status: st, Every: 12 * time.Second, Logf: lg.logf}
	ctx, cancel := context.WithCancel(ctx0)
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
	if len(sc.waits) != 3 || sc.waits[0] != 12*time.Second {
		t.Fatalf("waits %v: one wait per step", sc.waits)
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
	capLoop2, lg2 := rtArbLoop(t, &rtArbL1{head: 50}, st2)
	if _, err := capLoop2.Cap.Tick(ctx0); err != nil {
		t.Fatal(err)
	}
	loop2 := &ArbIndexLoop{Index: &rtArbIndexer{err: errors.New("database is down")}, Store: capLoop2.Cap.Store, Status: st2, Every: 12 * time.Second, Logf: lg2.logf}
	ctx2, cancel2 := context.WithCancel(ctx0)
	defer cancel2()
	loop2.Clock = loopClock{After: (&rtScript{stopAfter: 1, cancel: cancel2}).After}
	_ = loop2.Run(ctx2)
	if st2.n != 0 || !lg2.has("database is down") {
		t.Fatalf("unnamed failure: %d status writes, logged %v", st2.n, lg2.has("database is down"))
	}
	// a cancelled context does not step, and a capture that has written no cursor row gives the index nothing to step to
	loop3 := &ArbIndexLoop{Index: &rtArbIndexer{}, Store: capLoop.Cap.Store, Logf: lg.logf}
	cctx, ccancel := context.WithCancel(ctx0)
	ccancel()
	loop3.runIndex(cctx, statusSink{})
	if len(loop3.Index.(*rtArbIndexer).upTo) != 0 {
		t.Fatal("a cancelled context must not step the index")
	}
	empty := &ArbIndexLoop{Index: &rtArbIndexer{}, Store: finality.NewMemCaptureStore(), Logf: lg.logf}
	empty.runIndex(ctx0, statusSink{})
	if len(empty.Index.(*rtArbIndexer).upTo) != 0 {
		t.Fatal("the index stepped without a capture cursor")
	}
}

// The blocks whose blob rows were all stored this tick are noted to the index, which may have passed them while they were incomplete.
func TestRTArbLoopNotesTheBlocksWhoseBlobsArrived(t *testing.T) {
	loop, _ := rtArbLoop(t, &rtArbL1{head: 100}, nil)
	idx := &rtArbIndexer{}
	loop.Notes = idx
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

// RB12-TRAIN3-INT duty (1): the Arbitrum wiring sets the capturer's authorization explicitly, so the live capture and the prefix scan judge a
// batch by the one function the readers and the writer use.
func TestRTArbWiringSetsTheCapturersOneAuthorization(t *testing.T) {
	rtProviderEnv(t)
	_, reg, _ := rtWire(t)
	found := false
	for _, c := range reg.Capturers() {
		if l, ok := c.(*ArbPostedLoop); ok {
			found = true
			if l.Cap.Authorize == nil {
				t.Fatal("the capturer must carry THE authorization (capture.AuthorizeBatch), set by the wiring")
			}
			rec := capture.BatchRecord{N: 1}
			if got, want := l.Cap.Authorize(rec, [20]byte{1}, 3, nil), capture.AuthorizeBatch(rec, [20]byte{1}, 3, nil); got != want {
				t.Fatalf("not the one function: %v vs %v", got, want)
			}
			if l.Cap.Prefix == nil {
				t.Fatal("the prefix scan is wired on the same capturer, so it judges by the same field")
			}
		}
	}
	if !found {
		t.Fatal("the Arbitrum capture loop is registered")
	}
}

// RB12-TRAIN3-INT duty (2): the Arbitrum prefix scan's stored batches reach the batch index (NoteLate) and the index reader's Floor follows the
// archive backfill's windows, so a batch stored far below the index cursor is found within one step, not after a walk of the table.
type arbNotes struct {
	noted  []uint64
	ranges [][2]uint64
}

func (n *arbNotes) NoteLate(b uint64)         { n.noted = append(n.noted, b) }
func (n *arbNotes) NoteLateRange(a, b uint64) { n.ranges = append(n.ranges, [2]uint64{a, b}) }

func TestRTArbPrefixScanBatchesAreNotedToTheIndexAndTheFloorFollowsTheWindows(t *testing.T) {
	notes := &arbNotes{}
	l := &ArbPostedLoop{Notes: notes}
	// the prefix scan closes ranges highest-first, far below the index cursor: every range and every stored batch is told, in that order
	l.noteBlobs(capture.Report{BlobBlocks: []uint64{500}, PrefixBlocks: []uint64{905, 805}, PrefixRanges: [][2]uint64{{900, 909}, {800, 809}}})
	if len(notes.noted) != 3 || notes.noted[1] != 905 || notes.noted[2] != 805 {
		t.Fatalf("blob blocks and prefix-scan blocks are both told: %v", notes.noted)
	}
	if len(notes.ranges) != 2 || notes.ranges[0] != [2]uint64{900, 909} || notes.ranges[1] != [2]uint64{800, 809} {
		t.Fatalf("a closed gapscan range is told as a range, highest first as scanned: %v", notes.ranges)
	}
	rtProviderEnv(t)
	w, reg, _ := rtWire(t)
	_ = w
	var floor func(context.Context) (uint64, bool, error)
	for _, p := range reg.Provers(finality.ChainArbitrumSepolia) {
		if b, ok := p.(*arbposted.Builder); ok && b.Index != nil {
			floor = b.Index.Floor
		}
	}
	if floor == nil {
		t.Fatal("the Arbitrum index reader has a Floor")
	}
	if _, ok, err := floor(context.Background()); err != nil || ok {
		t.Fatalf("with no prefix window there is no floor: %v %v", ok, err)
	}
}

// RB12-TRAIN3-INT duty (1): the default floor of the Arbitrum index is read from the SAME rows the archive backfill's prefix scan works on.
func TestRTArbDefaultFloorIsTheLowestRecordedPrefixWindow(t *testing.T) {
	ctx := context.Background()
	st := finality.NewMemCaptureStore()
	floor := prefixFloorOf(st, finality.ChainArbitrumSepolia)
	if _, ok, err := floor(ctx); err != nil || ok {
		t.Fatalf("no window, no floor: %v %v", ok, err)
	}
	for _, w := range [][2]uint64{{9_000, 9_099}, {4_000, 4_099}} { // recorded out of order, as the scan closes them
		if err := finality.RecordGap(ctx, st, finality.ChainArbitrumSepolia, w[0], w[1], finality.GapCapturePrefix); err != nil {
			t.Fatal(err)
		}
	}
	if lo, ok, err := floor(ctx); err != nil || !ok || lo != 4_000 {
		t.Fatalf("the floor is the lowest block of the recorded windows: %d %v %v", lo, ok, err)
	}
}
