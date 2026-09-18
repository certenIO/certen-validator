// Copyright 2026 Certen Protocol
//
// Discovery replaces a hand-exported candidate file. These tests pin the properties that make it safe to
// rely on: it never reports a range it could not read as empty, it never re-offers an anchor that already
// has a canonical row, and it covers the whole range it was asked for.

package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeScanner serves ProofExecuted logs from a per-block map and records which windows were requested.
type fakeScanner struct {
	head     uint64
	byBlock  map[uint64][]ProofExecutedLog
	windows  [][2]uint64
	failFrom uint64 // a window starting at or after this block fails
	headErr  error
}

func (f *fakeScanner) LatestBlock(_ context.Context, _ int64) (uint64, error) {
	if f.headErr != nil {
		return 0, f.headErr
	}
	return f.head, nil
}

func (f *fakeScanner) ScanProofExecuted(_ context.Context, chainID int64, from, to uint64) ([]ProofExecutedLog, error) {
	f.windows = append(f.windows, [2]uint64{from, to})
	if f.failFrom != 0 && to >= f.failFrom {
		return nil, errors.New("fictional: this endpoint refuses that range")
	}
	var out []ProofExecutedLog
	for b := from; b <= to; b++ {
		for _, l := range f.byBlock[b] {
			l.ChainID = chainID
			l.BlockNumber = b
			out = append(out, l)
		}
	}
	return out, nil
}

func bundleAt(n byte) [32]byte {
	var b [32]byte
	for i := range b {
		b[i] = n
	}
	return b
}

func txAt(n byte) string { return "0x" + strings.Repeat(fmt.Sprintf("%02x", n), 32) }

func allHeld(context.Context, int64, string) (bool, error)  { return true, nil }
func noneHeld(context.Context, int64, string) (bool, error) { return false, nil }

func TestDiscoveryReportsAnchorsWithNoCanonicalRow(t *testing.T) {
	s := &fakeScanner{
		head: 100,
		byBlock: map[uint64][]ProofExecutedLog{
			10: {{BundleID: bundleAt(1), TxHash: txAt(1)}},
			50: {{BundleID: bundleAt(2), TxHash: txAt(2)}},
			99: {{BundleID: bundleAt(3), TxHash: txAt(3)}},
		},
	}
	got, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 100, WindowSize: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProvenOnChain != 3 {
		t.Fatalf("proven = %d, want 3", got.ProvenOnChain)
	}
	if len(got.Candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(got.Candidates))
	}
	if got.ScannedTo[84532] != 100 {
		t.Fatalf("scanned to %d, want 100", got.ScannedTo[84532])
	}
}

// The healthy steady state: everything proven is already recorded, so a routine run finds nothing to do
// and never touches a transaction.
func TestDiscoverySkipsAnchorsAlreadyRecorded(t *testing.T) {
	s := &fakeScanner{
		head: 50,
		byBlock: map[uint64][]ProofExecutedLog{
			10: {{BundleID: bundleAt(1), TxHash: txAt(1)}},
			20: {{BundleID: bundleAt(2), TxHash: txAt(2)}},
		},
	}
	got, err := DiscoverAnchorQuorumCandidates(context.Background(), s, allHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProvenOnChain != 2 || got.AlreadyCanonical != 2 {
		t.Fatalf("proven=%d already=%d, want 2 and 2", got.ProvenOnChain, got.AlreadyCanonical)
	}
	if len(got.Candidates) != 0 {
		t.Fatalf("candidates = %d; an anchor with a canonical row must not be re-offered", len(got.Candidates))
	}
}

// THE FAILURE THAT MUST NOT BE SILENT. A provider that refuses a window has established nothing about it.
// Returning the anchors from the windows that did succeed would report a partial scan as a complete one.
func TestDiscoveryFailsWhenAWindowCannotBeRead(t *testing.T) {
	s := &fakeScanner{
		head:     100,
		byBlock:  map[uint64][]ProofExecutedLog{10: {{BundleID: bundleAt(1), TxHash: txAt(1)}}},
		failFrom: 60,
	}
	_, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 100, WindowSize: 25,
	})
	if err == nil {
		t.Fatal("a refused window was reported as an empty one")
	}
	if !strings.Contains(err.Error(), "scanning blocks") {
		t.Fatalf("error does not name the range that failed: %v", err)
	}
}

func TestDiscoveryFailsWhenTheHeadCannotBeRead(t *testing.T) {
	s := &fakeScanner{headErr: errors.New("fictional: endpoint down")}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532},
	}); err == nil {
		t.Fatal("discovery continued without knowing where the chain ends")
	}
}

// Every block in the requested range must be covered exactly once, with no gap at a window boundary and
// no block scanned twice. A gap is an anchor that is never backfilled.
func TestDiscoveryWindowsCoverTheWholeRangeWithoutGaps(t *testing.T) {
	s := &fakeScanner{head: 1000, byBlock: map[uint64][]ProofExecutedLog{}}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 100, ToBlock: 350, WindowSize: 100,
	}); err != nil {
		t.Fatal(err)
	}

	want := [][2]uint64{{100, 199}, {200, 299}, {300, 350}}
	if len(s.windows) != len(want) {
		t.Fatalf("windows = %v, want %v", s.windows, want)
	}
	for i, w := range want {
		if s.windows[i] != w {
			t.Fatalf("window %d = %v, want %v (full list %v)", i, s.windows[i], w, s.windows)
		}
	}
	assertWindowsAreContiguous(t, s.windows)
}

// A range that divides exactly into windows must not scan a phantom window past the end.
func TestDiscoveryStopsAtTheEndOfAnExactlyDivisibleRange(t *testing.T) {
	s := &fakeScanner{head: 1000, byBlock: map[uint64][]ProofExecutedLog{}}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 200, WindowSize: 100,
	}); err != nil {
		t.Fatal(err)
	}
	want := [][2]uint64{{1, 100}, {101, 200}}
	if len(s.windows) != 2 || s.windows[0] != want[0] || s.windows[1] != want[1] {
		t.Fatalf("windows = %v, want %v", s.windows, want)
	}
}

// One anchor proven once but logged in several places must be offered once.
func TestDiscoveryDeduplicatesAnAnchorSeenMoreThanOnce(t *testing.T) {
	s := &fakeScanner{
		head: 100,
		byBlock: map[uint64][]ProofExecutedLog{
			10: {{BundleID: bundleAt(7), TxHash: txAt(7)}},
			11: {{BundleID: bundleAt(7), TxHash: txAt(7)}},
			12: {{BundleID: bundleAt(7), TxHash: txAt(9)}}, // same anchor, different tx
		},
	}
	got, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProvenOnChain != 1 {
		t.Fatalf("proven = %d, want 1 — identity is the bundle id", got.ProvenOnChain)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got.Candidates))
	}
}

// The same bundle id on two chains is two anchors, and each needs its own row.
func TestDiscoveryTreatsTheSameBundleOnTwoChainsAsTwoAnchors(t *testing.T) {
	s := &fakeScanner{
		head:    100,
		byBlock: map[uint64][]ProofExecutedLog{10: {{BundleID: bundleAt(5), TxHash: txAt(5)}}},
	}
	got, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532, 11155111}, FromBlock: 1, ToBlock: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProvenOnChain != 2 {
		t.Fatalf("proven = %d, want 2", got.ProvenOnChain)
	}
	if len(got.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(got.Candidates))
	}
	if got.Candidates[0].ChainID == got.Candidates[1].ChainID {
		t.Fatal("both candidates landed on one chain")
	}
}

// With no explicit range, discovery scans back from the head rather than from genesis.
func TestDiscoveryDerivesItsRangeFromTheHead(t *testing.T) {
	s := &fakeScanner{head: 100000, byBlock: map[uint64][]ProofExecutedLog{}}
	got, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, LookbackBlocks: 500, WindowSize: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	// head-500 .. head inclusive is 501 blocks, so a 500-block window covers it in two passes. What
	// matters is the boundary, not the count: it starts at the lookback and finishes exactly at the head.
	if len(s.windows) == 0 {
		t.Fatal("nothing was scanned")
	}
	if first := s.windows[0][0]; first != 99500 {
		t.Fatalf("scan started at %d, want 99500 (head - lookback)", first)
	}
	if last := s.windows[len(s.windows)-1][1]; last != 100000 {
		t.Fatalf("scan ended at %d, want the head 100000", last)
	}
	assertWindowsAreContiguous(t, s.windows)
	if got.ScannedTo[84532] != 100000 {
		t.Fatalf("scanned to %d", got.ScannedTo[84532])
	}
}

// assertWindowsAreContiguous fails if the scan left a gap or repeated a block. A gap is an anchor that is
// never discovered and therefore never backfilled.
func assertWindowsAreContiguous(t *testing.T, windows [][2]uint64) {
	t.Helper()
	for i := 1; i < len(windows); i++ {
		if windows[i][0] != windows[i-1][1]+1 {
			t.Fatalf("window %d starts at %d but the previous ended at %d: %v",
				i, windows[i][0], windows[i-1][1], windows)
		}
	}
}

// A lookback longer than the chain must start at genesis, not underflow to a huge number.
func TestDiscoveryClampsALookbackLongerThanTheChain(t *testing.T) {
	s := &fakeScanner{head: 10, byBlock: map[uint64][]ProofExecutedLog{}}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, LookbackBlocks: 1000000, WindowSize: 100,
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.windows) != 1 || s.windows[0] != [2]uint64{0, 10} {
		t.Fatalf("windows = %v, want a single window from genesis", s.windows)
	}
}

func TestDiscoveryRefusesAnInvertedRange(t *testing.T) {
	s := &fakeScanner{head: 100}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, noneHeld, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 90, ToBlock: 10,
	}); err == nil {
		t.Fatal("an inverted range was accepted")
	}
}

func TestDiscoveryNeedsAScannerAndAtLeastOneChain(t *testing.T) {
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), nil, noneHeld,
		DiscoverOptions{Chains: []int64{1}}); err == nil {
		t.Fatal("discovery ran without a scanner")
	}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), &fakeScanner{}, noneHeld,
		DiscoverOptions{}); err == nil {
		t.Fatal("discovery ran with no chains")
	}
}

// A database that cannot answer "do I hold this anchor" must fail the run, not be read as "no".
// Treating the error as "not held" would re-backfill anchors that are already correct.
func TestDiscoveryFailsWhenTheDatabaseCannotAnswer(t *testing.T) {
	s := &fakeScanner{
		head:    100,
		byBlock: map[uint64][]ProofExecutedLog{10: {{BundleID: bundleAt(1), TxHash: txAt(1)}}},
	}
	broken := func(context.Context, int64, string) (bool, error) {
		return false, errors.New("fictional: database unavailable")
	}
	if _, err := DiscoverAnchorQuorumCandidates(context.Background(), s, broken, DiscoverOptions{
		Chains: []int64{84532}, FromBlock: 1, ToBlock: 100,
	}); err == nil {
		t.Fatal("a database failure was treated as 'this anchor is not recorded'")
	}
}

// Two runs over the same range must produce the same list, so a dry run can be compared with the apply.
func TestDiscoveryIsOrderedStably(t *testing.T) {
	byBlock := map[uint64][]ProofExecutedLog{
		10: {{BundleID: bundleAt(3), TxHash: txAt(3)}},
		11: {{BundleID: bundleAt(1), TxHash: txAt(1)}},
		12: {{BundleID: bundleAt(2), TxHash: txAt(2)}},
	}
	var first []BackfillCandidate
	for run := 0; run < 3; run++ {
		got, err := DiscoverAnchorQuorumCandidates(context.Background(),
			&fakeScanner{head: 100, byBlock: byBlock}, noneHeld,
			DiscoverOptions{Chains: []int64{84532}, FromBlock: 1, ToBlock: 100})
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			first = got.Candidates
			continue
		}
		if len(got.Candidates) != len(first) {
			t.Fatalf("run %d returned %d candidates, first returned %d", run, len(got.Candidates), len(first))
		}
		for i := range first {
			if got.Candidates[i] != first[i] {
				t.Fatalf("run %d differs at %d: %v vs %v", run, i, got.Candidates[i], first[i])
			}
		}
	}
}
