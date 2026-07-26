package consensus

import "testing"

// RetainHeight controls how much consensus history CometBFT keeps. It used to
// be hardcoded to `height - 100`, which was costly in two ways:
//
//   - it made a mismatched volume reset UNRECOVERABLE (the app restarts at
//     height 0 against a pruned store, and replay from genesis is impossible:
//     "app block height (0) is too far below block store base (4)"), and
//   - it discarded the BFT precommit record proving a quorum agreed at a
//     height, which nothing else currently captures externally.
//
// Retain-all is therefore the default and pruning is opt-in.

func TestRetainsAllHistoryByDefault(t *testing.T) {
	app := &ValidatorApp{} // blockRetention zero value = retain all
	for _, h := range []int64{0, 1, 99, 100, 101, 5000} {
		if got := app.retainHeightFor(h); got != 0 {
			t.Errorf("retainHeightFor(%d) = %d, want 0 (retain all)", h, got)
		}
	}
}

func TestPruningIsOptInAndBounded(t *testing.T) {
	app := &ValidatorApp{blockRetention: 100}

	// Below the window nothing is pruned, and RetainHeight is never negative —
	// a negative value would be rejected by CometBFT.
	for _, h := range []int64{0, 1, 50, 100} {
		if got := app.retainHeightFor(h); got != 0 {
			t.Errorf("retainHeightFor(%d) = %d, want 0 while inside the window", h, got)
		}
	}

	if got := app.retainHeightFor(150); got != 50 {
		t.Errorf("retainHeightFor(150) = %d, want 50", got)
	}
	if got := app.retainHeightFor(5000); got != 4900 {
		t.Errorf("retainHeightFor(5000) = %d, want 4900", got)
	}
}

func TestNegativeRetentionIsTreatedAsRetainAll(t *testing.T) {
	app := &ValidatorApp{blockRetention: -5}
	if got := app.retainHeightFor(1000); got != 0 {
		t.Errorf("retainHeightFor(1000) with negative retention = %d, want 0 (retain all)", got)
	}
}

func TestBlockRetentionFromEnv(t *testing.T) {
	cases := map[string]int64{
		"":       0,
		"0":      0,
		"  ":     0,
		"abc":    0,  // unparseable must not silently enable pruning
		"-10":    0,  // negative must not silently enable pruning
		"100":    100,
		" 250 ":  250,
	}
	for raw, want := range cases {
		t.Setenv("CERTEN_BLOCK_RETENTION", raw)
		if got := blockRetentionFromEnv(); got != want {
			t.Errorf("CERTEN_BLOCK_RETENTION=%q -> %d, want %d", raw, got, want)
		}
	}
}
