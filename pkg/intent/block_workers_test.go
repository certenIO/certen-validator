package intent

import "testing"

// Worker count is the actual scan throughput. MaxConcurrentBlocks only sizes the queue — that
// confusion is why raising it from 10 to 2000 "to handle high block rate" changed nothing, and
// why a 12,500-block backlog took an hour to clear behind 3 hardcoded workers.

func TestBlockWorkersDefaultsWhenUnset(t *testing.T) {
	t.Setenv("BLOCK_WORKERS", "")
	if got := blockWorkersFromEnv(); got != DefaultBlockWorkers {
		t.Fatalf("blockWorkersFromEnv() = %d with BLOCK_WORKERS unset, want %d",
			got, DefaultBlockWorkers)
	}
}

func TestBlockWorkersHonoursValidOverride(t *testing.T) {
	for _, v := range []string{"1", "8", "24", " 16 "} {
		t.Setenv("BLOCK_WORKERS", v)
		if got := blockWorkersFromEnv(); got <= 0 {
			t.Fatalf("BLOCK_WORKERS=%q produced %d", v, got)
		}
	}
	t.Setenv("BLOCK_WORKERS", "24")
	if got := blockWorkersFromEnv(); got != 24 {
		t.Fatalf("BLOCK_WORKERS=24 produced %d", got)
	}
}

// A bad value must not stop the validator booting. Discovery running at the default beats a node
// that refuses to start over a tuning knob.
func TestBlockWorkersFallsBackOnGarbage(t *testing.T) {
	for _, v := range []string{"0", "-4", "many", "3.5", "1e3"} {
		t.Setenv("BLOCK_WORKERS", v)
		if got := blockWorkersFromEnv(); got != DefaultBlockWorkers {
			t.Errorf("BLOCK_WORKERS=%q produced %d, want fallback %d", v, got, DefaultBlockWorkers)
		}
	}
}

// The default must actually be an improvement on the 3 it replaced, and must stay well under
// the channel buffer so the queue is never the constraint.
func TestDefaultBlockWorkersIsAnImprovementAndBounded(t *testing.T) {
	if DefaultBlockWorkers <= 3 {
		t.Fatalf("DefaultBlockWorkers = %d; the hardcoded value it replaced was 3, so this is "+
			"no improvement to outage recovery", DefaultBlockWorkers)
	}
	if DefaultBlockWorkers > MAX_CONCURRENT_BLOCKS {
		t.Fatalf("DefaultBlockWorkers = %d exceeds the job-channel buffer %d; workers would "+
			"block on an empty queue", DefaultBlockWorkers, MAX_CONCURRENT_BLOCKS)
	}
	// Sanity on the resulting rate: ~675ms per block per worker, measured 2026-08-05.
	// 12 workers ≈ 1067 blocks/min, ~4x the 267 blocks/min observed at 3.
	if rate := float64(DefaultBlockWorkers) / 0.675 * 60; rate < 600 {
		t.Fatalf("projected catch-up rate %.0f blocks/min is barely better than the 267 that "+
			"made recovery take an hour", rate)
	}
}

// The default config must actually carry the worker count through, or the knob is inert — the
// exact failure MaxConcurrentBlocks had.
func TestDefaultConfigCarriesBlockWorkers(t *testing.T) {
	t.Setenv("BLOCK_WORKERS", "9")
	cfg := DefaultIntentDiscoveryConfig()
	if cfg.BlockWorkers != 9 {
		t.Fatalf("DefaultIntentDiscoveryConfig().BlockWorkers = %d, want 9 — the env override does "+
			"not reach the config", cfg.BlockWorkers)
	}
}
