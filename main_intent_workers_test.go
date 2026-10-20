// Copyright 2026 Certen Protocol

package main

import (
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/intent"
)

// V-A defect 4: BLOCK_WORKERS sets the intent workers as well, so the most intents processed at once is what the operator set.
func TestBlockWorkersSetTheIntentWorkersToo(t *testing.T) {
	t.Setenv("BLOCK_WORKERS", "7")
	blockWorkers, err := intent.BlockWorkersFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg := intentDiscoveryConfig(time.Minute, blockWorkers)
	if cfg.BlockWorkers != 7 || cfg.IntentWorkers != 7 {
		t.Fatalf("BLOCK_WORKERS=7 gives block workers %d and intent workers %d, want 7 and 7", cfg.BlockWorkers, cfg.IntentWorkers)
	}
	if cfg.BFTTimeout != time.Minute || cfg.IntentBatchSize != 100 || cfg.MaxConcurrentBlocks != 2000 {
		t.Fatalf("the rest of the configuration changed: %+v", cfg)
	}
}
