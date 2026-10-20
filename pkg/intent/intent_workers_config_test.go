// Copyright 2026 Certen Protocol

package intent

import "testing"

// V-A defect 4: the intent workers bound how many intents are processed at once, which BLOCK_WORKERS bounded when each block
// worker processed its own intents. A configuration that names block workers and no intent workers gets as many intent
// workers as block workers; an operator running BLOCK_WORKERS=5 must not get 12 intents at once.
func TestIntentWorkersFollowTheBlockWorkersUnlessNamed(t *testing.T) {
	cases := []struct {
		name          string
		block, intent int
		want          int
	}{
		{"block workers set, intent workers not", 5, 0, 5},
		{"block workers raised", 24, 0, 24},
		{"neither set", 0, 0, DefaultIntentWorkers},
		{"intent workers named win", 5, 3, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := NewIntentDiscovery(nil, "", &IntentDiscoveryConfig{BlockWorkers: c.block, IntentWorkers: c.intent}, nil, nil, "v")
			if got := id.config.IntentWorkers; got != c.want {
				t.Fatalf("BlockWorkers=%d IntentWorkers=%d gives %d intent workers, want %d", c.block, c.intent, got, c.want)
			}
		})
	}
	if got := NewIntentDiscoveryLegacy(nil, "").config.IntentWorkers; got != DefaultIntentWorkers {
		t.Fatalf("the default configuration gives %d intent workers, want %d", got, DefaultIntentWorkers)
	}
}

// The workers that are started are the number configured, and a stop is waited for (V-A defect 2).
func TestStartIntentWorkersStartsTheConfiguredNumberAndAStopIsWaitedFor(t *testing.T) {
	id := retryDiscovery(nil, nil, nil, 0)
	id.intentCh = make(chan *intentRetryJob, 4)
	if got := id.startIntentWorkers(5); got != 5 {
		t.Fatalf("started %d workers, want 5", got)
	}
	close(id.stopCh)
	id.WaitIntentWorkers() // returns only when all five exited; it hangs (and the test times out) if one is lost track of
}
