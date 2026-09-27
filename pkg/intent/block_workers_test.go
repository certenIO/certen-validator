package intent

import "testing"

// Worker count is the actual scan throughput. MaxConcurrentBlocks only sizes the queue — that
// confusion is why raising it from 10 to 2000 "to handle high block rate" changed nothing, and
// why a 12,500-block backlog took an hour to clear behind 3 hardcoded workers.

func TestBlockWorkersDefaultsWhenUnset(t *testing.T) {
	t.Setenv("BLOCK_WORKERS", "")
	if got, err := BlockWorkersFromEnv(); err != nil || got != DefaultBlockWorkers {
		t.Fatalf("BlockWorkersFromEnv() = (%d, %v) with BLOCK_WORKERS unset, want %d",
			got, err, DefaultBlockWorkers)
	}
}

func TestBlockWorkersHonoursValidOverride(t *testing.T) {
	for _, v := range []string{"1", "8", "24", " 16 "} {
		t.Setenv("BLOCK_WORKERS", v)
		if got, err := BlockWorkersFromEnv(); err != nil || got <= 0 {
			t.Fatalf("BLOCK_WORKERS=%q produced (%d, %v)", v, got, err)
		}
	}
	t.Setenv("BLOCK_WORKERS", "24")
	if got, _ := BlockWorkersFromEnv(); got != 24 {
		t.Fatalf("BLOCK_WORKERS=24 produced %d", got)
	}
}

// A value that is not a positive integer is refused by name (RB3-F71 sweep). It used to become the
// default with a log line, on the argument that a node should not refuse to boot over a tuning knob - but
// the operator who set it meant a number, and the node ran on another without telling them.
func TestBlockWorkersRefusesGarbage(t *testing.T) {
	for _, v := range []string{"0", "-4", "many", "3.5", "1e3"} {
		t.Setenv("BLOCK_WORKERS", v)
		if got, err := BlockWorkersFromEnv(); err == nil {
			t.Errorf("BLOCK_WORKERS=%q was accepted as %d", v, got)
		}
	}
}
