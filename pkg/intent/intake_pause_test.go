package intent

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RB3-F8: while the pause file exists nothing new starts - no block is queued, a queued block is not
// processed - the watermark holds and the head is still seen; removing the file resumes from the
// watermark. Status says so, with the intents still in progress, and a paused node is not "stalled".
func TestAPausedIntakeStartsNothingAndLosesNothing(t *testing.T) {
	pause := filepath.Join(t.TempDir(), "intake.paused")
	id := &IntentDiscovery{
		client:             tipClient{tip: 120},
		logger:             log.New(io.Discard, "", 0),
		pauseFile:          pause,
		lastProcessedBlock: 100,
		lastAdvanceAt:      time.Now().Add(-time.Hour),
		blockProcessCh:     make(chan *BlockProcessJob, 64),
		stopCh:             make(chan struct{}),
		intentStatus:       map[string]IntentStatus{"a": IntentStatusInProgress, "b": IntentStatusCompleted},
	}
	if err := os.WriteFile(pause, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := id.checkForNewBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(id.blockProcessCh); n != 0 {
		t.Fatalf("%d blocks queued while paused", n)
	}
	st := id.Status()
	if !st.IntakePaused || st.InProgress != 1 || st.Watermark != 100 || st.ChainHead != 120 {
		t.Fatalf("paused status: %+v", st)
	}
	if st.Stalled(time.Minute) {
		t.Fatal("a paused node was reported stalled")
	}

	// A worker holding a queued job does not start it while paused.
	started := make(chan bool, 1)
	intakePausePoll = 10 * time.Millisecond
	go func() { started <- id.waitWhilePaused() }()
	select {
	case <-started:
		t.Fatal("a queued job started while paused")
	case <-time.After(100 * time.Millisecond):
	}

	if err := os.Remove(pause); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-started:
		if !ok {
			t.Fatal("the worker stopped instead of resuming")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the worker did not resume after the pause was lifted")
	}
	if err := id.checkForNewBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(id.blockProcessCh); n == 0 {
		t.Fatal("nothing queued after resuming")
	}
	if first := <-id.blockProcessCh; first.BlockHeight != 101 {
		t.Fatalf("resumed at %d, want 101 (the first block not processed)", first.BlockHeight)
	}
	if id.Status().IntakePaused {
		t.Fatal("still reported paused")
	}
}

// A pause file that cannot be checked counts as present.
func TestAnUncheckablePauseFileHoldsIntake(t *testing.T) {
	id := &IntentDiscovery{pauseFile: string([]byte{0})}
	if paused, why := id.intakePaused(); !paused || why == "" {
		t.Fatalf("paused=%v why=%q", paused, why)
	}
	if paused, _ := (&IntentDiscovery{}).intakePaused(); paused {
		t.Fatal("no pause file configured, yet paused")
	}
}
