// Copyright 2026 Certen Protocol

package intent

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"
)

// Pausing intent intake (RB3-F8).
//
// A maintenance window - a key rotation, a consensus deploy - needs nothing new to start while it runs. The
// gateway cannot provide that: an ADI can write an intent to Accumulate directly, and every validator
// discovers it there. The pause is therefore at discovery, on every validator: while it holds, no block is
// queued and no queued block is processed, so no intent starts; intents already running finish. The
// watermark stays where it is, so nothing is lost - when the pause is lifted, discovery resumes at the
// first block it had not processed.
//
// It is a file, not an endpoint: an operator creates it inside the container (docker exec ... touch) and
// removes it to resume, and no new network surface exists to pause the chain's intake. Status reports it
// with the number of intents still in progress, which is what "nothing in flight" is read from.

// intakePauseFile is INTENT_INTAKE_PAUSE_FILE, default data/intake.paused (the data volume, /app/data).
func intakePauseFile() string {
	if p := strings.TrimSpace(os.Getenv("INTENT_INTAKE_PAUSE_FILE")); p != "" {
		return p
	}
	return "data/intake.paused"
}

// intakePausePoll is how often a paused worker looks again.
var intakePausePoll = 2 * time.Second

// intakePaused reports whether intake is paused, and why. A pause file that cannot be checked counts as
// present: during a window, starting work that was meant to wait is the failure that matters.
func (id *IntentDiscovery) intakePaused() (bool, string) {
	if id.pauseFile == "" {
		return false, ""
	}
	_, err := os.Stat(id.pauseFile)
	switch {
	case err == nil:
		return true, "pause file " + id.pauseFile + " is present"
	case errors.Is(err, fs.ErrNotExist):
		return false, ""
	default:
		return true, "pause file " + id.pauseFile + " cannot be checked: " + err.Error()
	}
}

// notePause logs a change of pause state once, at the edge.
func (id *IntentDiscovery) notePause(paused bool, why string) {
	id.watermarkMu.Lock()
	changed := paused != id.paused
	id.paused = paused
	id.watermarkMu.Unlock()
	if !changed {
		return
	}
	if paused {
		id.logger.Printf("⏸️ [INTAKE] PAUSED (%s): no block is queued or processed; intents already running finish; the watermark holds", why)
	} else {
		id.logger.Printf("▶️ [INTAKE] RESUMED: discovery continues from the watermark")
	}
}

// waitWhilePaused holds a worker before it starts a job while intake is paused. False when the service is
// stopping.
func (id *IntentDiscovery) waitWhilePaused() bool {
	for {
		paused, why := id.intakePaused()
		id.notePause(paused, why)
		if !paused {
			return true
		}
		select {
		case <-time.After(intakePausePoll):
		case <-id.stopCh:
			return false
		}
	}
}

// inProgress is the number of intents this validator is processing now.
func (id *IntentDiscovery) inProgress() int {
	id.mu.Lock()
	defer id.mu.Unlock()
	n := 0
	for _, s := range id.intentStatus {
		if s == IntentStatusInProgress {
			n++
		}
	}
	return n
}
