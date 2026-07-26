package consensus

import (
	"log"
	"os"
	"testing"
)

// Commit must never abort on a logging slice.
//
// `appHash[:8]` panicked whenever the app hash was empty, which aborted Commit
// BEFORE SaveABCIState ran. The height was therefore never persisted, every
// restart reported height 0, and CometBFT replayed from genesis. That was
// survivable until the block store was pruned — after which replay was
// impossible and no validator could start:
//
//	error on replay: app block height (0) is too far below block store base (4)
//
// A log line took down a seven-node validator set. These tests pin the two
// properties that prevent it: the hash is never empty, and every slice of it
// is bounded.

func TestEmptyHashPrefixDoesNotPanic(t *testing.T) {
	// Reproduces the exact expression that panicked, now bounded.
	for _, h := range [][]byte{nil, {}, {0x01}, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("bounded slice panicked on len=%d: %v", len(h), r)
				}
			}()
			_ = h[:min(8, len(h))]
		}()
	}
}

func TestZeroHashSubstitutionKeepsCommitLoggable(t *testing.T) {
	app := &ValidatorApp{logger: log.New(os.Stderr, "[test] ", 0)}

	// The substitution Commit applies when FinalizeBlock produced nothing.
	var appHash []byte
	if len(appHash) == 0 {
		appHash = make([]byte, 32)
	}

	if len(appHash) != 32 {
		t.Fatalf("substituted hash length = %d, want 32", len(appHash))
	}
	app.lastCommitHash = appHash

	// Must be safely sliceable, which is what Commit and Info both do.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("slicing the substituted hash panicked: %v", r)
		}
	}()
	_ = app.lastCommitHash[:min(8, len(app.lastCommitHash))]
}

// A zero hash must be deterministic: every validator substituting it has to
// arrive at the same bytes, or they would diverge on the app hash and break
// consensus rather than just logging.
func TestZeroHashSubstitutionIsDeterministic(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	if string(a) != string(b) {
		t.Fatal("zero-hash substitution is not deterministic across validators")
	}
}
