// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// logSink collects what a capturer logs.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// has is the logged line that contains every part, or "".
func (l *logSink) has(parts ...string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
next:
	for _, line := range l.lines {
		for _, p := range parts {
			if !strings.Contains(line, p) {
				continue next
			}
		}
		return line
	}
	return ""
}

func (l *logSink) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// verifierFailures are the two ways verifying a proven settlement fails: with an error, and with a panic.
var verifierFailures = []struct {
	name   string
	text   string
	verify func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error)
}{
	{"an error", "the receipt leaf does not hash into the header", func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error) {
		return nil, nil, errors.New("the receipt leaf does not hash into the header")
	}},
	{"a panic", "the settlement verifier failed", func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error) {
		panic("the settlement verifier failed")
	}},
}

// RB10-B10 (V-R10B3 note): Resolve runs in the observation's own path and used to drop why the evidence did not hold; what
// it recovered from, and the settlement-verification error behind a named state, are logged. A logger that panics is not
// what fails the observation.
func TestCapturer_ResolveLogsWhyTheEvidenceDoesNotHold(t *testing.T) {
	for _, vf := range verifierFailures {
		t.Run(vf.name, func(t *testing.T) {
			f := newChain(t, worldOpts{after: 0}, testN)
			f.add("p", testN, testN)
			sink := &logSink{}
			cfg := cfgFor(f)
			cfg.Logf = sink.logf
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(cfg, store)
			cp.Begin(f.w.tx.Hash())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
				t.Fatal(err)
			}
			cp.SetSettlementVerifierForTest(vf.verify)
			ev := cp.Resolve(f.w.settlement)
			if ev == nil || ev.State == nil || ev.State.Reason != ethproof.ReasonSettlementUnproven {
				t.Fatalf("not the settlement_unproven named state: %+v", ev)
			}
			if line := sink.has("Resolve", f.w.tx.Hash().Hex(), vf.text); line == "" {
				t.Fatalf("Resolve did not log why the settlement does not verify (%s); logged:\n%s", vf.text, sink.all())
			}
		})
	}
	t.Run("a logger that panics never fails Resolve", func(t *testing.T) {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("p", testN, testN)
		cfg := cfgFor(f)
		// Only what Resolve logs fails; the capture's own lines are not under test.
		cfg.Logf = func(format string, args ...interface{}) {
			if strings.Contains(format, "Resolve") {
				panic("the logger failed")
			}
		}
		store := ethproof.NewReplayGuardStore(16)
		cp := ethproof.NewReplayGuardCapturer(cfg, store)
		cp.Begin(f.w.tx.Hash())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
			t.Fatal(err)
		}
		cp.SetSettlementVerifierForTest(verifierFailures[0].verify)
		ev := cp.Resolve(f.w.settlement)
		if ev == nil || ev.State == nil || ev.State.Reason != ethproof.ReasonSettlementUnproven {
			t.Fatalf("a failing logger changed what Resolve returns: %+v", ev)
		}
	})
}

// RB10-B10 (V-R10B3 note): Bind of a settlement first seen at finality stores the named state and logs why its settlement
// does not verify, as its refusal branch does.
func TestCapturer_BindLogsWhyTheSettlementDoesNotVerifyWhenFirstSeenAtFinality(t *testing.T) {
	for _, vf := range verifierFailures {
		t.Run(vf.name, func(t *testing.T) {
			w := replayworld.New(t, replayworld.Opts{})
			sink := &logSink{}
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(ethproof.ReplayCaptureConfig{ChainID: replayworld.ChainID, Budget: 50 * time.Millisecond,
				Poll: time.Millisecond, Logf: sink.logf}, store)
			cp.SetSettlementVerifierForTest(vf.verify)
			cp.Bind(w.Settlement)
			ev := waitStored(t, store, replayworld.ChainID, w.Tx.Hash(), true)
			if ev.State == nil || ev.State.Reason != ethproof.ReasonCaptureNotAttempted {
				t.Fatalf("not the first-seen named state: %+v", ev)
			}
			if line := sink.has("first observed at finality", w.Tx.Hash().Hex(), vf.text); line == "" {
				t.Fatalf("Bind did not log why the settlement does not verify (%s); logged:\n%s", vf.text, sink.all())
			}
		})
	}
}
