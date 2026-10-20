// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10-B10 (V-R10B3 note): a Bind that waits for a capture that does not finish names the wait and logs why the settlement
// does not verify, as the first-seen branch does.
func TestCapturer_BindLogsWhyTheSettlementDoesNotVerifyWhenTheCaptureDoesNotFinish(t *testing.T) {
	for _, vf := range verifierFailures {
		t.Run(vf.name, func(t *testing.T) {
			g := newGated(t) // the capture's receipt read is held until its budget ends (500ms), far past the Bind's wait (50ms)
			sink := &logSink{}
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 500 * time.Millisecond,
				Poll: 5 * time.Millisecond, Logf: sink.logf}, store)
			cp.SetSettlementVerifierForTest(vf.verify)
			cp.SetBindWaitForTest(50 * time.Millisecond)
			tx := g.w.tx.Hash()
			cp.Begin(tx)
			cp.Bind(g.w.settlement)
			ev := waitStored(t, store, testChainID, tx, true)
			if ev.State == nil || ev.State.Reason != ethproof.ReasonStateUnavailable || !strings.Contains(ev.State.Detail, "the capture did not finish") {
				t.Fatalf("not the named state of the wait: %+v", ev)
			}
			if line := sink.has("did not finish", tx.Hex(), vf.text); line == "" {
				t.Fatalf("Bind did not log why the settlement does not verify (%s); logged:\n%s", vf.text, sink.all())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, tx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
