// Copyright 2026 Certen Protocol
//
// The batch-attestation read-back, and why it is retried and pinned.
//
// MEASURED LIVE, 2026-08-25, intent c5392a5b-c6a0-479f-a738-238beda3b0e9:
//
//	10:47:08  anchor created  tx=0xf1980de5… gas=278081        (status 1, block 45943270)
//	10:47:30  "batch anchor 0xf744aa41… still reports proofExecuted=false after
//	           submission; no account will accept it"
//	10:47:30  every member attested as FAILED
//	later     anchors(0xf744aa41…) -> proofExecuted: TRUE, governanceLevel: 2
//
// The proof had executed the whole time. executeComprehensiveProof waits for its receipt and
// rejects status 0, so the transaction really had mined — but the state read that followed
// went to a different node in the RPC pool and answered from an older block. Read-your-own-
// write does not hold across two requests to a load balancer.
//
// The cost was not cosmetic: TX3 never ran, so the value never moved, and the intent was
// recorded as a hard failure. That is the Stage 1 defect exactly — inferring failure from
// "I have not observed success yet" — in a path Stage 1 did not touch.
//
//	go test ./pkg/execution/ -run 'TestAnchorConfirm' -count=1 -v
package execution

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// fakeAnchorReads replays a sequence of (executed, err) answers, one per call, so a lagging
// RPC pool can be reproduced deterministically.
type fakeAnchorReads struct {
	answers []struct {
		executed bool
		err      error
	}
	calls  int
	pinned []*big.Int
}

func (f *fakeAnchorReads) read(_ context.Context, block *big.Int) (bool, error) {
	f.pinned = append(f.pinned, block)
	if f.calls >= len(f.answers) {
		f.calls++
		return false, nil
	}
	a := f.answers[f.calls]
	f.calls++
	return a.executed, a.err
}

// confirmWithRetry mirrors AnchorProofExecutedConfirmed's loop over an injectable read.
//
// The production function reaches the chain through EVMChainResolver, which needs a live
// client; this exercises the DECISION LOGIC — how many times it asks, and what it concludes
// from each shape of answer — which is the part that was wrong.
func confirmWithRetry(ctx context.Context, read func(context.Context, *big.Int) (bool, error),
	pinned *big.Int, attempts int, delay time.Duration) (bool, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		executed, err := read(ctx, pinned)
		if err == nil {
			if executed {
				return true, nil
			}
			lastErr = nil
		} else {
			lastErr = err
		}
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(delay):
		}
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, nil
}

// THE REGRESSION. A read that is merely early must not become a failure.
func TestAnchorConfirm_EarlyReadIsRetriedNotFailed(t *testing.T) {
	f := &fakeAnchorReads{answers: []struct {
		executed bool
		err      error
	}{
		{false, nil}, // the RPC node has not imported the block yet
		{false, nil}, // still lagging
		{true, nil},  // caught up — the attestation was there all along
	}}

	got, err := confirmWithRetry(context.Background(), f.read, big.NewInt(45943270), 8, time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("CRITICAL REGRESSION: a mined attestation was reported as not executed because " +
			"the first read was early. This is the c5392a5b failure: the batch is declared " +
			"unattestable, TX3 never runs, and the value does not move.")
	}
	if f.calls != 3 {
		t.Fatalf("expected 3 reads before observing the flag, got %d", f.calls)
	}
	t.Logf("observed on read %d; the two earlier falses were RPC lag, not a failed attestation", f.calls)
}

// A transient read ERROR must not be read as "not executed" either. A pinned call against a
// node without that block errors — that is the mechanism working, and it must be retried.
func TestAnchorConfirm_TransientErrorIsRetried(t *testing.T) {
	boom := errors.New("header not found")
	f := &fakeAnchorReads{answers: []struct {
		executed bool
		err      error
	}{
		{false, boom},
		{false, boom},
		{true, nil},
	}}

	got, err := confirmWithRetry(context.Background(), f.read, big.NewInt(45943270), 8, time.Millisecond)
	if err != nil {
		t.Fatalf("a transient read error must be retried, not returned: %v", err)
	}
	if !got {
		t.Fatal("a recoverable read error was treated as a failed attestation")
	}
}

// Exhausting the budget on ERRORS reports the error, so the caller can say "not observed"
// rather than "not executed". Those are different facts about someone's money.
func TestAnchorConfirm_ExhaustedErrorsAreReportedAsUnknown(t *testing.T) {
	boom := errors.New("header not found")
	f := &fakeAnchorReads{answers: []struct {
		executed bool
		err      error
	}{
		{false, boom}, {false, boom}, {false, boom},
	}}

	got, err := confirmWithRetry(context.Background(), f.read, big.NewInt(1), 3, time.Millisecond)
	if got {
		t.Fatal("must not report executed when every read failed")
	}
	if err == nil {
		t.Fatal("exhausting the budget on read errors must return the error — a silent false " +
			"is indistinguishable from a genuine negative, and the caller would attest FAILED")
	}
}

// A genuine negative still reports false, or the fix would mask real failures — the harm in
// the opposite direction, and the one rule 8 warned about.
func TestAnchorConfirm_GenuineNegativeStillFails(t *testing.T) {
	f := &fakeAnchorReads{answers: []struct {
		executed bool
		err      error
	}{
		{false, nil}, {false, nil}, {false, nil},
	}}

	got, err := confirmWithRetry(context.Background(), f.read, big.NewInt(1), 3, time.Millisecond)
	if err != nil {
		t.Fatalf("a clean false is not an error: %v", err)
	}
	if got {
		t.Fatal("CRITICAL: retrying must not invent a success. An anchor whose flag is false at " +
			"the mining block really is unattested, and hiding that would let an unverified " +
			"batch be treated as spendable.")
	}
}

// The read must be PINNED to the mining block on every attempt. Unpinned, a lagging node
// answers from an older block and a stale false is indistinguishable from a true negative.
func TestAnchorConfirm_ReadIsPinnedToTheMiningBlock(t *testing.T) {
	f := &fakeAnchorReads{answers: []struct {
		executed bool
		err      error
	}{
		{false, nil}, {true, nil},
	}}
	block := big.NewInt(45943270)

	if _, err := confirmWithRetry(context.Background(), f.read, block, 4, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(f.pinned) < 2 {
		t.Fatalf("expected at least 2 reads, got %d", len(f.pinned))
	}
	for i, b := range f.pinned {
		if b == nil || b.Cmp(block) != 0 {
			t.Fatalf("read %d was not pinned to the mining block (got %v, want %v); an unpinned "+
				"read can answer from a block that predates the attestation", i, b, block)
		}
	}
}

// The production constants must actually cover a lagging pool. Eight attempts three seconds
// apart is ~21s of tolerance against a ~2s base-sepolia block; the live failure gave up after
// a single read.
func TestAnchorConfirm_BudgetCoversRealisticLag(t *testing.T) {
	if anchorFlagConfirmAttempts < 2 {
		t.Fatal("a single attempt is what produced the c5392a5b failure")
	}
	total := time.Duration(anchorFlagConfirmAttempts-1) * anchorFlagConfirmDelay
	if total < 15*time.Second {
		t.Fatalf("confirmation budget is %s; too short to ride out an RPC pool that lags a "+
			"block or two", total)
	}
	t.Logf("confirmation budget: %d attempts over %s", anchorFlagConfirmAttempts, total)
}
