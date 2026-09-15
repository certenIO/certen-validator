package consensus

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
)

// These tests pin the broadcaster half of the 2026-09-15 fix: a lost BroadcastTxSync reply is not a
// verdict. Validator-3 declared intent 770f02b8 failed while its ValidatorBlock was committed at height
// 2187, because three retries 2 s and 4 s apart all landed inside 15 s block commits.

var broadcastQuietLog = log.New(io.Discard, "", 0)

var eofErr = fmt.Errorf(`post failed: Post "http://127.0.0.1:26657": EOF`)

// fakeCometRPC scripts the node: broadcast answers per attempt, and when the transaction becomes visible in
// the mempool and in a block.
type fakeCometRPC struct {
	mu sync.Mutex

	broadcasts     int
	broadcastReply func(attempt int) (*coretypes.ResultBroadcastTx, error)

	// The transaction is admitted/committed once this many broadcasts have been made (0 = never).
	admittedAfter  int
	committedAfter int
	// Or after this many Tx lookups (0 = not by lookups).
	committedAfterTxCalls int
	txCode                uint32
	height                int64

	txCalls          int
	unconfirmedCalls int
	mempoolTxs       []cmttypes.Tx // other transactions in the mempool

	// While true, UnconfirmedTxs blocks until its context ends (the mempool lock held by a slow commit).
	mempoolLocked bool
}

func (f *fakeCometRPC) BroadcastTxSync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error) {
	f.mu.Lock()
	f.broadcasts++
	n := f.broadcasts
	reply := f.broadcastReply
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return reply(n)
}

func (f *fakeCometRPC) committed() bool {
	return (f.committedAfter > 0 && f.broadcasts >= f.committedAfter) ||
		(f.committedAfterTxCalls > 0 && f.txCalls >= f.committedAfterTxCalls)
}

func (f *fakeCometRPC) Tx(ctx context.Context, hash []byte, prove bool) (*coretypes.ResultTx, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txCalls++
	if !f.committed() {
		return nil, fmt.Errorf("tx (%X) not found", hash)
	}
	return &coretypes.ResultTx{Hash: hash, Height: f.height, TxResult: abcitypes.ExecTxResult{Code: f.txCode, Log: "fictional"}}, nil
}

func (f *fakeCometRPC) UnconfirmedTxs(ctx context.Context, limit *int) (*coretypes.ResultUnconfirmedTxs, error) {
	f.mu.Lock()
	locked := f.mempoolLocked
	f.mu.Unlock()
	if locked {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unconfirmedCalls++
	txs := append([]cmttypes.Tx(nil), f.mempoolTxs...)
	if f.admittedAfter > 0 && f.broadcasts >= f.admittedAfter && !f.committed() {
		txs = append(txs, cmttypes.Tx(testPayload))
	}
	return &coretypes.ResultUnconfirmedTxs{Count: len(txs), Txs: txs}, nil
}

var testPayload = []byte(`{"bundle_id":"0xfictional-broadcast-test"}`)

func testHash() []byte { h := sha256.Sum256(testPayload); return h[:] }

func fastTiming() broadcastTiming {
	return broadcastTiming{
		attemptTimeout: 200 * time.Millisecond,
		submitBudget:   300 * time.Millisecond,
		retryBase:      5 * time.Millisecond,
		retryMax:       20 * time.Millisecond,
		lookupTimeout:  50 * time.Millisecond,
		inclusionPoll:  100 * time.Millisecond,
		pollInterval:   5 * time.Millisecond,
	}
}

func ok() (*coretypes.ResultBroadcastTx, error) {
	return &coretypes.ResultBroadcastTx{Code: 0, Hash: testHash()}, nil
}

// The incident: the reply is lost (EOF) but the node admitted the block and committed it. The broadcast is
// a success with the committed height, without retrying.
func TestLostReplyForACommittedValidatorBlockIsSuccess(t *testing.T) {
	rpc := &fakeCometRPC{
		broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr },
		committedAfter: 1,
		height:         2187,
	}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("committed block reported as failure: %v", err)
	}
	if res.Height != 2187 || string(res.TxHash) != string(testHash()) {
		t.Fatalf("result = height %d hash %X, want 2187 %X", res.Height, res.TxHash, testHash())
	}
	if rpc.broadcasts != 1 {
		t.Fatalf("broadcasts = %d, want 1 (no retry once the block is known committed)", rpc.broadcasts)
	}
}

// The reply is lost while the block waits in the mempool: no retry, poll for inclusion.
func TestLostReplyForAnAdmittedValidatorBlockPollsForInclusion(t *testing.T) {
	rpc := &fakeCometRPC{
		broadcastReply:        func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr },
		admittedAfter:         1,
		committedAfterTxCalls: 4, // committed while polling
		height:                2188,
		mempoolTxs:            []cmttypes.Tx{cmttypes.Tx("other-fictional-tx")},
	}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err != nil {
		t.Fatalf("admitted block reported as failure: %v", err)
	}
	if res.Height != 2188 || rpc.broadcasts != 1 {
		t.Fatalf("height=%d broadcasts=%d, want 2188 and 1", res.Height, rpc.broadcasts)
	}
}

// A slow commit makes more consecutive broadcasts fail than the old three-attempt limit allowed. The
// budget, not a count, decides; the seventh attempt is admitted.
func TestRetriesOutlastASlowCommit(t *testing.T) {
	timing := fastTiming()
	timing.submitBudget = 2 * time.Second
	rpc := &fakeCometRPC{
		broadcastReply: func(n int) (*coretypes.ResultBroadcastTx, error) {
			if n < 7 {
				return nil, eofErr
			}
			return ok()
		},
		committedAfter: 7,
		height:         2190,
	}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, timing, broadcastQuietLog)
	if err != nil {
		t.Fatalf("gave up during a slow commit: %v", err)
	}
	if rpc.broadcasts != 7 || res.Height != 2190 {
		t.Fatalf("broadcasts=%d height=%d, want 7 and 2190", rpc.broadcasts, res.Height)
	}
}

// A retry that answers "already exists in cache" means the earlier, lost broadcast was admitted.
func TestAlreadyInCacheAfterALostReplyIsSubmittedAndPolled(t *testing.T) {
	rpc := &fakeCometRPC{
		broadcastReply: func(n int) (*coretypes.ResultBroadcastTx, error) {
			if n == 1 {
				return nil, eofErr
			}
			return nil, errors.New("RPC error -32603 - Internal error: tx already exists in cache")
		},
		committedAfterTxCalls: 3,
		height:                2191,
	}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err != nil || res.Height != 2191 {
		t.Fatalf("res=%+v err=%v, want committed at 2191", res, err)
	}
}

// Nothing admitted anywhere within the budget: a real failure, reported with the transport error.
func TestNeverAdmittedFailsAfterTheBudget(t *testing.T) {
	timing := fastTiming()
	rpc := &fakeCometRPC{broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr }}
	start := time.Now()
	_, err := submitValidatorBlock(context.Background(), rpc, testPayload, timing, broadcastQuietLog)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "BroadcastTxSync") || !strings.Contains(err.Error(), "not committed and not in the mempool") {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, eofErr) {
		t.Fatalf("transport error not wrapped: %v", err)
	}
	if elapsed < timing.submitBudget || elapsed > timing.submitBudget+500*time.Millisecond {
		t.Fatalf("gave up after %v, want about the %v budget", elapsed, timing.submitBudget)
	}
	if rpc.broadcasts < 3 {
		t.Fatalf("broadcasts = %d, expected several attempts within the budget", rpc.broadcasts)
	}
}

func TestCheckTxRejectionIsReportedWithoutRetry(t *testing.T) {
	rpc := &fakeCometRPC{broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) {
		return &coretypes.ResultBroadcastTx{Code: 4, Log: "entitlement check failed: fictional"}, nil
	}}
	_, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err == nil || !strings.Contains(err.Error(), "CheckTx failed: code=4") || rpc.broadcasts != 1 {
		t.Fatalf("err=%v broadcasts=%d, want CheckTx code 4 and one broadcast", err, rpc.broadcasts)
	}
}

func TestNonTransientBroadcastErrorIsReportedWithoutRetry(t *testing.T) {
	rpc := &fakeCometRPC{broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) {
		return nil, errors.New("RPC error -32600 - Invalid request: fictional")
	}}
	_, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err == nil || rpc.broadcasts != 1 || rpc.txCalls != 0 {
		t.Fatalf("err=%v broadcasts=%d txCalls=%d, want an error, one broadcast, no lookups", err, rpc.broadcasts, rpc.txCalls)
	}
}

// A committed transaction the block rejected is a failure, whether it is found by the lost-reply lookup
// or by the inclusion poll.
func TestCommittedWithAFailureCodeIsReported(t *testing.T) {
	for name, reply := range map[string]func(int) (*coretypes.ResultBroadcastTx, error){
		"lost reply": func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr },
		"ack":        func(int) (*coretypes.ResultBroadcastTx, error) { return ok() },
	} {
		rpc := &fakeCometRPC{broadcastReply: reply, committedAfter: 1, txCode: 2, height: 2192}
		_, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
		if err == nil || !strings.Contains(err.Error(), "transaction failed in block: code=2") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// Admitted but not yet in a block within the inclusion poll: Height 0 (pending consensus), as before.
func TestAdmittedButNotYetCommittedReturnsPending(t *testing.T) {
	rpc := &fakeCometRPC{broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) { return ok() }}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err != nil || res.Height != 0 || string(res.TxHash) != string(testHash()) {
		t.Fatalf("res=%+v err=%v, want pending with the tx hash", res, err)
	}
}

// The submit budget shrinks so the last attempt, its lookups and the inclusion poll all fit in the caller's
// context: the function ends on its own budget, not by running the caller's context out.
func TestHonoursTheCallersDeadline(t *testing.T) {
	timing := fastTiming() // attempt 200ms, lookup 50ms, inclusion poll 100ms
	timing.submitBudget = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	rpc := &fakeCometRPC{broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr }}
	start := time.Now()
	_, err := submitValidatorBlock(ctx, rpc, testPayload, timing, broadcastQuietLog)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "not committed and not in the mempool") {
		t.Fatalf("err = %v, want the budget failure (not the caller's context expiring)", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("used the caller's whole context (%v) instead of reserving room for the inclusion poll", elapsed)
	}
	if reserve := timing.inclusionPoll + timing.attemptTimeout + 2*timing.lookupTimeout; elapsed > time.Second-reserve+100*time.Millisecond {
		t.Fatalf("ended after %v; the budget should stop new attempts %v before the caller deadline", elapsed, reserve)
	}
}

// A lookup that does not answer (unconfirmed_txs blocks on the mempool lock during a slow commit) is not
// evidence of absence: the failure must say admission is unknown, not "not in the mempool".
func TestUnansweredLookupIsNotReportedAsAbsence(t *testing.T) {
	rpc := &fakeCometRPC{
		broadcastReply: func(int) (*coretypes.ResultBroadcastTx, error) { return nil, eofErr },
		mempoolLocked:  true,
	}
	_, err := submitValidatorBlock(context.Background(), rpc, testPayload, fastTiming(), broadcastQuietLog)
	if err == nil || strings.Contains(err.Error(), "not in the mempool") || !strings.Contains(err.Error(), "admission could not be confirmed") {
		t.Fatalf("err = %v, want an 'admission could not be confirmed' failure", err)
	}
	if !errors.Is(err, eofErr) {
		t.Fatalf("transport error not wrapped: %v", err)
	}
}

// The slow-commit timeline end to end: broadcasts and the mempool lookup block while a commit holds the
// lock; when it ends the node has admitted the transaction. The broadcaster must end on inclusion.
func TestSlowCommitWithBlockedLookupsStillConfirmsInclusion(t *testing.T) {
	timing := fastTiming()
	timing.submitBudget = 2 * time.Second
	commitEnds := time.Now().Add(250 * time.Millisecond)
	rpc := &fakeCometRPC{mempoolLocked: true, height: 2187}
	rpc.broadcastReply = func(n int) (*coretypes.ResultBroadcastTx, error) {
		if time.Now().Before(commitEnds) {
			time.Sleep(time.Until(commitEnds))
			rpc.mu.Lock()
			rpc.mempoolLocked = false
			rpc.admittedAfter = n // admitted when the commit released the lock
			rpc.committedAfterTxCalls = rpc.txCalls + 3
			rpc.mu.Unlock()
			return nil, eofErr // the reply was lost to the RPC write timeout
		}
		return nil, errors.New("tx already exists in cache")
	}
	res, err := submitValidatorBlock(context.Background(), rpc, testPayload, timing, broadcastQuietLog)
	if err != nil || res.Height != 2187 {
		t.Fatalf("res=%+v err=%v, want committed at 2187", res, err)
	}
}

// The production engine satisfies the interfaces the new code depends on.
func TestCometHTTPClientSatisfiesTheBroadcastInterfaces(t *testing.T) {
	var e RealCometBFTEngine
	var _ broadcastRPC = e.rpcClient
	var _ blockReader = e.rpcClient
}
