package consensus

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

// The fleet's most common broadcast failure is a stale keep-alive answering EOF; it must be
// retried, not treated as a verdict on the intent.
func TestIsTransientBroadcastError(t *testing.T) {
	transient := []error{
		fmt.Errorf("BroadcastTxSync: post failed: Post \"http://127.0.0.1:26657\": EOF"),
		io.EOF,
		fmt.Errorf("wrap: %w", io.ErrUnexpectedEOF),
		errors.New("read tcp 127.0.0.1:1->127.0.0.1:26657: read: connection reset by peer"),
		errors.New("context deadline exceeded"),
		errors.New("dial tcp 127.0.0.1:26657: connect: connection refused"),
		errors.New("write: broken pipe"),
	}
	for _, err := range transient {
		if !isTransientBroadcastError(err) {
			t.Errorf("expected transient: %v", err)
		}
	}
	permanent := []error{
		nil,
		errors.New("tx already exists in cache"),
		errors.New("CheckTx failed: code=1 log=invalid ValidatorBlock"),
	}
	for _, err := range permanent {
		if isTransientBroadcastError(err) {
			t.Errorf("expected permanent: %v", err)
		}
	}
}

// "tx already exists in cache" is neither worth retrying nor a failure: a peer validator broadcast
// the identical canonical block first, so the transaction is queued and will be committed.
//
// The two classifiers deliberately disagree about it. isTransientBroadcastError says "do not retry"
// — correct, a retry earns the same answer. isAlreadyInMempool says "it is already done". Before
// this existed the first verdict stood alone, so the later broadcaster called a successful
// deduplication a failure: on 2026-09-12 validator-6 broadcast intent ec656887 and validator-7 hit
// the cache twelve seconds later, marked the intent failed, then timed out recording even that.
// The intent was left in `anchoring` with no terminal state anywhere, and the gateway polled for a
// proof that could never be produced.
func TestIsAlreadyInMempool(t *testing.T) {
	queued := []error{
		errors.New("tx already exists in cache"),
		fmt.Errorf("BroadcastTxSync: error in json rpc client, with http response metadata: (Status: 200 OK, Protocol HTTP/1.1). RPC error -32603 - Internal error: tx already exists in cache"),
		fmt.Errorf("wrap: %w", errors.New("Tx Already Exists In Cache")),
	}
	for _, err := range queued {
		if !isAlreadyInMempool(err) {
			t.Errorf("expected already-queued: %v", err)
		}
		if isTransientBroadcastError(err) {
			t.Errorf("already-queued must not also be retried: %v", err)
		}
	}
	other := []error{
		nil,
		io.EOF,
		errors.New("context deadline exceeded"),
		errors.New("CheckTx failed: code=1 log=invalid ValidatorBlock"),
	}
	for _, err := range other {
		if isAlreadyInMempool(err) {
			t.Errorf("not an already-queued answer: %v", err)
		}
	}
}
