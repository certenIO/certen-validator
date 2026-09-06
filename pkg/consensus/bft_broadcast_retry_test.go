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
