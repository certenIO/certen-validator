package intent

// C5-D1: how discovery treats the consensus layer's named refusal tx_too_large{size,limit,bound}.
//
// The refusal means the intent certificate's transaction is larger than the path accepts (consensus.TxTooLargeError).
// Its size grows with the time since the last Accumulate major block (the document's `certify` member), so the same
// intent produces a smaller certificate after the next major: it is NOT a permanent defect of the intent
// (ErrIntentPermanentlyInvalid is for conditions "no later attempt can fix"), and the bytes themselves cannot be sent
// again (so it is not the decoupled retry queue's errChainedProofUnavailable, whose backoff - ten attempts, at most
// five minutes apart - ends long before the next major). It is CERTEN failing to process the intent now: class
// processing_failed, lifecycle failed with the named state in its message, and the intent stays re-drivable
// (IntentStatusFailed), exactly as every untyped consensus failure does.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

func txTooLargeAsDiscoveryReceivesIt() error {
	tl := &consensus.TxTooLargeError{Size: 1_150_000, Limit: 1 << 20, Bound: "mempool.max_tx_bytes"}
	// the path from the proposer back to discovery: bft_integration's task result, then the workflow wrappers
	return fmt.Errorf("canonical BFT execution failed: %w", fmt.Errorf("canonical BFT workflow failed: %w",
		fmt.Errorf("intent i: %w", fmt.Errorf("BFT broadcast failed: %w", tl))))
}

func TestATxTooLargeRefusalIsProcessingFailedAndNeitherPermanentNorRequeued(t *testing.T) {
	err := txTooLargeAsDiscoveryReceivesIt()
	if got := failureClassOf(err); got != database.FailureProcessingFailed {
		t.Fatalf("classified %s, want %s", got, database.FailureProcessingFailed)
	}
	if !errors.Is(err, consensus.ErrTxTooLarge) {
		t.Fatal("the named state does not survive discovery's wrapping")
	}
	if errors.Is(err, consensus.ErrIntentPermanentlyInvalid) {
		t.Fatal("tx_too_large is permanent: the certificate is smaller after the next Accumulate major block")
	}
	if errors.Is(err, errChainedProofUnavailable) {
		t.Fatal("tx_too_large is on the chained-proof retry queue, whose backoff ends hours before the document shrinks")
	}
	if !strings.Contains(err.Error(), "tx_too_large{size=1150000,limit=1048576,bound=mempool.max_tx_bytes}") {
		t.Fatalf("the failure does not carry the named state with its size and limit: %v", err)
	}
}

// Through the block: the intent is recorded failed with the named state, nothing is queued, and a later re-drive is
// admitted (the intent is not parked as permanently failed).
func TestATxTooLargeIntentIsRecordedFailedAndStaysRedrivable(t *testing.T) {
	const intentID = "tx-too-large-1"
	tx := blockTx("dd44", intentID, 600)
	failures := &failureLog{}
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{tx}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), failures, 4)
	id.blockProcess = func(*CertenIntent, uint64) (consensus.TargetChainOutcome, error) {
		return consensus.TargetChainFailed, txTooLargeAsDiscoveryReceivesIt()
	}
	startIntentWorkers(t, id, 1) // the block job hands the intent to an intent worker (RB8-H)

	if err := id.processBlock(&BlockProcessJob{BlockHeight: 600}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}
	waitUntil(t, "the intent's lifecycle was recorded failed", 5*time.Second, func() bool {
		s, ok := failures.status(intentID)
		return ok && s == database.IntentLifecycleFailed
	})
	if n := len(id.retryCh); n != 0 {
		t.Fatalf("%d retry job(s) queued for a refusal no resend can change", n)
	}
	if got := id.getIntentStatus(intentID); got != IntentStatusFailed {
		t.Fatalf("status %v, want failed (re-drivable), not parked", got)
	}
	if !id.markInProgress(intentID) {
		t.Fatal("a re-drive after the next major block is refused")
	}
}
