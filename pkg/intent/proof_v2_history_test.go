// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// AGT-F104: when the v3 certificate requires proof v2 and a governing page's admissible block (design D2) is below the Accumulate node's
// retained history, the capture refuses it as g1_historical_unavailable{<partition>,<block>}. proveV2 wrapped that cause as text (%v), so
// it was retried ~10 times (~30 min) and then recorded failed as processing_failed with the cause only in free text: no client could tell
// by type that the payment failed because the node lacked history (an infrastructure limit) rather than for a validator defect.
//
// Retrying it is NOT right, and these pin that it is failed at once (closed: no proof, no execution):
//   - D2 fixes the admissible blocks of every partition by the transaction's own Directory anchor (xcapture.go SelectPartitionBlock: the
//     anchors the Directory executed at or before dnLimit, the DN block that executed the transaction's partition's anchor). That set is
//     final once the transaction executed; a later anchor never becomes admissible.
//   - The capture already passes over a block that left retention for the next admissible one (collect.go advance ->
//     NextPartitionBlock); the refusal is returned only when no admissible block after it remains (xcapture.go NextPartitionBlock), or when
//     the block is below the node's advertised retained range, which only moves forward on a pruning node.
//   - A capture that kept pages is never replaced (ProofV2ShadowRepository.RecordCapture: WHERE captured IS NULL), so a retry re-reads
//     the same stored refusal.
// A retry can therefore only repeat the same answer after a longer wait; the honest remedy is a node that keeps the history (OQ12).

// historyRefusal is the error the shadow's certificate proof returns for the F104 capture: the stored text carrying its named state.
func historyRefusal() error {
	return fmt.Errorf("proof v2: key book acc://officer-2.acme/book: %w", &proofv2.NamedState{
		Code: proofv2.StateHistoricalUnavailable, Partition: "BVN3", Block: 17540539,
		Detail: "acc://officer-2.acme/book is below the retained range [17542319, 17543113]"})
}

func TestProveV2FailsAHistoryRefusalTypedAndTerminal(t *testing.T) {
	p := &g1Prover{err: historyRefusal()}
	cp := &proof.CertenProof{}
	err := discoveryWith(g1Gate{required: true, g1: true}, p).proveV2(context.Background(), "i1", "acc://a.acme/x", "tx", "BVN1", cp)
	var hist *ProofV2HistoryUnavailableError
	if !errors.As(err, &hist) || hist.Partition != "BVN3" || hist.Height != 17540539 {
		t.Fatalf("a history refusal is not the typed failure: %v", err)
	}
	if !errors.Is(err, errChainedProofTerminal) || errors.Is(err, errChainedProofUnavailable) {
		t.Fatalf("a history refusal must fail the intent at once, not retry it: %v", err)
	}
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHistoricalUnavailable {
		t.Fatalf("the cause was not kept (%%w): %v", err)
	}
	if !strings.HasPrefix(err.Error(), "proof_v2_history_unavailable{partition=BVN3,height=17540539}: ") {
		t.Fatalf("the failure does not start with its token: %q", err.Error())
	}
	if cp.ProofV2 != nil {
		t.Fatal("a refused proof was attached to the certificate")
	}

	// The 2.0 certificate path (activation not in force) answers the same refusal the same way.
	p = &g1Prover{err: historyRefusal()}
	err = discoveryWith(g1Gate{required: true}, p).proveV2(context.Background(), "i1", "a", "tx", "BVN1", &proof.CertenProof{})
	if !errors.As(err, &hist) || !errors.Is(err, errChainedProofTerminal) {
		t.Fatalf("2.0 path: %v", err)
	}
}

// Every other refusal is answered exactly as before: retried, untyped, the cause in the text.
func TestProveV2AnswersEveryOtherRefusalAsBefore(t *testing.T) {
	for name, cause := range map[string]error{
		"not ready":           &proofv2.NamedState{Code: proofv2.StateNotReady, Partition: "BVN3", Block: 17540539},
		"chain moved":         &proofv2.NamedState{Code: proofv2.StateChainMoved, Partition: "BVN3", Block: 5},
		"history, no place":   errors.New("proof v2: g1_historical_unavailable: no pages were captured at discovery"),
		"history, no block":   &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "BVN3"},
		"history, no part":    &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Block: 9},
		"plain":               errors.New("proof v2: the chain has verified no major block to start from"),
		"history named, text": errors.New("g1_historical_unavailable{BVN3,17540539}"), // text is never classified here (RB4-F13)
	} {
		t.Run(name, func(t *testing.T) {
			p := &g1Prover{err: cause}
			err := discoveryWith(g1Gate{required: true, g1: true}, p).proveV2(context.Background(), "i1", "a", "tx", "BVN1", &proof.CertenProof{})
			var hist *ProofV2HistoryUnavailableError
			if errors.As(err, &hist) || !errors.Is(err, errChainedProofUnavailable) || errors.Is(err, errChainedProofTerminal) {
				t.Fatalf("answered %v", err)
			}
			if !strings.Contains(err.Error(), cause.Error()) || strings.HasPrefix(err.Error(), ProofV2HistoryUnavailable) {
				t.Fatalf("message %q", err.Error())
			}
			if got := failureClassOf(err); got != database.FailureProcessingFailed {
				t.Fatalf("class %s", got)
			}
		})
	}
}

// optionLog records what each terminal-failure write recorded.
type optionLog struct {
	mu      sync.Mutex
	message map[string]string
	class   map[string]string
}

func (o *optionLog) UpdateStatus(_ context.Context, intentID string, status database.IntentLifecycleStatus, opts ...database.UpdateOption) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.message == nil {
		o.message, o.class = map[string]string{}, map[string]string{}
	}
	msg, class := database.UpdateOptionValues(opts...)
	if status == database.IntentLifecycleFailed {
		o.message[intentID], o.class[intentID] = msg, class
	}
	return nil
}

// The lifecycle failure carries the stable machine reason first: proof_v2_history_unavailable{partition=<P>,height=<H>}, then the cause.
// Its class stays processing_failed (an infrastructure limit, not a verdict on the intent; the schema's classes are unchanged).
func TestTheLifecycleFailureStartsWithTheHistoryToken(t *testing.T) {
	hist := &ProofV2HistoryUnavailableError{Partition: "BVN3", Height: 17540539, Cause: historyRefusal()}
	for name, cause := range map[string]error{
		"as returned":         hist,
		"wrapped by a caller": fmt.Errorf("intent i9 (proofClass=on_demand): %w", hist),
		"abandoned retry":     fmt.Errorf("%w; its retry on this validator ended: stopped", hist),
	} {
		t.Run(name, func(t *testing.T) {
			w := &optionLog{}
			if err := recordLifecycleFailed(w, "i9", cause); err != nil {
				t.Fatal(err)
			}
			msg := w.message["i9"]
			if !strings.HasPrefix(msg, "proof_v2_history_unavailable{partition=BVN3,height=17540539}: ") || strings.Count(msg, ProofV2HistoryUnavailable) != 1 {
				t.Fatalf("message %q", msg)
			}
			if !strings.Contains(msg, "g1_historical_unavailable{BVN3,17540539}") {
				t.Fatalf("the cause is missing from %q", msg)
			}
			if w.class["i9"] != string(database.FailureProcessingFailed) {
				t.Fatalf("class %q", w.class["i9"])
			}
		})
	}

	// Any other failure is recorded exactly as its text, as before.
	w := &optionLog{}
	other := fmt.Errorf("intent i8: %w: %v", errChainedProofUnavailable, &proofv2.NamedState{Code: proofv2.StateNotReady, Partition: "BVN3", Block: 4})
	if err := recordLifecycleFailed(w, "i8", other); err != nil {
		t.Fatal(err)
	}
	if w.message["i8"] != other.Error() || w.class["i8"] != string(database.FailureProcessingFailed) {
		t.Fatalf("recorded %q / %q", w.message["i8"], w.class["i8"])
	}
	w = &optionLog{}
	refused := fmt.Errorf("%w: bad bytes", consensus.ErrIntentPermanentlyInvalid)
	if err := recordLifecycleFailed(w, "i7", refused); err != nil {
		t.Fatal(err)
	}
	if w.message["i7"] != refused.Error() || w.class["i7"] != string(database.FailureRefused) {
		t.Fatalf("recorded %q / %q", w.message["i7"], w.class["i7"])
	}
}

// Through the retry path: a retried intent whose re-processing meets the history refusal is recorded failed at once, with the token -
// not requeued for the remaining attempts - and its retry leaves the journal.
func TestARetryThatMeetsAHistoryRefusalIsRecordedAtOnce(t *testing.T) {
	const intentID = "f104-retry-1"
	w := &optionLog{}
	id := retryDiscovery(&blockClient{}, openJournal(t, filepath.Join(t.TempDir(), "r.json")), nil, 4)
	id.failureWriter = w
	runs := 0
	id.retryProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		runs++
		p := &g1Prover{err: historyRefusal()}
		return consensus.TargetChainFailed, discoveryWith(g1Gate{required: true, g1: true}, p).proveV2(context.Background(), ci.IntentID, "a", "tx", "BVN1", &proof.CertenProof{})
	}
	job := &intentRetryJob{intent: &CertenIntent{IntentID: intentID}, blockHeight: 6, lastErr: unavailable(intentID)}
	if err := id.keepRetry(job); err != nil {
		t.Fatal(err)
	}
	id.handleRetryJob(job)
	if runs != 1 || len(id.retryCh) != 0 {
		t.Fatalf("the refused intent was requeued (runs %d, queued %d)", runs, len(id.retryCh))
	}
	if msg := w.message[intentID]; !strings.HasPrefix(msg, "proof_v2_history_unavailable{partition=BVN3,height=17540539}: ") {
		t.Fatalf("recorded %q", msg)
	}
	if got := kept(t, id.retries); len(got) != 0 {
		t.Fatalf("a recorded failure must end the retry, kept %+v", got)
	}
}
