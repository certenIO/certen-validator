package consensus

import (
	"reflect"
	"strings"
	"testing"
)

// =============================================================================
// The enqueue must happen on EVERY validator, not only the elected executor
// =============================================================================
//
// This is the single most load-bearing ordering constraint in the batch path, and it is
// invisible at runtime when it is wrong: every peer simply answers "no members ... in this
// validator's mempool", the leader never reaches quorum, and every batch falls back to the
// per-intent path. That looks exactly like ordinary peer disagreement, so the batch feature
// would appear wired and be dead.
//
// A peer attests by rebuilding the batch from its OWN mempool and comparing bundleIds. If only
// the round's elected executor enqueued, no peer could ever rebuild anything.
//
// The test reads the source rather than driving a round, because executeCanonicalBFTWorkflow
// needs a full consensus engine, chain clients and a proof pipeline to reach the relevant
// lines. What matters is a property of the ORDER of two statements, and that is exactly what
// this can assert cheaply and unambiguously.

func workflowSource(t *testing.T) string {
	t.Helper()
	b, err := readRepoFile("bft_integration.go")
	if err != nil {
		t.Fatalf("reading bft_integration.go: %v", err)
	}
	return string(b)
}

func TestBatchEnqueueHappensBeforeExecutorGate(t *testing.T) {
	src := workflowSource(t)

	enqueue := strings.Index(src, "bv.enqueueForBatch(")
	if enqueue < 0 {
		t.Fatal("enqueueForBatch call not found; the batch enqueue was removed or renamed")
	}
	gate := strings.Index(src, "if selectedExecutorID != bv.validatorID {")
	if gate < 0 {
		t.Fatal("elected-executor gate not found")
	}

	if enqueue > gate {
		t.Fatal("the batch enqueue moved BELOW the elected-executor gate. Only the elected " +
			"executor would populate its mempool, every peer would refuse to attest with " +
			"\"no members in this validator's mempool\", and cross-ADI quorum would be " +
			"impossible — while looking like ordinary peer disagreement.")
	}
}

// The consensus height must advance on every committed round. Recording it only on rounds that
// enqueue a batch member means a single queued intent never settles: the period cutoff only
// moves when a LATER intent arrives, so one intent alone waits forever.
func TestConsensusHeightRecordedBeforeExecutorGate(t *testing.T) {
	src := workflowSource(t)

	note := strings.Index(src, "bv.noteConsensusHeight(uint64(bftRes.Height))")
	if note < 0 {
		t.Fatal("noteConsensusHeight call not found; the period cutoff has no height source")
	}
	gate := strings.Index(src, "if selectedExecutorID != bv.validatorID {")
	if gate < 0 {
		t.Fatal("elected-executor gate not found")
	}
	if note > gate {
		t.Fatal("the consensus height is recorded only on the elected executor. Every other " +
			"node's cutoff would stay behind, so peers could not select the period the leader " +
			"formed and would refuse to attest.")
	}
}

// enqueueForBatch must not be reachable only under a proofClass check that excludes peers.
// Guarding on batchEnqueuer being wired is correct; guarding on executor identity is not.
func TestEnqueueForBatchIsNotGuardedByExecutorIdentity(t *testing.T) {
	src := workflowSource(t)
	enqueue := strings.Index(src, "bv.enqueueForBatch(")
	if enqueue < 0 {
		t.Fatal("enqueueForBatch call not found")
	}
	// Inspect the guard immediately preceding the call.
	window := src[max0(enqueue-400):enqueue]
	if strings.Contains(window, "selectedExecutorID") {
		t.Fatal("the batch enqueue is guarded by executor identity; peers would not enqueue " +
			"and could never attest")
	}
	if !strings.Contains(window, "bv.batchEnqueuer != nil") {
		t.Fatal("the batch enqueue should be guarded on the enqueuer being wired")
	}
}

// enqueueForBatch must exist as a method with a bool result the caller can act on: a silent
// enqueue would leave the elected executor unable to tell "queued, stop here" from "not
// queued, fall through to the per-intent path" — and falling through after a successful
// enqueue double-executes the intent.
func TestEnqueueForBatchReportsWhetherItQueued(t *testing.T) {
	m, ok := reflect.TypeOf(&BFTValidator{}).MethodByName("enqueueForBatch")
	if ok {
		if m.Type.NumOut() != 1 || m.Type.Out(0).Kind() != reflect.Bool {
			t.Fatal("enqueueForBatch must return a single bool")
		}
		return
	}
	// Unexported methods are not reported by MethodByName on some Go versions; fall back to
	// asserting the signature in source.
	src := readRepoFileMust(t, "batch_quorum_prover.go")
	if !strings.Contains(src, "commitHeight uint64,\n) bool {") {
		t.Fatal("enqueueForBatch must return bool so the caller can distinguish queued from " +
			"not-queued; falling through after a successful enqueue double-executes the intent")
	}
}

func max0(i int) int {
	if i < 0 {
		return 0
	}
	return i
}
