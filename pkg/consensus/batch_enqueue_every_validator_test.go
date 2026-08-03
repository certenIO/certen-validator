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

	note := strings.Index(src, "bv.noteConsensusHeight(blockHeight)")
	if note < 0 {
		t.Fatal("noteConsensusHeight is not called with blockHeight; the period cutoff has no " +
			"globally-agreed height source")
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

// THE determinism invariant.
//
// A member's period must be keyed on a height every validator computes identically for a given
// intent. blockHeight (the ACCUMULATE height the intent was written in) is such a value.
// bftRes.Height is NOT: each validator broadcasts its own ValidatorBlock transaction, so one
// intent commits at a different CometBFT height on every node -- observed live at
// 230/232/234/235/235/236/237 across the seven. Keying on that puts the same member in
// different periods on different nodes, and no two validators can ever derive the same batch.
func TestPeriodHeightIsAccumulateNotCometBFT(t *testing.T) {
	src := workflowSource(t)

	if strings.Contains(src, "bv.noteConsensusHeight(uint64(bftRes.Height))") {
		t.Fatal("the period cutoff is keyed on the CometBFT height, which differs per validator " +
			"for the same intent — batches could never be co-signed")
	}
	// The enqueue must carry the same units as the cutoff.
	enq := strings.Index(src, "bv.enqueueForBatch(")
	if enq < 0 {
		t.Fatal("enqueueForBatch call not found")
	}
	call := src[enq:min(enq+600, len(src))]
	if strings.Contains(call, "bftRes.Height") {
		t.Fatal("enqueueForBatch is passed the CometBFT height; members would fall into " +
			"different periods on different validators")
	}
	if !strings.Contains(call, "blockHeight") {
		t.Fatal("enqueueForBatch must be passed the Accumulate blockHeight")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// PROOF CLASS MUST NOT GATE THE ENQUEUE.
//
// Restricting it to on_cadence sent on_demand intents down a per-intent path that cannot settle
// against the deployed contracts: CertenAccountV7._authorizeLeaf computes ONLY the batch-form
// leaf, so a V7 account can never authorise against a V6-form single-intent anchor. On top of
// that the per-intent submitter declared voting power unrelated to any signer set, and proved
// against the block signer's recorded key rather than the key that signed (constraint #774716).
//
// "N=1 IS NOT A SPECIAL CASE" — an intent alone in its period is a one-member batch and gets
// the same real quorum as any other. Intents the batch path cannot represent still fall through
// via EnqueueForBatch / batchInputsFromIntent refusing them, which keeps non-EVM targets intact.
func TestEnqueueIsNotGatedOnProofClass(t *testing.T) {
	src := workflowSource(t)
	enq := strings.Index(src, "bv.enqueueForBatch(")
	if enq < 0 {
		t.Fatal("enqueueForBatch call not found")
	}
	window := src[max0(enq-300):enq]
	if strings.Contains(window, `proofClass == "on_cadence"`) {
		t.Fatal("the batch enqueue is gated on proofClass again. on_demand intents would go to " +
			"the per-intent path, which cannot settle a CertenAccountV7 account: _authorizeLeaf " +
			"computes only the batch-form leaf.")
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
