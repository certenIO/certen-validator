// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// RB3-F123: a completion the store fails is kept and closed once the store answers - it used to be logged
// and dropped, leaving a proof whose four levels were complete marked incomplete for good.
func TestAFailedCompletionIsKeptAndClosedLater(t *testing.T) {
	f := newLevelFixture(t)
	f.record(t)
	outbox, err := NewFileProofCompletionOutbox(filepath.Join(t.TempDir(), "completions"))
	if err != nil {
		t.Fatal(err)
	}
	f.orch.config.ProofCompletions = outbox

	// The store does not answer when the cycle closes its records.
	down, cancel := context.WithCancel(context.Background())
	cancel()
	f.orch.completeProofCycles(down, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root, "writeback-tx")
	ctx := context.Background()
	record, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
	if err != nil || record == nil || record.AllLevelsComplete {
		t.Fatalf("record after the failed pass: (%+v, %v)", record, err)
	}
	if n, _ := outbox.Depth(); n != len(f.cycle.Completions) {
		t.Fatalf("outbox holds %d, want %d", n, len(f.cycle.Completions))
	}

	// The store answers: the reconciler closes the record exactly as the cycle would have.
	rep, err := (&ProofCompletionReconciler{Outbox: outbox, Store: f.repos.ProofArtifacts, Logf: t.Logf}).RunOnce(ctx)
	if err != nil || rep.Completed != len(f.cycle.Completions) || rep.Remaining != 0 {
		t.Fatalf("reconcile: (%+v, %v)", rep, err)
	}
	done, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
	if err != nil || done == nil || !done.AllLevelsComplete || !done.BindingsValid {
		t.Fatalf("record after the reconciler: (%+v, %v)", done, err)
	}
	if string(done.CycleHash) != string(proofCycleHash(record, "writeback-tx")) {
		t.Fatal("the reconciler bound a different cycle hash than the cycle would have")
	}
}

// A record missing a level is a real incompleteness, not a failed call: it is reported and not queued; an
// entry naming a record that cannot be closed is quarantined, not retried for ever.
func TestAnUnclosableCompletionIsNotRetriedForEver(t *testing.T) {
	f := newLevelFixture(t)
	f.inputs.ChainedProof = nil
	f.record(t)
	outbox, err := NewFileProofCompletionOutbox(filepath.Join(t.TempDir(), "completions"))
	if err != nil {
		t.Fatal(err)
	}
	f.orch.config.ProofCompletions = outbox
	f.orch.completeProofCycles(context.Background(), f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root, "writeback-tx")
	if n, _ := outbox.Depth(); n != 0 {
		t.Fatalf("a record missing a level was queued (%d)", n)
	}

	if err := outbox.Put(ProofCompletion{CompletionID: uuid.New(), CycleID: "c", WriteBackTx: "tx"}); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Put(ProofCompletion{CompletionID: f.cycle.Completions[0], CycleID: "c", WriteBackTx: "tx"}); err != nil {
		t.Fatal(err)
	}
	rep, err := (&ProofCompletionReconciler{Outbox: outbox, Store: f.repos.ProofArtifacts, Logf: t.Logf}).RunOnce(context.Background())
	if err != nil || rep.Quarantined != 2 || rep.Remaining != 0 {
		t.Fatalf("reconcile: (%+v, %v)", rep, err)
	}
	if err := outbox.Put(ProofCompletion{CompletionID: uuid.New()}); err == nil {
		t.Fatal("a completion without its write-back transaction was kept")
	}
}

// Level records close only on a write-back that happened: the cycle hash binds its transaction.
func TestLevelRecordsCloseOnlyOnAWrittenBack(t *testing.T) {
	f := newLevelFixture(t)
	f.record(t)
	ctx := context.Background()
	for _, state := range []string{WriteBackRefusedQuorumNotMet, WriteBackFailed, ""} {
		f.cycle.Result.WriteBackState, f.cycle.Result.WriteBackTxHash = state, "tx"
		if f.orch.closeLevelRecords(ctx, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root) {
			t.Fatalf("closed on write-back %q", state)
		}
	}
	f.cycle.Result.WriteBackState, f.cycle.Result.WriteBackTxHash = WriteBackWritten, ""
	if f.orch.closeLevelRecords(ctx, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root) {
		t.Fatal("closed with no write-back transaction")
	}
	record, _ := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
	if record == nil || record.AllLevelsComplete {
		t.Fatalf("a record closed without a write-back: %+v", record)
	}
	f.cycle.Result.WriteBackTxHash = "writeback-tx"
	if !f.orch.closeLevelRecords(ctx, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root) {
		t.Fatal("not closed on a written-back cycle")
	}
	if done, _ := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID); done == nil || !done.AllLevelsComplete {
		t.Fatalf("record not closed: %+v", done)
	}
}
