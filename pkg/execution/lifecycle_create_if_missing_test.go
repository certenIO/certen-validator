// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
)

// RB8-F (defect D4): four settled intents had no intent_lifecycle row, so their proof cycle died "lifecycle: mark <id>
// in_process: intent lifecycle not found" and they never got a proof. The cycle now creates the row it finds missing
// from its own request - idempotently - and goes on.

// fakeLifecycle is a lifecycle table of rows keyed by intent: UpdateStatus on a missing row is ErrIntentLifecycleNotFound
// exactly as the repository returns it.
type fakeLifecycle struct {
	rows       map[string]string // intent -> status
	created    map[string]createdRow
	updateErr  error // returned for every UpdateStatus when set (a row that exists)
	ensureErr  error
	ensureRuns int
}

type createdRow struct {
	tx, user, class, chain string
	height                 int64
}

func (f *fakeLifecycle) UpdateStatus(_ context.Context, id string, st database.IntentLifecycleStatus, _ ...database.UpdateOption) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if _, ok := f.rows[id]; !ok {
		return database.ErrIntentLifecycleNotFound
	}
	f.rows[id] = string(st)
	return nil
}

func (f *fakeLifecycle) EnsureOnProofCycle(_ context.Context, id, tx, user, class, chain string, height int64) (bool, error) {
	f.ensureRuns++
	if f.ensureErr != nil {
		return false, f.ensureErr
	}
	if tx == "" {
		return false, errors.New("names no Accumulate transaction")
	}
	if _, ok := f.rows[id]; ok {
		return false, nil
	}
	f.rows[id] = "authorized"
	if f.created == nil {
		f.created = map[string]createdRow{}
	}
	f.created[id] = createdRow{tx, user, class, chain, height}
	return true, nil
}

func cycleRequest(id string) *UnifiedProofCycleRequest {
	user := "gateway-user"
	return &UnifiedProofCycleRequest{IntentID: id, ProofClass: "on_demand", TargetChain: "base_sepolia",
		AccumulateTxHash: "5b4a370a195f6dfb5dc1a4669dd4dad58310cd600e9e338428d047538b2e8d1e", UserID: &user, AccumulateHeight: 11243840}
}

func TestAProofCycleCreatesTheLifecycleRowItFindsMissing(t *testing.T) {
	f := &fakeLifecycle{rows: map[string]string{}}
	req := cycleRequest("1c152f20-2f5a-40cb-b10c-6d266a5b4e48")

	if err := ensureLifecycleInProcess(context.Background(), f, req, "cycle-1"); err != nil {
		t.Fatalf("a settled intent with no row was refused its proof cycle: %v", err)
	}
	if f.rows[req.IntentID] != string(database.IntentLifecycleInProcess) {
		t.Fatalf("the intent is %q, want in_process", f.rows[req.IntentID])
	}
	got := f.created[req.IntentID]
	if got.tx != req.AccumulateTxHash || got.user != "gateway-user" || got.class != "on_demand" || got.chain != "base_sepolia" || got.height != 11243840 {
		t.Fatalf("the row was not created from the request's own data: %+v", got)
	}
}

func TestACreatedRowIsIdempotentAndAnExistingRowIsNotRecreated(t *testing.T) {
	f := &fakeLifecycle{rows: map[string]string{"have-row": "authorized"}}
	if err := ensureLifecycleInProcess(context.Background(), f, cycleRequest("have-row"), "c"); err != nil {
		t.Fatal(err)
	}
	if f.ensureRuns != 0 {
		t.Fatalf("an intent that has its row had it ensured %d time(s)", f.ensureRuns)
	}
	// A second cycle for an intent whose row the first one created finds it and creates nothing.
	req := cycleRequest("made-by-first")
	_ = ensureLifecycleInProcess(context.Background(), f, req, "c1")
	_ = ensureLifecycleInProcess(context.Background(), f, req, "c2")
	if f.ensureRuns != 1 {
		t.Fatalf("the row was ensured %d times, want exactly once", f.ensureRuns)
	}
}

// Nothing is invented: a request that names no Accumulate transaction cannot have its row created, and the refusal
// says both what was missing and why it could not be made.
func TestAProofCycleWithoutATransactionDoesNotInventARow(t *testing.T) {
	f := &fakeLifecycle{rows: map[string]string{}}
	req := cycleRequest("no-tx")
	req.AccumulateTxHash, req.AccumulateHash = "", ""
	err := ensureLifecycleInProcess(context.Background(), f, req, "c")
	if err == nil || !errors.Is(err, database.ErrIntentLifecycleNotFound) || !strings.Contains(err.Error(), "names no Accumulate transaction") {
		t.Fatalf("expected the not-found refusal naming why the row could not be created, got %v", err)
	}
	if _, ok := f.rows[req.IntentID]; ok {
		t.Fatal("a row was invented without a transaction hash")
	}
}

// RB8-G (verifier defect 1): AccumulateHash of the anchor request is the Accumulate BLOCK hash, not a transaction hash.
// A request that names only a block hash names no Accumulate transaction: its row is not created from the block hash.
func TestABlockHashIsNotATransactionHashForTheCreatedRow(t *testing.T) {
	f := &fakeLifecycle{rows: map[string]string{}}
	req := cycleRequest("only-a-block-hash")
	req.AccumulateTxHash = ""
	req.AccumulateHash = "e0d1c2b3a4f5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff" // the block hash
	err := ensureLifecycleInProcess(context.Background(), f, req, "c")
	if err == nil || !errors.Is(err, database.ErrIntentLifecycleNotFound) || !strings.Contains(err.Error(), "names no Accumulate transaction") {
		t.Fatalf("a request with only a block hash was not refused for naming no transaction: %v", err)
	}
	if _, ok := f.rows[req.IntentID]; ok {
		t.Fatalf("a row was created from the block hash: %+v", f.created[req.IntentID])
	}
}

// Any other failure of the move is returned as it always was; it is not "fixed" by creating rows.
func TestOtherLifecycleFailuresAreStillReturned(t *testing.T) {
	boom := errors.New("pq: the database is shutting down")
	f := &fakeLifecycle{rows: map[string]string{}, updateErr: boom}
	err := ensureLifecycleInProcess(context.Background(), f, cycleRequest("x"), "c")
	if !errors.Is(err, boom) || f.ensureRuns != 0 {
		t.Fatalf("a database error was handled as a missing row: %v (ensure ran %d times)", err, f.ensureRuns)
	}
}
