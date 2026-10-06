// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RB6-F11: an on-demand member refused by name before any chain transaction leaves the settling queue (never attempted
// again) but is KEPT, so this validator - as every peer must - can verify the member's non-settlement claim from its own
// copy. Removed on refusal, no peer held it, and no refused member's non-settlement could ever be attested
// (live: intents 96d22380 and fab16fc4, "member … is not held by this validator").
func TestARefusedMemberIsKeptForItsNonSettlementButNeverAttemptedAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_mempool.json")
	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestMempool(BatchMempoolConfig{})
	m.SetStore(store, nil)
	member := odMember(7, odChain, 2886)
	if err := m.AddOnDemand(member); err != nil {
		t.Fatal(err)
	}
	refusedAt := time.Now().UTC().Truncate(time.Second)
	if !m.RefuseOnDemand(odChain, member.OperationID, refusedAt) {
		t.Fatal("a queued member was not refused")
	}
	if m.GetOnDemand(odChain, member.OperationID) != nil || m.PendingOnDemandCount() != 0 {
		t.Fatal("THE regression: a refused member is still queued to settle")
	}
	if got, ok := m.FindMember(odChain, member.OperationID); !ok || got.IntentID != member.IntentID {
		t.Fatal("THE regression: a refused member is not held for its non-settlement's verification")
	}

	// A restart keeps it refused - not queued, still held.
	restored := newTestMempool(BatchMempoolConfig{})
	if _, err := store.Load(restored); err != nil {
		t.Fatal(err)
	}
	if restored.PendingOnDemandCount() != 0 {
		t.Fatal("a refused member restored as queued")
	}
	if _, ok := restored.FindMember(odChain, member.OperationID); !ok {
		t.Fatal("a refused member was lost across a restart")
	}

	// Written as an on-demand member with refused_at: an older binary restores it queued (and refuses it again) instead
	// of refusing to load the file.
	raw, _ := os.ReadFile(path)
	var file []map[string]any
	if err := json.Unmarshal(raw, &file); err != nil || len(file) != 1 || file[0]["lane"] != "on_demand" || file[0]["refused_at"] == nil {
		t.Fatalf("snapshot %s (%v)", raw, err)
	}

	// Kept for RefusedKeep, then forgotten.
	restored.mu.Lock()
	restored.pruneRefusedLocked(refusedAt.Add(RefusedKeep-time.Minute), nil)
	restored.mu.Unlock()
	if _, ok := restored.FindMember(odChain, member.OperationID); !ok {
		t.Fatal("pruned before RefusedKeep")
	}
	restored.mu.Lock()
	restored.pruneRefusedLocked(refusedAt.Add(RefusedKeep+time.Minute), nil)
	restored.mu.Unlock()
	if _, ok := restored.FindMember(odChain, member.OperationID); ok {
		t.Fatal("kept past RefusedKeep")
	}
}

// The on-demand submitter, refusing a member by name before any chain transaction, keeps it for its non-settlement and
// hands the named refusal to the drop handler, which records the intent refused (RB6-F10/F11).
func TestTheSubmitterKeepsARefusedMemberAndNamesTheRefusal(t *testing.T) {
	s, _ := settlementSubmitter(t, &fakeODChain{})
	var droppedRefusal, droppedCause string
	s.cfg.OnDropped = func(_ context.Context, m *PendingBatchIntent, cause string) {
		droppedRefusal, droppedCause = m.Refusal, cause
	}
	m := odMember(3, odChain, 2886)
	if err := s.cfg.Stack.Mempool.AddOnDemand(m); err != nil {
		t.Fatal(err)
	}
	cause := &IntentRefusedError{Err: errors.New("member c-intent account unusable: account verifies certen:batchleaf:v1 leaves, not v3")}
	s.dispose(context.Background(), m, &OnDemandOutcome{}, false, cause)
	if _, ok := s.cfg.Stack.Mempool.FindMember(odChain, m.OperationID); !ok {
		t.Fatal("THE regression: the refused member is no longer held, so no peer can verify its non-settlement")
	}
	if s.cfg.Stack.Mempool.PendingOnDemandCount() != 0 {
		t.Fatal("the refused member is still queued to settle")
	}
	if droppedRefusal == "" || !strings.Contains(droppedRefusal, "account unusable") || !strings.Contains(droppedCause, "account unusable") {
		t.Fatalf("the refusal was not named to the drop handler: refusal %q cause %q", droppedRefusal, droppedCause)
	}

	// A failure that is not the intent's own defect (CERTEN missed its deadline) is not a refusal: removed, unnamed.
	late := odMember(4, odChain, 2887)
	if err := s.cfg.Stack.Mempool.AddOnDemand(late); err != nil {
		t.Fatal(err)
	}
	droppedRefusal = "unset"
	s.dispose(context.Background(), late, &OnDemandOutcome{}, false, errMemberPastDeadline)
	if _, ok := s.cfg.Stack.Mempool.FindMember(odChain, late.OperationID); ok || droppedRefusal != "" {
		t.Fatalf("a deadline failure was kept or named a refusal (%q)", droppedRefusal)
	}
}

// Only an answer the chain gave refuses a member by name; a screen read that failed is not a verdict and never becomes a
// refusal (the member waits for a read that succeeds).
func TestOnlyAChainVerdictRefusesAMember(t *testing.T) {
	m := odMember(5, odChain, 2888)
	verdict := &fakeODChain{accountErr: errors.New("account 0x96b9 verifies \"certen:batchleaf:v1\" leaves, not \"certen:batchleaf:v3\"")}
	_, err := odOrchestrator(verdict).SettleOnDemandMember(context.Background(), m, proveOK)
	var refused *IntentRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("a chain verdict was not a refusal: %v", err)
	}
	flaky := &fakeODChain{accountErr: readErr(errors.New("reading LEAF_DOMAIN: 429 Too Many Requests"))}
	_, err = odOrchestrator(flaky).SettleOnDemandMember(context.Background(), m, proveOK)
	if err == nil || errors.As(err, &refused) || !IsChainReadError(err) {
		t.Fatalf("THE regression: a failed read was turned into a refusal: %v", err)
	}
}
