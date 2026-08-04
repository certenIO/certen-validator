package execution

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// odMember builds a valid member. id varies the intentID and operationID together, the way a
// real intent does — the operationID IS the intent's identity.
func odMember(id byte, chainID int64, height uint64) *PendingBatchIntent {
	return &PendingBatchIntent{
		IntentID:     string(rune('a'+id)) + "-intent",
		ADIURL:       "acc://org" + string(rune('a'+id)) + ".acme",
		ChainID:      chainID,
		Account:      common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
		OperationID:  [32]byte{id},
		CommitHeight: height,
		Legs: []LegExecution{{
			LegID:   "leg-0",
			ChainID: chainID,
			Target:  common.HexToAddress("0x1111111111111111111111111111111111111111"),
			Value:   big.NewInt(0),
			Data:    []byte{0xde, 0xad},
		}},
	}
}

const odChain = int64(11155111)

// THE load-bearing test for step 1. The whole reason on-demand members live in a separate
// structure is that the period path must not be able to see them — if it can, every period call
// site needs a lane filter and the ones that get missed form batches over the wrong members.
func TestOnDemandIndexIsInvisibleToPeriodSelection(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})

	// Same chain, same height window as the period member below.
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if err := m.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Period selection must see ONLY the period member.
	got := m.PeekForPeriod(odChain, 100, 100)
	if len(got) != 1 {
		t.Fatalf("PeekForPeriod returned %d member(s), want 1 — the on-demand member leaked into "+
			"the period path and would be batched with members it must never share an anchor with", len(got))
	}
	if got[0].OperationID != ([32]byte{2}) {
		t.Fatalf("PeekForPeriod selected the wrong member: got opID %v", got[0].OperationID[:1])
	}

	// Every other period-path accessor must agree.
	if n := m.PendingCount(); n != 1 {
		t.Errorf("PendingCount = %d, want 1 (on-demand members must not be counted)", n)
	}
	if n := m.PendingCountForChain(odChain); n != 1 {
		t.Errorf("PendingCountForChain = %d, want 1", n)
	}
	if periods := m.PendingPeriods(odChain, 100, 1000); len(periods) != 1 {
		t.Errorf("PendingPeriods = %v, want exactly the period member's bucket", periods)
	}
	if due := m.DueChains(time.Now(), true); len(due) != 1 {
		t.Errorf("DueChains = %v, want only the period pool's chain", due)
	}

	// And the reverse: the period member must not appear in the on-demand index.
	if n := m.PendingOnDemandCount(); n != 1 {
		t.Errorf("PendingOnDemandCount = %d, want 1 (the period member must not leak in)", n)
	}
	if m.GetOnDemand(odChain, [32]byte{2}) != nil {
		t.Error("GetOnDemand returned the PERIOD member; the two structures are not independent")
	}
}

// TakeForPeriod removes members. It must not remove on-demand ones — a member silently taken
// out from under the on-demand submitter would never settle and never fail.
func TestTakeForPeriodDoesNotConsumeOnDemandMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if err := m.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	taken := m.TakeForPeriod(odChain, 100, 100)
	if len(taken) != 1 {
		t.Fatalf("TakeForPeriod took %d, want 1", len(taken))
	}
	if m.GetOnDemand(odChain, [32]byte{1}) == nil {
		t.Fatal("the on-demand member was consumed by a period flush; it can now never settle")
	}
}

// Each pruner must be blind to the other lane. A shared pruner using one lane's horizon would
// silently delete the other's members — the highest-consequence failure in this file.
func TestOnDemandPruneDoesNotTouchPeriodPool(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	old := odMember(1, odChain, 105)
	old.EnqueuedAt = time.Now().Add(-3 * time.Hour)
	if err := m.AddOnDemand(old); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if err := m.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if pruned := m.PruneOnDemandOlderThan(DefaultOnDemandTTL, time.Now()); pruned != 1 {
		t.Fatalf("PruneOnDemandOlderThan pruned %d, want 1", pruned)
	}
	if n := m.PendingCount(); n != 1 {
		t.Fatalf("the on-demand pruner deleted %d period member(s); the pools are not independent",
			1-n)
	}
}

// The converse: the period pruner is height-based and must not reach into the on-demand index.
func TestPeriodPruneDoesNotTouchOnDemandMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if err := m.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// A horizon far above both members' heights: the period pool is emptied.
	m.PruneOlderThan(100000)
	if n := m.PendingCount(); n != 0 {
		t.Fatalf("period prune left %d member(s); test setup is wrong", n)
	}
	if n := m.PendingOnDemandCount(); n != 1 {
		t.Fatalf("the height-based period pruner deleted %d on-demand member(s)", 1-n)
	}
}

// TTL is wall clock, not a count of periods. The period path measures retention in periods,
// which is meaningless without a period width — scaling that constant into this lane is the
// bug class this test exists to prevent.
func TestOnDemandTTLIsWallClock(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	now := time.Now()

	young := odMember(1, odChain, 105)
	young.EnqueuedAt = now.Add(-30 * time.Minute)
	oldOne := odMember(2, odChain, 999999) // absurd height: must not influence the decision
	oldOne.EnqueuedAt = now.Add(-3 * time.Hour)

	for _, p := range []*PendingBatchIntent{young, oldOne} {
		if err := m.AddOnDemand(p); err != nil {
			t.Fatalf("AddOnDemand: %v", err)
		}
	}

	if pruned := m.PruneOnDemandOlderThan(DefaultOnDemandTTL, now); pruned != 1 {
		t.Fatalf("pruned %d, want 1 — only the member older than the TTL", pruned)
	}
	if m.GetOnDemand(odChain, [32]byte{1}) == nil {
		t.Error("the 30-minute-old member was pruned under a 2h TTL")
	}
	if m.GetOnDemand(odChain, [32]byte{2}) != nil {
		t.Error("the 3-hour-old member survived a 2h TTL")
	}
	if DefaultOnDemandTTL < time.Hour {
		t.Errorf("DefaultOnDemandTTL %s is too short to outlast a leader failover", DefaultOnDemandTTL)
	}
}

// I3: the key is (chainID, operationID). A cross-chain intent contributes one member per chain
// under the SAME operationID, and both must survive — this is the multi-chain case the design
// has to support even though production has never exercised it.
func TestSameOperationIDOnTwoChainsAreDistinctMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	a := odMember(1, odChain, 105)
	b := odMember(1, 84532, 105) // same intentID AND operationID, different chain
	b.Legs[0].ChainID = 84532

	if err := m.AddOnDemand(a); err != nil {
		t.Fatalf("AddOnDemand chain A: %v", err)
	}
	if err := m.AddOnDemand(b); err != nil {
		t.Fatalf("AddOnDemand chain B rejected as a duplicate: %v — a cross-chain intent would "+
			"settle on one chain and silently lose the other", err)
	}
	if m.GetOnDemand(odChain, [32]byte{1}) == nil || m.GetOnDemand(84532, [32]byte{1}) == nil {
		t.Fatal("one of the two chain members is missing")
	}
	if n := m.PendingOnDemandCount(); n != 2 {
		t.Fatalf("PendingOnDemandCount = %d, want 2", n)
	}
}

// Idempotency matches the period pool's contract: same intent, same chain, refused.
func TestAddOnDemandIsIdempotentPerChain(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("first AddOnDemand: %v", err)
	}
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err == nil {
		t.Fatal("duplicate AddOnDemand was accepted; the member would be submitted twice")
	}
	if n := m.PendingOnDemandCount(); n != 1 {
		t.Fatalf("PendingOnDemandCount = %d, want 1", n)
	}
}

// A malformed member must be refused identically in both lanes — the shared validateMember.
func TestOnDemandRejectsWhatThePeriodPoolRejects(t *testing.T) {
	cases := map[string]func(*PendingBatchIntent){
		"no legs":       func(p *PendingBatchIntent) { p.Legs = nil },
		"zero opID":     func(p *PendingBatchIntent) { p.OperationID = [32]byte{} },
		"no ADI URL":    func(p *PendingBatchIntent) { p.ADIURL = "" },
		"no account":    func(p *PendingBatchIntent) { p.Account = common.Address{} },
		"leg off-chain": func(p *PendingBatchIntent) { p.Legs[0].ChainID = 999 },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewBatchMempool(BatchMempoolConfig{})
			p := odMember(1, odChain, 105)
			corrupt(p)
			if err := m.AddOnDemand(p); err == nil {
				t.Fatalf("AddOnDemand accepted a member the period pool rejects (%s)", name)
			}
		})
	}
}

func TestRemoveOnDemandReportsWhetherItRemoved(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if !m.RemoveOnDemand(odChain, [32]byte{1}) {
		t.Fatal("RemoveOnDemand reported false for a member that was present")
	}
	if m.RemoveOnDemand(odChain, [32]byte{1}) {
		t.Fatal("RemoveOnDemand reported true twice; a double-settle would be invisible")
	}
	if n := m.PendingOnDemandCount(); n != 0 {
		t.Fatalf("PendingOnDemandCount = %d after removal, want 0", n)
	}
}

func TestPendingOnDemandIsDeterministicallyOrdered(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	for _, id := range []byte{3, 1, 2} {
		if err := m.AddOnDemand(odMember(id, odChain, uint64(100+id))); err != nil {
			t.Fatalf("AddOnDemand: %v", err)
		}
	}
	// Repeat: Go randomises map iteration, so a single pass can pass by luck.
	for i := 0; i < 20; i++ {
		got := m.PendingOnDemand(odChain)
		if len(got) != 3 {
			t.Fatalf("PendingOnDemand returned %d, want 3", len(got))
		}
		for j, want := range []byte{1, 2, 3} {
			if got[j].OperationID[0] != want {
				t.Fatalf("iteration %d: order was %d,%d,%d; want ascending by CommitHeight",
					i, got[0].OperationID[0], got[1].OperationID[0], got[2].OperationID[0])
			}
		}
	}
}

// =============================================================================
// Persistence
// =============================================================================

func TestOnDemandMembersRoundTripThroughStoreIntoTheirOwnIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_mempool.json")
	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatalf("NewBatchMempoolStore: %v", err)
	}

	src := NewBatchMempool(BatchMempoolConfig{})
	src.SetStore(store, nil)
	if err := src.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}
	if err := src.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	dst := NewBatchMempool(BatchMempoolConfig{})
	n, err := store.Load(dst)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n != 2 {
		t.Fatalf("restored %d member(s), want 2", n)
	}
	if dst.GetOnDemand(odChain, [32]byte{1}) == nil {
		t.Error("the on-demand member did not restore into the on-demand index")
	}
	if dst.PendingCount() != 1 {
		t.Errorf("period pool restored %d member(s), want 1 — a lane was mis-routed",
			dst.PendingCount())
	}
	if dst.PendingOnDemandCount() != 1 {
		t.Errorf("on-demand index restored %d member(s), want 1", dst.PendingOnDemandCount())
	}
	// The restored member must keep the height its bundleId derives from.
	if got := dst.GetOnDemand(odChain, [32]byte{1}); got != nil && got.CommitHeight != 105 {
		t.Errorf("restored CommitHeight = %d, want 105 — the bundleId would differ from its peers'",
			got.CommitHeight)
	}
}

// A snapshot written by an OLDER binary has no lane field. Every member must restore to the
// period pool: that is where on-demand intents went before this change, so the default is the
// behaviour they already had, not a silent re-routing.
func TestLaneLessSnapshotRestoresToThePeriodPool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "batch_mempool.json")

	// Write a member with no lane field, exactly as the previous format did.
	legacy := `[{
	  "intent_id": "legacy-intent",
	  "adi_url": "acc://orga.acme",
	  "chain_id": 11155111,
	  "account": "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B",
	  "operation_id": "0x0100000000000000000000000000000000000000000000000000000000000000",
	  "legs": [{"leg_id":"leg-0","target":"0x1111111111111111111111111111111111111111","value":"0","data":"0xdead"}],
	  "commit_height": 105
	}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("seeding legacy snapshot: %v", err)
	}

	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatalf("NewBatchMempoolStore: %v", err)
	}
	m := NewBatchMempool(BatchMempoolConfig{})
	n, err := store.Load(m)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored %d, want 1", n)
	}
	if m.PendingCount() != 1 {
		t.Errorf("lane-less member did not restore to the period pool (PendingCount=%d)",
			m.PendingCount())
	}
	if m.PendingOnDemandCount() != 0 {
		t.Errorf("lane-less member was routed to the on-demand index; a member would change "+
			"settlement mechanism across a restart (count=%d)", m.PendingOnDemandCount())
	}
}

// The snapshot must stay a bare JSON array so an OLDER binary can still read it after a
// rollback. Turning it into an object would make the old binary's unmarshal fail and drop the
// entire queue back to re-derivation.
func TestSnapshotRemainsABareArrayForRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_mempool.json")
	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatalf("NewBatchMempoolStore: %v", err)
	}
	m := NewBatchMempool(BatchMempoolConfig{})
	m.SetStore(store, nil)
	if err := m.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading snapshot: %v", err)
	}
	trimmed := bytes.TrimSpace(blob)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		t.Fatalf("snapshot is not a bare JSON array; an older binary would fail to parse it and "+
			"drop the whole queue:\n%s", blob)
	}
	// And it must decode into the old shape.
	var legacyShape []persistedMember
	if err := json.Unmarshal(blob, &legacyShape); err != nil {
		t.Fatalf("snapshot no longer decodes into []persistedMember: %v", err)
	}
	if len(legacyShape) != 1 || legacyShape[0].Lane != string(LaneOnDemand) {
		t.Fatalf("expected one on_demand-tagged member, got %+v", legacyShape)
	}
}

// With no on-demand members queued, the file must be byte-identical to what the previous
// format produced — omitempty keeps this change from churning every node's snapshot.
func TestSnapshotOmitsLaneForPeriodMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_mempool.json")
	store, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatalf("NewBatchMempoolStore: %v", err)
	}
	m := NewBatchMempool(BatchMempoolConfig{})
	m.SetStore(store, nil)
	if err := m.Add(odMember(2, odChain, 106)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading snapshot: %v", err)
	}
	if bytes.Contains(blob, []byte(`"lane"`)) {
		t.Fatalf("a period-only snapshot contains a lane field; every node's file would churn "+
			"on deploy:\n%s", blob)
	}
}
