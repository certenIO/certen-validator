package consensus

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Re-driving one decided member's proof cycle (RB4-F55 repair).
//
// A member with a recorded outcome is never queued again (RB3-F141), so nothing re-runs a proof cycle that failed
// for reasons that were not the member's: on 2026-09-29 intent 000ac79a's base member settled on chain and was
// recorded failed by a cycle a fleet restart broke. A repair names the member; its intent is re-processed exactly
// as discovery processes it - its round re-derived and checked against the committed block - and at that member,
// where the round captures its snapshot and finds the member decided, the member's proof cycle is run on its
// settlement from that snapshot. Only a member a repair names, only once, and never from a snapshot that lacks
// what the proof cycle binds.

// MemberRepair names one member to re-drive.
type MemberRepair struct {
	IntentID     string
	ChainID      int64
	SettlementTx string
	// Apply runs the proof cycle; without it the member's re-derived snapshot is reported and nothing runs.
	Apply bool
}

// MemberRepairSnapshot is what the re-derived round captured for the member.
type MemberRepairSnapshot struct {
	IntentID            string
	Lane                string
	BundleID            string
	GovernanceRoot      string
	OperationCommitment string
	AccumulateHeight    uint64
	GovernanceLevel     string
	GovernanceLevels    bool // G0, G1 and G2 are all present
	BLSSignature        bool
	AccountURL          string
	TransactionHash     string
}

// MemberRepairReach is what happened when the re-derived round reached the named member.
type MemberRepairReach struct {
	Snapshot MemberRepairSnapshot
	// Started: the member's proof cycle was started (Apply). Its outcome is recorded by the cycle.
	Started bool
	Err     error
}

type armedRepair struct {
	MemberRepair
	reach chan MemberRepairReach
}

func memberRepairKey(intentID string, chainID int64) string {
	return fmt.Sprintf("%s|%d", intentID, chainID)
}

// ArmMemberRepair names a member for re-driving the next time its round reaches it. The channel receives what
// happened then, once; disarm withdraws it if the round never reaches the member.
func (bv *BFTValidator) ArmMemberRepair(r MemberRepair) (<-chan MemberRepairReach, func()) {
	a := &armedRepair{MemberRepair: r, reach: make(chan MemberRepairReach, 1)}
	key := memberRepairKey(r.IntentID, r.ChainID)
	bv.memberRepairsMu.Lock()
	if bv.memberRepairs == nil {
		bv.memberRepairs = map[string]*armedRepair{}
	}
	bv.memberRepairs[key] = a
	bv.memberRepairsMu.Unlock()
	return a.reach, func() {
		bv.memberRepairsMu.Lock()
		if bv.memberRepairs[key] == a {
			delete(bv.memberRepairs, key)
		}
		bv.memberRepairsMu.Unlock()
	}
}

// takeMemberRepair returns and withdraws the repair naming this member, if any: a repair is used once.
func (bv *BFTValidator) takeMemberRepair(intentID string, chainID int64) *armedRepair {
	bv.memberRepairsMu.Lock()
	defer bv.memberRepairsMu.Unlock()
	key := memberRepairKey(intentID, chainID)
	a := bv.memberRepairs[key]
	delete(bv.memberRepairs, key)
	return a
}

// memberRepairState is the repair registry and the proof-cycle starter a BFTValidator carries.
type memberRepairState struct {
	memberRepairsMu sync.Mutex
	memberRepairs   map[string]*armedRepair
	// memberRepairStart starts a member's proof cycle; nil is RunBatchMemberAttestation (tests replace it).
	memberRepairStart func(ctx context.Context, att *PendingAttestation, tx string, chainID int64, lane string)
}

// repairDecidedMember runs the repair armed for this decided member, if one is: from the round's snapshot, on the
// settlement the repair names.
func (bv *BFTValidator) repairDecidedMember(att *PendingAttestation, chainID int64, lane string) {
	a := bv.takeMemberRepair(att.IntentID, chainID)
	if a == nil {
		return
	}
	snap := MemberRepairSnapshot{
		IntentID: att.IntentID, Lane: lane, BundleID: att.BundleIDHex, GovernanceRoot: att.GovernanceProofRoot,
		OperationCommitment: att.OperationCommitment, AccumulateHeight: att.AccumulateBlockHeight,
		GovernanceLevel: att.GovernanceLevel, GovernanceLevels: att.G0Proof != nil && att.G1Proof != nil && att.G2Proof != nil,
		BLSSignature: att.BLSSignature != "", AccountURL: att.AccountURL, TransactionHash: att.TransactionHash,
	}
	var missing []string
	for _, m := range []struct {
		absent bool
		name   string
	}{
		{att.CertenIntent == nil, "the intent"},
		{att.BundleIDHex == "", "the committed block's bundle id"},
		{att.GovernanceProofRoot == "", "the governance root"},
		{att.OperationCommitment == "", "the operation commitment"},
		{att.G0Proof == nil, "G0"}, {att.G1Proof == nil, "G1"}, {att.G2Proof == nil, "G2"},
		{att.AccountURL == "", "the Accumulate account"},
		{att.TransactionHash == "", "the Accumulate transaction"},
		{a.SettlementTx == "", "the settlement transaction"},
	} {
		if m.absent {
			missing = append(missing, m.name)
		}
	}
	if len(missing) > 0 {
		err := fmt.Errorf("intent %s member %d: the re-derived round lacks %s; its proof cycle is not run",
			att.IntentID, chainID, strings.Join(missing, ", "))
		bv.logger.Printf("🛑 [MEMBER-REPAIR] %v", err)
		a.reach <- MemberRepairReach{Snapshot: snap, Err: err}
		return
	}
	if !a.Apply {
		bv.logger.Printf("🔎 [MEMBER-REPAIR] intent %s member %d reached (dry run): bundle %s, governance root %s, lane %s",
			att.IntentID, chainID, att.BundleIDHex, att.GovernanceProofRoot, lane)
		a.reach <- MemberRepairReach{Snapshot: snap}
		return
	}
	start := bv.memberRepairStart
	if start == nil {
		start = func(ctx context.Context, att *PendingAttestation, tx string, chainID int64, lane string) {
			bv.RunBatchMemberAttestation(ctx, att, tx, chainID, true, lane)
		}
	}
	bv.logger.Printf("🔧 [MEMBER-REPAIR] intent %s member %d: running its proof cycle on settlement %s (lane %s)",
		att.IntentID, chainID, a.SettlementTx, lane)
	start(context.Background(), att, a.SettlementTx, chainID, lane)
	a.reach <- MemberRepairReach{Snapshot: snap, Started: true}
}
