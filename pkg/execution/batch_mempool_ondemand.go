package execution

import (
	"fmt"
	"sort"
	"time"
)

// =============================================================================
// On-demand: intent-keyed members
// =============================================================================
//
// # WHY THIS IS NOT A PERIOD
//
// An on-demand batch holds exactly one intent, so its entire on-chain identity is a pure
// function of that intent:
//
//	leaf   = ComputeBatchLeaf(chainID, {ADIURL, ExecutionCommitment, OperationID})
//	root   = leaf                       // N=1: MerkleRoot returns the leaf unchanged
//	opID   = DeriveBatchOperationID([OperationID])
//	height = the member's own CommitHeight
//	bundle = DeriveBatchBundleID(chainID, root, 1, opID, height)
//
// Nothing in that derivation depends on what else a validator is holding, so there is no
// member SET for validators to agree on — and therefore nothing for a settle grace to wait
// for. That is the whole difference from the period path, where a peer holding some but not
// all of a period's members derives a different bundleId (the 2026-08-02 2-of-7 failure) and
// the grace exists to let peers converge.
//
// CertenAnchorV8_1.createBatchAnchor designs for this explicitly: "N=1 is a legitimate batch:
// a one-leaf tree whose root equals the leaf. Callers need no special case, and single/batch
// cannot drift apart into two code paths." Production agrees — every on-demand batch ever
// recorded has exactly one member (max_members = 1 across 62,296 rows, 45 days).
//
// # KEYED ON (chainID, operationID)
//
// The operationID is the Accumulate 4-blob intent hash: the intent's identity, and the lookup
// key an attester is handed. It is NOT unique on its own — a cross-chain intent contributes one
// member per chain under the same operationID — so the chain is always part of the key. The
// leaf binds chainID and the bundleId binds chainId, so those members cannot collide on chain
// either.
//
// # INDEPENDENT OF THE PERIOD POOL
//
// These members live in their own map and are invisible to DueChains, Take, PeekForPeriod,
// TakeForPeriod, PendingPeriods, PendingCount and PruneOlderThan. That independence is the
// design: the period path is not modified to accommodate this one, so it cannot be broken by
// it. Nothing here registers in `seen`, which is the period pool's idempotency map.

// DefaultOnDemandTTL bounds how long an intent-keyed member may sit before it is pruned as
// garbage.
//
// Expressed in WALL CLOCK, deliberately. The period path measures retention in periods
// (DefaultBatchRetentionPeriods), which is meaningful only because a period has a fixed width;
// there are no periods here, and a count of them would be meaningless. Sized to match the
// period pool's horizon in real time (50 periods x 100 blocks x ~1.43s is roughly two hours) so
// a member waiting out a failover is not deleted mid-recovery.
const DefaultOnDemandTTL = 2 * time.Hour

// AddOnDemand queues an intent-keyed member.
//
// Idempotent per (chainID, operationID): re-adding the same intent for the same chain is
// refused, matching the period pool's contract. Re-adding it for a DIFFERENT chain is accepted,
// because that is a genuinely different member with a different leaf.
func (m *BatchMempool) AddOnDemand(p *PendingBatchIntent) error {
	if err := m.addOnDemand(p); err != nil {
		return err
	}
	// Snapshot after the lock is released — persist() re-acquires m.mu.
	m.persist()
	return nil
}

func (m *BatchMempool) addOnDemand(p *PendingBatchIntent) error {
	// The same admission rules as the period pool. A member that could not form a valid leaf
	// there cannot form one here either.
	if err := validateMember(p); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.onDemand == nil {
		m.onDemand = make(map[int64]map[[32]byte]*PendingBatchIntent)
	}
	byOp, ok := m.onDemand[p.ChainID]
	if !ok {
		byOp = make(map[[32]byte]*PendingBatchIntent)
		m.onDemand[p.ChainID] = byOp
	}
	if _, dup := byOp[p.OperationID]; dup {
		return fmt.Errorf("intent %s is already queued on-demand for chain %d", p.IntentID, p.ChainID)
	}
	byOp[p.OperationID] = p
	return nil
}

// GetOnDemand returns the member an attester should rebuild from, or nil if this validator does
// not hold it.
//
// Nil is the "not ready yet" signal, not an error: a peer that has not finished processing the
// round genuinely does not have it, and the proposer should retry rather than count a refusal.
func (m *BatchMempool) GetOnDemand(chainID int64, opID [32]byte) *PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.onDemand[chainID][opID]
}

// RemoveOnDemand drops a member once it has settled or been routed to fallback. Reports whether
// anything was removed, so a double-settle is visible rather than silent.
func (m *BatchMempool) RemoveOnDemand(chainID int64, opID [32]byte) bool {
	removed := m.removeOnDemand(chainID, opID)
	if removed {
		m.persist()
	}
	return removed
}

func (m *BatchMempool) removeOnDemand(chainID int64, opID [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	byOp, ok := m.onDemand[chainID]
	if !ok {
		return false
	}
	if _, exists := byOp[opID]; !exists {
		return false
	}
	delete(byOp, opID)
	if len(byOp) == 0 {
		delete(m.onDemand, chainID)
	}
	return true
}

// PendingOnDemand lists a chain's queued intent-keyed members.
//
// Ordered by (CommitHeight, IntentID) — the same rule the period path sorts by. Map iteration
// is randomised in Go, and an unordered result would make the submitter's behaviour differ run
// to run for no reason; settlement order is not consensus-critical here (each member is its own
// batch) but reproducibility in logs and tests is worth having.
func (m *BatchMempool) PendingOnDemand(chainID int64) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()

	byOp := m.onDemand[chainID]
	if len(byOp) == 0 {
		return nil
	}
	out := make([]*PendingBatchIntent, 0, len(byOp))
	for _, p := range byOp {
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CommitHeight != out[j].CommitHeight {
			return out[i].CommitHeight < out[j].CommitHeight
		}
		return out[i].IntentID < out[j].IntentID
	})
	return out
}

// PendingOnDemandCount returns queued intent-keyed members across all chains.
func (m *BatchMempool) PendingOnDemandCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, byOp := range m.onDemand {
		n += len(byOp)
	}
	return n
}

// PruneOnDemandOlderThan removes members enqueued longer ago than ttl and reports how many.
//
// Scoped to the on-demand index ONLY. The period pool's PruneOlderThan is height-based and
// operates on `pool`; neither can reach the other's members. That separation is deliberate: a
// prune horizon appropriate for one lane would be wildly wrong for the other, and a shared
// pruner would silently delete members that were merely waiting.
//
// Correctness does not depend on this — it is a memory backstop. A member pruned while it was
// still settling would be re-derived by the discovery watermark rewind if it is inside that
// window, and lost if it is not, which is why the horizon is generous.
func (m *BatchMempool) PruneOnDemandOlderThan(ttl time.Duration, now time.Time) int {
	if ttl <= 0 {
		ttl = DefaultOnDemandTTL
	}
	pruned := m.pruneOnDemandOlderThan(ttl, now)
	if pruned > 0 {
		m.persist()
	}
	return pruned
}

func (m *BatchMempool) pruneOnDemandOlderThan(ttl time.Duration, now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	pruned := 0
	for chainID, byOp := range m.onDemand {
		for opID, p := range byOp {
			if p == nil || now.Sub(p.EnqueuedAt) >= ttl {
				delete(byOp, opID)
				pruned++
			}
		}
		if len(byOp) == 0 {
			delete(m.onDemand, chainID)
		}
	}
	return pruned
}
