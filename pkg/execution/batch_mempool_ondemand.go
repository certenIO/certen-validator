package execution

import (
	"fmt"
	"sort"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
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
//	leaf   = ComputeBatchLeafV2(chainID, {ADIURL, ExecutionCommitment, OperationID}, certified authority page)
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
	// Snapshot after the lock is released — persist() re-acquires m.mu. A member the disk does not hold
	// is taken back and refused as this validator's outage (see Add).
	if err := m.persist(); err != nil {
		m.removeOnDemand(p.ChainID, p.OperationID)
		return fmt.Errorf("%w: intent %s on chain %d could not be persisted: %v", consensus.ErrBatchUnavailable, p.IntentID, p.ChainID, err)
	}
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
	if err := m.certifiableLocked(p); err != nil {
		return err
	}

	if m.onDemand == nil {
		m.onDemand = make(map[int64]map[[32]byte]*PendingBatchIntent)
	}
	byOp, ok := m.onDemand[p.ChainID]
	if !ok {
		byOp = make(map[[32]byte]*PendingBatchIntent)
		m.onDemand[p.ChainID] = byOp
	}
	if held, dup := byOp[p.OperationID]; dup {
		if held.IntentID == p.IntentID {
			return fmt.Errorf("%w: intent %s on chain %d (on-demand)", ErrMemberAlreadyQueued, p.IntentID, p.ChainID)
		}
		return fmt.Errorf("%w: intent %s carries operation %x, already queued on chain %d by intent %s",
			ErrOperationAlreadyQueued, p.IntentID, p.OperationID[:8], p.ChainID, held.IntentID)
	}
	// Queued in the period lane already (the lane flag changed between two runs of the same
	// intent): it is queued, and a second member would settle it twice.
	if m.seen[memberKey(p.IntentID, p.ChainID)] {
		return fmt.Errorf("%w: intent %s on chain %d (period lane)", ErrMemberAlreadyQueued, p.IntentID, p.ChainID)
	}
	if holder := m.operationHolderLocked(p.ChainID, p.OperationID, p.IntentID); holder != "" {
		return fmt.Errorf("%w: intent %s carries operation %x, already queued on chain %d by intent %s",
			ErrOperationAlreadyQueued, p.IntentID, p.OperationID[:8], p.ChainID, holder)
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

// RefusedKeep is how long a member refused before any chain transaction is kept after its refusal: past its deadline (at
// most an hour after its commit), the non-settlement give-up (50 minutes past the deadline) and margin.
const RefusedKeep = 3 * time.Hour

// refusedMember is an on-demand member refused by name before any chain transaction, and when.
type refusedMember struct {
	member *PendingBatchIntent
	at     time.Time
}

// RefuseOnDemand moves a queued on-demand member that was refused by name before any chain transaction out of the
// settling queue into the refused set (RB6-F11): it is never attempted again on this validator, and FindMember still
// finds it, so this validator verifies the member's non-settlement claim from its own copy. It reports whether the
// member was queued.
func (m *BatchMempool) RefuseOnDemand(chainID int64, opID [32]byte, at time.Time) bool {
	m.mu.Lock()
	p := m.onDemand[chainID][opID]
	if p == nil {
		m.mu.Unlock()
		return false
	}
	m.mu.Unlock()
	if !m.removeOnDemand(chainID, opID) {
		return false
	}
	m.mu.Lock()
	m.keepRefusedLocked(p, at)
	m.mu.Unlock()
	m.persist()
	return true
}

func (m *BatchMempool) keepRefusedLocked(p *PendingBatchIntent, at time.Time) {
	if m.refused == nil {
		m.refused = make(map[int64]map[[32]byte]*refusedMember)
	}
	if m.refused[p.ChainID] == nil {
		m.refused[p.ChainID] = make(map[[32]byte]*refusedMember)
	}
	m.refused[p.ChainID][p.OperationID] = &refusedMember{member: p, at: at}
}

// RefusedPruneCandidates are the refused members kept longer than RefusedKeep (this machine's clock: a trigger only).
func (m *BatchMempool) RefusedPruneCandidates(now time.Time) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*PendingBatchIntent
	for _, byOp := range m.refused {
		for _, r := range byOp {
			if now.Sub(r.at) > RefusedKeep {
				out = append(out, r.member)
			}
		}
	}
	return out
}

// PruneRefusedExcept forgets the refused members kept longer than RefusedKeep, except those in keep - whose chain is
// not past their attestation window yet (BatchStack.settleOnDemandAtTTL).
func (m *BatchMempool) PruneRefusedExcept(now time.Time, keep map[*PendingBatchIntent]bool) {
	m.mu.Lock()
	m.pruneRefusedLocked(now, keep)
	m.mu.Unlock()
	m.persist()
}

// pruneRefusedLocked forgets refused members kept longer than RefusedKeep, except those in keep.
func (m *BatchMempool) pruneRefusedLocked(now time.Time, keep map[*PendingBatchIntent]bool) {
	for chainID, byOp := range m.refused {
		for op, r := range byOp {
			if now.Sub(r.at) > RefusedKeep && !keep[r.member] {
				delete(byOp, op)
			}
		}
		if len(byOp) == 0 {
			delete(m.refused, chainID)
		}
	}
}

// NoteOnDemandProgress records this validator's own progress on a queued on-demand member and
// persists it. It reports whether the member was queued; a member that is not (the period lane, or
// one already released) is left alone.
//
// The update runs under the mempool lock, so a concurrent snapshot never reads a half-written
// member.
func (m *BatchMempool) NoteOnDemandProgress(chainID int64, opID [32]byte, update func(p *PendingBatchIntent)) bool {
	m.mu.Lock()
	p := m.onDemand[chainID][opID]
	if p != nil {
		update(p)
	}
	m.mu.Unlock()
	if p == nil {
		return false
	}
	m.persist()
	return true
}

// SetCommitTime records a queued member's commit time, read from its commit block (ResolveCommitTime), and persists it -
// in either lane. A member that already has one keeps it: it is one value, the same on every validator. It reports
// whether the member is queued.
func (m *BatchMempool) SetCommitTime(chainID int64, opID [32]byte, t time.Time) bool {
	m.mu.Lock()
	var held *PendingBatchIntent
	if p := m.onDemand[chainID][opID]; p != nil {
		held = p
	} else {
		for _, p := range m.pool[chainID] {
			if p != nil && p.OperationID == opID {
				held = p
				break
			}
		}
	}
	if held != nil && held.CommitTime.IsZero() {
		held.CommitTime = t
	}
	m.mu.Unlock()
	if held == nil {
		return false
	}
	m.persist()
	return true
}

// HeldPastTTL is how many on-demand members the last prune kept past their TTL because this
// validator has acted on them - settlements in flight, or anchors it attested - and must see resolve.
func (m *BatchMempool) HeldPastTTL() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.heldPastTTL
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
	return m.PruneOnDemandOlderThanExcept(ttl, now, nil)
}

// OnDemandPruneCandidates is every on-demand member a prune at (ttl, now) would remove, in (chain, IntentID) order.
func (m *BatchMempool) OnDemandPruneCandidates(ttl time.Duration, now time.Time) []*PendingBatchIntent {
	if ttl <= 0 {
		ttl = DefaultOnDemandTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*PendingBatchIntent
	for _, byOp := range m.onDemand {
		for _, p := range byOp {
			if p != nil && onDemandPrunable(p, ttl, now) {
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChainID != out[j].ChainID {
			return out[i].ChainID < out[j].ChainID
		}
		return out[i].IntentID < out[j].IntentID
	})
	return out
}

// PruneOnDemandOlderThanExcept is PruneOnDemandOlderThan keeping the members in keep: those whose fate could not be
// read yet.
func (m *BatchMempool) PruneOnDemandOlderThanExcept(ttl time.Duration, now time.Time, keep map[*PendingBatchIntent]bool) int {
	if ttl <= 0 {
		ttl = DefaultOnDemandTTL
	}
	pruned := m.pruneOnDemandOlderThan(ttl, now, keep)
	if pruned > 0 {
		m.persist()
	}
	return pruned
}

// onDemandPrunable is the prune predicate: a member this validator never acted on, past the point its
// non-settlement can still be attested, queued for longer than the TTL.
func onDemandPrunable(p *PendingBatchIntent, ttl time.Duration, now time.Time) bool {
	if p.AnchorProved || p.AttestedSeen || p.SettlementNonceSet || len(p.SettlementTxs) > 0 || p.SettlementTx != "" {
		return false
	}
	if d, ok := p.Deadline(); ok && now.Before(d.Add(nonSettlementFinality+nonSettlementGiveUp)) {
		return false
	}
	return now.Sub(p.EnqueuedAt) >= ttl
}

func (m *BatchMempool) pruneOnDemandOlderThan(ttl time.Duration, now time.Time, keep map[*PendingBatchIntent]bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	pruned := 0
	m.heldPastTTL = 0
	for chainID, byOp := range m.onDemand {
		for opID, p := range byOp {
			if p == nil {
				delete(byOp, opID)
				pruned++
				continue
			}
			// Never prune a member this validator has acted on: it attested the anchor or sent a
			// settlement. Its outcome may still land - a settlement in flight, an attestation it must
			// settle under - and pruning it would drop a real result unrecorded. Such a member leaves
			// the queue only through its outcome.
			// A member seen attested is held too: a later settlement window may be this validator's,
			// and dropping it would lose the takeover that window exists for.
			if p.AnchorProved || p.AttestedSeen || p.SettlementNonceSet || len(p.SettlementTxs) > 0 || p.SettlementTx != "" {
				if now.Sub(p.EnqueuedAt) >= ttl {
					m.heldPastTTL++
				}
				continue
			}
			// Held until its non-settlement can no longer be attested: a peer verifies a member's
			// failure from its own copy of the member (RB3-F49), and a successor's deadline may lie
			// well past the TTL (batch_sequence.go). One predicate decides, here and for the candidates.
			if onDemandPrunable(p, ttl, now) && !keep[p] {
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
