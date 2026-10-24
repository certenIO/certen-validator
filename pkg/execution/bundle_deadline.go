// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"time"
)

// BundleDeadlineState says what BundleChainDeadline could establish. Every state but BundleDeadlineKnown leaves the caller with NO deadline: the
// caller then keeps whatever bound it has otherwise (the capture's tick loop keeps its reach bound B_v + 16 ticks + W). Nothing here ever invents a
// deadline.
type BundleDeadlineState string

const (
	// BundleDeadlineKnown: at least one member of the bundle on the chain can still execute and every such member has a chain deadline.
	BundleDeadlineKnown BundleDeadlineState = "known"
	// BundleDeadlineNotWired: the stack has no mempool or no outcome tree store to read.
	BundleDeadlineNotWired BundleDeadlineState = "not_wired"
	// BundleDeadlineTreeNotHeld: this validator keeps no tree for the bundle on the chain (it never signed or proved it, or it was released).
	BundleDeadlineTreeNotHeld BundleDeadlineState = "tree_not_held"
	// BundleDeadlineTreeUnreadable: the kept tree could not be read or does not rebuild its anchor.
	BundleDeadlineTreeUnreadable BundleDeadlineState = "tree_unreadable"
	// BundleDeadlineReadPanicked: reading the deadline panicked; it was recovered.
	BundleDeadlineReadPanicked BundleDeadlineState = "read_panicked"
	// BundleDeadlineMembersFinished: no member of the bundle can still execute here (each has an outcome, was refused, or is no longer held).
	BundleDeadlineMembersFinished BundleDeadlineState = "members_finished"
	// BundleDeadlineNoMemberDeadline: a member that can still execute has nothing to measure a deadline from, so nothing bounds the bundle.
	BundleDeadlineNoMemberDeadline BundleDeadlineState = "no_member_deadline"
)

// BundleDeadline is the answer of BundleChainDeadline.
type BundleDeadline struct {
	State BundleDeadlineState
	// Earliest and Latest are the smallest and the largest memberChainDeadline over the members that can still execute; both are zero unless
	// State is BundleDeadlineKnown. Latest is the instant after which no member of the bundle can execute any more: the anchor's hop ticks
	// serve every member's settlement, so they are needed until then, not until the first member's deadline.
	Earliest, Latest time.Time
	// Pending counts the members that can still execute and have a deadline, Undated those that can and have none.
	Pending, Undated int
}

// Known reports whether the bundle has a deadline.
func (d BundleDeadline) Known() bool { return d.State == BundleDeadlineKnown }

// BundleChainDeadline is the chain deadline (memberChainDeadline) of the bundle's members on chainID, for the S8 capture's hop tick loop
// (RB12 WP-S8-3c, D-R34-6): which members the bundle has comes from the outcome tree this validator kept for it before it signed or proved it,
// and whether a member can still execute from this validator's own copy in the mempool.
//
// It is read-only and bounded. It writes nothing: the mempool is read in one pass under the mempool's own lock (the lock every pool operation
// takes for the length of a slice walk, never across a chain call or a disk write), and the tree is read through OutcomeTreeStore.Load (one file
// read; the store's lock is held for that read only). It calls out to nothing else, and a panic in it is recovered into
// BundleDeadlineReadPanicked. A member is finished - and no longer counts - when it has an outcome, was refused, or the mempool no longer holds
// it (a mempool forgets a member once it is disposed).
func (s *BatchStack) BundleChainDeadline(chainID int64, bundleID [32]byte) (res BundleDeadline) {
	defer func() {
		if r := recover(); r != nil {
			res = BundleDeadline{State: BundleDeadlineReadPanicked}
		}
	}()
	if s == nil || s.Mempool == nil || s.OutcomeTrees == nil {
		return BundleDeadline{State: BundleDeadlineNotWired}
	}
	tree, err := s.OutcomeTrees.Load(chainID, bundleID)
	switch {
	case errors.Is(err, ErrOutcomeTreeNotHeld):
		return BundleDeadline{State: BundleDeadlineTreeNotHeld}
	case err != nil || tree == nil:
		return BundleDeadline{State: BundleDeadlineTreeUnreadable}
	}
	ops := make([][32]byte, 0, len(tree.Members))
	for _, m := range tree.Members {
		ops = append(ops, [32]byte(m.OperationID))
	}
	views := s.Mempool.memberDeadlineViews(chainID, ops)
	var earliest, latest time.Time
	for _, op := range ops {
		v := views[op]
		switch {
		case !v.pending:
		case !v.hasDeadline:
			res.Undated++
		default:
			res.Pending++
			if earliest.IsZero() || v.deadline.Before(earliest) {
				earliest = v.deadline
			}
			if latest.IsZero() || v.deadline.After(latest) {
				latest = v.deadline
			}
		}
	}
	switch {
	case res.Undated > 0:
		res.State = BundleDeadlineNoMemberDeadline
	case res.Pending == 0:
		res.State = BundleDeadlineMembersFinished
	default:
		res.State, res.Earliest, res.Latest = BundleDeadlineKnown, earliest, latest
	}
	return res
}

// memberDeadlineView is what BundleChainDeadline needs of one pooled member.
type memberDeadlineView struct {
	pending     bool      // held, without an outcome, and not refused: it can still execute
	deadline    time.Time // its memberChainDeadline, when pending
	hasDeadline bool
}

// memberDeadlineViews reads the members holding ops on chainID in one pass under m.mu, in FindMember's order of lanes; an operation that is
// not held is absent from the result.
func (m *BatchMempool) memberDeadlineViews(chainID int64, ops [][32]byte) map[[32]byte]memberDeadlineView {
	want := make(map[[32]byte]bool, len(ops))
	for _, op := range ops {
		want[op] = true
	}
	out := make(map[[32]byte]memberDeadlineView, len(ops))
	note := func(p *PendingBatchIntent, refused bool) {
		if p == nil || !want[p.OperationID] {
			return
		}
		if _, seen := out[p.OperationID]; seen {
			return
		}
		v := memberDeadlineView{pending: !refused && p.pending()}
		if v.pending {
			v.deadline, v.hasDeadline = memberChainDeadline(p)
		}
		out[p.OperationID] = v
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.onDemand[chainID] {
		note(p, false)
	}
	for _, r := range m.refused[chainID] {
		if r != nil {
			note(r.member, true)
		}
	}
	for _, p := range m.pool[chainID] {
		note(p, false)
	}
	return out
}
