// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// Sequential execution across chains
// =============================================================================
//
// An intent whose legs span chains and declare execution_mode "sequential" is one member per chain,
// in the order its legs declare. The first member settles like any other. Every later member - a
// successor - carries its predecessor (After), and is settled only once the predecessor's outcome is
// a chain fact every validator can read for itself (RB3-F52):
//
//   - the predecessor's leaf is consumed at a finalized block: it settled, and the successor is ready;
//   - the finalized chain is past the predecessor's deadline (with the non-settlement finality margin)
//     and the leaf is not consumed: it did not settle. The intent's rollback policy decides - with
//     continue_on_failure the successor is ready; otherwise it is stopped, never executed, and its
//     failure is recorded and attested like any member that did not settle (RB3-F49);
//   - neither yet: the successor waits.
//
// The leader and every co-signing peer apply the same rule, each from its OWN copy of the successor
// and its OWN chain reads, so a successor's anchor is co-signed only by validators that see its
// predecessor settled. A successor settles in the intent-keyed lane: a one-member anchor makes
// readiness a question about one member, with no member set for validators to disagree on.

// MemberPredecessor is the member an intent's declared order places immediately before this one, on
// another chain: what readiness is read from. Every field is derived from the signed intent and the
// predecessor member, so every validator holds the same one.
type MemberPredecessor struct {
	ChainID     int64
	OperationID [32]byte
	Account     common.Address
	Leaf        [32]byte
	Deadline    time.Time
	// ContinueOnFailure: the intent's rollback policy is continue_on_failure, so a predecessor that did
	// not settle does not stop this member.
	ContinueOnFailure bool
}

// sequenceState is where a successor stands against its predecessor.
type sequenceState int

const (
	sequenceWaiting sequenceState = iota
	sequenceReady
	sequenceStopped
)

// sequenceReadiness decides a member's readiness against its predecessor, at the predecessor chain's
// latest finalized block. A member with no predecessor is ready. A failed read is a chain read error
// (IsChainReadError): it decides nothing.
func sequenceReadiness(ctx context.Context, rd NonSettlementChain, m *PendingBatchIntent) (sequenceState, string, error) {
	if m == nil || m.After == nil {
		return sequenceReady, "", nil
	}
	a := m.After
	if rd == nil {
		return sequenceWaiting, "", readErr(fmt.Errorf("no chain reader to read the predecessor on chain %d", a.ChainID))
	}
	head, err := rd.FinalizedHeader(ctx, a.ChainID)
	if err != nil {
		return sequenceWaiting, "", readErr(fmt.Errorf("reading the finalized block of chain %d: %w", a.ChainID, err))
	}
	consumed, err := rd.LeafConsumedAt(ctx, a.ChainID, a.Account, a.Leaf, head.Number.Uint64())
	if err != nil {
		return sequenceWaiting, "", readErr(fmt.Errorf("reading the predecessor's leaf at block %d of chain %d: %w",
			head.Number.Uint64(), a.ChainID, err))
	}
	if consumed {
		return sequenceReady, "", nil
	}
	at := time.Unix(int64(head.Time), 0).UTC()
	if at.After(a.Deadline.Add(nonSettlementFinality)) {
		if a.ContinueOnFailure {
			return sequenceReady, "", nil
		}
		return sequenceStopped, fmt.Sprintf("its predecessor on chain %d did not settle by its deadline %s, and the intent "+
			"does not continue on failure", a.ChainID, a.Deadline.Format(time.RFC3339)), nil
	}
	if d, ok := m.Deadline(); ok && at.After(d) {
		return sequenceStopped, fmt.Sprintf("its deadline %s passed before its predecessor on chain %d settled",
			d.Format(time.RFC3339), a.ChainID), nil
	}
	return sequenceWaiting, "", nil
}

// settlementHorizon is how long after its commit time CERTEN will keep trying to settle the member.
// Each position in a sequence adds one horizon: a successor cannot start before its predecessor
// settles and is finalized, so a fixed horizon from the commit would expire later members by
// construction.
func (p *PendingBatchIntent) settlementHorizon() time.Duration {
	pos := 0
	if p != nil && p.SequencePosition > 0 {
		pos = p.SequencePosition
	}
	return time.Duration(pos+1) * maxGasDeferral
}
