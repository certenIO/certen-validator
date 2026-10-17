package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// =============================================================================
// Deriving a batch anchor's outcome from the chain (RB5 D4, RB5_CLOSEOUT_PLAN.md §1b)
// =============================================================================
//
// One function states every member's outcome, and the leader and every peer run it: a peer signs an outcome root only
// when this derivation, over its OWN kept tree (outcome_retention.go) and its own reads of the chain, reproduces it.
//
// Every fact comes from the chain, read through independent providers that agree (RB5-F53) and final under the F49
// rule: a block at or below the agreed finalized block, canonical at its height. A member whose state is not final yet
// is ErrOutcomeNotYet - retryable, never a guess. The outcome is written once to the registry, so a leaf states only
// what can no longer change:
//
//	1 EXECUTED                    the member's account executed exactly its committed calls, consumed the member's
//	                              leaf under THIS anchor, and every committed effect is proven present
//	2 EXECUTED_EFFECTS_NOT_PROVEN as 1, with a committed effect proven ABSENT (RB3-F67)
//	3 NOT_SETTLED                 at the first block past the member's deadline (and the finality margin), final, the
//	                              leaf is unconsumed; tx is the last finalized reverted attempt of the member, or zero
//	4 CONSUMED_ELSEWHERE          the leaf was consumed under another anchor (a leaf carries no anchor id)
//
// "Reverted" alone is not final: a leaf stays spendable until its deadline, so a reverted member waits for status 3.

// LeafConsumption is the chain's record of a leaf being spent: the account's LeafConsumed(anchorId, leaf, operationID)
// log, in a transaction whose agreed receipt holds it.
type LeafConsumption struct {
	Anchor    [32]byte
	Tx        common.Hash
	Block     uint64
	BlockHash common.Hash
}

// OutcomeChain is what deriving an outcome reads of one chain. Every fact it returns is agreed by independent
// providers; a fact they do not (yet) agree on is ErrOutcomeNotYet, a failed read a chain read error.
type OutcomeChain interface {
	ChainID() int64
	// FinalizedHeader is the chain's finalized head - the lowest any agreeing provider reports.
	FinalizedHeader(ctx context.Context) (*types.Header, error)
	// HeaderAt is the agreed header at a height.
	HeaderAt(ctx context.Context, number uint64) (*types.Header, error)
	// LeafConsumption is the consumption of leaf on account, searching from the earliest time it could have happened;
	// nil when the leaf is not consumed as of the agreed block asOf.
	LeafConsumption(ctx context.Context, account common.Address, leaf [32]byte, searchFrom time.Time) (c *LeafConsumption, asOf uint64, err error)
	// MemberExecution classifies tx as the member's execution (ExternalChainObserver.ClassifyMemberExecution).
	MemberExecution(ctx context.Context, tx common.Hash, legs []CommittedLeg, opID [32]byte, account common.Address) (*ExternalChainResult, []CommittedEffect, []CommittedEffect, error)
	// RevertedAttempt is tx as a finalized, reverted attempt of the member (ExternalChainObserver.VerifyRevertedCall);
	// ErrNotAnAttempt when the chain shows it is not one.
	RevertedAttempt(ctx context.Context, tx common.Hash, legs []CommittedLeg, opID [32]byte, account common.Address) (*ExternalChainResult, error)
}

// chainTimeAwaiter is an OutcomeChain whose clock can be told that a derivation waits only for a later block.
type chainTimeAwaiter interface {
	AwaitTime(rule string, after uint64)
	AwaitBlock(rule string, number uint64)
}

// ErrNotAnAttempt: a transaction offered as a member's reverted attempt is, by the chain, not one.
var ErrNotAnAttempt = errors.New("not a reverted attempt of the member")

// DerivedOutcome is a batch anchor's outcome as this validator derives it.
type DerivedOutcome struct {
	ChainID  int64
	BundleID [32]byte
	Leaves   []OutcomeLeaf
	Root     [32]byte
	// ResolvedAt is the latest time among the blocks the leaves name: when the chain had decided every member. The
	// recorder's failover rotation is measured from it, so every validator places the outcome at the same point.
	ResolvedAt time.Time
	// Attempts are the reverted attempts considered per member (operation id): every one verified, the last named in
	// its leaf. Carried so a peer that knows another can say so, and the quorum converges on the same set.
	Attempts map[[32]byte][]common.Hash
}

// outcomeNotYet wraps a reason the outcome is not final.
func outcomeNotYet(format string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOutcomeNotYet, fmt.Sprintf(format, a...))
}

// IsOutcomeRetryable reports whether an outcome failure may resolve by waiting: not final, not agreed, or a failed read.
func IsOutcomeRetryable(err error) bool {
	return errors.Is(err, ErrOutcomeNotYet) || IsChainReadError(err) || errors.Is(err, ethrpc.ErrNotYetFinalized) ||
		errors.Is(err, ethrpc.ErrProvidersDisagree) || errors.Is(err, ethrpc.ErrTooFewProviders)
}

// DeriveOutcome states every member of the kept tree t from the chain. attempts are candidate reverted attempts per
// member (operation id) - hints from anywhere: each is verified on the chain before it is named, and one that is not an
// attempt of the member is left out.
func DeriveOutcome(ctx context.Context, c OutcomeChain, t *OutcomeTree, attempts map[[32]byte][]common.Hash) (*DerivedOutcome, error) {
	if c == nil || t == nil {
		return nil, fmt.Errorf("%w: no chain or no tree", ErrOutcome)
	}
	if c.ChainID() != t.ChainID {
		return nil, fmt.Errorf("%w: a chain %d reader for a chain %d tree", ErrOutcome, c.ChainID(), t.ChainID)
	}
	if err := t.Verify(); err != nil {
		return nil, err
	}
	fin, err := c.FinalizedHeader(ctx)
	if err != nil {
		return nil, notYetIfUnsettled(fmt.Errorf("the finalized block of chain %d: %w", t.ChainID, err))
	}
	out := &DerivedOutcome{ChainID: t.ChainID, BundleID: t.BundleID, Attempts: map[[32]byte][]common.Hash{}}
	for _, m := range t.Members {
		leaf, at, tried, err := deriveMember(ctx, c, t, m, fin, attempts[m.OperationID])
		if err != nil {
			return nil, fmt.Errorf("chain %d anchor 0x%x member %d (operation %x): %w", t.ChainID, t.BundleID[:8], m.LeafIndex,
				m.OperationID[:8], err)
		}
		out.Leaves = append(out.Leaves, leaf)
		if at.After(out.ResolvedAt) {
			out.ResolvedAt = at
		}
		if len(tried) > 0 {
			out.Attempts[m.OperationID] = tried
		}
	}
	root, err := OutcomeRoot(out.Leaves, uint64(len(t.Members)))
	if err != nil {
		return nil, err
	}
	out.Root = root
	return out, nil
}

// notYetIfUnsettled marks a disagreement or a shortage of providers as not final yet.
func notYetIfUnsettled(err error) error {
	if errors.Is(err, ethrpc.ErrProvidersDisagree) || errors.Is(err, ethrpc.ErrTooFewProviders) || errors.Is(err, ethrpc.ErrNotYetFinalized) {
		return fmt.Errorf("%w: %v", ErrOutcomeNotYet, err)
	}
	return err
}

func deriveMember(ctx context.Context, c OutcomeChain, t *OutcomeTree, m OutcomeTreeMember, fin *types.Header,
	candidates []common.Hash) (OutcomeLeaf, time.Time, []common.Hash, error) {
	var none OutcomeLeaf
	leaf := OutcomeLeaf{ChainID: t.ChainID, BundleID: t.BundleID, LeafIndex: m.LeafIndex, BatchLeaf: m.Leaf, OperationID: m.OperationID}
	legs := m.CommittedLegs()

	cons, asOf, err := c.LeafConsumption(ctx, m.Account, m.Leaf, time.Unix(m.SearchFrom, 0))
	if err != nil {
		return none, time.Time{}, nil, notYetIfUnsettled(err)
	}
	if cons != nil {
		// The consumption is final once its block is at or below the finalized block and is the canonical block at its
		// height there - otherwise its transaction may yet be re-mined elsewhere, or not at all.
		if cons.Block > fin.Number.Uint64() {
			return none, time.Time{}, nil, outcomeNotYet("its leaf was consumed in block %d, not final (finalized %d)", cons.Block, fin.Number.Uint64())
		}
		hdr, err := c.HeaderAt(ctx, cons.Block)
		if err != nil {
			return none, time.Time{}, nil, notYetIfUnsettled(err)
		}
		if hdr.Hash() != cons.BlockHash {
			return none, time.Time{}, nil, outcomeNotYet("its consumption %s names block %s, the finalized block at %d is %s",
				cons.Tx.Hex(), cons.BlockHash.Hex(), cons.Block, hdr.Hash().Hex())
		}
		leaf.Tx, leaf.BlockNumber, leaf.BlockHash, leaf.ReceiptsRoot = cons.Tx, cons.Block, cons.BlockHash, hdr.ReceiptHash
		if cons.Anchor != t.BundleID {
			leaf.Status = OutcomeConsumedElsewhere
			return leaf, time.Unix(int64(hdr.Time), 0).UTC(), nil, nil
		}
		res, missing, unset, err := c.MemberExecution(ctx, cons.Tx, legs, m.OperationID, m.Account)
		if err != nil {
			return none, time.Time{}, nil, notYetIfUnsettled(fmt.Errorf("its leaf was consumed under this anchor by %s, which is "+
				"not established as its execution: %w", cons.Tx.Hex(), err))
		}
		if res.BlockHash != cons.BlockHash || res.BlockNumber == nil || res.BlockNumber.Uint64() != cons.Block {
			return none, time.Time{}, nil, outcomeNotYet("its execution %s was observed in block %s, its consumption in %s",
				cons.Tx.Hex(), res.BlockHash.Hex(), cons.BlockHash.Hex())
		}
		committed := CommittedEffectsHash(legEvents(legs), legState(legs))
		if len(missing) == 0 && len(unset) == 0 {
			leaf.Status, leaf.EffectsHash = OutcomeExecuted, committed
		} else {
			sh, err := ShortfallEffectsHash(committed, missing, unset)
			if err != nil {
				return none, time.Time{}, nil, err
			}
			leaf.Status, leaf.EffectsHash = OutcomeEffectsNotProven, sh
		}
		return leaf, time.Unix(int64(hdr.Time), 0).UTC(), nil, nil
	}

	// Unconsumed as of asOf. It is the member's outcome only past its deadline: a settlement may still execute until
	// then, and nonSettlementFinality after it lets a settlement broadcast before the deadline be mined or revert.
	horizon := uint64(m.Deadline) + uint64(nonSettlementFinality/time.Second)
	if fin.Time <= horizon {
		// Waiting only for a finalized block past the horizon: on a chain whose blocks stop when idle the clock's
		// heartbeat makes one (RB7 T-9). The FIRST block past it is the claim, whoever's transaction made it.
		if a, ok := c.(chainTimeAwaiter); ok {
			a.AwaitTime(fmt.Sprintf("the outcome of operation %x", m.OperationID[:8]), horizon)
		}
		return none, time.Time{}, nil, outcomeNotYet("its leaf is unconsumed and the finalized chain (time %d) is not past its "+
			"deadline %d with the finality margin", fin.Time, m.Deadline)
	}
	// The claim block is the FIRST block past that horizon: one block every validator finds, so every validator's leaf
	// names the same block.
	before, err := searchBlockAtOrBefore(fin.Number.Uint64(), fin.Time, horizon, func(n uint64) (uint64, error) {
		h, err := c.HeaderAt(ctx, n)
		if err != nil {
			return 0, err
		}
		return h.Time, nil
	})
	if err != nil {
		return none, time.Time{}, nil, notYetIfUnsettled(err)
	}
	claim, err := c.HeaderAt(ctx, before+1)
	if err != nil {
		return none, time.Time{}, nil, notYetIfUnsettled(err)
	}
	if claim.Time <= horizon || claim.Number.Uint64() > fin.Number.Uint64() {
		return none, time.Time{}, nil, fmt.Errorf("%w: the block after %d (time %d) is not past the horizon %d within the finalized chain",
			ErrOutcome, before, claim.Time, horizon)
	}
	if asOf < claim.Number.Uint64() {
		// The leaf is read unconsumed at an agreed block ethrpc.RecentStateDepthFor(chain) below the head: the claim block is
		// covered once the head is that far past it. On a chain whose blocks stop when idle only transactions make
		// those blocks: the clock's heartbeat is told (RB7 T-9).
		if a, ok := c.(chainTimeAwaiter); ok {
			a.AwaitBlock(fmt.Sprintf("the outcome of operation %x", m.OperationID[:8]), claim.Number.Uint64()+ethrpc.RecentStateDepthFor(t.ChainID))
		}
		return none, time.Time{}, nil, outcomeNotYet("its leaf is known unconsumed only as of block %d, before the claim block %d",
			asOf, claim.Number.Uint64())
	}
	leaf.Status, leaf.BlockNumber, leaf.BlockHash, leaf.ReceiptsRoot = OutcomeNotSettled, claim.Number.Uint64(), claim.Hash(), claim.ReceiptHash

	// The last finalized reverted attempt of the member, among every candidate offered: each verified on the chain.
	tried := uniqueHashes(candidates)
	var last *ExternalChainResult
	for _, tx := range tried {
		res, err := c.RevertedAttempt(ctx, tx, legs, m.OperationID, m.Account)
		switch {
		case errors.Is(err, ErrNotAnAttempt):
			continue
		case err != nil:
			return none, time.Time{}, nil, notYetIfUnsettled(fmt.Errorf("reverted attempt %s: %w", tx.Hex(), err))
		}
		if last == nil || laterResult(res, last) {
			last = res
		}
	}
	if last != nil {
		leaf.Tx = last.TxHash
	}
	return leaf, time.Unix(int64(claim.Time), 0).UTC(), tried, nil
}

// laterResult reports whether a is mined after b.
func laterResult(a, b *ExternalChainResult) bool {
	an, bn := a.BlockNumber.Uint64(), b.BlockNumber.Uint64()
	if an != bn {
		return an > bn
	}
	return a.TxIndex > b.TxIndex
}

func uniqueHashes(in []common.Hash) []common.Hash {
	seen := map[common.Hash]bool{}
	var out []common.Hash
	for _, h := range in {
		if h != (common.Hash{}) && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

func legEvents(legs []CommittedLeg) [][]ExpectedEvent {
	out := make([][]ExpectedEvent, len(legs))
	for i, l := range legs {
		out[i] = l.Events
	}
	return out
}

func legState(legs []CommittedLeg) [][]ExpectedStateSlot {
	out := make([][]ExpectedStateSlot, len(legs))
	for i, l := range legs {
		out[i] = l.State
	}
	return out
}
