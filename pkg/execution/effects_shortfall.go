// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
)

// =============================================================================
// Settled, but its committed effects are provably absent (RB3-F67)
// =============================================================================
//
// A contract-call leg commits the effects its success is proven by (RB-4 events, RB-5 storage). The
// Phase 7 gate proves them from the settlement's inclusion-proven receipt; a revert of the committed call
// is proven and attested as the failure it is (VerifyRevertedCall). The case in between - the committed
// call EXECUTED (status 1) under the member's leaf, and a committed effect is not there - used to be
// recorded only as a failed proof cycle. It is an outcome the chain proves, and it is attested by quorum
// and written back like any other:
//
//   - the transaction and its receipt are included in their block (RB-2);
//   - it is THIS intent's execution: addressed to the member's account, executing exactly the committed
//     calls, under the intent's operationID, and the account consumed the member's leaf in it
//     (LeafConsumed in the inclusion-proven logs) - so it was authorised, not a stray transaction;
//   - a committed event is absent from the inclusion-proven logs, or a committed slot is proven, against
//     the block's stateRoot, to hold another value.
//
// Anything that cannot be established - a failed read, a state proof that does not verify - is an error,
// never a shortfall: absence is claimed only where the evidence of absence is itself proven.

// effectsShortfallDomain separates a shortfall's result hash from any settlement's or non-settlement's.
const effectsShortfallDomain = "certen:effects-not-proven:v1"

// effectsShortfallResultHash is what a shortfall attestation signs: the observed settlement's own result
// hash, bound to the claim.
func effectsShortfallResultHash(observed [32]byte, c *attestation.EffectsShortfallClaim) [32]byte {
	h := sha256.New()
	h.Write([]byte(effectsShortfallDomain))
	h.Write(observed[:])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(c.ChainID))
	h.Write(b[:])
	for _, s := range []string{c.TxHash, c.Account, c.OperationID, c.Leaf} {
		h.Write([]byte(strings.ToLower(s)))
		h.Write([]byte{0})
	}
	for _, list := range [][]string{c.MissingEvents, c.UnsetState} {
		binary.BigEndian.PutUint64(b[:], uint64(len(list)))
		h.Write(b[:])
		for _, k := range list {
			h.Write([]byte(k))
			h.Write([]byte{0})
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// eventPresent reports whether an inclusion-proven log carries the committed event (same rule as the
// success gate, verifyExpectedEventsStrict).
func eventPresent(logs []LogEntry, exp ExpectedEvent) bool {
	var zero [32]byte
	for _, lg := range logs {
		if len(lg.Topics) == 0 || lg.Address != exp.Contract || lg.Topics[0] != exp.Topic0 {
			continue
		}
		if exp.DataHash != zero && crypto.Keccak256Hash(lg.Data) != common.Hash(exp.DataHash) {
			continue
		}
		return true
	}
	return false
}

// VerifyEffectsNotProven proves that txHash is the member's execution (observeMemberExecution: its
// account, exactly its committed calls, its operationID, its leaf consumed) and that at least one
// committed effect is absent. It returns the claim; an error when any part cannot be established, or
// when every committed effect is in fact present.
func (o *ExternalChainObserver) VerifyEffectsNotProven(
	ctx context.Context,
	txHash common.Hash,
	legs []CommittedLeg,
	opID [32]byte,
	account common.Address,
) (*ExternalChainResult, *attestation.EffectsShortfallClaim, error) {
	result, leaf, err := o.observeMemberExecution(ctx, txHash, legs, opID, account)
	if err != nil {
		return nil, nil, err
	}

	// The shortfall: absent events among the inclusion-proven logs; slots proven to hold another value.
	claim := &attestation.EffectsShortfallClaim{
		ChainID: o.chainID, TxHash: strings.ToLower(txHash.Hex()), Account: strings.ToLower(account.Hex()),
		OperationID: strings.ToLower(common.Hash(opID).Hex()), Leaf: strings.ToLower(common.Hash(leaf).Hex()),
	}
	for li, l := range legs {
		for ei, e := range l.Events {
			if !eventPresent(result.Logs, e) {
				claim.MissingEvents = append(claim.MissingEvents, strconv.Itoa(li)+":"+strconv.Itoa(ei))
			}
		}
		holds, err := o.committedSlotsHold(ctx, result, l.State)
		if err != nil {
			return nil, nil, fmt.Errorf("the absence of a committed slot cannot be claimed: %w", err)
		}
		for si, ok := range holds {
			if !ok {
				claim.UnsetState = append(claim.UnsetState, strconv.Itoa(li)+":"+strconv.Itoa(si))
			}
		}
	}
	sort.Strings(claim.MissingEvents)
	sort.Strings(claim.UnsetState)
	if len(claim.MissingEvents) == 0 && len(claim.UnsetState) == 0 {
		return nil, nil, fmt.Errorf("every committed effect of settlement %s is proven: there is no shortfall", txHash.Hex())
	}
	return result, claim, nil
}

// cycleEffectsProven is what the member's outcome records about its committed effects: false when a
// shortfall was proven, true when the gate proved every committed call, nil when none was committed.
func cycleEffectsProven(cycle *activeCycle) *bool {
	if cycle == nil {
		return nil
	}
	if cycle.EffectsShortfall != nil {
		f := false
		return &f
	}
	// TRUE only for a settlement that executed with every committed effect proven. A member that
	// committed none (a native transfer) and a settlement that reverted assessed no effect: NULL.
	if !cycle.CommittedEffects {
		return nil
	}
	for _, res := range cycle.VerifiedCalls {
		if res != nil && res.Status == 1 {
			t := true
			return &t
		}
	}
	return nil
}
