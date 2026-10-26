// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// CapturedLeg is what the runtime holds when the settlement station of a leg has finished: the two station results (captured or Stated),
// the settlement transaction, and the source the attestation part is read through. It is handed to Deps.OnLeg exactly once per finished
// settle job, after the settle row is stored.
type CapturedLeg struct {
	Chain    uint64
	AnchorID common.Hash
	Tx       common.Hash
	Attest   *AttestResult // nil: no attestation capture was found for the anchor
	Settle   *SettleResult
	Source   AttestSource
}

// reasonAttestOutOfReach and reasonAttestUnavailable are Stated reasons of the attestation part (the vocabulary of V2_SPEC_S8 Q2).
const (
	reasonAttestOutOfReach  = "attest_block_out_of_reach"
	reasonAttestUnavailable = "attest_block_state_unavailable"
)

func statedAt(b ci.BlockRef, reason, detail string) *ci.Stated {
	return &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: b.Number, JudgedHash: b.Hash, Detail: detail}
}

// AssembleParts builds the Parts of a finished leg from the runtime's own results, the stored hop chain and the source: the same
// pieces the world tests assemble by hand (DeriveFacts + the attestation's operation id and index; ChooseLink or the stored hop chain;
// BuildAttestPartHops). Nothing here is a fallback: every part that cannot be captured is a Stated part naming why and where it was
// judged.
//
//   - A Stated settle part (the station could not capture) carries a Stated attest part: the container then states both, and the verifier
//     reports contract_identity_unproven. The attestation capture, if it exists, is not attached to a leg whose settle part is not evidence.
//   - A captured settle part with no captured attestation states the attest part with the attestation's own Stated reason, or
//     attest_block_state_unavailable when there is none.
//   - A leg beyond the window with no hop chain is attest_block_out_of_reach; a failing read of the attestation block's proofs is
//     attest_block_state_unavailable with the bounded error text as its detail.
func AssembleParts(ctx context.Context, st Store, m *ci.Manifest, l CapturedLeg) (Parts, error) {
	if l.Settle == nil {
		return Parts{}, errors.New("capture: a leg needs its settle result")
	}
	set := l.Settle
	parts := Parts{Chain: l.Chain, Leg: set.Block, Settle: set}
	if set.Stated != nil {
		parts.Attest = &AttestPart{Stated: statedAt(set.Block, reasonAttestUnavailable, "the settle part is stated")}
		return parts, nil
	}
	if set.Facts == nil {
		return Parts{}, errors.New("capture: the captured settle result carries no facts")
	}
	base := *set.Facts
	parts.Facts = &base // a captured settle part needs the plan facts whatever the attest part is
	if l.Attest == nil || l.Attest.Stated != nil {
		stated := statedAt(set.Block, reasonAttestUnavailable, "the attestation station holds no capture for the anchor")
		if l.Attest != nil && l.Attest.Stated != nil {
			stated = l.Attest.Stated
		}
		parts.Attest = &AttestPart{Stated: stated}
		return parts, nil
	}
	att := l.Attest
	facts := base
	facts.OperationID, facts.TxIndex = att.OperationID, att.TxIndex
	parts.Facts = &facts
	plan, hc, err := PlanLink(ctx, st, m, l.Chain, l.AnchorID, att.Block, set.Block.Number)
	if err != nil {
		var oor *OutOfReachError
		if errors.As(err, &oor) {
			parts.Attest = &AttestPart{Stated: statedAt(att.Block, reasonAttestOutOfReach, "")}
			return parts, nil
		}
		return Parts{}, fmt.Errorf("capture: the link of the leg cannot be planned: %w", err)
	}
	header, err := l.Source.HeaderByHash(ctx, set.Block.Hash)
	if err != nil || header == nil {
		parts.Attest = &AttestPart{Stated: statedAt(att.Block, reasonAttestUnavailable, "the settlement header is not served")}
		return parts, nil
	}
	part, err := BuildAttestPartHops(ctx, l.Source, att, header, plan, hc)
	if err != nil {
		parts.Attest = &AttestPart{Stated: statedAt(att.Block, reasonAttestUnavailable, ethproof.BoundProviderText(err.Error()))}
		return parts, nil
	}
	parts.Attest = part
	return parts, nil
}
