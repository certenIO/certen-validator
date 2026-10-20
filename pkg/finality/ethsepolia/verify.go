// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Verifier is the eth-sepolia/finalized/v1 Kind. It is pure: the pins, the leg block and the evidence are its only inputs.
type Verifier struct {
	// Lim overrides the generic bounds (finality.DefaultLimits when nil); the chain-specific ones (max_links,
	// max_spine_headers) always come from the pins.
	Lim *finality.Limits
}

// New returns the production verifier.
func New() *Verifier { return &Verifier{} }

var _ finality.Kind = (*Verifier)(nil)

// Name, Chain and Level implement finality.Kind.
func (v *Verifier) Name() string          { return Name }
func (v *Verifier) Chain() uint64         { return finality.ChainSepolia }
func (v *Verifier) Level() finality.Level { return finality.LevelFinalized }

// Register adds the kind to reg. It is explicit: there is no init(), and wiring into finality.Default is the integration
// package's job.
func Register(reg *finality.Registry) error { return reg.RegisterKind(New()) }

func (v *Verifier) limits() finality.Limits {
	if v.Lim != nil {
		return *v.Lim
	}
	return finality.DefaultLimits()
}

// Verify is spec 5.3, step by step. The result fields are those of 5.3 step 4.
func (v *Verifier) Verify(p *finality.Pins, leg finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	e, err := p.Sepolia()
	if err != nil {
		return finality.Verdict{}, err
	}
	l1 := e.L1Pins(e.Anchors)
	lim := v.limits()
	c, err := finality.DecodeContainer(evidence, lim)
	if err != nil {
		return finality.Verdict{}, err
	}
	// 5.3 step 1 [PIN]: chain 11155111, level 3, this kind, and the leg's own block.
	h := c.Header
	if h.Kind != Name {
		return finality.Verdict{}, finality.Malformed("header.kind", finality.ReasonDiffersFromAddendum, 0, 0)
	}
	if h.Chain != finality.ChainSepolia {
		return finality.Verdict{}, finality.BlockMismatch("chain", uint64(finality.ChainSepolia), h.Chain)
	}
	if h.Level != finality.LevelFinalized {
		return finality.Verdict{}, finality.Malformed("header.level", finality.ReasonLevelNotFinalized, int(h.Level), int(finality.LevelFinalized))
	}
	if leg.Chain != finality.ChainSepolia {
		return finality.Verdict{}, finality.BlockMismatch("chain", uint64(finality.ChainSepolia), leg.Chain)
	}
	if h.BlockNumber != leg.Number {
		return finality.Verdict{}, finality.BlockMismatch("blockNumber", leg.Number, h.BlockNumber)
	}
	if h.BlockHash != leg.Hash {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", leg.Hash, h.BlockHash)
	}
	body, err := DecodeBody(c.Body, lim, l1.MaxLinks, l1.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, err
	}
	// every spine header is read positionally by the framework first, so a header that cannot be read is a malformed part with
	// its index, never a header-chain reason outside the registry's set.
	for i, raw := range body.Spine {
		if _, err := finality.ReadHeader(raw); err != nil {
			return finality.Verdict{}, indexed(err, i)
		}
	}
	// 5.3 step 2 [L1]
	head, err := ethl1.VerifyFinalizedHead(l1, body.LC)
	if err != nil {
		return finality.Verdict{}, stateOf(err)
	}
	// 5.3 step 3 [C]: Covers(spine) returns the leg's block.
	covered, err := head.Covers(body.Spine, l1.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, stateOf(err)
	}
	at, err := ethl1.BlockAt(covered, leg.Number)
	if err != nil {
		return finality.Verdict{}, stateOf(err)
	}
	if at.Hash != leg.Hash {
		return finality.Verdict{}, finality.BlockMismatch("hash", leg.Hash, at.Hash)
	}
	if at.Number != leg.Number {
		return finality.Verdict{}, finality.BlockMismatch("number", leg.Number, at.Number)
	}
	// h_k is the leg block itself: the spine ends there (section 0), and its last element is byte-identical to Settlement.Header.
	if last := len(body.Spine) - 1; covered[last].Number != leg.Number {
		return finality.Verdict{}, finality.Malformed("spine", finality.ReasonSpineNotEndingAtBlock, len(body.Spine), int(covered[0].Number-leg.Number)+1)
	}
	if leg.HeaderRLP != nil && !bytes.Equal(body.Spine[len(body.Spine)-1], leg.HeaderRLP) {
		return finality.Verdict{}, finality.BlockMismatch("header", crypto.Keccak256Hash(leg.HeaderRLP), covered[len(covered)-1].Hash)
	}
	return finality.Verdict{Level: finality.LevelFinalized, Kind: Name, Fields: map[string]any{
		"finalized_slot":        head.Slot,
		"finalized_exec_number": covered[0].Number,
		"participants":          uint64(head.Participants),
		"periods_crossed":       head.PeriodsCrossed,
		"headers_walked":        uint64(len(body.Spine)),
		"anchor_period":         body.LC.AnchorPeriod,
	}}, nil
}

// indexed adds the spine index to a framework malformed state.
func indexed(err error, i int) error {
	if s, ok := finality.AsNamed(err); ok {
		out := finality.NewState(s.Code)
		for k, v := range s.Fields {
			out.Fields[k] = v
		}
		out.Fields["part"] = "spine"
		out.Fields["index"] = uint64(i)
		return out
	}
	return err
}
