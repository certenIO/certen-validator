// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

// SlotsPerPeriod and the timing of a finality update on Sepolia.
const (
	slotsPerEpoch  = 32
	slotsPerPeriod = 8192
	secondsPerSlot = 12
	// pendingETA is the time from inclusion to the finality update that covers a block: 13-19 min measured (spec 8.1); the
	// builder reports the late end and, once past it, one more epoch.
	pendingETA   = 19 * time.Minute
	epochSeconds = slotsPerEpoch * secondsPerSlot * time.Second
)

// Prover builds eth-sepolia/finalized/v1 addenda (finality.Prover). It may do I/O (the LC source, the execution header source),
// takes the first finality update whose finalized execution number covers the leg, assembles the container from the ledger
// anchor <= the final update's signature period, and runs the registered verifier on it before returning.
type Prover struct {
	Source   LCSource
	Exec     HeaderSource
	Pins     *finality.Pins
	Verifier *Verifier
	Now      func() time.Time
	// ExtraLinks supplies the bytes of ledger link files (finality-pins-links/<period>.ssz) by period; the anchor's committee body
	// is read from them when present and from the LC source otherwise. Neither is trusted: the body is hashed against the ledger.
	ExtraLinks map[uint64][]byte
}

var (
	_ finality.Prover    = (*Prover)(nil)
	_ finality.Ceilinged = (*Prover)(nil)
)

// Chain implements finality.Prover.
func (p *Prover) Chain() uint64 { return finality.ChainSepolia }

// Ceiling implements finality.Ceilinged: Sepolia's top level is finalized.
func (p *Prover) Ceiling() finality.Level { return finality.LevelFinalized }

func (p *Prover) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Build implements finality.Prover.
func (p *Prover) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelFinalized {
		if target == finality.LevelL1Posted {
			return nil, nil, finality.NotApplicableState(finality.ChainSepolia, target, finality.ReasonChainIsL1)
		}
		return nil, nil, finality.NewState(finality.CodeEvidenceUnrecognised, "kind", "level:"+target.String(), "version", "")
	}
	if have.Has(finality.LevelFinalized) {
		return nil, nil, finality.NewState(finality.CodeLevelAlreadyPresent, "chain", finality.ChainSepolia, "level", finality.LevelFinalized)
	}
	leg, err := finality.DeriveIncluded(finality.ChainSepolia, s)
	if err != nil {
		return nil, nil, err
	}
	return p.BuildLeg(ctx, leg)
}

func unavailable(err error) *finality.PendingState {
	var se *SourceError
	eps := []string{err.Error()}
	if errors.As(err, &se) {
		eps = eps[:0]
		for _, f := range se.Failures {
			eps = append(eps, f.String())
		}
	}
	return &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: PendingLCUnavailable, Judged: map[string]any{"endpoints": eps}}
}

// candidate is one final update the builder can end a walk with: its finality-update bytes, layout and finalized execution head.
type candidate struct {
	final      []byte
	layout     lcssz.Layout
	finSlot    uint64
	sigSlot    uint64
	execHash   [32]byte
	execNumber uint64
}

func (p *Prover) candidateOf(ctx context.Context, fu []byte) (candidate, error) {
	c := candidate{final: fu, layout: lcssz.LayoutOfFinalityUpdate(fu)}
	var err error
	if _, c.finSlot, c.sigSlot, err = lcssz.FinalityUpdateSlots(c.layout, fu); err != nil {
		return c, err
	}
	hash, num, has, err := lcssz.FinalizedExec(c.layout, fu)
	if err != nil {
		return c, err
	}
	c.execHash, c.execNumber = hash, num
	if !has {
		raw, err := p.Exec.HeaderByHash(ctx, hash)
		if err != nil {
			return c, err
		}
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return c, err
		}
		c.execNumber = h.Number
	}
	return c, nil
}

// BuildLeg builds the evidence for a leg block already derived at level 1.
func (p *Prover) BuildLeg(ctx context.Context, leg finality.BlockRef) (*finality.Addendum, *finality.PendingState, error) {
	if p.Verifier == nil {
		p.Verifier = New()
	}
	e, err := p.Pins.Sepolia()
	if err != nil {
		return nil, nil, err
	}
	lh, err := finality.ReadHeader(leg.HeaderRLP)
	if err != nil {
		return nil, nil, err
	}
	// the latest finality update
	lfBytes, err := p.Source.FinalityUpdate(ctx)
	if err != nil {
		return nil, unavailable(err), nil
	}
	latest, err := p.candidateOf(ctx, lfBytes)
	if err != nil {
		if _, named := finality.AsNamed(err); named {
			return nil, nil, err
		}
		return nil, unavailable(err), nil
	}
	if latest.execNumber < leg.Number {
		pend := &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
			Reason: PendingBlockNotYetCovered, Judged: map[string]any{
				"latest_finalized_exec_number": latest.execNumber, "latest_finalized_slot": latest.finSlot,
			}}
		if head, herr := p.Source.HeadSlot(ctx); herr == nil {
			pend.Judged["observed_head_slot"] = head
		} else {
			pend.Judged["observed_head_slot"] = latest.sigSlot
		}
		eta := time.Unix(int64(lh.Timestamp), 0).Add(pendingETA)
		if now := p.now(); !eta.After(now) {
			eta = now.Add(epochSeconds)
		}
		pend.ETA = eta.UTC()
		return nil, pend, nil
	}
	chosen := latest
	if uint64(e.MaxSpineHeaders) < latest.execNumber-leg.Number+1 {
		// The leg is older than the spine bound allows from the latest update: the objects that still exist for it are the
		// per-period best updates, whose finalized heads sit anywhere in their period (the legacy-leg case, ~2.6 MB).
		chosen, err = p.periodCandidate(ctx, e, leg, lh, latest)
		if err != nil {
			if pend, ok := err.(*pendingErr); ok {
				return nil, pend.p, nil
			}
			return nil, unavailable(err), nil
		}
	}
	return p.assemble(ctx, e, leg, chosen)
}

type pendingErr struct{ p *finality.PendingState }

func (p *pendingErr) Error() string { return p.p.Error() }

// periodCandidate finds, among the best updates of the periods from the leg's own to the latest finality update's, the first
// whose finalized execution head covers the leg.
func (p *Prover) periodCandidate(ctx context.Context, e *finality.EthSepoliaPins, leg finality.BlockRef, lh finality.HeaderFields, latest candidate) (candidate, error) {
	slot := (lh.Timestamp - e.GenesisTime) / secondsPerSlot
	p0 := slot / slotsPerPeriod
	pn := latest.sigSlot / slotsPerPeriod
	if p0 > pn {
		p0 = pn
	}
	ups, err := p.Source.Updates(ctx, p0, int(pn-p0)+1)
	if err != nil {
		return candidate{}, err
	}
	for _, up := range ups {
		l := lcssz.LayoutOfUpdate(up)
		fu, err := lcssz.UpdateToFinalityUpdate(l, up)
		if err != nil {
			return candidate{}, err
		}
		c, err := p.candidateOf(ctx, fu)
		if err != nil {
			return candidate{}, err
		}
		if c.execNumber >= leg.Number && c.execNumber-leg.Number+1 <= uint64(e.MaxSpineHeaders) {
			return c, nil
		}
	}
	return candidate{}, &pendingErr{&finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: PendingHistoryProof, Judged: map[string]any{"block": leg.Number, "latest_finalized_exec_number": latest.execNumber}}}
}

// assemble builds the LC part and the spine for the chosen final update, runs the verifier and wraps the container.
func (p *Prover) assemble(ctx context.Context, e *finality.EthSepoliaPins, leg finality.BlockRef, c candidate) (*finality.Addendum, *finality.PendingState, error) {
	sigPeriod := c.sigSlot / slotsPerPeriod
	anchor, err := e.AnchorFor(sigPeriod)
	if err != nil {
		return nil, &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
			Reason: PendingLedgerIncomplete, Judged: map[string]any{"missing_period": sigPeriod}}, nil
	}
	if sigPeriod-anchor.Period > uint64(e.MaxLinks) {
		return nil, &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
			Reason: PendingLedgerIncomplete, Judged: map[string]any{"missing_period": anchor.Period + uint64(e.MaxLinks) + 1}}, nil
	}
	lc := ethl1.LC{Profile: ethl1.ProfileLC, AnchorPeriod: anchor.Period}
	if err := p.anchorEvidence(ctx, anchor, &lc); err != nil {
		return nil, unavailable(err), nil
	}
	if n := int(sigPeriod - anchor.Period); n > 0 {
		ups, err := p.Source.Updates(ctx, anchor.Period, n)
		if err != nil {
			return nil, unavailable(err), nil
		}
		for _, up := range ups {
			lc.Links = append(lc.Links, ethl1.LB{Layout: ethl1Layout(lcssz.LayoutOfUpdate(up)), SSZ: up})
		}
	}
	lc.FinalUpdate = ethl1.LB{Layout: ethl1Layout(c.layout), SSZ: c.final}

	// the spine h_0 = the finalized execution head ... h_k = the leg block
	h0, err := p.Exec.HeaderByHash(ctx, c.execHash)
	if err != nil {
		return nil, unavailable(err), nil
	}
	spine := [][]byte{h0}
	if c.execNumber > leg.Number {
		lower, err := p.Exec.HeadersByNumber(ctx, leg.Number, c.execNumber-1)
		if err != nil {
			return nil, unavailable(err), nil
		}
		for i := len(lower) - 1; i >= 0; i-- {
			spine = append(spine, lower[i])
		}
	}
	ev, err := BuildContainer(leg, Body{LC: lc, Spine: spine})
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Verifier.Verify(p.Pins, leg, ev); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainSepolia, Kind: Name, Evidence: ev}, nil, nil
}

func ethl1Layout(l lcssz.Layout) ethl1.Layout {
	if l == lcssz.Gloas {
		return ethl1.LayoutGloas
	}
	return ethl1.LayoutElectra
}

// anchorEvidence fills the anchor of lc: a committee_root anchor with the committee body (kind 1). The body is the next
// committee of the update that derived the entry (ExtraLinks, else the LC source), or the bootstrap committee of the root pin;
// it is hashed against the ledger entry here, and the verifier hashes it again.
func (p *Prover) anchorEvidence(ctx context.Context, a finality.AnchorPin, lc *ethl1.LC) error {
	want := a.CommitteeRoot
	lc.AnchorKind = 1
	copy(lc.AnchorRoot[:], mustHex32(want))
	lc.AnchorBody = ethl1.LB{Layout: ethl1.LayoutNone}
	var body []byte
	if raw, ok := p.ExtraLinks[a.Period]; ok {
		var err error
		if a.BlockRoot != "" {
			body, err = lcssz.BootstrapCommittee(lcssz.LayoutOfBootstrap(raw), raw)
		} else {
			body, err = lcssz.NextCommittee(lcssz.LayoutOfUpdate(raw), raw)
		}
		if err != nil {
			return err
		}
	} else if a.BlockRoot != "" {
		var root [32]byte
		copy(root[:], mustHex32(a.BlockRoot))
		boot, err := p.Source.Bootstrap(ctx, root)
		if err != nil {
			return err
		}
		if body, err = lcssz.BootstrapCommittee(lcssz.LayoutOfBootstrap(boot), boot); err != nil {
			return err
		}
	} else {
		ups, err := p.Source.Updates(ctx, a.Period-1, 1)
		if err != nil {
			return err
		}
		if body, err = lcssz.NextCommittee(lcssz.LayoutOfUpdate(ups[0]), ups[0]); err != nil {
			return err
		}
	}
	root, err := ethl1.HashTreeRootSyncCommittee(body)
	if err != nil {
		return err
	}
	if "0x"+hex.EncodeToString(root[:]) != strings.ToLower(want) {
		return &SourceError{Failures: []EndpointFailure{{Op: "anchor", Reason: "the committee served for period " + itoa(a.Period) + " does not hash to the ledger entry"}}}
	}
	lc.AnchorBody.SSZ = append([]byte(nil), body...)
	return nil
}

func mustHex32(h string) []byte {
	b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	return b
}

func itoa(v uint64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	return string(b[i:])
}
