// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// GameInfo is one DisputeGameFactory list entry.
type GameInfo struct {
	Type      uint32
	CreatedAt uint64
	Proxy     [20]byte
}

// GameSource is the builder's view of the factory and of games at the L1 head. Nothing it returns is evidence: it only decides
// which game to capture and what to tell the operator; the captured proofs are verified under the finalized L1 state.
type GameSource interface {
	GameCount(ctx context.Context) (uint64, error)
	GameAt(ctx context.Context, index uint64) (GameInfo, error)
	Code(ctx context.Context, proxy [20]byte) ([]byte, error)
	Slot(ctx context.Context, proxy [20]byte, slot [32]byte) ([32]byte, error)
}

// L1Source adds the L1 headers by hash (not windowed) to the near-head proof source.
type L1Source interface {
	ProofSource
	L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error)
}

// L2Source serves Base Sepolia headers (not windowed).
type L2Source interface {
	L2HeaderByNumber(ctx context.Context, n uint64) (HeaderInfo, error)
}

// LCSource serves the L1 light-client evidence of the current finalized head and the beacon head slot it observed.
type LCSource interface {
	Finalized(ctx context.Context) (lc ethl1.LC, observedHeadSlot uint64, err error)
}

// Builder is the finality.Prover of Base Sepolia level 3 (V2_SPEC_S7 2.8): capture near the L1 head, attest once the finalized
// head covers A, and return only evidence its own Kind has verified.
type Builder struct {
	Pins      *finality.Pins
	Store     CaptureStore
	Games     GameSource
	L1        L1Source
	L2        L2Source
	LC        LCSource
	Now       func() time.Time
	Back      uint64   // capture this many blocks behind the proof provider head (default 12)
	Providers []string // names carried by the provider-window states
	MaxScan   int      // bound of the factory scan (default 64)
}

func (b *Builder) Chain() uint64 { return uint64(Chain) }

// Ceiling is the highest level this prover can return: finalized (the l1_posted prover is the sibling package's).
func (b *Builder) Ceiling() finality.Level { return finality.LevelFinalized }

// RegisterProver adds a Builder to a registry.
func RegisterProver(reg *finality.Registry, b *Builder) error { return reg.RegisterProver(b) }

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func reached(have finality.LevelSet) finality.Level {
	if have.Has(finality.LevelL1Posted) {
		return finality.LevelL1Posted
	}
	return finality.LevelIncluded
}

func (b *Builder) pending(have finality.LevelSet, reason string, eta time.Time, kv ...any) *finality.PendingState {
	p := &finality.PendingState{Chain: uint64(Chain), LevelReached: reached(have), NextLevel: finality.LevelFinalized, Reason: reason, ETA: eta, Judged: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		p.Judged[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return p
}

func redactState(code string, err error, kv ...any) *finality.StateError {
	return finality.NewState(code, append(kv, "cause", ethrpc.RedactText(err.Error()))...)
}

// gameFacts are the values decoded from a game proxy's code (spec 5.5 O3), used to choose the output-root anchor.
type gameFacts struct {
	Index    uint64
	Info     GameInfo
	Code     []byte
	Row      ImplRow
	Start    uint64
	L2Seq    uint64
	Interval uint64
}

func (b *Builder) facts(p *Pins, info GameInfo, code []byte, start uint64Reader) (gameFacts, error) {
	lay := p.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	f := gameFacts{Info: info, Code: code}
	if len(code) < tl+2+lay.ArgsBaseLen {
		return f, st(CodeGameUnrecognised, "reason", ReasonArgsLen)
	}
	var impl [20]byte
	copy(impl[:], code[len(lay.CloneHead)+2+len(lay.CloneMid):])
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Impl == impl && r.Complete(p.Layouts) {
			f.Row = r
		}
	}
	if f.Row.Role == "" {
		return f, st(CodeContractIdentity, "role", RoleGameImpl, "address", impl, "code_hash", [32]byte{}, "judged_at", uint64(0))
	}
	f.L2Seq = binary.BigEndian.Uint64(code[tl+84+24 : tl+84+32])
	s, err := start(info.Proxy)
	if err != nil {
		return f, err
	}
	f.Start = s
	total := f.L2Seq - f.Start
	for _, pr := range f.Row.IntervalPairs {
		if pr[0] == total {
			f.Interval = pr[1]
		}
	}
	if f.Interval == 0 {
		return f, st(CodeGameUnrecognised, "reason", ReasonIntervalPair, "total", total, "n", uint64(f.Row.NIntermediate))
	}
	return f, nil
}

type uint64Reader func(proxy [20]byte) (uint64, error)

// Build implements finality.Prover for level 3 of Base Sepolia.
func (b *Builder) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelFinalized {
		return nil, nil, nil // l1_posted is the sibling prover's level
	}
	leg, err := finality.DeriveIncluded(uint64(Chain), s)
	if err != nil {
		return nil, nil, err
	}
	return b.build(ctx, leg, have)
}

// build is Build for a leg block that level 1 has already derived.
func (b *Builder) build(ctx context.Context, leg finality.BlockRef, have finality.LevelSet) (*finality.Addendum, *finality.PendingState, error) {
	bp, err := ParsePins(b.Pins)
	if err != nil {
		return nil, nil, err
	}
	startOf := func(proxy [20]byte) (uint64, error) {
		w, err := b.Games.Slot(ctx, proxy, be32(slotGameStartL2Seq))
		if err != nil {
			return 0, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
		}
		return binary.BigEndian.Uint64(w[24:]), nil
	}
	g, pend, err := b.covering(ctx, bp, leg.Number, startOf, have)
	if err != nil || pend != nil {
		return nil, pend, err
	}
	// the live view of the game decides between "wait" and "capture"
	w0, err := b.Games.Slot(ctx, g.Info.Proxy, be32(slotGameMain))
	if err != nil {
		return nil, nil, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
	}
	created, resolved, status := u64Of(w0, 0), u64Of(w0, 8), w0[15]
	switch status {
	case StatusInProgress:
		return nil, b.unresolved(ctx, g, created, have), nil
	case StatusChallengerWins:
		return nil, nil, st(CodeGameChallengerWins)
	}
	// the output-root anchor: the nearest intermediate root at or above the leg
	k := uint32((leg.Number - g.Start + g.Interval - 1) / g.Interval)
	outBlock := g.Start + g.Interval*uint64(k)
	l2, err := b.l2Headers(ctx, outBlock, leg.Number)
	if err != nil {
		return nil, nil, err
	}
	rows, err := b.Store.Rows(ctx, uint64(Chain), ItemGame(g.Info.Proxy))
	if err != nil {
		return nil, nil, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
	}
	for _, row := range rows {
		c, err := DecodeGameCapture(row.Data)
		if err != nil {
			continue
		}
		body := Body{StateBlock: c.L1Block, GameProxy: c.Game, GameCode: c.GameCode, OutputRootIndex: k, L2Spine: l2, Nodes: c.Nodes}
		ah, err := b.L1.L1HeaderByHash(ctx, c.L1Hash)
		if err != nil {
			continue // the capture's block is not (or no longer) a block of the canonical chain: it is not used
		}
		a := ethl1.L1Block{Hash: ah.Hash, Number: ah.Number, StateRoot: ah.StateRoot, Timestamp: ah.Timestamp}
		if _, jerr := Judge(bp, a, body, leg, ethl1.FinalizedHead{}); jerr != nil {
			if n, ok := finality.AsNamed(jerr); ok && (n.Code == CodeGameNotResolved || n.Code == CodeGameWithinDelay) {
				if n.Code == CodeGameWithinDelay {
					delay, _ := n.Fields["delay"].(uint64)
					return nil, b.pending(have, "within_finality_delay", time.Unix(int64(resolved+delay), 0)), nil
				}
				continue // captured before the game resolved: stale, recapture below
			}
			return nil, nil, jerr
		}
		return b.attest(ctx, bp, leg, body, ah, have)
	}
	// nothing usable captured: capture now, near the head, and wait for A to be final
	c, err := CaptureGame(ctx, b.L1, b.Store, bp, g.Info.Proxy, b.back())
	if err != nil {
		return nil, b.pending(have, "l1_proof_window_unavailable", time.Time{}, "l1_block", uint64(0), "providers", b.Providers), nil
	}
	eta := b.now().Add(19 * time.Minute)
	return nil, b.pending(have, "block_not_yet_covered", eta, "latest_finalized_exec_number", uint64(0), "latest_finalized_slot", uint64(0), "observed_head_slot", uint64(0), "captured_l1_block", c.L1Block), nil
}

func (b *Builder) back() uint64 {
	if b.Back == 0 {
		return 12
	}
	return b.Back
}

func (b *Builder) l2Headers(ctx context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; ; n-- {
		h, err := b.L2.L2HeaderByNumber(ctx, n)
		if err != nil {
			return nil, redactState("l2_header_unavailable", err, "block", n)
		}
		out = append(out, h.Raw)
		if n == to {
			return out, nil
		}
	}
}

// covering scans the factory for the game whose range (start, l2seq] holds the leg block.
func (b *Builder) covering(ctx context.Context, bp *Pins, leg uint64, startOf uint64Reader, have finality.LevelSet) (gameFacts, *finality.PendingState, error) {
	maxScan := b.MaxScan
	if maxScan == 0 {
		maxScan = 64
	}
	count, err := b.Games.GameCount(ctx)
	if err != nil || count == 0 {
		if err == nil {
			err = fmt.Errorf("the factory lists no game")
		}
		return gameFacts{}, nil, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
	}
	load := func(i uint64) (gameFacts, error) {
		info, err := b.Games.GameAt(ctx, i)
		if err != nil {
			return gameFacts{}, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
		}
		code, err := b.Games.Code(ctx, info.Proxy)
		if err != nil {
			return gameFacts{}, redactState(finality.CodeVerifierFailed, err, "chain", uint64(Chain), "kind", KindName)
		}
		f, err := b.facts(bp, info, code, startOf)
		f.Index = i
		return f, err
	}
	newest, err := load(count - 1)
	if err != nil {
		return gameFacts{}, nil, err
	}
	if leg > newest.L2Seq {
		return gameFacts{}, b.pending(have, "no_covering_game", time.Time{}, "leg_block", leg, "newest_l2_sequence_number", newest.L2Seq), nil
	}
	// games are 600 blocks apart and ordered: estimate, then walk
	idx := count - 1
	if d := (newest.L2Seq - leg) / (newest.L2Seq - newest.Start); d < idx {
		idx -= d
	}
	for step := 0; step < maxScan; step++ {
		f, err := load(idx)
		if err != nil {
			return gameFacts{}, nil, err
		}
		switch {
		case leg > f.L2Seq:
			if idx+1 >= count {
				return gameFacts{}, b.pending(have, "no_covering_game", time.Time{}, "leg_block", leg, "newest_l2_sequence_number", f.L2Seq), nil
			}
			idx++
		case leg <= f.Start:
			if idx == 0 {
				return gameFacts{}, b.pending(have, "no_covering_game", time.Time{}, "leg_block", leg, "newest_l2_sequence_number", f.L2Seq), nil
			}
			idx--
		default:
			return f, nil, nil
		}
	}
	return gameFacts{}, nil, st(finality.CodeVerifierFailed, "chain", uint64(Chain), "kind", KindName, "cause", "the factory scan did not reach the covering game within its bound")
}

// unresolved is the pending state of a game still IN_PROGRESS: the upper bound of its resolution time and what the proofs on it
// are (expectedResolution can only decrease with a second proof or increase when a proof is nullified).
func (b *Builder) unresolved(ctx context.Context, g gameFacts, created uint64, have finality.LevelSet) *finality.PendingState {
	var exp, proofs uint64
	if w, err := b.Games.Slot(ctx, g.Info.Proxy, be32(slotGameExpectedRes)); err == nil {
		exp, proofs = u64Of(w, 0), u64Of(w, 8)
	}
	var gs GameState
	if w, err := b.Games.Slot(ctx, g.Info.Proxy, mapSlot(be32(0), mapGameProver)); err == nil {
		gs.TEEProver = w
	}
	if w, err := b.Games.Slot(ctx, g.Info.Proxy, mapSlot(be32(1), mapGameProver)); err == nil {
		gs.ZKProver = w
	}
	parent := "unknown"
	lay := b.pinsLayout()
	if lay.ArgsBaseLen > 0 {
		tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
		var pa [20]byte
		copy(pa[:], g.Code[tl+116:tl+136])
		if w, err := b.Games.Slot(ctx, pa, be32(slotGameMain)); err == nil {
			parent = fmt.Sprint(w[15])
		}
	}
	eta := time.Unix(int64(exp), 0)
	remaining := int64(exp) - b.now().Unix()
	if remaining < 0 {
		remaining = 0
	}
	return b.pending(have, "game_unresolved", eta, "createdAt", created, "expectedResolution", exp, "proofCount", proofs,
		"proof_system", gs.proofSystem(), "parent_status", parent, "seconds_remaining", uint64(remaining))
}

func (b *Builder) pinsLayout() GameLayout {
	bp, err := ParsePins(b.Pins)
	if err != nil {
		return GameLayout{}
	}
	return bp.Layouts[LayoutAggregateV1]
}

// attest assembles the container once the finalized head covers A and returns the addendum its own Kind has verified.
func (b *Builder) attest(ctx context.Context, bp *Pins, leg finality.BlockRef, body Body, a HeaderInfo, have finality.LevelSet) (*finality.Addendum, *finality.PendingState, error) {
	lc, headSlot, err := b.LC.Finalized(ctx)
	if err != nil {
		return nil, b.pending(have, "finality_lc_unavailable", time.Time{}, "endpoints", b.Providers), nil
	}
	es, err := b.Pins.Sepolia()
	if err != nil {
		return nil, nil, err
	}
	ep := ethl1Pins(es)
	head, err := ethl1.VerifyFinalizedHead(ep, lc)
	if err != nil {
		return nil, nil, st(CodeL1FinalityUnproven, "reason", LCRefused, "inner", faultCode(err))
	}
	exec, err := b.L1.L1HeaderByHash(ctx, head.ExecHash)
	if err != nil {
		return nil, b.pending(have, "l1_state_unavailable", time.Time{}, "block", head.Slot, "providers", b.Providers), nil
	}
	if exec.Number < a.Number {
		return nil, b.pending(have, "block_not_yet_covered", b.now().Add(7*time.Minute),
			"latest_finalized_exec_number", exec.Number, "latest_finalized_slot", head.Slot, "observed_head_slot", headSlot), nil
	}
	spine := [][]byte{exec.Raw}
	cur := exec
	for cur.Number > a.Number {
		cur, err = b.L1.L1HeaderByHash(ctx, cur.Parent)
		if err != nil {
			return nil, b.pending(have, "l1_state_unavailable", time.Time{}, "block", a.Number, "providers", b.Providers), nil
		}
		spine = append(spine, cur.Raw)
	}
	body.LC, body.L1Spine = lc, spine
	lh, err := finality.ReadHeader(leg.HeaderRLP)
	if err != nil {
		return nil, nil, err
	}
	c := finality.Container{Header: finality.ContainerHeader{Kind: KindName, Chain: uint64(Chain), Level: finality.LevelFinalized, BlockNumber: lh.Number, BlockHash: lh.Hash}, Body: EncodeBody(body)}
	ev, encErr := c.Encode()
	if encErr != nil {
		return nil, nil, encErr
	}
	if _, err := (Kind{}).Verify(b.Pins, leg, ev); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelFinalized, Chain: uint64(Chain), Kind: KindName, Evidence: ev}, nil, nil
}

func faultCode(err error) string {
	if f, ok := err.(*ethl1.Fault); ok {
		return f.Code
	}
	return ""
}
