// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/build"
)

func cryptoKeccak(b []byte) [32]byte { return crypto.Keccak256Hash(b) }

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// pickConfirmation waits for an honest AssertionConfirmed (tx.to = Rollup, selector confirmAssertion) at most `fresh` blocks below
// the head, so that its state proofs are still inside the providers' window.
func pickConfirmation(ctx context.Context, deadline time.Time, arb *arbfinal.Pins, l1 *build.LiveL1, fresh uint64) (build.Log, error) {
	for time.Now().Before(deadline) {
		head, err := l1.Head(ctx)
		if err != nil {
			return build.Log{}, err
		}
		from := uint64(0)
		if head > 400 {
			from = head - 400
		}
		logs, err := l1.Logs(ctx, arb.Rollup, [][]common.Hash{{arb.Topic.Confirmed}}, from, head)
		if err != nil {
			return build.Log{}, err
		}
		for i := len(logs) - 1; i >= 0; i-- {
			c := logs[i]
			if head-c.Block > fresh {
				break
			}
			blk, err := l1.Block(ctx, c.Block)
			if err != nil {
				return build.Log{}, err
			}
			if c.TxIndex >= uint64(len(blk.Txs)) {
				continue
			}
			var tx types.Transaction
			if err := tx.UnmarshalBinary(blk.Txs[c.TxIndex]); err != nil {
				continue
			}
			d := tx.Data()
			if tx.To() != nil && *tx.To() == arb.Rollup && len(d) >= 4 && hex.EncodeToString(d[:4]) == selectorConfirm {
				logf("confirmation: L1 block %d (%d below head %d), tx %x, honest (to = Rollup, selector %s)", c.Block, head-c.Block, head, c.TxHash[:6], selectorConfirm)
				return c, nil
			}
			logf("confirmation at L1 block %d is not on the direct path (to %v): not used", c.Block, tx.To())
		}
		sleepCtx(ctx, 12*time.Second)
	}
	return build.Log{}, fmt.Errorf("no fresh honest confirmation before the deadline")
}

// cachedL2 serves the L2 headers read once, so that a rate-limited public provider cannot fail the attestation after the
// near-head capture is done.
type cachedL2 struct {
	*build.LiveL2
	hdrs map[uint64][]byte
}

func (c *cachedL2) Headers(ctx context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; n <= to; n++ {
		h, ok := c.hdrs[n]
		if !ok {
			out = nil
			break
		}
		out = append(out, h)
	}
	if out != nil {
		return out, nil
	}
	hs, err := c.LiveL2.Headers(ctx, from, to)
	if err != nil {
		return nil, err
	}
	for i, h := range hs {
		c.hdrs[from+uint64(i)] = h
	}
	return hs, nil
}

type legFile struct {
	Chain     uint64 `json:"chain"`
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	HeaderHex string `json:"header_hex"`
	Note      string `json:"note"`
	EndBlock  uint64 `json:"assertion_end_block"`
	Assertion string `json:"assertion_hash"`
	Parent    string `json:"parent_assertion_hash"`
	ConfL1    uint64 `json:"confirmation_l1_block"`
	ConfTx    string `json:"confirmation_tx"`
	CreatedL1 uint64 `json:"created_l1_block"`
	Gap       uint64 `json:"leg_below_assertion_end"`
}

// liveAttempt runs one capture-and-attest cycle. It returns (false, nil) when the capture missed its proof window and the whole
// cycle must restart with the next confirmation.
func liveAttempt(ctx context.Context, attempt int, deadline time.Time, pins *finality.Pins, arb *arbfinal.Pins, l1 *build.LiveL1, l2 *build.LiveL2, lc *build.BeaconLC, out string, gap, fresh, stateAhead uint64) (bool, error) {
	logf("attempt %d: waiting for a fresh honest confirmation", attempt)
	conf, err := pickConfirmation(ctx, deadline, arb, l1, fresh)
	if err != nil {
		return false, err
	}
	hash := conf.Topics[1]
	lo := uint64(0)
	if conf.Block > 700 {
		lo = conf.Block - 700
	}
	logs, err := l1.Logs(ctx, arb.Rollup, [][]common.Hash{{build.TopicAssertionCreated}, {hash}}, lo, conf.Block)
	if err != nil {
		return false, err
	}
	if len(logs) == 0 {
		return false, fmt.Errorf("no AssertionCreated for the confirmed assertion in L1 blocks %d..%d", lo, conf.Block)
	}
	created := logs[len(logs)-1]
	a, err := build.DecodeCreated(created)
	if err != nil {
		return false, err
	}
	raw, err := l2.HeaderByHash(ctx, a.After.BlockHash)
	if err != nil {
		return false, err
	}
	endHdr, err := finality.ReadHeader(raw)
	if err != nil {
		return false, err
	}
	n := endHdr.Number - gap
	legRaw, err := l2.HeaderByNumber(ctx, n)
	if err != nil {
		return false, err
	}
	lh, err := finality.ReadHeader(legRaw)
	if err != nil {
		return false, err
	}
	leg := finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: lh.Number, Hash: lh.Hash, HeaderRLP: legRaw}
	lf := legFile{Chain: leg.Chain, Number: leg.Number, Hash: "0x" + hex.EncodeToString(leg.Hash[:]), HeaderHex: hex.EncodeToString(legRaw),
		Note:     "a real Arbitrum Sepolia block, not a CERTEN leg: the legs of research/R11-legs.md are 1.5-3 days old (about 345k L2 blocks per day), so their header chain to any recent confirmed assertion exceeds max_header_chain (32768); this block lies a fixed number of blocks below the covering assertion's end block",
		EndBlock: endHdr.Number, Assertion: "0x" + hex.EncodeToString(a.Hash[:]), Parent: "0x" + hex.EncodeToString(a.Parent[:]), ConfL1: conf.Block,
		ConfTx: "0x" + hex.EncodeToString(conf.TxHash[:]), CreatedL1: created.Block, Gap: gap}
	writeJSON(out, "leg.json", lf)
	logf("leg: L2 block %d (assertion end block %d, %d headers), assertion %x, confirmed at L1 block %d", leg.Number, endHdr.Number, gap+1, a.Hash[:6], conf.Block)

	store := build.NewMemStore()
	cl2 := &cachedL2{LiveL2: l2, hdrs: map[uint64][]byte{}}
	if _, err := cl2.Headers(ctx, leg.Number, endHdr.Number); err != nil {
		logf("L2 header warm-up failed (the build retries): %v", err)
	}
	prover := &build.Prover{Pins: pins, L1: l1, L2: cl2, LC: lc, Store: store, StateAhead: stateAhead,
		OnStatus: func(reason string, info map[string]any) { logf("status %s %v", reason, info) }}
	start := time.Now()
	for time.Now().Before(deadline) {
		add, pend, err := prover.BuildLeg(ctx, leg, 0)
		if err != nil {
			if s, ok := finality.AsNamed(err); ok {
				switch s.Code {
				case arbfinal.CodeL2HeadersUnavail, arbfinal.CodeL2HeaderUnavail, arbfinal.CodeHistoryUnavailable:
					// builder-side unavailability (a rate-limited public provider): the captured proofs stay in the store, retry
					logf("unavailable: %s (retrying; the capture is kept)", s.Canonical())
					sleepCtx(ctx, 25*time.Second)
					continue
				}
				return false, fmt.Errorf("%s", s.Canonical())
			}
			return false, err
		}
		if pend != nil {
			logf("pending: %s", pend.State().Canonical())
			if pend.Reason == build.PendingProofWindow {
				logf("the capture missed the provider window; restarting with the next confirmation")
				return false, nil
			}
			sleepCtx(ctx, 30*time.Second)
			continue
		}
		buildSecs := time.Since(start).Seconds()
		t0 := time.Now()
		v, verr := arbfinal.New().Verify(pins, leg, add.Evidence)
		verifyMs := float64(time.Since(t0).Microseconds()) / 1000
		if verr != nil {
			return false, fmt.Errorf("independent re-verification refused: %v", verr)
		}
		write(out, "evidence.bin", add.Evidence)
		writeJSON(out, "measure.json", map[string]any{
			"evidence_bytes": len(add.Evidence), "wall_seconds_from_first_build_call": buildSecs, "verify_ms": verifyMs,
			"l2_spine_headers": gap + 1, "state_block": v.Fields["s_number"], "conf_block": v.Fields["k_number"],
			"verdict": string(finality.NewState("finalized", flat(v.Fields)...).Canonical()), "captured_utc": time.Now().UTC().Format(time.RFC3339),
		})
		logf("DONE: evidence %d bytes, verify %.1f ms", len(add.Evidence), verifyMs)
		return true, nil
	}
	return false, fmt.Errorf("deadline before the evidence could be attested")
}

func flat(m map[string]any) []any {
	var kv []any
	for k, v := range m {
		kv = append(kv, k, v)
	}
	return kv
}
