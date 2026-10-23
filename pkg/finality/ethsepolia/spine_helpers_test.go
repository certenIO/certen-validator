// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// ---- synthetic Sepolia-shaped chains ----

// spineSynthHeader is a 23-item header (the shape Sepolia has had since 2026-10-06, about 650 bytes) whose parent is parent.
func spineSynthHeader(number uint64, parent [32]byte, seed byte) []byte {
	fill := func(n int, b byte) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = b ^ byte(i)
		}
		return out
	}
	items := []any{
		parent[:], fill(32, 0x11), fill(20, seed), fill(32, byte(number)^seed), fill(32, 0x22), fill(32, 0x33), fill(256, 0x44^seed),
		uint64(0), number, uint64(30_000_000), number % 1_000_003, 1_700_000_000 + number*12, []byte("synthetic"), fill(32, 0x55), fill(8, 0x66),
		uint64(7), fill(32, 0x77), uint64(0), uint64(0), fill(32, 0x88), fill(32, 0x99), fill(32, 0xaa), number * 2,
	}
	enc, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return enc
}

type synthChain struct {
	base   uint64
	hs     [][]byte
	byNum  map[uint64][]byte
	byHash map[[32]byte][]byte
}

// newSynth builds n linked headers numbered base..base+n-1. seed makes a different (fork) chain over the same numbers.
func newSynth(base uint64, n int, seed byte) *synthChain {
	s := &synthChain{base: base, byNum: map[uint64][]byte{}, byHash: map[[32]byte][]byte{}}
	var parent [32]byte
	parent[0], parent[1] = 0xde, seed
	for i := 0; i < n; i++ {
		h := spineSynthHeader(base+uint64(i), parent, seed)
		s.hs = append(s.hs, h)
		s.byNum[base+uint64(i)] = h
		parent = crypto.Keccak256Hash(h)
		s.byHash[parent] = h
	}
	return s
}

func (s *synthChain) top() uint64 { return s.base + uint64(len(s.hs)) - 1 }

func (s *synthChain) hashOf(n uint64) [32]byte { return crypto.Keccak256Hash(s.byNum[n]) }

// candidate is the finalized head the walk is judged against: the top of the chain.
func (s *synthChain) candidate() candidate {
	return candidate{execHash: s.hashOf(s.top()), execNumber: s.top()}
}

func (s *synthChain) leg(n uint64) finality.BlockRef {
	return finality.BlockRef{Chain: finality.ChainSepolia, Number: n, Hash: s.hashOf(n), HeaderRLP: s.byNum[n]}
}

func (s *synthChain) model(clk *fakeClock, perHdr time.Duration) *modelHeaders {
	return &modelHeaders{byNum: s.byNum, byHash: s.byHash, clock: clk, perHdr: perHdr}
}

// spineProver is a Prover with only what the spine walk uses.
func spineProver(src HeaderSource, store finality.CaptureStore, clk *fakeClock, budget time.Duration) *Prover {
	p := &Prover{Exec: src, Store: store, SpineBudget: budget}
	if clk != nil {
		p.Now = clk.Now
	}
	return p
}

// storedSpineKeys lists the kept chunk rows of the chain.
func storedSpineKeys(t testing.TB, st finality.CaptureStore) []finality.CaptureKey {
	t.Helper()
	ks, err := st.ListByRange(context.Background(), finality.ChainSepolia, 0, finality.MaxCaptureBlock, "spine/")
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// legAt is the block at index idx of a recorded spine (0 is the finalized head) as a leg of its own: the verifier accepts any block of
// the spine, so one recorded finality update stands for as many legs as the spine has blocks.
func legAt(t testing.TB, l recordedLeg, idx int) finality.BlockRef {
	t.Helper()
	raw := l.body.Spine[idx]
	f, err := finality.ReadHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return finality.BlockRef{Chain: finality.ChainSepolia, Number: f.Number, Hash: f.Hash, HeaderRLP: raw}
}

func pendingOf(t testing.TB, pend *finality.PendingState) (have, need uint64, next string) {
	t.Helper()
	if pend == nil || pend.Reason != PendingAwaitingSpine {
		t.Fatalf("want finality_pending{awaiting_spine}, got %v", pend)
	}
	h, ok1 := pend.Judged["have"].(uint64)
	n, ok2 := pend.Judged["need"].(uint64)
	x, ok3 := pend.Judged["next_attempt_at"].(string)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("awaiting_spine fields %v", pend.Judged)
	}
	return h, n, x
}

func isNamed(t testing.TB, err error, code, reason string) {
	t.Helper()
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != code || (reason != "" && fmt.Sprint(s.Fields["reason"]) != reason) {
		t.Fatalf("want %s{reason=%s}, got %v", code, reason, err)
	}
}

// peakHeap is how far the heap in use rose above its level before f ran, sampled every millisecond while f ran.
func peakHeap(f func()) uint64 {
	// a tight GC target, so that what is sampled is the live heap and not garbage waiting for the next cycle
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak {
				peak = m.HeapAlloc
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	if peak > base.HeapAlloc {
		return peak - base.HeapAlloc
	}
	return 0
}
