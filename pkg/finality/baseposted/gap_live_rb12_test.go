//go:build rb12live

// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP: the LIVE replay of the three outage holes of the Base capture (build tag rb12live; it reads public providers, read-only,
// and runs for minutes, so it is not part of the default build; its offline sibling TestRB12ReplayTheThreeHolesGapRecordedCoverageNamed...
// pins the same lifecycle on the recorded answers). Every block of the three holes (684 blocks, 80 of them with Base batch-inbox transactions
// and 519 blobs) is captured by the production capturer through the production backfill, from the public providers, into an in-memory store;
// the test requires every gap closed and every captured block's rows to verify against the block's own header.
//
//	CERTEN_RB12_LIVE_BLOCK_URL   Sepolia execution endpoint   (default https://ethereum-sepolia-rpc.publicnode.com)
//	CERTEN_RB12_LIVE_PROOF_URLS  comma list, near-head then archive (default the same, then https://rpc.sepolia.ethpandaops.io)
//	CERTEN_RB12_LIVE_BEACON_URL  beacon API base               (default https://ethereum-sepolia-beacon-api.publicnode.com)
func TestRB12LiveReplayOfTheThreeHolesFromPublicProviders(t *testing.T) {
	rs := loadReplay(t)
	env := func(k, d string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return d
	}
	blockURL := env("CERTEN_RB12_LIVE_BLOCK_URL", "https://ethereum-sepolia-rpc.publicnode.com")
	proofURLs := strings.Split(env("CERTEN_RB12_LIVE_PROOF_URLS", blockURL+",https://rpc.sepolia.ethpandaops.io"), ",")
	beacon := env("CERTEN_RB12_LIVE_BEACON_URL", "https://ethereum-sepolia-beacon-api.publicnode.com")
	ctx := context.Background()
	st := NewMemStore()
	c := &Capturer{Chain: uint64(Chain), Pins: replayPins(t), L1: &JSONRPCSource{BlockURLs: []string{blockURL}, ProofURLs: proofURLs},
		Beacon: &BeaconHTTP{Bases: []string{beacon}}, Store: st, GenesisTime: SepoliaBeaconGenesis, SlotSeconds: 12}
	var holes [][2]uint64
	for _, h := range rs.Holes {
		holes = append(holes, [2]uint64{h.After + 1, h.Before - 1})
		if err := finality.RecordGap(ctx, st, uint64(Chain), h.After+1, h.Before-1, finality.GapSpacingUnproven); err != nil {
			t.Fatal(err)
		}
	}
	say := func(f string, a ...any) { fmt.Println("RB12-LIVE-REPLAY " + fmt.Sprintf(f, a...)) }
	bf := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: CapturerOf(c), Providers: []string{"beacon"}, Policy: DefaultBackfillPolicy(), Pick: func(int) int { return 0 }, Logf: say}
	start := time.Now()
	for i := 0; i < 400; i++ {
		rep, err := bf.Step(ctx, 25)
		if err != nil {
			t.Fatal(err)
		}
		say("step %d: attempted %d filled %d failed %d open %d (%s)", i, rep.Attempted, rep.Filled, rep.Failed, rep.Open, time.Since(start).Round(time.Second))
		if rep.Open == 0 {
			break
		}
		if rep.Attempted == 0 { // every open block is waiting out its backoff: wait for the shortest one
			time.Sleep(31 * time.Second)
		}
	}
	open, err := finality.GapsIn(ctx, st, uint64(Chain), 0, finality.MaxCaptureBlock)
	if err != nil || len(open) != 0 {
		t.Fatalf("the holes %v are not closed: %v %v", holes, open, err)
	}
	bp := replayPins(t)
	verified, blobs := 0, 0
	for _, h := range rs.Holes {
		for _, b := range h.Blocks {
			if b.Inbox == 0 {
				continue
			}
			var want [32]byte
			copy(want[:], common.FromHex(b.Hash))
			verifyCapturedBlock(t, st, bp, b.N, want)
			verified++
			blobs += b.Blobs
		}
	}
	say("closed %d blocks of the three holes in %s: %d inbox blocks captured and verified against their headers (%d blobs)", 684, time.Since(start).Round(time.Second), verified, blobs)
	if verified != 80 || blobs != 519 {
		t.Fatalf("verified %d inbox blocks and %d blobs, the scan says 80 and 519", verified, blobs)
	}
}
