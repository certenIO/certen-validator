// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// newCapturer is the Capturer `watch` runs, over the same providers, for a directory store.
func newCapturer(dir string) (*baseposted.Capturer, *baseposted.JSONRPCSource, error) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return nil, nil, err
	}
	bp, err := baseposted.ParsePins(pins)
	if err != nil {
		return nil, nil, err
	}
	src := &baseposted.JSONRPCSource{
		BlockURLs: []string{"https://ethereum-sepolia-rpc.publicnode.com"},
		ProofURLs: []string{"https://0xrpc.io/sep", "https://api.zan.top/eth-sepolia", "https://ethereum-sepolia-rpc.publicnode.com"},
	}
	c := &baseposted.Capturer{
		Chain: uint64(baseposted.Chain), Pins: bp, L1: src, Store: baseposted.DirStore{Dir: dir},
		Beacon:      &baseposted.BeaconHTTP{Bases: []string{"https://ethereum-sepolia-beacon-api.publicnode.com", "https://lodestar-sepolia.chainsafe.io"}},
		GenesisTime: 1655733600, SlotSeconds: 12,
		Record: func(l1 uint64, s *finality.StateError) {
			fmt.Printf("%s STATE l1=%d %s\n", time.Now().UTC().Format(time.RFC3339), l1, s.Error())
		},
	}
	return c, src, nil
}

// captureRange captures the L1 blocks from..to (to 0: the current head; follow > 0: keep following the head for that long) into dir, each block retried; the live-capture flow of
// `watch` for blocks that are already on the chain (the beacon serves their blobs for about 18 days).
func captureRange(dir string, from, to uint64, follow time.Duration) error {
	c, src, err := newCapturer(dir)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if to == 0 {
		if to, err = src.Head(ctx); err != nil {
			return err
		}
	}
	var failed []uint64
	end := time.Now().Add(follow)
	for n := from; ; n++ {
		if n > to {
			// follow the head until the deadline: a block's state proof is only served by the public providers near the head, so a leg
			// can be captured only while its channel is being posted
			if time.Now().After(end) {
				break
			}
			time.Sleep(5 * time.Second)
			h, err := src.Head(ctx)
			if err != nil || h < n {
				n--
				continue
			}
			to = h
		}
		var last error
		for try := 0; try < 4; try++ {
			ok, err := c.CaptureBlock(ctx, n)
			if err == nil {
				if ok {
					fmt.Printf("%s block %d: CAPTURED\n", time.Now().UTC().Format(time.RFC3339), n)
				}
				last = nil
				break
			}
			last = err
			time.Sleep(time.Duration(2+try*3) * time.Second)
		}
		if last != nil {
			fmt.Printf("block %d: %v\n", n, last)
			failed = append(failed, n)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d block(s) not captured: %v", len(failed), failed)
	}
	fmt.Printf("captured %d..%d\n", from, to)
	return nil
}

func exitf(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
