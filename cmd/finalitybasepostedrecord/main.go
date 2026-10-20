// Copyright 2026 Certen Protocol

// Command finalitybasepostedrecord is the recorder of the finality_base_posted1 vector set and a live exercise of the Capturer:
// `watch` follows the Sepolia head and captures every block that holds a batch-inbox transaction into a directory store.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: finalitybasepostedrecord watch -dir DIR [-for 30m]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "watch":
		fs := flag.NewFlagSet("watch", flag.ExitOnError)
		dir := fs.String("dir", "", "capture directory")
		dur := fs.Duration("for", 30*time.Minute, "how long to follow the head")
		fs.Parse(os.Args[2:])
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "-dir is required")
			os.Exit(2)
		}
		if err := watch(*dir, *dur); err != nil {
			fmt.Fprintln(os.Stderr, "watch:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func watch(dir string, d time.Duration) error {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return err
	}
	bp, err := baseposted.ParsePins(pins)
	if err != nil {
		return err
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	end := time.Now().Add(d)
	head, err := src.Head(ctx)
	if err != nil {
		return err
	}
	next := head
	fmt.Printf("%s start head=%d\n", time.Now().UTC().Format(time.RFC3339), head)
	for time.Now().Before(end) && ctx.Err() == nil {
		h, err := src.Head(ctx)
		if err != nil {
			fmt.Printf("%s head: %v\n", time.Now().UTC().Format(time.RFC3339), err)
			time.Sleep(6 * time.Second)
			continue
		}
		for ; next <= h; next++ {
			t0 := time.Now()
			ok, err := c.CaptureBlock(ctx, next)
			switch {
			case err != nil:
				fmt.Printf("%s block %d: capture error: %v\n", time.Now().UTC().Format(time.RFC3339), next, err)
			case ok:
				fmt.Printf("%s block %d: CAPTURED in %s\n", time.Now().UTC().Format(time.RFC3339), next, time.Since(t0).Round(time.Millisecond))
			}
		}
		time.Sleep(5 * time.Second)
	}
	return nil
}
