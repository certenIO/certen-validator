// Copyright 2026 Certen Protocol

// Command finalityarbpostedcapture is the live runner of the Arbitrum Sepolia l1_posted CAPTURE phase (V2_SPEC_S7 2.8): on every
// interval it reads the Sepolia head, captures SequencerBatchDelivered events with their batch transactions and blobs, and the
// Bridge accumulator proofs near the head, into an insert-only DirStore. It is a recorder for vector building and the live read
// of the capture logic; the validator embeds capture.Capturer with the database store.
//
//	finalityarbpostedcapture -dir <dir> [-interval 12s] [-for 60m] [-start-back 0]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

func main() {
	dir := flag.String("dir", "", "capture store directory (required)")
	interval := flag.Duration("interval", 12*time.Second, "tick interval")
	forDur := flag.Duration("for", 60*time.Minute, "run for this long")
	startBack := flag.Uint64("start-back", 0, "with no cursor, start scanning this many L1 blocks below the head")
	l1 := flag.String("l1", "https://0xrpc.io/sep,https://api.zan.top/eth-sepolia,https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.gateway.tenderly.co,https://1rpc.io/sepolia", "comma separated L1 JSON-RPC providers, tried in order")
	beacon := flag.String("beacon", "https://ethereum-sepolia-beacon-api.publicnode.com,https://lodestar-sepolia.chainsafe.io", "comma separated beacon API bases")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "-dir is required")
		os.Exit(2)
	}
	store, err := capture.NewDirStore(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, ethrpc.RedactText(err.Error()))
		os.Exit(1)
	}
	logf := func(f string, a ...any) {
		fmt.Printf("%s "+f+"\n", append([]any{time.Now().UTC().Format("15:04:05")}, a...)...)
	}
	cp := capture.NewCapturer(store, capture.NewHTTPL1(strings.Split(*l1, ",")...), capture.NewHTTPBeacon(strings.Split(*beacon, ",")...),
		capture.Config{StartBack: *startBack, Logf: logf})
	ctx, cancel := context.WithTimeout(context.Background(), *forDur)
	defer cancel()
	tk := time.NewTicker(*interval)
	defer tk.Stop()
	for {
		rep, err := cp.Tick(ctx)
		if err != nil {
			logf("tick error: %s", ethrpc.RedactText(err.Error()))
		} else {
			logf("head %d scanned %d-%d new batches %v blobs +%d proofs %v at %d unavailable %v errors %d",
				rep.Head, rep.ScannedFrom, rep.ScannedTo, rep.NewBatches, rep.BlobsStored, rep.Proofs, rep.ProofBlock, rep.Unavailable, len(rep.Errors))
		}
		select {
		case <-ctx.Done():
			logf("done")
			return
		case <-tk.C:
		}
	}
}
