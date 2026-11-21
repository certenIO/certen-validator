// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// The history floor of the node proof v2 reads (AGT-F104, OQ12; pkg/proof/v2/historyfloor.go). Proof v2 reads a governing page
// as of its partition's latest block anchored at or before the transaction's own anchor; on a quiet partition that block is
// old, and a node that prunes its history refuses it, so the intent can never be proven. The validator therefore refuses to
// start proof v2 against a node that does not keep every block from PROOF_V2_HISTORY_FLOOR on, and keeps judging the node
// while it runs.

// historyFloorReadBudget bounds how long startup retries a node that cannot be read (a definitive refusal is never retried).
var historyFloorReadBudget = 2 * time.Minute

// historyFloorRecheck is how often the running validator judges the node again.
var historyFloorRecheck = 10 * time.Minute

// historyFloorDeps are the network reads of the check (tests replace them).
type historyFloorDeps struct {
	partitions func(ctx context.Context) ([]string, error)
	retention  proofv2.Retention
	sleep      func(time.Duration)
}

func liveHistoryFloorDeps(v3 string) historyFloorDeps {
	return historyFloorDeps{
		partitions: func(ctx context.Context) ([]string, error) {
			r, err := proof.LoadNetworkRouter(ctx, v3)
			if err != nil {
				return nil, err
			}
			return r.Partitions(), nil
		},
		retention: &proofv2.ClientRetention{C: jsonrpc.NewClient(v3)},
		sleep:     time.Sleep,
	}
}

// judgeHistoryFloor reads the floor from raw and judges the node once.
func judgeHistoryFloor(ctx context.Context, raw string, d historyFloorDeps) (proofv2.HistoryFloor, error) {
	floor, err := proofv2.ParseHistoryFloor(raw)
	if err != nil {
		return nil, err
	}
	parts, err := d.partitions(ctx)
	if err != nil {
		return floor, fmt.Errorf("the network's partitions: %w", err)
	}
	return floor, floor.Check(ctx, d.retention, parts)
}

// startupHistoryFloor is the start gate: nil only when the node keeps the floor. A definitive refusal (*FloorError) returns at
// once; a node that cannot be read is retried within historyFloorReadBudget and then refused as well.
func startupHistoryFloor(raw string, d historyFloorDeps) (proofv2.HistoryFloor, error) {
	deadline := time.Now().Add(historyFloorReadBudget)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		floor, err := judgeHistoryFloor(ctx, raw, d)
		cancel()
		var fe *proofv2.FloorError
		if err == nil || errors.As(err, &fe) {
			return floor, err
		}
		if !time.Now().Before(deadline) {
			return floor, fmt.Errorf("proof v2 history floor: the node could not be read within %s: %w", historyFloorReadBudget, err)
		}
		d.sleep(10 * time.Second)
	}
}

// watchHistoryFloor judges the node every historyFloorRecheck while the validator runs and logs each failure by name, so a
// node that starts pruning (or a node swapped behind the URL) is reported, not discovered as unprovable intents.
func watchHistoryFloor(ctx context.Context, raw string, d historyFloorDeps) {
	t := time.NewTicker(historyFloorRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := judgeHistoryFloor(rctx, raw, d)
		cancel()
		if err != nil {
			log.Printf("❌ [PROOF-V2-HISTORY] the Accumulate node fails the history floor: %v - intents whose governing pages sit on a quiet partition cannot be proven until it keeps the floor (AGT-F104)", err)
		}
	}
}

// runProofV2HistoryCheck is `validator proofv2-history-check <accumulate-url> <floor>`: the read-only deploy check an operator
// runs before pointing validators at a node. It prints each partition's retained range and the verdict, never anything else.
// Exit status: 0 the node keeps the floor, 1 refused, 2 usage or the node could not be read.
func runProofV2HistoryCheck(args []string, out, errw io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(errw, "usage: validator proofv2-history-check <accumulate-url> <Partition=height,...>")
		return 2
	}
	v3 := strings.TrimSuffix(args[0], "/") + "/v3"
	d := liveHistoryFloorDeps(v3)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if parts, err := d.partitions(ctx); err == nil {
		for _, p := range parts {
			if e, l, rerr := d.retention.Retained(ctx, p); rerr == nil {
				fmt.Fprintf(out, "%-10s retains [%d, %d]\n", p, e, l)
			} else {
				fmt.Fprintf(out, "%-10s unreadable: %v\n", p, rerr)
			}
		}
	}
	floor, err := judgeHistoryFloor(ctx, args[1], d)
	var fe *proofv2.FloorError
	switch {
	case err == nil:
		fmt.Fprintf(out, "OK the node keeps the floor %s\n", floor)
		return 0
	case errors.As(err, &fe):
		fmt.Fprintf(out, "REFUSED %v\n", err)
		return 1
	default:
		fmt.Fprintf(errw, "proofv2-history-check: %v\n", err)
		return 2
	}
}
