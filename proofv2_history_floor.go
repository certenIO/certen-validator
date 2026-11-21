// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/metrics"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// The history floor of the node proof v2 reads (AGT-F104, OQ12; pkg/proof/v2/historyfloor.go). Proof v2 reads a governing page
// as of its partition's latest block anchored at or before the transaction's own anchor; on a quiet partition that block is
// old, and a node that prunes its history refuses it, so the intent cannot be proven. The validator judges the node against
// PROOF_V2_HISTORY_FLOOR at start and every historyFloorRecheck while it runs and REPORTS the verdict (log, the
// certen_proof_v2_history_floor_met gauge, /health/detailed). It does not stop the validator: consensus, intent processing and
// every provable intent carry on, and each intent that cannot be proven is refused by name (g1_historical_unavailable).
// Stopping every validator for a node limit that already refuses its own victims by name would only remove capability.

// historyFloorRecheck is how often the running validator judges the node again.
var historyFloorRecheck = 10 * time.Minute

// historyFloorDeps are the network reads of the check (tests replace them).
type historyFloorDeps struct {
	partitions func(ctx context.Context) ([]string, error)
	retention  proofv2.Retention
	now        func() time.Time
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
		now:       time.Now,
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

// historyVerdict names a judgement: "met", the FloorError code without its prefix, or "unreadable" for a read failure (which is
// never counted as met).
func historyVerdict(err error) (verdict, partition string) {
	if err == nil {
		return "met", ""
	}
	var fe *proofv2.FloorError
	if errors.As(err, &fe) {
		return strings.TrimPrefix(fe.Code, "proof_v2_history_floor_"), fe.Partition
	}
	return "unreadable", ""
}

// reportHistoryFloor judges the node once and reports the verdict: the metrics and health block always, the log on every
// failure and on the first judgement and each change of verdict. It returns the verdict.
func reportHistoryFloor(ctx context.Context, raw, url string, d historyFloorDeps, prev string, logf func(string, ...any)) string {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	floor, err := judgeHistoryFloor(rctx, raw, d)
	cancel()
	verdict, partition := historyVerdict(err)
	detail, shown := "", ""
	if err != nil {
		detail = err.Error()
	}
	if floor != nil {
		shown = floor.String()
	}
	metrics.ReportProofV2HistoryFloor(verdict, partition, detail, shown, d.now())
	switch {
	case verdict == "met" && prev != "met":
		logf("📚 [PROOF-V2-HISTORY] %s keeps every block from the floor %s", url, shown)
	case verdict != "met":
		logf("❌ [PROOF-V2-HISTORY] the Accumulate node %s fails the history floor: %v - the validator runs on; intents whose governing pages sit on a partition quiet for longer than the node's retention are refused by name (g1_historical_unavailable) until it keeps the floor (AGT-F104, OQ12)", url, err)
	}
	return verdict
}

// watchHistoryFloor judges the node at once and then every historyFloorRecheck while the validator runs, so a node that does
// not keep the floor, starts pruning, or is swapped behind the URL is reported, not discovered as unprovable intents.
func watchHistoryFloor(ctx context.Context, raw, url string, d historyFloorDeps, logf func(string, ...any)) {
	prev := reportHistoryFloor(ctx, raw, url, d, "", logf)
	t := time.NewTicker(historyFloorRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		prev = reportHistoryFloor(ctx, raw, url, d, prev, logf)
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
