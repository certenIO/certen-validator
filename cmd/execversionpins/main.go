// Copyright 2026 Certen Protocol
//
// execversionpins re-derives the executor-version activation table (pkg/proof/v2 xexecutor_table.go over liteclient govsig) from the
// network and exits non-zero when it differs from the compiled one (RB9 verifier round VA, note (b)).
//
// The table is a pinned trust input of the proof (docs/proof/EXECUTOR_VERSION_PINS.md). For each partition (the Directory and every
// block validator partition) the tool reads the partition ADI's main chain (acc://dn.acme, acc://bvn-BVNn.acme), takes every
// activateProtocolVersion message on it with the chain-entry receipt that places it in the partition's chain at a local block, checks
// that receipt (it starts at the entry and validates to the anchor it names), and compares the activation's version and local block with
// the compiled row. A partition with no activation, with more than one (the compiled table has one row per partition), or with a
// different version or block is a difference; a partition missing from either side is a difference.
//
//	go run ./cmd/execversionpins -endpoint https://kermit.accumulatenetwork.io/v3
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Observed is one activateProtocolVersion message read from a partition's main chain.
type Observed struct {
	Version protocol.ExecutorVersion
	Block   uint64 // the partition's local block the chain-entry receipt names
	Entry   [32]byte
	Index   uint64
}

// Compare returns the differences between the compiled table and what the network shows, one line each, sorted. Empty means equal.
func Compare(compiled map[string]proofv2.ExecutorActivation, observed map[string][]Observed) []string {
	var out []string
	seen := map[string]bool{}
	for part, rows := range observed {
		key := proofv2.NormalizeExecutorPartition(part)
		seen[key] = true
		want, ok := compiled[key]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: the network shows %d activation(s), the compiled table has no row", key, len(rows)))
		case len(rows) == 0:
			out = append(out, fmt.Sprintf("%s: the network shows no activateProtocolVersion message, the compiled table has version %v at block %d", key, want.Version, want.Block))
		case len(rows) > 1:
			out = append(out, fmt.Sprintf("%s: the network shows %d activations (%s), the compiled table has one row (version %v at block %d)", key, len(rows), describe(rows), want.Version, want.Block))
		case rows[0].Version != want.Version || rows[0].Block != want.Block:
			out = append(out, fmt.Sprintf("%s: the network shows %s, the compiled table has version %v at block %d", key, describe(rows), want.Version, want.Block))
		}
	}
	for key, want := range compiled {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s: the compiled table has version %v at block %d, the network was not read for this partition", key, want.Version, want.Block))
		}
	}
	sort.Strings(out)
	return out
}

func describe(rows []Observed) string {
	var s []string
	for _, r := range rows {
		s = append(s, fmt.Sprintf("version %v at block %d (chain index %d)", r.Version, r.Block, r.Index))
	}
	return strings.Join(s, "; ")
}

// partitionADIs are the accounts whose main chains hold the partitions' activations, by the table's partition keys.
func partitionADIs(table map[string]proofv2.ExecutorActivation) map[string]*url.URL {
	out := map[string]*url.URL{}
	for key := range table {
		id := strings.ToUpper(key)
		if key == "directory" {
			id = protocol.Directory
		}
		out[key] = protocol.PartitionUrl(id)
	}
	return out
}

func read(ctx context.Context, c *jsonrpc.Client, adi *url.URL) ([]Observed, error) {
	count, expand := uint64(100), true
	r, err := c.Query(ctx, adi, &api.ChainQuery{Name: "main", Range: &api.RangeOptions{Start: 0, Count: &count, Expand: &expand}})
	if err != nil {
		return nil, fmt.Errorf("%v main chain: %w", adi, err)
	}
	rr, ok := r.(*api.RecordRange[api.Record])
	if !ok {
		return nil, fmt.Errorf("%v main chain: got %T, not a range of chain entries", adi, r)
	}
	if rr.Total > uint64(len(rr.Records)) {
		return nil, fmt.Errorf("%v main chain: %d entries, only %d read (raise the range)", adi, rr.Total, len(rr.Records))
	}
	var out []Observed
	for _, rec := range rr.Records {
		ce, ok := rec.(*api.ChainEntryRecord[api.Record])
		if !ok {
			return nil, fmt.Errorf("%v main chain: an entry is a %T, not a chain entry", adi, rec)
		}
		mr, ok := ce.Value.(*api.MessageRecord[messaging.Message])
		if !ok {
			continue
		}
		tm, ok := mr.Message.(*messaging.TransactionMessage)
		if !ok || tm.Transaction == nil {
			continue
		}
		body, ok := tm.Transaction.Body.(*protocol.ActivateProtocolVersion)
		if !ok {
			continue
		}
		// The range does not carry receipts: the entry is read again, alone, with the receipt that places it in the chain at a local block.
		idx := ce.Index
		er, err := c.Query(ctx, adi, &api.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
		if err != nil {
			return nil, fmt.Errorf("%v main[%d]: %w", adi, idx, err)
		}
		ent, ok := er.(*api.ChainEntryRecord[api.Record])
		if !ok || ent.Index != idx || ent.Entry != ce.Entry {
			return nil, fmt.Errorf("%v main[%d]: got %T, not the entry", adi, idx, er)
		}
		if ent.Receipt == nil || ent.Receipt.LocalBlock == 0 {
			return nil, fmt.Errorf("%v main[%d]: the activation carries no receipt naming its block", adi, idx)
		}
		rc := ent.Receipt.Receipt
		if string(rc.Start) != string(ent.Entry[:]) || !rc.Validate(nil) {
			return nil, fmt.Errorf("%v main[%d]: the chain-entry receipt does not validate from the entry to its anchor", adi, idx)
		}
		out = append(out, Observed{Version: body.Version, Block: ent.Receipt.LocalBlock, Entry: ent.Entry, Index: idx})
	}
	return out, nil
}

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	compiled := proofv2.KermitExecutorActivations()
	c := jsonrpc.NewClient(*endpoint)
	observed := map[string][]Observed{}
	adis := partitionADIs(compiled)
	var keys []string
	for k := range adis {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rows, err := read(ctx, c, adis[k])
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(2)
		}
		observed[k] = rows
		fmt.Printf("%-10s %s: %s\n", k, adis[k], describe(rows))
	}
	diff := Compare(compiled, observed)
	if len(diff) > 0 {
		fmt.Println("DIFFERS from the compiled activation table:")
		for _, d := range diff {
			fmt.Println("  " + d)
		}
		os.Exit(1)
	}
	fmt.Println("the compiled activation table equals what", *endpoint, "shows: one activateProtocolVersion per partition, each with a validating chain-entry receipt")
}
