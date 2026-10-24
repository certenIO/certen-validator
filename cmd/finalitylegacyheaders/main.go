// Copyright 2026 Certen Protocol

// finalitylegacyheaders runs the legacy-header reconstruction (pkg/finality/legacyhdr, RB12-LEGACY-191) OFFLINE over legacy execution
// proofs extracted from production bundles, against real providers, with the SAME code the validator's loop runs (legacyhdr.Judge).
// It writes nothing to any database and prints no bundle bytes: one line per leg (proof id, chain, block, state, the check or the
// counts that name it) and a summary.
//
//	finalitylegacyheaders -in legacy_comp5.jsonl -rpc 84532=URL[,URL...] -rpc 421614=URL -rpc 11155111=URL [-store DIR] [-gap 150ms]
//
// The input is JSON lines {"proof_id","bundle_id","comp5":{...}} where comp5 is the bundle's 5_execution_proof component (extracted
// read-only on the validator host). -store keeps the verified headers as files (finality.DirCaptureStore) so a second run asks no
// provider for a header already kept; without it the store is in memory. Provider URLs are given on the command line and are never
// printed (a provider is named by its position in the list). Exit status 1 when any leg is not reconstructed, 2 on a usage error.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
)

type rpcFlags map[uint64][]string

func (f rpcFlags) String() string { return fmt.Sprint(len(f)) }
func (f rpcFlags) Set(v string) error {
	id, urls, ok := strings.Cut(v, "=")
	chain, err := strconv.ParseUint(id, 10, 64)
	if !ok || err != nil || chain == 0 || urls == "" {
		return fmt.Errorf("-rpc wants <chain id>=<url>[,<url>...]")
	}
	ethrpc.RegisterProviderURLs(strings.Split(urls, ",")...)
	f[chain] = append(f[chain], strings.Split(urls, ",")...)
	return nil
}

type line struct {
	ProofID  string          `json:"proof_id"`
	BundleID string          `json:"bundle_id"`
	Comp5    json.RawMessage `json:"comp5"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("finalitylegacyheaders", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "JSON lines of legacy execution-proof components")
	storeDir := fs.String("store", "", "directory to keep the verified headers in (default: memory)")
	gap := fs.Duration("gap", 150*time.Millisecond, "pause between legs")
	timeout := fs.Duration("timeout", 60*time.Second, "per provider request")
	urls := rpcFlags{}
	fs.Var(urls, "rpc", "chain=url[,url...] (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || len(urls) == 0 {
		fmt.Fprintln(stderr, "usage: finalitylegacyheaders -in FILE -rpc CHAIN=URL[,URL...] [-rpc ...] [-store DIR]")
		return 2
	}
	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer f.Close()
	var store finality.CaptureStore = finality.NewMemCaptureStore()
	if *storeDir != "" {
		ds, err := finality.NewDirCaptureStore(*storeDir)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		store = ds
	}
	src := &legacyhdr.RPCSource{URLs: urls, Client: &http.Client{Timeout: *timeout}}

	counts := map[string]map[string]int{} // chain -> state -> n
	failures := map[string]int{}
	n, derived := 0, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	ctx := context.Background()
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			fmt.Fprintf(stderr, "line %d: %v\n", n+1, err)
			return 2
		}
		n++
		leg, perr := legacyhdr.ParseLeg(l.ProofID, l.BundleID, l.Comp5)
		chainKey, state, detail := strconv.FormatUint(leg.Chain, 10), legacyhdr.StateInvalid, ""
		if perr != nil {
			detail = perr.Error()
			failures["unreadable component"]++
		} else {
			out := legacyhdr.Judge(ctx, leg, store, src, nil)
			state = out.State
			switch out.State {
			case legacyhdr.StateReconstructed:
				// the Settlement the new-shape path holds: level 1 must derive from it
				hdr, _, _ := store.Get(ctx, leg.Key())
				if _, err := finality.DeriveIncluded(leg.Chain, leg.Settlement(hdr)); err != nil {
					state, detail = legacyhdr.StateInvalid, "level 1 does not derive: "+err.Error()
					failures["level 1 does not derive"]++
				} else {
					derived++
					detail = fmt.Sprintf("fetched=%t", out.Fetched)
				}
			case legacyhdr.StateUnserved:
				detail = out.Cause
				failures["unserved (no provider served the block)"]++
			case legacyhdr.StateInvalid:
				detail = out.Cause
				if out.Named != nil {
					failures["invalid: "+fmt.Sprint(out.Named.Fields["check"])]++
				}
			default:
				detail = out.Cause
				failures["pending: "+out.Cause]++
			}
		}
		if counts[chainKey] == nil {
			counts[chainKey] = map[string]int{}
		}
		counts[chainKey][state]++
		fmt.Fprintf(stdout, "%s chain=%s block=%d %s %s\n", l.ProofID, chainKey, leg.BlockNumber, state, detail)
		time.Sleep(*gap)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	chains := make([]string, 0, len(counts))
	for c := range counts {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	total := 0
	fmt.Fprintf(stdout, "\nSUMMARY legs=%d level1_derived=%d\n", n, derived)
	for _, c := range chains {
		m := counts[c]
		fmt.Fprintf(stdout, "  chain %s: reconstructed %d, unserved %d, invalid %d, pending %d\n", c, m[legacyhdr.StateReconstructed], m[legacyhdr.StateUnserved], m[legacyhdr.StateInvalid], m[legacyhdr.StatePending])
		total += m[legacyhdr.StateReconstructed]
	}
	reasons := make([]string, 0, len(failures))
	for r := range failures {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		fmt.Fprintf(stdout, "  not reconstructed: %d x %s\n", failures[r], r)
	}
	if total != n || derived != n {
		return 1
	}
	return 0
}
