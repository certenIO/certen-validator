package main

// The RB9-E commands (live hard cases for the cross-partition G1, docs/proof/G1_CROSS_PARTITION.md): the same style as the
// signature-type run - keys generated here and kept in the gitignored keys/, every write confirmed by reading it back, the
// sponsor key only from ETH_PRIVATE_KEY in the process environment.
//
//	sigtypelive g1route [-from 500 -to 560]                   where identities live (g1route.go)
//	sigtypelive g1setup  -kind cross -n 508 -want-cust BVN2 -want-bank BVN3
//	                                                          create the scenario's identities, books, delegation chain, data account
//	sigtypelive g1account -n 508 -rpc <base sepolia rpc> -create -fund 20000000000000
//	                                                          the CertenAccount of pv2-cust-<n> (governing book pv2-cust-<n>.acme/book)
//	sigtypelive g1intent -kind cross -n 508 [-out captures-g1] write the scenario's CERTEN_INTENT and wait for delivery
//
// kinds: same (the customer's book alone: the regression), cross (customer book + a foreign book, both required: the tcl model),
// bankonly (the foreign book alone), deleg (the foreign book's page delegates, -depth hops through -hosts identities).

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type g1Flags struct {
	kind, hosts, wantCust, wantBank, wantDel, out, accounts, rpc, factory string
	n, depth                                                              int
	create                                                                bool
	fund                                                                  string
	keys                                                                  string
	wait                                                                  time.Duration
}

func parseG1(cmd string, args []string) (g1Flags, g1Topo) {
	var f g1Flags
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.StringVar(&f.kind, "kind", "cross", "same|cross|bankonly|deleg")
	fs.IntVar(&f.n, "n", 0, "scenario number: acc://pv2-cust-<n>.acme and pv2-bank-<n>")
	fs.IntVar(&f.depth, "depth", 0, "deleg: delegators between the bank book's page and the key")
	fs.StringVar(&f.hosts, "hosts", "", "deleg: comma-separated numbers of the pv2-deleg-<h> identities hosting the chain")
	fs.StringVar(&f.wantCust, "want-cust", "", "partition the customer identity must route to")
	fs.StringVar(&f.wantBank, "want-bank", "", "partition the bank identity must route to")
	fs.StringVar(&f.wantDel, "want-deleg", "", "comma-separated partitions of the -hosts, in order")
	fs.StringVar(&f.out, "out", "captures-g1", "where the intent's capture is written")
	fs.StringVar(&f.accounts, "accounts", filepath.Join("captures-g1", "accounts.json"), "g1account: accounts file (scenario tag -> address)")
	fs.StringVar(&f.rpc, "rpc", "", "g1account: JSON-RPC URL of Base Sepolia")
	fs.StringVar(&f.factory, "factory", factoryV11Address, "g1account: CertenAccountFactoryV11")
	fs.BoolVar(&f.create, "create", false, "g1account: create the missing account (sender key from ETH_PRIVATE_KEY in the environment only)")
	fs.StringVar(&f.fund, "fund", "0", "g1account: fund the account up to this many wei")
	fs.StringVar(&f.keys, "keys", "keys", "key directory root (gitignored)")
	fs.DurationVar(&f.wait, "wait", 5*time.Minute, "how long to wait for the intent to be delivered")
	_ = fs.Parse(args)
	t := g1Topo{Kind: f.kind, N: f.n, Depth: f.depth, WantCst: f.wantCust, WantBnk: f.wantBank}
	for _, h := range strings.Split(f.hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			v, err := strconv.Atoi(h)
			if err != nil {
				fatal("-hosts %q: %v", f.hosts, err)
			}
			t.Hosts = append(t.Hosts, v)
		}
	}
	for _, p := range strings.Split(f.wantDel, ",") {
		if p = strings.TrimSpace(p); p != "" {
			t.WantDel = append(t.WantDel, p)
		}
	}
	return f, t
}

func runG1(cmd string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()
	a := &app{k: newKermit(kermitV3)}
	var err error
	switch cmd {
	case "g1route":
		err = a.g1route(ctx, args)
	case "g1setup", "g1intent":
		f, t := parseG1(cmd, args)
		if f.n == 0 {
			fatal("-n is required")
		}
		var e *g1Env
		if e, err = newG1Env(ctx, a.k, f.keys, fmt.Sprintf("%s-%d", t.Kind, t.N)); err != nil {
			break
		}
		var plan *g1Plan
		if plan, err = e.setup(ctx, t); err != nil {
			break
		}
		fmt.Printf("placement (routing table, both sources agree):\n")
		for _, k := range sortedKeys(plan.Placement) {
			fmt.Printf("  %-22s %s\n", k, plan.Placement[k])
		}
		if t.Kind == "authop" {
			// the transactions to capture, with the time each was executed (the pages are servable for about 945 s)
			b, _ := json.MarshalIndent(e.ops, "", "  ")
			dir := filepath.Join(f.out, fmt.Sprintf("authop-%d", t.N))
			if err = os.MkdirAll(dir, 0o755); err == nil {
				err = os.WriteFile(filepath.Join(dir, "ops.json"), append(b, byte(10)), 0o644)
			}
			fmt.Printf("account-level transactions executed:%c%s%c", 10, b, 10)
			break
		}
		if cmd == "g1intent" {
			accts, aerr := parseAccounts(f.accounts, "", nil)
			if aerr != nil {
				err = aerr
				break
			}
			tag := fmt.Sprintf("g1-%d", t.N)
			from, ok := accts[tag]
			if !ok {
				err = fmt.Errorf("no CertenAccount for %s in %s: run g1account first", tag, f.accounts)
				break
			}
			_, err = e.submit(ctx, t, plan, from, f.wait, f.out)
		}
	case "g1account":
		f, _ := parseG1(cmd, args)
		if f.n == 0 {
			fatal("-n is required")
		}
		fundWei, ok := bigFromDec(f.fund)
		if !ok {
			fatal("-fund %q is not a wei amount", f.fund)
		}
		cust := adiURL(fmt.Sprintf("pv2-cust-%d", f.n))
		err = accountsOf(ctx, liveConfig{RPC: f.rpc}, accountsOpts{Factory: f.factory, Create: f.create, FundWei: fundWei, File: f.accounts},
			[]acctTarget{{Name: "g1", Tag: fmt.Sprintf("g1-%d", f.n), ADI: cust, Book: cust + "/book"}})
	default:
		fmt.Fprintln(os.Stderr, "usage: sigtypelive g1route|g1setup|g1account|g1intent (see g1main.go)")
		os.Exit(2)
	}
	if err != nil {
		fatal("%v", err)
	}
}
