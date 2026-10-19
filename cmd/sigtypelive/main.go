// Copyright 2026 Certen Protocol

// sigtypelive - the live signature-type run against Kermit (RB8 phase D, gap G-42).
//
// It proves, with real Accumulate transactions, that a CERTEN intent approved by a key of each type Accumulate accepts
// is carried by the network and, after the RB8 deploy, settled and verified offline by CERTEN.
//
//	sigtypelive setup   -n 1                 create/complete acc://pv2-sig-1.acme: books, pages, data accounts (idempotent)
//	sigtypelive submit  -n 1 [-cases a,b]    write a CERTEN_INTENT per case, approved by that case's key; capture what Kermit
//	                                         delivered into captures/ (binary signature, JSON, key, tx hash)
//	sigtypelive accounts -rpc <url> [-create] [-fund wei]
//	                                         the CertenAccount of each case's governing key book on the target chain (one per book)
//	sigtypelive rerun   -n 1 -base <url>     submit every case, then assert each settles and verifies offline (see rerun.go)
//	sigtypelive vectors -n 1                  turn captures/ into kermit2.json + manifest2.json beside the shared sigtypes vectors (written once)
//
// Keys are generated locally and kept in keys/pv2-sig-<n>/ (gitignored). No owner, admin or production key is used.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if strings.HasPrefix(cmd, "g1") { // the RB9-E cross-identity / cross-partition / delegation scenarios (g1main.go)
		runG1(cmd, os.Args[2:])
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var (
		n        = fs.Int("n", 1, "identity number: acc://pv2-sig-<n>.acme")
		endpoint = fs.String("endpoint", kermitV3, "Accumulate v3 endpoint")
		keysDir  = fs.String("keys", "keys", "key directory root (gitignored)")
		outDir   = fs.String("out", "captures", "where captured evidence is written")
		cases    = fs.String("cases", "", "comma-separated case names (default: all)")
		chain    = fs.String("chain", "base-sepolia", "target chain of the intent leg")
		account  = fs.String("account", "", "CertenAccount(s), the leg's from: tag=0x..,tag=0x.. (each case's governing key book has its own account), or one bare address for a single selected case")
		accounts = fs.String("accounts", filepath.Join("captures", "accounts.json"), "accounts file written by `accounts` (tag -> address); -account is merged over it")
		factory  = fs.String("factory", factoryV11Address, "accounts: CertenAccountFactoryV11 on the target chain")
		create   = fs.Bool("create", false, "accounts: create the missing accounts (sender key from ETH_PRIVATE_KEY in the environment only)")
		dataRoot = fs.Bool("data-root", false, "write each intent to <adi>/data (the one principal CERTEN binds to the ADI's account); needs one ADI per case: -n <k> -cases <case>")
		fund     = fs.String("fund", "0", "accounts: fund each deployed account up to this many wei (sender key from ETH_PRIVATE_KEY)")
		rpc      = fs.String("rpc", "", "JSON-RPC URL of the target chain (accounts)")
		wait     = fs.Duration("wait", 0, "how long to wait for each transaction (0: the command's default - rerun 60m, the rest 5m)")
		base     = fs.String("base", "", "rerun: the proofs service / gateway base URL to read settlement and proofs from")
		ssh      = fs.String("ssh", "", "rerun: read-only ssh target (user@host) for settlement and offline verification")
		verify   = fs.String("verify", "", "rerun: offline verification command, with {proof} and {tx}, e.g. 'proofverify --offline --governance --l5 --proof-id {proof}'")
		vecDir   = fs.String("vectors", filepath.Join("accumulate-lite-client-2", "liteclient", "proof", "govsig", "testdata", "sigtypes"), "vectors: the directory holding manifest.json (read) and receiving kermit2.json + manifest2.json")
	)
	_ = fs.Parse(os.Args[2:])
	dataAtRoot = *dataRoot

	*wait = resolveWait(cmd, *wait)
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout(cmd, *wait, *cases))
	defer cancel()
	a := &app{
		k:   newKermit(*endpoint),
		adi: fmt.Sprintf("acc://pv2-sig-%d.acme", *n),
		ks:  keyStore{dir: filepath.Join(*keysDir, fmt.Sprintf("pv2-sig-%d", *n))},
	}
	live := liveConfig{Chain: *chain, RPC: *rpc, Out: *outDir, Wait: *wait, Cases: *cases, Base: *base, SSH: *ssh, Verify: *verify}
	if cmd == "submit" || cmd == "rerun" {
		sel, err := live.selected()
		if err != nil {
			fatal("%v", err)
		}
		if live.Accounts, err = parseAccounts(*accounts, *account, sel); err != nil {
			fatal("%v", err)
		}
	}

	var err error
	switch cmd {
	case "setup":
		err = a.setup(ctx, live)
	case "submit":
		_, err = a.submit(ctx, live)
	case "accounts":
		fundWei, ok := new(big.Int).SetString(*fund, 10)
		if !ok {
			fatal("-fund %q is not a wei amount", *fund)
		}
		err = a.accounts(ctx, live, accountsOpts{Factory: *factory, Create: *create, FundWei: fundWei, File: *accounts})
	case "rerun":
		err = a.rerun(ctx, live)
	case "vectors":
		err = a.vectors(ctx, live, *vecDir, *vecDir)
	default:
		usage()
	}
	if err != nil {
		fatal("%v", err)
	}
}

// Waits (RB8-E): a rerun waits for the lifecycle to be `complete`, which takes about 6 minutes for the Accumulate
// certificate and about 20 for the target chain's finality before the proof forms (more on a slow chain), so its default
// is 60 minutes; the 25 it used to wait ended runs that were still healthy. A submit only waits for delivery.
const (
	rerunWait   = 60 * time.Minute
	defaultWait = 5 * time.Minute
)

// resolveWait is the per-transaction wait: the one given, else the command's own default.
func resolveWait(cmd string, given time.Duration) time.Duration {
	if given > 0 {
		return given
	}
	if cmd == "rerun" {
		return rerunWait
	}
	return defaultWait
}

// overallTimeout bounds the whole command: a rerun waits up to `wait` for each of its cases in turn.
func overallTimeout(cmd string, wait time.Duration, cases string) time.Duration {
	if cmd != "rerun" {
		return 60 * time.Minute
	}
	n := 10 // all the cases
	if strings.TrimSpace(cases) != "" {
		n = strings.Count(cases, ",") + 1
	}
	return wait*time.Duration(n) + 30*time.Minute
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sigtypelive setup|submit|accounts|rerun [-n 1] [-cases a,b] [-chain base-sepolia] ...")
	os.Exit(2)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sigtypelive: "+format+"\n", args...)
	os.Exit(1)
}
