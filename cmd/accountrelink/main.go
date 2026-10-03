// Copyright 2026 Certen Protocol

// accountrelink relinks a chain's CertenAccountV7_2 accounts (factory V10) to CertenAccountV7_3 accounts (factory V11)
// before the chain's account leaf version moves to v4 (RB5-F57). It reads only; it never signs, creates or sends.
//
//	accountrelink inventory --rpc <url> [--rpc <url> ...] --factory-v10 <addr> --v72-artifact <CertenAccountV7_2.json> --out inventory.json
//	accountrelink plan      --inventory inventory.json --factory-v11 <addr> --v73-artifact <CertenAccountV7_3.json> --deadline <RFC3339> --chain-name "base sepolia" --out plan.json
//	accountrelink verify    --rpc <url> [...] --plan plan.json --out verification.json
//	accountrelink retire    --plan plan.json --verification verification.json --out retired.json
//
// Every chain read is made at the chain's finalized block, from every --rpc given at the same block hash; a
// disagreement is refused by name. Exit 0 on success, 1 on any error, 3 when verify finds an account not relinked.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: accountrelink inventory|plan|verify|retire [flags]")
		os.Exit(1)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		if err == errNotRelinked {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "accountrelink:", err)
		os.Exit(1)
	}
}

var errNotRelinked = fmt.Errorf("an account is not relinked")

func dial(ctx context.Context, urls []string) ([]chainReader, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("at least one --rpc is required")
	}
	var out []chainReader
	for _, u := range urls {
		c, err := ethclient.DialContext(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("dial provider: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func run(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var rpcs multiFlag
	fs.Var(&rpcs, "rpc", "JSON-RPC endpoint (repeatable; every one must agree)")
	factoryV10 := fs.String("factory-v10", "0xaE0466c64b562cC623e1CcF142719d51Dd8EEa82", "CertenAccountFactoryV10")
	factoryV11 := fs.String("factory-v11", "", "CertenAccountFactoryV11")
	v72 := fs.String("v72-artifact", "", "Foundry artifact of CertenAccountV7_2")
	v73 := fs.String("v73-artifact", "", "Foundry artifact of CertenAccountV7_3")
	invPath := fs.String("inventory", "", "inventory file")
	planPath := fs.String("plan", "", "plan file")
	verPath := fs.String("verification", "", "verification file")
	deadline := fs.String("deadline", "", "the relink legs' signed deadline (RFC3339), before the cut-over")
	chainName := fs.String("chain-name", "base sepolia", "the chain's name in the relink legs")
	logChunk := fs.Uint64("log-chunk", 10000, "blocks per Transfer-log query")
	out := fs.String("out", "-", "output file (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	switch cmd {
	case "inventory":
		if *v72 == "" {
			return fmt.Errorf("--v72-artifact is required: every account's address is re-derived before its V11 address is trusted")
		}
		code, err := creationCodeOf(*v72)
		if err != nil {
			return err
		}
		ps, err := dial(ctx, rpcs)
		if err != nil {
			return err
		}
		inv, err := ReadInventory(ctx, ps, common.HexToAddress(*factoryV10), code, *logChunk)
		if err != nil {
			return err
		}
		return writeJSON(*out, inv)
	case "plan":
		if *factoryV11 == "" || *v73 == "" || *invPath == "" || *deadline == "" {
			return fmt.Errorf("plan needs --inventory, --factory-v11, --v73-artifact and --deadline")
		}
		var inv Inventory
		if err := readJSON(*invPath, &inv); err != nil {
			return err
		}
		code, err := creationCodeOf(*v73)
		if err != nil {
			return err
		}
		d, err := time.Parse(time.RFC3339, *deadline)
		if err != nil {
			return fmt.Errorf("--deadline: %w", err)
		}
		plan, err := MakePlan(&inv, common.HexToAddress(*factoryV11), code, d, *chainName)
		if err != nil {
			return err
		}
		return writeJSON(*out, plan)
	case "verify":
		var plan Plan
		if err := readJSON(*planPath, &plan); err != nil {
			return err
		}
		ps, err := dial(ctx, rpcs)
		if err != nil {
			return err
		}
		v, err := Verify(ctx, ps, &plan)
		if err != nil {
			return err
		}
		if err := writeJSON(*out, v); err != nil {
			return err
		}
		for _, s := range v.Statuses {
			if s.State == "not relinked" {
				return errNotRelinked
			}
		}
		return nil
	case "retire":
		var plan Plan
		var v Verification
		if err := readJSON(*planPath, &plan); err != nil {
			return err
		}
		if err := readJSON(*verPath, &v); err != nil {
			return err
		}
		return writeJSON(*out, Retire(&plan, &v, plan.Inventory.ChainID))
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
