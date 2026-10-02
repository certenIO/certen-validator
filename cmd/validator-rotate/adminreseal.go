package main

// The admin re-seal subcommand (rules v11, pkg/consensus/admin_reseal.go):
//
//	validator-rotate admin-reseal --rpc http://v1:26657,http://v2:26657,... [--dry-run]
//
// Every validator must run rules v11 on certen-testnet, within maxHeightLag of the highest - a node on older rules
// judges the transaction as a ValidatorBlock. GO, it commits the one re-seal the rule accepts (no signature: its
// authority is the rule) through the first RPC and prints the height; from the next height the admin set is the one
// written into the rule.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
)

// adminResealRulesVersion is the execution-rules version that recognises the re-seal.
const adminResealRulesVersion = 11

func adminReseal(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("admin-reseal", flag.ContinueOnError)
	rpcs := fs.String("rpc", "", "every validator's CometBFT RPC, comma-separated")
	dryRun := fs.Bool("dry-run", false, "check every validator is ready, commit nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*rpcs) == "" {
		return errors.New("--rpc is required (every validator)")
	}
	var views []*nodeView
	for _, base := range strings.Split(*rpcs, ",") {
		v, err := readNode(c, strings.TrimSpace(base))
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		views = append(views, v)
	}
	if problems := adminResealPreflight(views); len(problems) > 0 {
		return fmt.Errorf("NO-GO:\n  %s", strings.Join(problems, "\n  "))
	}
	chainID := views[0].chainID
	fmt.Printf("GO: %d validators on %s run rules v%d\n", len(views), chainID, adminResealRulesVersion)
	tx := consensus.NewAdminResealTx(chainID)
	if *dryRun {
		fmt.Printf("dry run: would commit re-seal %s…\n", tx.ResealID()[:16])
		return nil
	}
	b, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	path := filepath.Join(os.TempDir(), "certen-admin-reseal-"+tx.ResealID()[:16]+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(path)
	h, err := broadcastCommit(c, views[0].rpc, path)
	if err != nil {
		return err
	}
	fmt.Printf("ACCEPTED at height %d (re-seal %s…). From height %d the admin set is the one rules v11 install.\n",
		h, tx.ResealID()[:16], h+1)
	return nil
}

// adminResealPreflight lists why the fleet is not ready for the re-seal: a node on another chain, on rules other than
// v11, or lagging.
func adminResealPreflight(views []*nodeView) []string {
	problems := fleetRulesProblems(views, adminResealRulesVersion, "admin re-seal")
	var top int64
	for _, v := range views {
		if v.height > top {
			top = v.height
		}
	}
	for _, v := range views {
		if v.chainID != views[0].chainID {
			problems = append(problems, fmt.Sprintf("%s is on chain %q, %s on %q", v.rpc, v.chainID, views[0].rpc, views[0].chainID))
		}
		if top-v.height > maxHeightLag {
			problems = append(problems, fmt.Sprintf("%s is at height %d, %d behind", v.rpc, v.height, top-v.height))
		}
	}
	return problems
}
