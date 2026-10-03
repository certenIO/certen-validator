package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/strategy"
)

// runOutcomeTreeRepair runs `validator repair outcome-trees [--apply]`: it rebuilds, into THIS validator's own kept-tree
// store, the tree of every V8.2 anchor whose proof executed and whose outcome is not recorded - anchors attested before
// validators kept the trees they sign (RB5 D4). The shared database supplies hints only; a tree is kept only when it
// rebuilds the anchor on the chain exactly (execution.OutcomeBackfill). Without --apply it only reports. Nothing is
// deleted, and a tree already kept is never overwritten. Run it on every validator: each keeps its own trees.
//
// Exit status: 0 when nothing was refused, 2 when an anchor was refused, 1 on error.
func runOutcomeTreeRepair(apply bool) int {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("load configuration: %v", err)
		return 1
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		log.Printf("connect database: %v", err)
		return 1
	}
	defer client.Close()
	latest, err := schema.LatestVersion()
	if err == nil {
		err = (schema.Runner{DB: client.DB()}).Verify(context.Background(), latest)
	}
	if err != nil {
		log.Printf("the schema is older than this binary (%v); run `validator migrate up` first", err)
		return 1
	}
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		log.Printf("anchor config: %v", err)
		return 1
	}
	chains, err := execution.SettlementChainsFromEnv(strategy.SupportedChainIDs)
	if err != nil {
		log.Print(err)
		return 1
	}
	// The trees are rebuilt with each chain's account leaf version, exactly as the validator forms them (RB5-F57).
	leafVersions, err := execution.AccountLeafVersionsFromEnv(chains)
	if err != nil {
		log.Print(err)
		return 1
	}
	execution.SetAccountLeafVersions(leafVersions)
	resolver, err := execution.NewEVMChainResolverFromEnv(anchorCfg, chains)
	if err != nil {
		log.Print(err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	outcomeChains, err := execution.OutcomeChainsFromEnv(ctx, resolver, chains)
	if err != nil {
		log.Print(err)
		return 1
	}
	readers := make(map[int64]execution.OutcomeChainReader, len(outcomeChains))
	for id, c := range outcomeChains {
		readers[id] = c
	}
	trees, err := execution.NewOutcomeTreeStore(execution.OutcomeTreeDir())
	if err != nil {
		log.Print(err)
		return 1
	}
	adapter, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{NetworkURL: cfg.AccumulateURL, RequestTimeout: 30 * time.Second})
	if err != nil {
		log.Printf("Accumulate client: %v", err)
		return 1
	}
	b := &execution.OutcomeBackfill{Chains: readers, Hints: database.NewBatchOutcomeRepository(client),
		Intents: execution.AccumulateIntentSource{Adapter: adapter, URL: cfg.AccumulateURL}, Trees: trees, Apply: apply, Logf: log.Printf}
	results, err := b.Run(ctx)
	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))
	if err != nil {
		log.Printf("outcome tree repair stopped: %v", err)
		return 1
	}
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Outcome]++
	}
	mode := "dry run: nothing was written; re-run with --apply"
	if apply {
		mode = "applied"
	}
	log.Printf("outcome tree repair (%s) into %s: %v", mode, trees.Dir(), counts)
	if counts["refused"] > 0 {
		return 2
	}
	return 0
}
