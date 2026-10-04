package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
)

const staleLifecycleUsage = "usage: certen-validator repair stale-lifecycle [--apply] [--older-than DURATION] [--by NAME]"

// runStaleLifecycleCommand runs `validator repair stale-lifecycle` (RB6-F12): it lists every intent left `authorized` past
// the horizon with no member outcome, with the evidence each is judged on, and with --apply resolves to failed /
// processing_failed every one of them that nothing executed for - no batch ever anchored, no chain execution recorded -
// keeping the replaced state as a correction (database.ResolveStaleIntent). One that may have executed is listed and left.
// Run it once, on any validator: the lifecycle store is shared.
//
// Exit status: 0 on success, 1 on error.
func runStaleLifecycleCommand(args []string) int {
	apply, olderThan, by := false, 24*time.Hour, "repair stale-lifecycle"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--apply":
			apply = true
		case "--older-than", "--by":
			if i+1 >= len(args) {
				log.Print(staleLifecycleUsage)
				return 1
			}
			if args[i] == "--by" {
				by = args[i+1]
			} else {
				d, err := time.ParseDuration(args[i+1])
				if err != nil || d < time.Hour {
					log.Printf("--older-than must be a duration of at least 1h: %q", args[i+1])
					return 1
				}
				olderThan = d
			}
			i++
		default:
			log.Print(staleLifecycleUsage)
			return 1
		}
	}
	cfg, err := config.Load()
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		log.Printf("database: %v", err)
		return 1
	}
	defer client.Close()
	repo := database.NewIntentLifecycleRepository(client)
	ctx := context.Background()
	horizon := time.Now().Add(-olderThan)
	stale, err := repo.StaleIntents(ctx, horizon)
	if err != nil {
		log.Printf("❌ %v", err)
		return 1
	}
	type line struct {
		database.StaleIntent
		Action string `json:"action"`
	}
	var out []line
	resolved, kept := 0, 0
	for _, s := range stale {
		action := "would resolve: failed / processing_failed"
		if s.AnchoredBatch != 0 || s.Executions != 0 {
			action = "LEFT: a batch was anchored or a chain execution is recorded - it may have executed"
			kept++
		} else if apply {
			ok, err := repo.ResolveStaleIntent(ctx, s, horizon, by)
			if err != nil {
				log.Printf("❌ %s: %v", s.IntentID, err)
				return 1
			}
			if ok {
				action = "resolved: failed / processing_failed (correction recorded)"
				resolved++
			} else {
				action = "LEFT: it no longer qualifies"
				kept++
			}
		}
		out = append(out, line{s, action})
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Fprintln(os.Stdout, string(enc))
	log.Printf("%d stale intent(s) authorized before %s: %d resolved, %d left (apply=%v)", len(stale), horizon.UTC().Format(time.RFC3339),
		resolved, kept, apply)
	return 0
}
