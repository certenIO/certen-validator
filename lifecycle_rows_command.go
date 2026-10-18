package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/intent"
)

const lifecycleRowsUsage = "usage: certen-validator repair lifecycle-rows --block N --intent ID [--intent ID ...] [--apply]"

// runLifecycleRowsCommand runs `validator repair lifecycle-rows` (RB8-F, defect D4): intents whose discovery never wrote
// the intent_lifecycle row (a context that had expired, a database that refused the write) are owed that row. Without
// --apply it reads the lifecycle table and says which of the named intents have a row and which do not, and writes
// nothing. With --apply it adds the missing ones to this validator's owed-write journal (lifecycle_upserts.json in its
// data directory); the RUNNING validator's discovery loop then writes each row from the intent's own Directory Network
// block, exactly as discovery would have, within 15 seconds. An intent that already has a row is left alone, and the
// write is idempotent. Run it once, on any one validator: the lifecycle table is shared.
//
// Exit status: 0 when every named intent has a row (dry run) or was requested, 2 when one is not in its block, 1 on error.
func runLifecycleRowsCommand(args []string) int {
	var block uint64
	var ids []string
	apply := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--apply":
			apply = true
		case "--block", "--intent":
			if i+1 >= len(args) || args[i+1] == "" {
				log.Print(lifecycleRowsUsage)
				return 1
			}
			if args[i] == "--block" {
				n, err := strconv.ParseUint(args[i+1], 10, 64)
				if err != nil || n == 0 {
					log.Print(lifecycleRowsUsage)
					return 1
				}
				block = n
			} else {
				ids = append(ids, args[i+1])
			}
			i++
		default:
			log.Print(lifecycleRowsUsage)
			return 1
		}
	}
	if block == 0 || len(ids) == 0 {
		log.Print(lifecycleRowsUsage)
		return 1
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	type line struct {
		IntentID string `json:"intent_id"`
		HasRow   bool   `json:"has_row"`
		Status   string `json:"status,omitempty"`
		Action   string `json:"action"`
	}
	var out []line
	var owed []intent.PendingRetry
	for _, id := range ids {
		row, err := repo.GetByIntentID(ctx, id)
		switch {
		case err == nil:
			out = append(out, line{IntentID: id, HasRow: true, Status: string(row.Status), Action: "has a row; left alone"})
		case err == database.ErrIntentLifecycleNotFound:
			act := "no row: would be owed (use --apply)"
			if apply {
				act = "no row: owed to the running validator's discovery loop"
				owed = append(owed, intent.PendingRetry{IntentID: id, BlockHeight: block})
			}
			out = append(out, line{IntentID: id, Action: act})
		default:
			log.Printf("❌ lifecycle row of %s could not be read: %v", id, err)
			return 1
		}
	}
	if apply && len(owed) > 0 {
		dataDir := cfg.DataDir
		if dataDir == "" {
			dataDir = "data"
		}
		j, err := intent.OpenFileRetryJournal(filepath.Join(dataDir, intent.LifecycleQueueFile))
		if err != nil {
			log.Printf("❌ %v", err)
			return 1
		}
		if err := intent.RequestLifecycleRows(j, owed); err != nil {
			log.Printf("❌ %v", err)
			return 1
		}
	}
	blob, _ := json.MarshalIndent(out, "", "  ")
	fmt.Fprintln(os.Stdout, string(blob))
	return 0
}
