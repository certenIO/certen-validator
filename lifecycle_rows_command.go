package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/intent"
)

const lifecycleRowsUsage = "usage: certen-validator repair lifecycle-rows --block N --intent ID [--intent ID ...] [--apply]"

// runLifecycleRowsCommand runs `validator repair lifecycle-rows` (RB8-F, defect D4): intents whose discovery never wrote
// the intent_lifecycle row (a context that had expired, a database that refused the write) are owed that row. Without
// --apply it reads the lifecycle table, searches the named Directory Network block, and says which of the named intents are
// in that block and which have a row; it writes nothing. With --apply it adds the missing ones to this validator's owed-write
// journal (lifecycle_upserts.json in its data directory); the RUNNING validator's discovery loop then writes each row from
// the intent's own Directory Network block, exactly as discovery would have, within 15 seconds. An intent that already has a
// row is left alone, and the write is idempotent. Run it once, on any one validator: the lifecycle table is shared.
//
// Before anything is owed the block is searched with the Accumulate client and each named intent is matched on its id exactly
// as discovery's retry matches it (intent.IntentsInBlock, RB8-G); every line reports in_block. An intent the block does not
// carry makes the request a mistake (a wrong --block or a wrong id): the command exits 2 and owes NOTHING, dry run or not.
//
// Exit status: 0 when every named intent is in its block and has a row (dry run) or was requested, 2 when one is not in its
// block, 1 on error (including a block that cannot be searched).
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
	acc, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{
		NetworkURL:     cfg.AccumulateURL,
		EnableCaching:  true,
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Printf("accumulate: %v", err)
		return 1
	}
	defer acc.Close()
	repo := database.NewIntentLifecycleRepository(client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	out, owed, code, err := planLifecycleRows(ctx, repo,
		func(h uint64) (map[string]bool, error) { return intent.IntentsInBlock(acc, h) }, block, ids, apply)
	if err != nil {
		log.Printf("❌ %v", err)
		return 1
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
	return code
}

// lifecycleRowReader is the part of the lifecycle repository the command reads.
type lifecycleRowReader interface {
	GetByIntentID(ctx context.Context, intentID string) (*database.IntentLifecycle, error)
}

// lifecycleRowsLine is the report of one named intent.
type lifecycleRowsLine struct {
	IntentID string `json:"intent_id"`
	InBlock  bool   `json:"in_block"`
	HasRow   bool   `json:"has_row"`
	Status   string `json:"status,omitempty"`
	Action   string `json:"action"`
}

// planLifecycleRows decides what is owed. blockIntents is the set of intent ids the named block carries (a search of the
// block; an error is returned, never read as an empty block). Every named intent is reported with in_block and has_row. When
// any is not in the block the exit status is 2 and nothing is owed - for the intents that are in it as well, because a name
// or a block that is wrong in one place is not trusted in another. Otherwise an intent without a row is owed (when apply), and
// one with a row is left alone.
func planLifecycleRows(ctx context.Context, rows lifecycleRowReader, blockIntents func(height uint64) (map[string]bool, error),
	block uint64, ids []string, apply bool) ([]lifecycleRowsLine, []intent.PendingRetry, int, error) {
	inBlock, err := blockIntents(block)
	if err != nil {
		return nil, nil, 1, fmt.Errorf("block %d cannot be searched, so no intent can be said to be in it: %w", block, err)
	}
	var out []lifecycleRowsLine
	var wanted []intent.PendingRetry
	absent := 0
	for _, id := range ids {
		l := lifecycleRowsLine{IntentID: id, InBlock: inBlock[id]}
		row, err := rows.GetByIntentID(ctx, id)
		switch {
		case err == nil:
			l.HasRow, l.Status = true, string(row.Status)
		case errors.Is(err, database.ErrIntentLifecycleNotFound):
		default:
			return nil, nil, 1, fmt.Errorf("lifecycle row of %s could not be read: %w", id, err)
		}
		switch {
		case !l.InBlock:
			absent++
			l.Action = fmt.Sprintf("not in block %d: nothing is owed", block)
		case l.HasRow:
			l.Action = "has a row; left alone"
		case apply:
			l.Action = "no row: owed to the running validator's discovery loop"
			wanted = append(wanted, intent.PendingRetry{IntentID: id, BlockHeight: block})
		default:
			l.Action = "no row: would be owed (use --apply)"
		}
		out = append(out, l)
	}
	if absent > 0 {
		for i := range out {
			if out[i].InBlock && !out[i].HasRow {
				out[i].Action = "no row, but another named intent is not in its block: nothing is owed"
			}
		}
		return out, nil, 2, nil
	}
	return out, wanted, 0, nil
}
