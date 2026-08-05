// costbackfill re-probes historical on-chain executions and reports their cost to the gateway.
//
// The validator has stored tx_hash for every execution since 2026-01-26, but nothing shipped
// those costs until the batch settle path began reporting on 2026-08-05. This recovers the
// measurable history.
//
// Run it where the validator runs: it needs DATABASE_URL, CERTEN_GATEWAY_URL, the validator
// service-token secret, and the per-chain RPC endpoints. Chains this process has no endpoint for
// are skipped and counted, not failed.
//
//	costbackfill -dry-run          # show what would be sent, probe nothing
//	costbackfill -limit 20         # prove the pipeline on a small sample first
//	costbackfill                   # the full run
//
// Safe to re-run: the reporter keys events on (chain, tx, leg), so anything already delivered
// collapses to the existing row at the gateway.
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/execution"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "list what would be reported without probing or sending")
	limit := flag.Int("limit", 0, "stop after this many rows (0 = all)")
	pause := flag.Duration("pause", 250*time.Millisecond, "delay between rows, to spare shared RPC endpoints")
	drain := flag.Duration("drain", 3*time.Minute, "how long to wait for in-flight probes and deliveries before exiting")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("opening database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("connecting to database: %v", err)
	}

	// Ctrl-C leaves already-queued events in the write-ahead log; they deliver on the
	// validator's next start. Nothing is lost by stopping early.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Starting the reporter also replays anything already sitting in the WAL.
	execution.StartCostReporter(log.Printf)

	rep, err := execution.RunCostBackfill(ctx, db, execution.CostBackfillOptions{
		DryRun: *dryRun,
		Limit:  *limit,
		Pause:  *pause,
		Logf:   log.Printf,
	})
	if err != nil {
		log.Fatalf("backfill failed: %v", err)
	}

	if *dryRun {
		log.Printf("dry run complete: %d candidate(s), %d would be reported, %d skipped for chain",
			rep.Candidates, rep.Reported, rep.SkippedChain)
		return
	}

	// ObserveAndReport is asynchronous — each probe retries with backoff for up to three
	// minutes. Exiting immediately would drop in-flight work on the floor; the WAL would still
	// hold it, but only until something restarts the validator. Waiting here means one run
	// finishes its own job.
	log.Printf("queued %d event(s); waiting up to %s for probes and delivery to drain",
		rep.Reported, *drain)
	select {
	case <-ctx.Done():
		log.Printf("interrupted; queued events remain in the WAL and will be replayed on next start")
	case <-time.After(*drain):
	}
	log.Printf("backfill run finished: %d reported across %d chain(s)", rep.Reported, len(rep.ByChain))
}
