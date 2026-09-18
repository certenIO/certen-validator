// schemamigrate applies the shared schema catalog to a database, once, and exits.
//
// The validator applies migrations only when MIGRATE_ON_START=true; otherwise it verifies and refuses to
// run against a schema older than its catalog. That is the right default for a fleet — a binary must not
// silently run against a schema it does not understand — but it leaves no way to migrate WITHOUT starting
// a validator, which during an outage is exactly what an operator needs: bring the schema forward, then
// let the fleet come back on its own.
//
// It calls schema.Runner.Up, the same code path MIGRATE_ON_START takes, so the history rows and their
// checksums are written by the runner rather than by hand. Hand-inserting a history row would have to
// reproduce the migration's SHA-256 exactly, and getting it wrong fails Verify in a way that looks like
// corruption.
//
//	DATABASE_URL=... schemamigrate            # apply pending migrations
//	DATABASE_URL=... schemamigrate -verify    # report the gap, change nothing
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"

	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
)

func main() {
	verifyOnly := flag.Bool("verify", false, "report whether the schema satisfies this catalog; write nothing")
	appliedBy := flag.String("applied-by", "schemamigrate", "recorded in certen_schema_history.applied_by")
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

	required, err := schema.LatestVersion()
	if err != nil {
		log.Fatalf("loading catalog: %v", err)
	}
	runner := schema.Runner{DB: db}
	ctx := context.Background()

	if *verifyOnly {
		if err := runner.Verify(ctx, required); err != nil {
			log.Fatalf("schema does NOT satisfy catalog version %s: %v", required, err)
		}
		log.Printf("schema satisfies catalog version %s", required)
		return
	}

	log.Printf("applying catalog through %s", required)
	if err := runner.Up(ctx, *appliedBy); err != nil {
		log.Fatalf("migration failed: %v", err)
	}
	if err := runner.Verify(ctx, required); err != nil {
		log.Fatalf("migration reported success but verification failed: %v", err)
	}
	log.Printf("schema now satisfies catalog version %s", required)
}
