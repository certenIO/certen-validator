// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// RB12-DBFIX (Addendum C item 7): proofverify prints the pins the builder recorded in its status rows next to the pins it judged under.
func TestFinalityReportPrintsThePinsTheBuilderRecordedInItsStatusRows(t *testing.T) {
	url, err := testdb.PackageURL("proofverify")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(context.Background(), "proofverify-test"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	here, _ := pins.Identity()
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	id := uuid.MustParse(finalitytest.StoreProductionLeg(t, db, s))
	run := func() (int, string) {
		var out bytes.Buffer
		code := reportFinality(ctx, &out, db, id, baseRegistry(), pins)
		return code, out.String()
	}
	builderLines := func(out string) []string {
		var ls []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "  S7  builder pins") {
				ls = append(ls, l)
			}
		}
		return ls
	}

	baseCode, out := run()
	if ls := builderLines(out); len(ls) != 0 {
		t.Fatalf("a builder that judged nothing was reported:\n%s", out)
	}
	repo := database.NewFinalityStatusRepository(database.NewClientFromDB(db))
	pending := func(level finality.Level, pinsHash string) finality.BuilderStatus {
		pd := &finality.PendingState{Chain: s.Chain, LevelReached: finality.LevelIncluded, NextLevel: level, Reason: "awaiting_batch_post"}
		row := finality.BuilderStatusOf(id.String(), s.Chain, level, finality.LevelIncluded, pd, nil, false, time.Now())
		row.PinsSHA256 = pinsHash
		return row
	}
	other := strings.Repeat("ab", 32)
	for _, st := range []finality.BuilderStatus{pending(finality.LevelL1Posted, here), pending(finality.LevelFinalized, other)} {
		if err := repo.UpsertStatus(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	code, out := run()
	ls := builderLines(out)
	if len(ls) != 2 || code != baseCode {
		t.Fatalf("exit %d (without rows %d)\n%s", code, baseCode, out)
	}
	if !strings.Contains(ls[0], "l1_posted") || !strings.Contains(ls[0], here) || !strings.Contains(ls[0], "the pins used here") || strings.Contains(ls[0], "DIFFERENT") {
		t.Fatalf("l1_posted line: %q", ls[0])
	}
	if !strings.Contains(ls[1], "finalized") || !strings.Contains(ls[1], other) || !strings.Contains(ls[1], "DIFFERENT from the pins used here ("+here+")") {
		t.Fatalf("finalized line: %q", ls[1])
	}
	// a row written before the hash was recorded says so
	if err := repo.UpsertStatus(ctx, pending(finality.LevelFinalized, "")); err != nil {
		t.Fatal(err)
	}
	_, out = run()
	if ls := builderLines(out); len(ls) != 2 || !strings.Contains(ls[1], "not recorded") {
		t.Fatalf("a row with no pins hash:\n%s", out)
	}
}
