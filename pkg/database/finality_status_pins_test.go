// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX (Addendum C item 7): the pins hash the builder recorded in a status document comes back with the row, and a row
// without one comes back without one (rows written before the member existed).
func TestFinalityStatusRowRoundTripsThePinsHashTheBuilderJudgedUnder(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	pd := &finality.PendingState{Chain: finality.ChainBaseSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, Reason: "awaiting_batch_post"}
	row := finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, finality.LevelIncluded, pd, nil, false, time.Now())
	row.PinsSHA256 = strings.Repeat("cd", 32)
	if err := repo.UpsertStatus(ctx, row); err != nil {
		t.Fatal(err)
	}
	got, ok, err := repo.GetStatus(ctx, pid, finality.LevelL1Posted)
	if err != nil || !ok || got.PinsSHA256 != row.PinsSHA256 || got.Class != finality.BuilderPending {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	row.PinsSHA256 = ""
	row.JudgedAt = time.Time{}
	later := row
	if err := repo.UpsertStatus(ctx, later); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := repo.GetStatus(ctx, pid, finality.LevelL1Posted); got.PinsSHA256 != "" {
		t.Fatalf("a later row with no pins hash kept the older one: %q", got.PinsSHA256)
	}
	row.PinsSHA256 = "not-a-hash"
	if err := repo.UpsertStatus(ctx, row); err == nil {
		t.Fatal("a malformed pins hash was stored")
	}
}
