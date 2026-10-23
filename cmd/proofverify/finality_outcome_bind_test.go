// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// RB12-DBFIX (Addendum C item 8): an exported outcome evidence file is the Settlement source of a portable document's finality
// section. The pair must be one pair: the outcome's chain and the block that holds its recorded transaction are the document's carried
// leg, or the verifier refuses by name (outcome_not_bound{field}) before it judges a single addendum - and the report says which
// transaction it judged and that the document, which names no settlement transaction, cannot bind that transaction itself.

func outcomeDoc(t *testing.T, carried finality.BlockRef) (string, *legSettlement) {
	t.Helper()
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	s := finality.Settlement{Chain: leg.chain, Included: leg.s}
	s.Subject, _ = finality.SubjectOfSettlement(leg.s)
	section := finality.NewSection(carried, chainFor(t, s, uuid.New(), finality.LegBindingOf(block), finality.LevelL1Posted))
	raw, err := json.Marshal(map[string]any{"finality": section})
	if err != nil {
		t.Fatal(err)
	}
	return writeDoc(t, raw), leg
}

func TestOutcomeFileIsBoundToTheDocumentsCarriedLegByChainBlockNumberAndBlockHash(t *testing.T) {
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, field string
		mutate      func(*finality.BlockRef)
	}{
		{"another chain", "chain", func(b *finality.BlockRef) { b.Chain = finality.ChainSepolia }},
		{"another block number", "block_number", func(b *finality.BlockRef) { b.Number++ }},
		{"another block hash", "block_hash", func(b *finality.BlockRef) { b.Hash[31] ^= 1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			carried := block
			carried.HeaderRLP = nil
			c.mutate(&carried)
			path, leg := outcomeDoc(t, carried)
			code, out := verifyFileWith(t, path, baseRegistry(), leg)
			want := "outcome_not_bound{field=" + c.field + ","
			if code != exitFailed || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want FAILED naming %s\n%s", code, want, out)
			}
			if strings.Contains(out, "VERIFIED") || strings.Contains(out, "level reached") {
				t.Fatalf("addenda were judged against an outcome that is not the document's leg:\n%s", out)
			}
		})
	}
}

func TestOutcomeFileReportNamesTheTransactionItJudgedAndWhatBindsIt(t *testing.T) {
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	carried := block
	carried.HeaderRLP = nil
	path, leg := outcomeDoc(t, carried)
	code, out := verifyFileWith(t, path, baseRegistry(), leg)
	ev := loadFixture(t, 84532)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"outcome transaction " + strings.ToLower(ev.Record.Tx) + " on chain 84532 in block " + fmt.Sprint(ev.Record.BlockNumber),
		"bound to the document's carried leg by chain, block number and block hash",
		"outcome_tx_unbound{reason=document_names_no_settlement_tx}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the report does not say %q:\n%s", want, out)
		}
	}
}

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
