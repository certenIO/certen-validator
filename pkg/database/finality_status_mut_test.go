// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// Mutation-gate killers for FinalityStatusRepository (RB12-DBFIX): the refusals of UpsertStatus before any query, the database's
// error from both methods, and a stored document that does not read back.

func TestUpsertStatusRefusesByNameBeforeAnyQuery(t *testing.T) {
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	at := time.Now()

	// a proof id that is not a UUID is the error ParseProofID names, not a database error
	_, want := finality.ParseProofID("not-a-uuid")
	pd := &finality.PendingState{Chain: finality.ChainBaseSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, Reason: "awaiting_batch_post"}
	bad := finality.BuilderStatusOf("not-a-uuid", finality.ChainBaseSepolia, finality.LevelL1Posted, finality.LevelIncluded, pd, nil, false, at)
	if err := repo.UpsertStatus(canceled(), bad); err == nil || want == nil || err.Error() != want.Error() {
		t.Errorf("a bad proof id: %v, want %v", err, want)
	}

	// a verified status names the addendum of its own level: seq > 0 and levelReached = target
	for name, row := range map[string]finality.BuilderStatus{
		"seq 0":                  finality.VerifiedBuilderStatus(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, 0, at),
		"levelReached != target": {ProofID: pid, Chain: finality.ChainBaseSepolia, TargetLevel: finality.LevelL1Posted, Class: finality.BuilderVerified, LevelReached: finality.LevelFinalized, NextLevel: finality.LevelL1Posted, Seq: 1, JudgedAt: at},
	} {
		err := repo.UpsertStatus(canceled(), row) // refused before a query: the cancelled context is never looked at
		st, ok := finality.AsNamed(err)
		if !ok || st.Code != finality.CodeGuardRefused || !strings.Contains(st.Fields["cause"].(string), "seq > 0") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a verified status that is well formed passes this check and meets the database (here: the cancelled context)
	ok := finality.VerifiedBuilderStatus(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, 1, at)
	if err := repo.UpsertStatus(canceled(), ok); !errors.Is(err, context.Canceled) {
		t.Errorf("a well formed verified status: %v", err)
	}
	// a status the document cannot render (a pending row that names no state) is the document's error
	broken := finality.BuilderStatus{ProofID: pid, Chain: finality.ChainBaseSepolia, TargetLevel: finality.LevelL1Posted, Class: finality.BuilderPending, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, JudgedAt: at}
	if err := repo.UpsertStatus(canceled(), broken); err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "names its state") {
		t.Errorf("a pending row with no state: %v", err)
	}
}

func TestStatusRepositoryReturnsTheDatabasesErrorAndRefusesAStoredDocumentThatDoesNotRead(t *testing.T) {
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	at := time.Now()
	pd := &finality.PendingState{Chain: finality.ChainBaseSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, Reason: "awaiting_batch_post"}
	row := finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, finality.LevelIncluded, pd, nil, false, at)
	if err := repo.UpsertStatus(canceled(), row); !errors.Is(err, context.Canceled) {
		t.Errorf("UpsertStatus on a database that cannot answer: %v", err)
	}
	if _, ok, err := repo.GetStatus(canceled(), pid, finality.LevelL1Posted); !errors.Is(err, context.Canceled) || ok {
		t.Errorf("GetStatus on a database that cannot answer: %v %v", ok, err)
	}
	if _, ok, err := repo.GetStatus(context.Background(), "not-a-uuid", finality.LevelL1Posted); err == nil || ok {
		t.Errorf("GetStatus of a bad proof id: %v %v", ok, err)
	}
	// a row whose document is not a certen-finality-status/1 document (written by hand, or by a newer writer): an error, never a row
	if _, err := testDB.Exec(`INSERT INTO proof_finality_status (proof_id, chain, target_level, state) VALUES ($1::uuid, $2, $3, $4::jsonb)`,
		pid, int64(finality.ChainBaseSepolia), int16(finality.LevelFinalized), `{"format":"certen-finality-status/9","class":"pending"}`); err != nil {
		t.Fatal(err)
	}
	v, ok, err := repo.GetStatus(context.Background(), pid, finality.LevelFinalized)
	if err == nil || ok || v.ProofID != "" || !strings.Contains(err.Error(), "status of "+pid) {
		t.Errorf("a stored document of another format: %+v %v %v", v, ok, err)
	}
}
