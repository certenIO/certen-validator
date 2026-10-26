// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"testing"
	"time"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

// statedLeg is a finished leg whose settle station captured nothing (a Stated settle part): the container states both parts, which the real
// Verify accepts as unproven when the context is complete and refuses when the stored rows leave it incomplete.
func statedLeg(t *testing.T, lc ci.LegContext) capture.CapturedLeg {
	t.Helper()
	blk := ci.BlockRef{Number: lc.S7.Block.Number, Hash: lc.S7.Block.Hash}
	return capture.CapturedLeg{Chain: lc.Chain, Tx: lc.Settlement.TxHash, Settle: capture.NotAttempted(lc.Chain, [32]byte{1}, blk, "no attestation capture")}
}

// isolateHash leaves proof pid the only proof that carries its settlement transaction (the shared test database holds every earlier test's proof of the
// same fixture leg, all with one hash): the other rows lose the recorded settlement, which LegSettlement treats as Unrecorded.
func isolateHash(t *testing.T, pid string) {
	t.Helper()
	if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = NULL WHERE proof_id <> $1::uuid AND lower(settlement_tx_hash) = (SELECT lower(settlement_tx_hash) FROM proof_artifacts WHERE proof_id = $1::uuid)`, pid); err != nil {
		t.Fatal(err)
	}
}

func newTestFinisher(t *testing.T) *IdentityFinisher {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewIdentityFinisher(context.Background(), NewClientFromDB(testDB), capture.NewMemStore(), m, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return f.WithTiming(0, time.Millisecond)
}

// WP-S8-7 on PostgreSQL: a finished leg (what capture.Deps.OnLeg delivers) is mapped to its proof by the settlement transaction, its context is
// composed from the stored rows, and the container is appended through the Appender with the REAL verifier; every other end is a named outcome
// that stores nothing.
func TestFinisherMapsALegToItsProofAndAppendsThroughTheRealVerify(t *testing.T) {
	ctx := context.Background()
	f := newTestFinisher(t)
	pid, lc := seedComposable(t)
	isolateHash(t, pid)
	leg := statedLeg(t, lc)

	// the OnLeg path (asynchronous) ends in the row
	f.OnLeg(leg)
	f.Wait()
	row, ok, err := f.repo.Latest(ctx, pid)
	if err != nil || !ok || row.Seq != 1 || row.Chain != lc.Chain {
		t.Fatalf("the leg must end as seq 1 of its proof: %+v %v %v", row, ok, err)
	}
	if out, err := f.Finish(ctx, leg); out != FinishDuplicate || err != nil {
		t.Fatalf("the same leg again is a duplicate: %s %v", out, err)
	}

	// another chain than the proof's leg: named, nothing stored
	wrong := leg
	wrong.Chain = lc.Chain + 1
	if out, _ := f.Finish(ctx, wrong); out != FinishChainMismatch {
		t.Fatalf("chain mismatch: %s", out)
	}
	// a transaction no proof carries (the wait is 0): no_proof
	unknown := leg
	unknown.Tx[0] ^= 0xff
	if out, _ := f.Finish(ctx, unknown); out != FinishNoProof {
		t.Fatalf("unknown transaction: %s", out)
	}
}

// Two proofs that carry one settlement hash (11 live hashes are shared) are ambiguous: nothing is stored for either.
func TestFinisherRefusesAnAmbiguousSettlementHashAndStoresNothing(t *testing.T) {
	ctx := context.Background()
	f := newTestFinisher(t)
	pid, lc := seedComposable(t)
	other, _ := storeLeg(t, "base_sepolia_47368146") // a second proof of the same settlement: the same hash
	out, err := f.Finish(ctx, statedLeg(t, lc))
	if out != FinishAmbiguous || err == nil {
		t.Fatalf("ambiguous: %s %v", out, err)
	}
	for _, id := range []string{pid, other} {
		if _, ok, _ := f.repo.Latest(ctx, id); ok {
			t.Fatalf("an ambiguous leg stores nothing, proof %s has a row", id)
		}
	}
}

// The real Verify refuses a container whose stored context is incomplete (a settled proof with no batch row: 192 of 575 live): named, no row.
func TestFinisherLeavesNoRowWhenTheRealVerifyRefusesTheStoredContext(t *testing.T) {
	ctx := context.Background()
	f := newTestFinisher(t)
	pid, lc := storeLegContext(t)
	isolateHash(t, pid)
	out, err := f.Finish(ctx, statedLeg(t, lc))
	if out != FinishRefused || err == nil {
		t.Fatalf("an incomplete stored context must be refused by the real Verify: %s %v", out, err)
	}
	if _, ok, _ := f.repo.Latest(ctx, pid); ok {
		t.Fatal("a refused container leaves no row")
	}
}
