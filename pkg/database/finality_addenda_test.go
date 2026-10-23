// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// storeLeg stores one real settled leg exactly as production does (summary-only proof_artifacts row with its settlement columns,
// the gzip bundle with component 5 in proof_bundles) and returns its proof id and settlement.
func storeLeg(t *testing.T, fixture string) (string, finality.Settlement) {
	t.Helper()
	s := finalitytest.Settlement(t, fixture)
	return finalitytest.StoreProductionLeg(t, testDB, s), s
}

// addendaChain builds the leg's chain for the given levels (Base kinds for a Base leg, the Adiri kind for Adiri), bound to the
// leg binding of the settlement's block.
func addendaChain(t *testing.T, proofID string, s finality.Settlement, levels ...finality.Level) []finality.Addendum {
	t.Helper()
	return addendaChainUnder(t, proofID, s, finality.LegBindingOf(s.Block()), levels...)
}

// addendaChainUnder is addendaChain bound to an arbitrary d0: the forged chain of a writer that is not the repository.
func addendaChainUnder(t *testing.T, proofID string, s finality.Settlement, d0 [32]byte, levels ...finality.Level) []finality.Addendum {
	t.Helper()
	pid, err := finality.ParseProofID(proofID)
	if err != nil {
		t.Fatal(err)
	}
	block := s.Block()
	var out []finality.Addendum
	for _, l := range levels {
		kind, err := finality.KindFor(block.Chain, l)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := finality.Container{Header: finality.ContainerHeader{Kind: kind, Chain: block.Chain, Level: l, BlockNumber: block.Number, BlockHash: block.Hash}, Body: []byte("b")}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		a, err := finality.NewAddendum(d0, pid, out, block.Chain, l, kind, ev)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func stateCode(err error) string {
	if n, ok := finality.AsNamed(err); ok {
		return n.Code
	}
	return ""
}

// The addenda are append-only at the repository AND in the database: a rewrite is refused by name through the repository,
// and the table itself refuses UPDATE, DELETE, TRUNCATE and an INSERT that does not extend the chain exactly.
func TestFinalityAddendaAreAppendOnly(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	proofID, settlement := storeLeg(t, "base_sepolia_47368146")
	reg := kindRegistry(t, nil)
	d0 := finality.LegBindingOf(settlement.Block())
	var chain []finality.Addendum
	for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
		a, err := repo.Append(ctx, appendRequest(t, reg, proofID, settlement, l, "b"))
		if err != nil {
			t.Fatalf("append %s: %v", l, err)
		}
		chain = append(chain, a)
	}
	got, err := repo.Chain(ctx, proofID)
	if err != nil || len(got) != 2 {
		t.Fatalf("read back: %v %d", err, len(got))
	}
	if err := finality.VerifyChain(d0, got); err != nil {
		t.Fatalf("the stored chain does not verify: %v", err)
	}
	rowCount := func() int {
		var n int
		if err := testDB.QueryRow(`SELECT count(*) FROM proof_finality_addenda WHERE proof_id = $1`, proofID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// -- repository level --
	t.Run("a second addendum at a stored level is level_already_present whatever its evidence, and changes nothing", func(t *testing.T) {
		for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
			if _, err := repo.Append(ctx, appendRequest(t, reg, proofID, settlement, l, "a different body")); stateCode(err) != finality.CodeLevelAlreadyPresent {
				t.Fatalf("%s: want %s, got %v", l, finality.CodeLevelAlreadyPresent, err)
			}
		}
		again, _ := repo.Chain(ctx, proofID)
		if len(again) != 2 || again[0].OwnHash != chain[0].OwnHash || again[1].OwnHash != chain[1].OwnHash {
			t.Fatal("the stored addenda changed")
		}
	})
	t.Run("the request carries no link: a gap in seq or a wrong prev_hash cannot be asked for", func(t *testing.T) {
		typ := reflect.TypeOf(finality.AppendRequest{})
		for i := 0; i < typ.NumField(); i++ {
			switch typ.Field(i).Name {
			case "Seq", "PrevHash", "OwnHash", "D0":
				t.Fatalf("AppendRequest.%s would let a caller form the link or the binding", typ.Field(i).Name)
			}
		}
	})
	t.Run("the repository has no method that changes or removes a row", func(t *testing.T) {
		// the whole method set, by name: Append writes new rows only; the rest read
		want := map[string]bool{"Append": true, "Chain": true, "SettledLegs": true, "LegSettlement": true, "LegRef": true}
		typ := reflect.TypeOf(repo)
		for i := 0; i < typ.NumMethod(); i++ {
			if !want[typ.Method(i).Name] {
				t.Fatalf("FinalityAddendaRepository.%s is not one of Append and the read methods", typ.Method(i).Name)
			}
			delete(want, typ.Method(i).Name)
		}
		if len(want) != 0 {
			t.Fatalf("methods missing: %v", want)
		}
	})

	// -- database level: the same refusals for any writer that is not the repository --
	t.Run("the table itself refuses UPDATE, DELETE and TRUNCATE", func(t *testing.T) {
		for name, stmt := range map[string]string{
			"update level":    `UPDATE proof_finality_addenda SET level = 2 WHERE proof_id = $1`,
			"update evidence": `UPDATE proof_finality_addenda SET evidence = '\x00' WHERE proof_id = $1`,
			"update hash":     `UPDATE proof_finality_addenda SET own_hash = prev_hash WHERE proof_id = $1`,
			"delete":          `DELETE FROM proof_finality_addenda WHERE proof_id = $1`,
		} {
			_, err := testDB.Exec(stmt, proofID)
			if err == nil || pgCode(err) != "23001" {
				t.Fatalf("%s: want SQLSTATE 23001, got %v", name, err)
			}
		}
		if _, err := testDB.Exec(`TRUNCATE proof_finality_addenda`); err == nil || pgCode(err) != "23001" {
			t.Fatalf("truncate: want SQLSTATE 23001, got %v", err)
		}
		if rowCount() != 2 {
			t.Fatalf("rows changed: %d", rowCount())
		}
	})
	t.Run("the table itself refuses an insert that does not extend the chain, and accepts one that does", func(t *testing.T) {
		pid := uuid.NewString()
		zero := make([]byte, 32)
		one := make([]byte, 32)
		one[0] = 1
		insert := func(id string, seq, level int, prev, own []byte, chainID int64) error {
			_, err := testDB.Exec(`INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
				VALUES ($1, $2, $3, $4, 'x.y/v1', '', $5, $6)`, id, seq, level, chainID, prev, own)
			return err
		}
		if err := insert(pid, 1, 2, one, one, 84532); pgCode(err) != "23001" {
			t.Fatalf("first addendum with a non-zero prev_hash: %v", err)
		}
		if err := insert(pid, 1, 2, zero, one, 84532); err != nil {
			t.Fatalf("a well-formed first addendum was refused: %v", err)
		}
		for name, err := range map[string]error{
			"wrong prev_hash":                 insert(pid, 2, 3, zero, one, 84532),
			"a level the proof already holds": insert(pid, 2, 2, one, one, 84532),
			"another chain":                   insert(pid, 2, 3, one, one, 421614),
			"a gap in seq":                    insert(pid, 3, 3, one, one, 84532),
			"no predecessor at all":           insert(uuid.NewString(), 2, 3, one, one, 84532),
		} {
			if pgCode(err) != "23001" {
				t.Fatalf("%s: want SQLSTATE 23001, got %v", name, err)
			}
		}
		// level 1 (included) is derived and never stored: the table's own CHECK refuses it, whatever the writer
		if err := insert(pid, 2, 1, one, one, 84532); pgCode(err) != "23514" {
			t.Fatalf("level 1: want SQLSTATE 23514 (check_violation), got %v", err)
		}
		if err := insert(pid, 2, 3, one, one, 84532); err != nil {
			t.Fatalf("a well-formed second addendum was refused: %v", err)
		}
		// a duplicate (proof_id, seq) repeats a level the proof already holds, so the trigger refuses it before the primary key can
		if err := insert(pid, 2, 3, one, one, 84532); pgCode(err) != "23001" {
			t.Fatalf("duplicate seq: %v", err)
		}
		if rowCount() != 2 {
			t.Fatalf("the proof under test changed: %d", rowCount())
		}
	})
}

// The source lists stored proofs that carry an L6 execution proof, loads and verifies their settlement, and stops listing a
// leg once it stands at finalized.
func TestFinalityLegSourceReadsTheStoredBundle(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	proofID, want := storeLeg(t, "telcoin_adiri_498759")

	var ref *finality.LegRef
	after := ""
	for {
		page, err := repo.SettledLegs(ctx, after, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		after = page[len(page)-1].ProofID
		for i := range page {
			if page[i].ProofID == proofID {
				ref = &page[i]
			}
		}
	}
	if ref == nil || ref.Chain != 2017 {
		t.Fatalf("the settled leg is not listed with its chain: %+v", ref)
	}
	got, err := repo.LegSettlement(ctx, *ref)
	if err != nil || got.Subject != want.Subject || got.Chain != 2017 || got.Included == nil {
		t.Fatalf("settlement: %v %+v", err, got)
	}

	// once its chain stands at finalized it is no longer listed
	if _, err := repo.Append(ctx, appendRequest(t, kindRegistry(t, nil), proofID, want, finality.LevelFinalized, "b")); err != nil {
		t.Fatal(err)
	}
	page, err := repo.SettledLegs(ctx, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page {
		if r.ProofID == proofID {
			t.Fatal("a finalized leg is still listed")
		}
	}
}
