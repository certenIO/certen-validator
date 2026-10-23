// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX-FIX (verifier V5): the guard trigger and the two functions it calls resolve every name they use in pg_catalog, whatever
// search_path the writing session has. A role that holds only INSERT (and SELECT) on the table but may CREATE in a schema it puts
// first in its search_path could otherwise shadow sha256() - or, through overload resolution, convert_to(text, text) - and forge any
// own_hash. The test is run as such a role.

func hostileWriter(t *testing.T) (*sql.Conn, func()) {
	t.Helper()
	ctx := context.Background()
	role := "probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	stmts := []string{
		`CREATE ROLE ` + role + ` NOLOGIN`,
		`GRANT SELECT, INSERT ON public.proof_finality_addenda TO ` + role,
		`GRANT SELECT ON public.proof_artifacts TO ` + role,
		`GRANT USAGE, CREATE ON SCHEMA public TO ` + role,
	}
	for _, s := range stmts {
		if _, err := testDB.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	conn, err := testDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`SET ROLE ` + role, `SET search_path = public, pg_catalog`} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	return conn, func() {
		_, _ = conn.ExecContext(ctx, `RESET ROLE`)
		_, _ = conn.ExecContext(ctx, `RESET search_path`)
		_ = conn.Close()
		_, _ = testDB.ExecContext(ctx, `DROP OWNED BY `+role)
		_, _ = testDB.ExecContext(ctx, `DROP ROLE `+role)
	}
}

func insertAs(conn *sql.Conn, a finality.Addendum) error {
	_, err := conn.ExecContext(context.Background(), `INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, finality.ProofIDString(a.ProofID), int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:])
	return err
}

func TestFinalityTriggerCannotBeForgedThroughAShadowingFunctionInTheWritersSchema(t *testing.T) {
	ctx := context.Background()
	blk := finalityTestBlock()
	posted, err := finality.KindFor(blk.Chain, finality.LevelL1Posted)
	if err != nil {
		t.Fatal(err)
	}
	newPid := func() [16]byte { u := uuid.New(); var id [16]byte; copy(id[:], u[:]); return id }
	var zero [32]byte
	ev := mustContainer(t, posted, blk.Chain, finality.LevelL1Posted, blk.Number, blk.Hash, "x")

	t.Run("a sha256 in the writer's schema that returns a constant: the forged own_hash is refused, the real one accepted", func(t *testing.T) {
		conn, done := hostileWriter(t)
		defer done()
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`CREATE FUNCTION public.sha256(bytea) RETURNS bytea LANGUAGE sql AS $$ SELECT '\x%s'::bytea $$`, strings.Repeat("ab", 32))); err != nil {
			t.Fatal(err)
		}
		// a well-formed container about the proof's block, whose own_hash is not the one the specification computes but the one a shadowing sha256 yields
		forgedRow := finality.Addendum{ProofID: newPid(), Seq: 1, Level: finality.LevelL1Posted, Chain: blk.Chain, Kind: posted, Evidence: ev, PrevHash: zero}
		for i := range forgedRow.OwnHash {
			forgedRow.OwnHash[i] = 0xab
		}
		if err := insertAs(conn, forgedRow); pgCode(err) != "23001" {
			t.Fatalf("a row carrying the hash the shadowing sha256 yields was not refused by the trigger: %v", err)
		}
		good := forged(newPid(), 1, finality.LevelL1Posted, blk.Chain, posted, ev, zero, finality.LegBindingOf(blk))
		if err := insertAs(conn, good); err != nil {
			t.Fatalf("the correctly hashed row was refused under the hostile search_path: %v", err)
		}
	})

	t.Run("a convert_to(text, text) in the writer's schema, which overload resolution prefers for an unknown-typed literal, is never called", func(t *testing.T) {
		conn, done := hostileWriter(t)
		defer done()
		if _, err := conn.ExecContext(ctx, `CREATE FUNCTION public.convert_to(text, text) RETURNS bytea LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the shadowing convert_to ran'; END $$`); err != nil {
			t.Fatal(err)
		}
		good := forged(newPid(), 1, finality.LevelL1Posted, blk.Chain, posted, ev, zero, finality.LegBindingOf(blk))
		if err := insertAs(conn, good); err != nil {
			t.Fatalf("the trigger called a function of the writer's schema: %v", err)
		}
	})
}
