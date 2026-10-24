// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D6: migration 00029. The table's trigger recomputes own_hash with the builtin sha256 exactly as pkg/finality OwnHash
// does and requires the evidence header's kind, chain and level to equal the row, so a writer that is not the repository (a
// direct INSERT) cannot link a row of garbage evidence and a garbage hash into a proof's chain, where it would void the chain for
// every verifier and could never be removed.

// insertAddendum is a writer that is not the repository: it takes no lock, verifies nothing, and sends the row as given.
func insertAddendum(a finality.Addendum) error {
	_, err := testDB.Exec(`INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, finality.ProofIDString(a.ProofID), int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:])
	return err
}

// insertAddendumUnguarded writes a row the way a table owner can: with the row trigger disabled for the one statement. It models
// a row that was stored before migration 00029 or by a session that switched the trigger off; the repository must still refuse
// to extend such a chain.
func insertAddendumUnguarded(t testing.TB, a finality.Addendum) {
	t.Helper()
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE proof_finality_addenda DISABLE TRIGGER proof_finality_addenda_row_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, finality.ProofIDString(a.ProofID), int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE proof_finality_addenda ENABLE TRIGGER proof_finality_addenda_row_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func mustContainer(t testing.TB, kind string, chain uint64, level finality.Level, number uint64, hash [32]byte, body string) []byte {
	t.Helper()
	ev, err := finality.Container{Header: finality.ContainerHeader{Kind: kind, Chain: chain, Level: level, BlockNumber: number, BlockHash: hash}, Body: []byte(body)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// forged builds the row a hostile writer would send: the fields as given and the own_hash a Go OwnHash computes for them under d0.
func forged(pid [16]byte, seq uint64, level finality.Level, chain uint64, kind string, evidence []byte, prev [32]byte, d0 [32]byte) finality.Addendum {
	a := finality.Addendum{ProofID: pid, Seq: seq, Level: level, Chain: chain, Kind: kind, Evidence: evidence, PrevHash: prev}
	a.OwnHash = finality.OwnHash(d0, a)
	return a
}

func TestFinalityTriggerAcceptsEveryGoBuiltRowOfTheTableAndRefusesGarbageLinkedToThem(t *testing.T) {
	s := finalityTestBlock()
	// every (chain, level, kind) row of the table: a Go-built addendum, bound to a block of that chain, inserts
	for _, row := range finality.KindRows() {
		blk := finality.BlockRef{Chain: row.Chain, Number: 123456789 + row.Chain, Hash: s.Hash}
		pid := uuid.New()
		var id [16]byte
		copy(id[:], pid[:])
		ev := mustContainer(t, row.Kind, row.Chain, row.Level, blk.Number, blk.Hash, "body of "+row.Kind)
		a, err := finality.NewAddendum(finality.LegBindingOf(blk), id, nil, row.Chain, row.Level, row.Kind, ev)
		if err != nil {
			t.Fatalf("%s: %v", row.Kind, err)
		}
		if err := insertAddendum(a); err != nil {
			t.Fatalf("%s: a Go-built valid first addendum was refused: %v", row.Kind, err)
		}
	}
}

func finalityTestBlock() finality.BlockRef {
	var h [32]byte
	for i := range h {
		h[i] = byte(0xA0 + i%7)
	}
	return finality.BlockRef{Chain: finality.ChainBaseSepolia, Number: 47368146, Hash: h}
}

func TestFinalityTriggerRefusesAGarbageRowEvenWhenItIsCorrectlyLinked(t *testing.T) {
	blk := finalityTestBlock()
	d0 := finality.LegBindingOf(blk)
	posted, err := finality.KindFor(blk.Chain, finality.LevelL1Posted)
	if err != nil {
		t.Fatal(err)
	}
	fin, err := finality.KindFor(blk.Chain, finality.LevelFinalized)
	if err != nil {
		t.Fatal(err)
	}
	good := func(level finality.Level, kind string, body string) []byte {
		return mustContainer(t, kind, blk.Chain, level, blk.Number, blk.Hash, body)
	}
	newPid := func() [16]byte { u := uuid.New(); var id [16]byte; copy(id[:], u[:]); return id }
	var zero [32]byte

	type variant struct {
		name  string
		build func(pid [16]byte) finality.Addendum // the first addendum of a fresh proof
	}
	one := func(b byte) [32]byte { var h [32]byte; h[0] = b; return h }
	variants := []variant{
		{"garbage evidence and a garbage own_hash, correctly linked (the reviewer's probe)", func(pid [16]byte) finality.Addendum {
			return finality.Addendum{ProofID: pid, Seq: 1, Level: finality.LevelL1Posted, Chain: blk.Chain, Kind: posted, Evidence: []byte("not a container"), PrevHash: zero, OwnHash: one(9)}
		}},
		{"valid evidence, garbage own_hash", func(pid [16]byte) finality.Addendum {
			a := forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), zero, d0)
			a.OwnHash = one(9)
			return a
		}},
		{"valid evidence, one flipped bit of own_hash", func(pid [16]byte) finality.Addendum {
			a := forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), zero, d0)
			a.OwnHash[31] ^= 1
			return a
		}},
		{"the own_hash of other evidence bytes", func(pid [16]byte) finality.Addendum {
			a := forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), zero, d0)
			a.Evidence = good(finality.LevelL1Posted, posted, "y")
			return a
		}},
		{"an own_hash under another leg binding", func(pid [16]byte) finality.Addendum {
			other := blk
			other.Number++
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), zero, finality.LegBindingOf(other))
		}},
		{"a header naming another kind than the row", func(pid [16]byte) finality.Addendum {
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, fin, "x"), zero, d0)
		}},
		{"a header naming another chain than the row", func(pid [16]byte) finality.Addendum {
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, mustContainer(t, posted, blk.Chain+1, finality.LevelL1Posted, blk.Number, blk.Hash, "x"), zero, d0)
		}},
		{"a header naming another level than the row", func(pid [16]byte) finality.Addendum {
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, mustContainer(t, posted, blk.Chain, finality.LevelFinalized, blk.Number, blk.Hash, "x"), zero, d0)
		}},
		{"evidence one byte short of a header", func(pid [16]byte) finality.Addendum {
			ev := good(finality.LevelL1Posted, posted, "")
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, ev[:len(ev)-1], zero, d0)
		}},
		{"evidence with a bad magic", func(pid [16]byte) finality.Addendum {
			ev := good(finality.LevelL1Posted, posted, "x")
			ev[3] = '2'
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, ev, zero, d0)
		}},
		{"a kind length that overruns the evidence", func(pid [16]byte) finality.Addendum {
			ev := good(finality.LevelL1Posted, posted, "x")
			ev[4], ev[5], ev[6], ev[7] = 0xff, 0xff, 0xff, 0xff
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, ev, zero, d0)
		}},
		{"a first addendum with a non-zero prev_hash and a matching own_hash", func(pid [16]byte) finality.Addendum {
			return forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), one(1), d0)
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			pid := newPid()
			a := v.build(pid)
			err := insertAddendum(a)
			if err == nil {
				t.Fatalf("the table accepted the row (and it can never be removed)")
			}
			if c := pgCode(err); c != "23001" {
				t.Fatalf("want SQLSTATE 23001 (restrict_violation), got %v", err)
			}
			if n := storedRows(t, finality.ProofIDString(pid)); n != 0 {
				t.Fatalf("%d rows stored", n)
			}
		})
	}

	t.Run("a chain's second row about another leg block, correctly hashed under its own binding, is refused", func(t *testing.T) {
		pid := newPid()
		first := forged(pid, 1, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), zero, d0)
		if err := insertAddendum(first); err != nil {
			t.Fatal(err)
		}
		other := blk
		other.Number++
		otherEv := mustContainer(t, fin, blk.Chain, finality.LevelFinalized, other.Number, other.Hash, "x")
		second := forged(pid, 2, finality.LevelFinalized, blk.Chain, fin, otherEv, first.OwnHash, finality.LegBindingOf(other))
		if err := insertAddendum(second); pgCode(err) != "23001" {
			t.Fatalf("want 23001, got %v", err)
		}
		// the same row about the chain's own block is accepted: the refusal is the block, not the link
		okEv := good(finality.LevelFinalized, fin, "x")
		okRow := forged(pid, 2, finality.LevelFinalized, blk.Chain, fin, okEv, first.OwnHash, d0)
		if err := insertAddendum(okRow); err != nil {
			t.Fatalf("a Go-built second addendum was refused: %v", err)
		}
		if n := storedRows(t, finality.ProofIDString(pid)); n != 2 {
			t.Fatalf("rows: %d", n)
		}
	})
	t.Run("a second row whose own_hash is garbage is refused although the link is exact", func(t *testing.T) {
		pid := newPid()
		first := forged(pid, 1, finality.LevelFinalized, blk.Chain, fin, good(finality.LevelFinalized, fin, "x"), zero, d0)
		if err := insertAddendum(first); err != nil {
			t.Fatal(err)
		}
		second := forged(pid, 2, finality.LevelL1Posted, blk.Chain, posted, good(finality.LevelL1Posted, posted, "x"), first.OwnHash, d0)
		second.OwnHash = one(7)
		if err := insertAddendum(second); pgCode(err) != "23001" {
			t.Fatalf("want 23001, got %v", err)
		}
		if n := storedRows(t, finality.ProofIDString(pid)); n != 1 {
			t.Fatalf("rows: %d", n)
		}
	})
}

// The repository's own path is unchanged by the stronger trigger: Append forms the link and the hash itself and the trigger
// accepts it, for each level in either order, and a stored chain it reads verifies.
func TestFinalityAppendStillStoresThroughTheRecomputingTrigger(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	for _, order := range [][]finality.Level{{finality.LevelL1Posted, finality.LevelFinalized}, {finality.LevelFinalized, finality.LevelL1Posted}} {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		reg := kindRegistry(t, nil)
		for _, l := range order {
			if _, err := repo.Append(ctx, appendRequest(t, reg, proofID, s, l, "body-"+l.String())); err != nil {
				t.Fatalf("append %s: %v", l, err)
			}
		}
		chain, err := repo.Chain(ctx, proofID)
		if err != nil || len(chain) != 2 {
			t.Fatalf("%v %d", err, len(chain))
		}
		if err := finality.VerifyChain(finality.LegBindingOf(s.Block()), chain); err != nil {
			t.Fatalf("stored chain: %v", err)
		}
		// the trigger's recomputation is the same bytes as Go's: the stored hash is exactly OwnHash under the leg binding
		for _, a := range chain {
			if !bytes.Equal(a.OwnHash[:], func() []byte { h := finality.OwnHash(finality.LegBindingOf(s.Block()), a); return h[:] }()) {
				t.Fatalf("seq %d: stored own_hash differs from OwnHash", a.Seq)
			}
		}
	}
}
