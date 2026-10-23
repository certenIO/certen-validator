// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// RB12-DBFIX-FIX (verifier finding F1): a row whose header names a block that is not the proof's own leg, hashed perfectly under that
// block's leg binding, was insertable (migration 00029 made stored hashes internally consistent, it did not know the proof's block).
// proof_artifacts.settlement_block_number records the block of the proof's settlement (the writer sets it from the same observation as
// the bundle's component 5, and FinalityAddendaRepository.LegSettlement refuses a leg whose bundle proves another block), so the trigger
// binds the header's block NUMBER to it whenever it is recorded. The hash of the block is recorded nowhere but in the gzip bundle, and a
// proof whose settlement is not recorded yet (the writer records it right after the bundle) has no number to bind: those two shapes are
// judged where the bundle is, at read time, by finality.CheckLegChain under the Settlement's own leg binding.

func bogusRow(t *testing.T, proofID string, s finality.Settlement, level finality.Level, mutate func(*finality.BlockRef)) finality.Addendum {
	t.Helper()
	pid, err := finality.ParseProofID(proofID)
	if err != nil {
		t.Fatal(err)
	}
	blk := s.Block()
	mutate(&blk)
	kind, ev := containerFor(t, blk, level, "x")
	var zero [32]byte
	return forged(pid, 1, level, blk.Chain, kind, ev, zero, finality.LegBindingOf(blk))
}

func TestFinalityTriggerBindsTheHeadersBlockNumberToTheProofsRecordedSettlementBlock(t *testing.T) {
	for _, level := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
		t.Run(level.String(), func(t *testing.T) {
			proofID, s := storeLeg(t, "base_sepolia_47368146")
			for _, tc := range []struct {
				name   string
				mutate func(*finality.BlockRef)
			}{
				{"the next block", func(b *finality.BlockRef) { b.Number++ }},
				{"the previous block", func(b *finality.BlockRef) { b.Number-- }},
				{"block 1", func(b *finality.BlockRef) { b.Number = 1 }},
				{"another hash and number", func(b *finality.BlockRef) {
					b.Number += 1000
					b.Hash[0] ^= 0xff
				}},
			} {
				a := bogusRow(t, proofID, s, level, tc.mutate)
				if err := insertAddendum(a); pgCode(err) != "23001" {
					t.Fatalf("%s: a self-consistent row naming a block that is not the proof's recorded settlement block: want SQLSTATE 23001, got %v", tc.name, err)
				}
			}
			if n := storedRows(t, proofID); n != 0 {
				t.Fatalf("%d rows stored", n)
			}
			// the row about the proof's own block inserts, and so does the next level of its chain
			own := bogusRow(t, proofID, s, level, func(*finality.BlockRef) {})
			if err := insertAddendum(own); err != nil {
				t.Fatalf("the row about the proof's own block was refused: %v", err)
			}
		})
	}

	t.Run("a proof that does not record its settlement yet cannot be bound by the trigger and is not refused", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = NULL, settlement_block_number = NULL WHERE proof_id = $1::uuid`, proofID); err != nil {
			t.Fatal(err)
		}
		if err := insertAddendum(bogusRow(t, proofID, s, finality.LevelL1Posted, func(*finality.BlockRef) {})); err != nil {
			t.Fatalf("the writer's row for an unrecorded settlement was refused: %v", err)
		}
	})
	t.Run("a proof with no artifact row at all is not refused (nothing to bind to)", func(t *testing.T) {
		_, s := storeLeg(t, "base_sepolia_47368146")
		if err := insertAddendum(bogusRow(t, uuid.NewString(), s, finality.LevelL1Posted, func(b *finality.BlockRef) { b.Number += 5 })); err != nil {
			t.Fatalf("a row of a proof with no artifact row: %v", err)
		}
	})
}

// What the trigger cannot bind is judged at read time. The proof records no settlement block (or the lie is in the hash, which only
// the bundle holds): the self-consistent row is stored, and every reader that holds the Settlement refuses the chain by name, and the
// repository refuses to extend it.
func TestFinalityABogusBlockRowTheTriggerCannotJudgeIsRefusedWhereTheBundleIs(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	reg := kindRegistry(t, nil)
	for _, tc := range []struct {
		name     string
		unrecord bool
		mutate   func(*finality.BlockRef)
	}{
		{"unrecorded settlement, another block number", true, func(b *finality.BlockRef) { b.Number += 7 }},
		{"recorded settlement, the right number and another block hash", false, func(b *finality.BlockRef) { b.Hash[5] ^= 0x5a }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proofID, s := storeLeg(t, "base_sepolia_47368146")
			if tc.unrecord {
				if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = NULL, settlement_block_number = NULL WHERE proof_id = $1::uuid`, proofID); err != nil {
					t.Fatal(err)
				}
			}
			if err := insertAddendum(bogusRow(t, proofID, s, finality.LevelL1Posted, tc.mutate)); err != nil {
				t.Fatalf("the trigger cannot know this block and must store the row: %v", err)
			}
			chain, err := repo.Chain(ctx, proofID)
			if err != nil || len(chain) != 1 {
				t.Fatalf("%v %d", err, len(chain))
			}
			carried := s.Block()
			err = finality.CheckLegChain(s.Block(), carried, chain)
			st, ok := finality.AsNamed(err)
			if !ok || st.Code != finality.CodeChainBroken || st.Fields["check"] != finality.CheckOwnHash {
				t.Fatalf("a reader holding the Settlement must refuse the chain by name finality_chain_broken{own_hash}: %v", err)
			}
			_, err = repo.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelFinalized, "next"))
			st, ok = finality.AsNamed(err)
			if !ok || st.Code != finality.CodeChainBroken {
				t.Fatalf("the repository must refuse to extend the chain by name finality_chain_broken: %v", err)
			}
			if n := storedRows(t, proofID); n != 1 {
				t.Fatalf("rows: %d", n)
			}
		})
	}
}

// The binding refuses no row the writer forms: every live chain's real leg, both level orders the chain supports, recorded and
// unrecorded settlement, appended by the repository exactly as production does, stores and verifies.
func TestFinalityTheBindingRefusesNoRowTheWriterForms(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	reg := kindRegistry(t, nil)
	for fixture := range finalitytest.Blocks {
		for _, unrecorded := range []bool{false, true} {
			for _, flip := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/unrecorded=%v/flip=%v", fixture, unrecorded, flip), func(t *testing.T) {
					proofID, s := storeLeg(t, fixture)
					if unrecorded {
						if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = NULL, settlement_block_number = NULL WHERE proof_id = $1::uuid`, proofID); err != nil {
							t.Fatal(err)
						}
					}
					var levels []finality.Level
					for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
						if _, err := finality.KindFor(s.Chain, l); err == nil {
							levels = append(levels, l)
						}
					}
					if flip {
						for i, j := 0, len(levels)-1; i < j; i, j = i+1, j-1 {
							levels[i], levels[j] = levels[j], levels[i]
						}
					}
					if len(levels) == 0 {
						t.Fatalf("%s: no stored level for chain %d", fixture, s.Chain)
					}
					for _, l := range levels {
						if _, err := repo.Append(ctx, appendRequest(t, reg, proofID, s, l, "body-"+l.String())); err != nil {
							t.Fatalf("append %s: %v", l, err)
						}
					}
					chain, err := repo.Chain(ctx, proofID)
					if err != nil || len(chain) != len(levels) {
						t.Fatalf("%v %d", err, len(chain))
					}
					if err := finality.CheckLegChain(s.Block(), s.Block(), chain); err != nil {
						t.Fatalf("stored chain: %v", err)
					}
				})
			}
		}
	}
}
