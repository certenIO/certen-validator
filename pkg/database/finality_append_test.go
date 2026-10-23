// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// dbKind stands in for a chain package's Kind: it accepts every container of its row unless refuse holds an error.
type dbKind struct {
	row    finality.KindRow
	refuse *atomic.Value // error
}

func (k dbKind) Name() string          { return k.row.Kind }
func (k dbKind) Chain() uint64         { return k.row.Chain }
func (k dbKind) Level() finality.Level { return k.row.Level }
func (k dbKind) Verify(*finality.Pins, finality.BlockRef, []byte) (finality.Verdict, error) {
	if k.refuse != nil {
		if e, _ := k.refuse.Load().(error); e != nil {
			return finality.Verdict{}, e
		}
	}
	return finality.Verdict{Level: k.row.Level, Kind: k.row.Kind}, nil
}

// kindRegistry registers a fake Kind for every row of the V2_SPEC_S7 table. refuse (may be nil) makes every Kind refuse.
func kindRegistry(t testing.TB, refuse *atomic.Value) *finality.Registry {
	t.Helper()
	reg := finality.NewRegistry()
	for _, row := range finality.KindRows() {
		if err := reg.RegisterKind(dbKind{row: row, refuse: refuse}); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

// containerFor builds the CFE1 container of one level about the settlement's own block.
func containerFor(t testing.TB, block finality.BlockRef, level finality.Level, body string) (string, []byte) {
	t.Helper()
	kind, err := finality.KindFor(block.Chain, level)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := finality.Container{Header: finality.ContainerHeader{Kind: kind, Chain: block.Chain, Level: level, BlockNumber: block.Number, BlockHash: block.Hash}, Body: []byte(body)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return kind, ev
}

// appendRequest builds the request of one level of a proof's leg.
func appendRequest(t testing.TB, reg *finality.Registry, proofID string, s finality.Settlement, level finality.Level, body string) finality.AppendRequest {
	t.Helper()
	pid, err := finality.ParseProofID(proofID)
	if err != nil {
		t.Fatal(err)
	}
	block := s.Block()
	kind, ev := containerFor(t, block, level, body)
	return finality.AppendRequest{ProofID: pid, Chain: block.Chain, Settlement: s.Included, Level: level, Kind: kind, Evidence: ev, Registry: reg}
}

func storedRows(t testing.TB, proofID string) int {
	t.Helper()
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM proof_finality_addenda WHERE proof_id = $1`, proofID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// rawInsert is a writer that is not the repository: it takes no lock and verifies nothing.
func rawInsert(t testing.TB, a finality.Addendum) {
	t.Helper()
	if _, err := testDB.Exec(`INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, finality.ProofIDString(a.ProofID), int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:]); err != nil {
		t.Fatal(err)
	}
}

// V2_SPEC_S7 2.4: Append stores an addendum only if it verifies; a refused build leaves no row and returns the verifier's
// named state; D0 is recomputed from the proof's verified Settlement and never taken from a file or a caller.
func TestFinalityAppendStoresOnlyWhatTheRegisteredKindVerifies(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))

	t.Run("a verifier refusal leaves nothing and returns its named state", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		refusal := &atomic.Value{}
		refusal.Store(error(finality.NewState("game_challenger_wins")))
		_, err := repo.Append(ctx, appendRequest(t, kindRegistry(t, refusal), proofID, s, finality.LevelFinalized, "x"))
		if stateCode(err) != "game_challenger_wins" {
			t.Fatalf("want the verifier's state, got %v", err)
		}
		if n := storedRows(t, proofID); n != 0 {
			t.Fatalf("a refused build left %d rows", n)
		}
		// the same request with a verifying Kind is stored: the refusal was the only obstacle
		if _, err := repo.Append(ctx, appendRequest(t, kindRegistry(t, nil), proofID, s, finality.LevelFinalized, "x")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a request with no registry cannot store anything", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		req := appendRequest(t, nil, proofID, s, finality.LevelL1Posted, "x")
		if _, err := repo.Append(ctx, req); err == nil || storedRows(t, proofID) != 0 {
			t.Fatalf("an unverified append was stored: %v", err)
		}
	})
	t.Run("the stored link is formed under D0 of the verified settlement, and level 1 is never stored", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		reg := kindRegistry(t, nil)
		a, err := repo.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelL1Posted, "x"))
		if err != nil || a.Seq != 1 || a.PrevHash != [32]byte{} {
			t.Fatalf("%v %+v", err, a)
		}
		b, err := repo.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelFinalized, "y"))
		if err != nil || b.Seq != 2 || b.PrevHash != a.OwnHash {
			t.Fatalf("%v %+v", err, b)
		}
		got, _ := repo.Chain(ctx, proofID)
		if err := finality.VerifyChain(finality.LegBindingOf(s.Block()), got); err != nil || len(got) != 2 {
			t.Fatalf("the stored chain does not verify under the settlement's D0: %v", err)
		}
		inc := appendRequest(t, reg, proofID, s, finality.LevelFinalized, "z")
		inc.Level = finality.LevelIncluded
		if _, err := repo.Append(ctx, inc); stateCode(err) != finality.CodeChainBroken || storedRows(t, proofID) != 2 {
			t.Fatalf("level 1: %v", err)
		}
	})
	t.Run("a chain forged under another D0 is refused and nothing is appended to it", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		other := s.Block()
		other.Number++
		// the table itself now refuses a row whose own_hash is not the one under the block named by its evidence header (migration
		// 00029, TestFinalityTriggerRefusesAGarbageRowEvenWhenItIsCorrectlyLinked), so a forged row can only exist if it was stored
		// before that trigger or with the trigger switched off by the table owner: the repository must still never extend it
		for _, a := range addendaChainUnder(t, proofID, s, finality.LegBindingOf(other), finality.LevelL1Posted) {
			insertAddendumUnguarded(t, a)
		}
		_, err := repo.Append(ctx, appendRequest(t, kindRegistry(t, nil), proofID, s, finality.LevelFinalized, "x"))
		st, ok := finality.AsNamed(err)
		if !ok || st.Code != finality.CodeChainBroken || st.Fields["check"] != finality.CheckOwnHash {
			t.Fatalf("want finality_chain_broken{own_hash}, got %v", err)
		}
		if n := storedRows(t, proofID); n != 1 {
			t.Fatalf("rows after the refusal: %d", n)
		}
	})
	t.Run("a settlement that is not the proof's own is refused", func(t *testing.T) {
		proofID, _ := storeLeg(t, "base_sepolia_47368146")
		_, other := storeLeg(t, "telcoin_adiri_498759")
		_, err := repo.Append(ctx, appendRequest(t, kindRegistry(t, nil), proofID, other, finality.LevelFinalized, "x"))
		st, ok := finality.AsNamed(err)
		if !ok || st.Code != finality.CodeBlockMismatch || st.Fields["field"] != "leg" || storedRows(t, proofID) != 0 {
			t.Fatalf("want finality_block_mismatch{leg}, got %v", err)
		}
	})
	t.Run("evidence about another block is refused, not stored", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		req := appendRequest(t, kindRegistry(t, nil), proofID, s, finality.LevelFinalized, "x")
		moved := s.Block()
		moved.Number++
		_, req.Evidence = containerFor(t, moved, finality.LevelFinalized, "x")
		if _, err := repo.Append(ctx, req); stateCode(err) != finality.CodeBlockMismatch || storedRows(t, proofID) != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an unknown proof id has no leg", func(t *testing.T) {
		_, s := storeLeg(t, "base_sepolia_47368146")
		req := appendRequest(t, kindRegistry(t, nil), uuid.NewString(), s, finality.LevelFinalized, "x")
		if _, err := repo.Append(ctx, req); err == nil {
			t.Fatal("an append for a proof that does not exist was stored")
		}
	})
}

// Two upgraders racing one leg: the proof's lock queues them, the loser reads the winner's row and reports level_already_present
// or appends at the next seq; the chain stays contiguous, hash-linked and verifying.
func TestFinalityAppendRacingWritersNeverForkTheChain(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	reg := kindRegistry(t, nil)

	t.Run("N goroutines racing the same level: exactly one stores it", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		const n = 12
		var wg sync.WaitGroup
		errs := make([]error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i] = repo.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelFinalized, fmt.Sprintf("racer %d", i)))
			}(i)
		}
		close(start)
		wg.Wait()
		wins, dups := 0, 0
		for i, err := range errs {
			switch {
			case err == nil:
				wins++
			case stateCode(err) == finality.CodeLevelAlreadyPresent:
				dups++
			default:
				t.Errorf("racer %d: %v", i, err)
			}
		}
		if wins != 1 || dups != n-1 || storedRows(t, proofID) != 1 {
			t.Fatalf("wins=%d already_present=%d rows=%d", wins, dups, storedRows(t, proofID))
		}
	})

	t.Run("N goroutines racing both levels: one row per level, contiguous, linked, verifying", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		const n = 16
		var wg sync.WaitGroup
		errs := make([]error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				level := finality.LevelL1Posted
				if i%2 == 1 {
					level = finality.LevelFinalized
				}
				_, errs[i] = repo.Append(ctx, appendRequest(t, reg, proofID, s, level, fmt.Sprintf("racer %d", i)))
			}(i)
		}
		close(start)
		wg.Wait()
		wins := 0
		for i, err := range errs {
			switch {
			case err == nil:
				wins++
			case stateCode(err) == finality.CodeLevelAlreadyPresent:
			default:
				t.Errorf("racer %d: %v", i, err)
			}
		}
		chain, err := repo.Chain(ctx, proofID)
		if err != nil || wins != 2 || len(chain) != 2 {
			t.Fatalf("wins=%d rows=%d err=%v", wins, len(chain), err)
		}
		if err := finality.VerifyChain(finality.LegBindingOf(s.Block()), chain); err != nil {
			t.Fatalf("the raced chain does not verify: %v", err)
		}
		if chain[0].Level == chain[1].Level {
			t.Fatal("two addenda at one level")
		}
	})

	t.Run("a writer that takes no lock: the loser retries on the unique key", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			competitor finality.Level
			ours       finality.Level
			wantState  string // "" = appended at the next seq
		}{
			{"same level", finality.LevelFinalized, finality.LevelFinalized, finality.CodeLevelAlreadyPresent},
			{"other level", finality.LevelL1Posted, finality.LevelFinalized, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				proofID, s := storeLeg(t, "base_sepolia_47368146")
				racing := NewFinalityAddendaRepository(NewClientFromDB(testDB))
				var attempts atomic.Int64
				racing.afterRead = func(attempt int) {
					attempts.Store(int64(attempt))
					if attempt == 1 { // a writer that does not take the lock slips its row in between our read and our insert
						for _, a := range addendaChain(t, proofID, s, tc.competitor) {
							rawInsert(t, a)
						}
					}
				}
				a, err := racing.Append(ctx, appendRequest(t, reg, proofID, s, tc.ours, "ours"))
				if tc.wantState != "" {
					if stateCode(err) != tc.wantState {
						t.Fatalf("want %s, got %v", tc.wantState, err)
					}
				} else if err != nil || a.Seq != 2 {
					t.Fatalf("want an append at seq 2, got %v %+v", err, a)
				}
				// "same level": the retry reads the winner's chain and stops at level_already_present before the hook can run again, so
				// the state itself (planned at seq 1, reported after re-reading) is the evidence; "other level" runs the hook twice.
				if tc.wantState == "" && attempts.Load() < 2 {
					t.Fatalf("the loser did not retry (attempts %d)", attempts.Load())
				}
				chain, _ := repo.Chain(ctx, proofID)
				if err := finality.VerifyChain(finality.LegBindingOf(s.Block()), chain); err != nil {
					t.Fatalf("%v", err)
				}
			})
		}
	})
}
