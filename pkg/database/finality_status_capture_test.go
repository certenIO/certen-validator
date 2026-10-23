// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// ---- proof_finality_status (V2_SPEC_S7 2.7): mutable, one row per (proof, target level) ----

func TestFinalityStatusRowIsReplacedByTheNextPassAndCarriesLevelNextAndEta(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	eta := time.Date(2026, 10, 25, 3, 4, 5, 0, time.UTC)
	pd := &finality.PendingState{Chain: finality.ChainBaseSepolia, LevelReached: finality.LevelL1Posted, NextLevel: finality.LevelFinalized, Reason: "game_unresolved", ETA: eta}
	pending := finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, finality.LevelFinalized, finality.LevelL1Posted, pd, nil, false, time.Now())

	if _, ok, err := repo.GetStatus(ctx, pid, finality.LevelFinalized); err != nil || ok {
		t.Fatalf("nothing judged yet: %v %v", ok, err)
	}
	if err := repo.UpsertStatus(ctx, pending); err != nil {
		t.Fatal(err)
	}
	got, ok, err := repo.GetStatus(ctx, pid, finality.LevelFinalized)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if got.Class != finality.BuilderPending || got.LevelReached != finality.LevelL1Posted || got.NextLevel != finality.LevelFinalized ||
		!got.ETA.Equal(eta) || got.Chain != finality.ChainBaseSepolia || got.TargetLevel != finality.LevelFinalized {
		t.Fatalf("%+v", got)
	}
	var st struct {
		Code   string            `json:"code"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(got.State, &st); err != nil || st.Code != "finality_pending" || st.Fields["reason"] != "game_unresolved" ||
		st.Fields["next_level"] != "finalized" || st.Fields["level_reached"] != "l1_posted" || st.Fields["eta"] != "2026-10-25T03:04:05Z" {
		t.Fatalf("the named state is stored with the row: %s %v", got.State, err)
	}

	// a later pass replaces the row of the same (proof, level); the other level has its own row
	if err := repo.UpsertStatus(ctx, finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, finality.LevelFinalized, finality.LevelL1Posted, nil,
		finality.NewState(finality.CodeBuildTimeout, "chain", uint64(84532), "after", time.Minute, "cause", "x"), false, time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertStatus(ctx, finality.VerifiedBuilderStatus(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, 1, time.Now())); err != nil {
		t.Fatal(err)
	}
	got, _, _ = repo.GetStatus(ctx, pid, finality.LevelFinalized)
	if got.Class != finality.BuilderUnavailable || !got.ETA.IsZero() || !bytes.Contains(got.State, []byte(finality.CodeBuildTimeout)) {
		t.Fatalf("not replaced: %+v", got)
	}
	l1, _, _ := repo.GetStatus(ctx, pid, finality.LevelL1Posted)
	if l1.Class != finality.BuilderVerified || l1.Seq != 1 || l1.State != nil {
		t.Fatalf("%+v", l1)
	}
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM proof_finality_status WHERE proof_id = $1`, pid).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows: %d %v", n, err)
	}

	// refusals: a level that is not stored, a bad proof id, an unknown class
	if err := repo.UpsertStatus(ctx, finality.BuilderStatusOf(pid, 84532, finality.LevelIncluded, finality.LevelIncluded, pd, nil, false, time.Now())); err == nil {
		t.Fatal("a status row for level 1 was accepted")
	}
	if err := repo.UpsertStatus(ctx, finality.BuilderStatusOf("not-a-uuid", 84532, finality.LevelFinalized, finality.LevelIncluded, pd, nil, false, time.Now())); err == nil {
		t.Fatal("a status row for a bad proof id was accepted")
	}
	if _, _, err := repo.GetStatus(ctx, "not-a-uuid", finality.LevelFinalized); err == nil {
		t.Fatal("a read for a bad proof id was accepted")
	}
}

// ---- proof_finality_capture (V2_SPEC_S7 2.8): insert-only ----

func key(chain, block uint64, hash byte, item string) finality.CaptureKey {
	k := finality.CaptureKey{Chain: chain, L1Block: block, Item: item}
	for i := range k.L1Hash {
		k.L1Hash[i] = hash
	}
	return k
}

func TestFinalityCaptureStoreIsInsertOnlyAndTheTableRefusesAnyOtherWriter(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000) // a chain id this run alone uses: the database outlives a run
	k := key(chain, 100, 0xaa, "tx/3")

	if _, ok, err := store.Get(ctx, k); err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := store.Put(ctx, k, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, k, []byte("one")); err != nil {
		t.Fatalf("the same bytes are a no-op: %v", err)
	}
	if err := store.Put(ctx, k, []byte("two")); !errors.Is(err, finality.ErrCaptureConflict) {
		t.Fatalf("different bytes under an existing key: %v", err)
	}
	if b, ok, err := store.Get(ctx, k); err != nil || !ok || string(b) != "one" {
		t.Fatalf("the stored row changed: %q %v %v", b, ok, err)
	}
	if err := store.Put(ctx, key(chain, 100, 0xaa, "Bad Item"), []byte("x")); err == nil {
		t.Fatal("an item outside the alphabet was accepted")
	}
	if err := store.Put(ctx, key(0, 100, 0xaa, "hdr"), []byte("x")); err == nil {
		t.Fatal("chain 0 was accepted")
	}
	// an empty capture is a capture: a block that holds no inbox transaction is recorded as such
	if err := store.Put(ctx, key(chain, 100, 0xaa, "inbox"), nil); err != nil {
		t.Fatal(err)
	}

	t.Run("a reorged height lists both hashes, ascending", func(t *testing.T) {
		for _, h := range []byte{0xcc, 0xbb} {
			if err := store.Put(ctx, key(chain, 101, h, "hdr"), []byte{h}); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := store.ListByBlock(ctx, chain, 101)
		if err != nil || len(rows) != 2 || rows[0].L1Hash[0] != 0xbb || rows[1].L1Hash[0] != 0xcc || !bytes.Equal(rows[1].Bytes, []byte{0xcc}) {
			t.Fatalf("%v %+v", err, rows)
		}
		if rows, _ := store.ListByBlock(ctx, chain, 102); len(rows) != 0 {
			t.Fatalf("%+v", rows)
		}
	})
	t.Run("a range lists keys by block then hash then item, filtered by item prefix", func(t *testing.T) {
		for _, kk := range []finality.CaptureKey{key(chain, 103, 0x01, "blob/0/1"), key(chain, 103, 0x01, "blob/0/0"), key(chain, 104, 0x02, "blob/1/0"), key(chain, 105, 0x03, "tx/0")} {
			if err := store.Put(ctx, kk, []byte("b")); err != nil {
				t.Fatal(err)
			}
		}
		keys, err := store.ListByRange(ctx, chain, 103, 105, "blob/")
		if err != nil || len(keys) != 3 {
			t.Fatalf("%v %+v", err, keys)
		}
		if !sort.SliceIsSorted(keys, func(i, j int) bool {
			if keys[i].L1Block != keys[j].L1Block {
				return keys[i].L1Block < keys[j].L1Block
			}
			return keys[i].Item < keys[j].Item
		}) || keys[0].Item != "blob/0/0" || keys[2].L1Block != 104 {
			t.Fatalf("%+v", keys)
		}
		all, _ := store.ListByRange(ctx, chain, 100, 105, "")
		if len(all) < 7 {
			t.Fatalf("an empty prefix lists everything: %d", len(all))
		}
		if keys, _ := store.ListByRange(ctx, chain, 105, 103, ""); len(keys) != 0 {
			t.Fatal("an inverted range is empty")
		}
		if keys, _ := store.ListByRange(ctx, chain+1, 0, 1<<62, ""); len(keys) != 0 {
			t.Fatal("another chain's rows leaked")
		}
	})
	t.Run("concurrent Puts of one key are safe: one row, no conflict for identical bytes", func(t *testing.T) {
		kk := key(chain, 200, 0x77, "syscfg")
		var wg sync.WaitGroup
		errs := make([]error, 10)
		for i := range errs {
			wg.Add(1)
			go func(i int) { defer wg.Done(); errs[i] = store.Put(ctx, kk, []byte("same")) }(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		rows, _ := store.ListByBlock(ctx, chain, 200)
		if len(rows) != 1 {
			t.Fatalf("%d rows", len(rows))
		}
	})
	t.Run("the table itself refuses UPDATE, DELETE and TRUNCATE", func(t *testing.T) {
		for name, stmt := range map[string]string{
			"update bytes": `UPDATE proof_finality_capture SET bytes = '\x00' WHERE chain = $1`,
			"update key":   `UPDATE proof_finality_capture SET l1_block = 1 WHERE chain = $1`,
			"delete":       `DELETE FROM proof_finality_capture WHERE chain = $1`,
		} {
			if _, err := testDB.Exec(stmt, int64(chain)); pgCode(err) != "23001" {
				t.Fatalf("%s: want SQLSTATE 23001, got %v", name, err)
			}
		}
		if _, err := testDB.Exec(`TRUNCATE proof_finality_capture`); pgCode(err) != "23001" {
			t.Fatalf("truncate: want SQLSTATE 23001, got %v", err)
		}
		if b, ok, _ := store.Get(ctx, k); !ok || string(b) != "one" {
			t.Fatal("the row changed")
		}
	})
	t.Run("the store has Put and reads, and no method that changes or removes a row", func(t *testing.T) {
		want := map[string]bool{"Put": true, "Get": true, "ListByBlock": true, "ListByRange": true, "BlockBounds": true}
		typ := reflect.TypeOf(store)
		for i := 0; i < typ.NumMethod(); i++ {
			if !want[typ.Method(i).Name] {
				t.Fatalf("FinalityCaptureStore.%s is not Put or a read", typ.Method(i).Name)
			}
			delete(want, typ.Method(i).Name)
		}
		if len(want) != 0 {
			t.Fatalf("methods missing: %v", want)
		}
	})
}

// The chain kind packages declare their own capture interface (baseposted.CaptureStore, basefinal.CaptureStore,
// arbposted/capture.CaptureStore); INT1 unifies them in pkg/finality. This is a tiny local copy of the common method set -
// Put, Get, the by-block read and the range read - over finality.CaptureKey, so a change of the DB-backed store that would
// break the unification fails here at compile time.
type commonCaptureStore interface {
	Put(ctx context.Context, k finality.CaptureKey, data []byte) error
	Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error)
	ListByBlock(ctx context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error)
	ListByRange(ctx context.Context, chain, from, to uint64, itemPrefix string) ([]finality.CaptureKey, error)
}

var (
	_ commonCaptureStore    = (*FinalityCaptureStore)(nil)
	_ finality.CaptureStore = (*FinalityCaptureStore)(nil)
	_ finality.BlockBounder = (*FinalityCaptureStore)(nil)
)

// BlockBounds is the aggregate read behind finality.CaptureCoverageOf (RB12-F2): the lowest and highest L1 block of the chain's rows of
// EXACTLY one item. It is a read like the others (the table stays insert-only), and its SQL is tested here against the real table.
func TestFinalityCaptureBlockBoundsAreExactPerChainAndItem(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(2_000_000_000 + time.Now().UnixNano()%1_000_000_000) // a chain id this run alone uses: the database outlives a run
	other := chain + 1
	put := func(c uint64, block uint64, h byte, item string) {
		t.Helper()
		if err := store.Put(ctx, key(c, block, h, item), []byte{h}); err != nil {
			t.Fatal(err)
		}
	}

	if lo, hi, ok, err := store.BlockBounds(ctx, chain, finality.CaptureCursorItem); err != nil || ok || lo != 0 || hi != 0 {
		t.Fatalf("a chain with no rows has no bounds: %d %d %v %v", lo, hi, ok, err)
	}
	if _, ok, err := finality.CaptureCoverageOf(ctx, store, chain); err != nil || ok {
		t.Fatalf("no cursor row: the coverage is not known: %v %v", ok, err)
	}

	put(chain, 500, 0x01, finality.CaptureCursorItem)
	put(chain, 900, 0x02, finality.CaptureCursorItem)
	put(chain, 700, 0x03, finality.CaptureCursorItem)
	put(chain, 100, 0x04, "runtime/cursorx") // a neighbouring item name: not the cursor
	put(chain, 9000, 0x05, "runtime/curso")
	put(chain, 300, 0x06, "inbox")
	put(other, 50, 0x07, finality.CaptureCursorItem) // another chain's cursor
	put(other, 99999, 0x08, finality.CaptureCursorItem)

	lo, hi, ok, err := store.BlockBounds(ctx, chain, finality.CaptureCursorItem)
	if err != nil || !ok || lo != 500 || hi != 900 {
		t.Fatalf("the cursor rows of the chain span 500..900, exactly this item and no other chain: %d %d %v %v", lo, hi, ok, err)
	}
	if lo, hi, ok, _ := store.BlockBounds(ctx, chain, "runtime/cursorx"); !ok || lo != 100 || hi != 100 {
		t.Fatalf("a single row bounds itself: %d %d %v", lo, hi, ok)
	}
	if lo, hi, ok, _ := store.BlockBounds(ctx, other, finality.CaptureCursorItem); !ok || lo != 50 || hi != 99999 {
		t.Fatalf("the other chain keeps its own bounds: %d %d %v", lo, hi, ok)
	}
	if _, _, ok, err := store.BlockBounds(ctx, chain, "no/such/item"); err != nil || ok {
		t.Fatalf("an item the chain has no rows of: %v %v", ok, err)
	}

	cov, ok, err := finality.CaptureCoverageOf(ctx, store, chain)
	if err != nil || !ok || cov.First != 500 || cov.Last != 900 {
		t.Fatalf("the coverage of the capture loop read through the store: %+v %v %v", cov, ok, err)
	}
	// the store and the generic key listing answer alike
	lo2, hi2, ok2, err := finality.BlockBoundsOf(ctx, struct{ finality.CaptureStore }{store}, chain, finality.CaptureCursorItem)
	if err != nil || !ok2 || lo2 != lo || hi2 != hi {
		t.Fatalf("the aggregate query and the key listing disagree: %d %d %v %v", lo2, hi2, ok2, err)
	}
}
