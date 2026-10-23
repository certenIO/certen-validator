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

	"github.com/certen/independant-validator/pkg/finality"
)

// ---- proof_finality_status (V2_SPEC_S7 2.7): mutable, one row per (proof, target level) ----

func TestFinalityStatusRowIsReplacedByTheNextPassAndCarriesLevelNextAndEta(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	// a leg that really holds its l1_posted addendum: the rows below claim that level was reached (RB11-DBFIX D1: a claim of a stored
	// level is written only for a proof that holds it)
	pid, leg := storeLeg(t, "base_sepolia_47368146")
	if _, err := NewFinalityAddendaRepository(NewClientFromDB(testDB)).Append(ctx, appendRequest(t, kindRegistry(t, nil), pid, leg, finality.LevelL1Posted, "x")); err != nil {
		t.Fatal(err)
	}
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
	t.Run("the store has Put, PutBlock (insert-only, one transaction) and reads (including BlockSizes), and no method that changes or removes a row", func(t *testing.T) {
		want := map[string]bool{"Put": true, "PutBlock": true, "Get": true, "ListByBlock": true, "ListByRange": true, "BlockSizes": true}
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
)
