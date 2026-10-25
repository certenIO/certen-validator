// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/capture/storetest"
)

// nsStore isolates one run of the store conformance suite inside the shared (insert-only, never cleared) table: the suite's anchors
// are uniform bytes, so the first 16 bytes carry a run-unique prefix on the way in and are restored on the way out.
type nsStore struct {
	inner capture.Store
	pre   [16]byte
}

func (s nsStore) in(a [32]byte) [32]byte {
	if a == ([32]byte{}) {
		return a // a zero anchor must stay zero: the suite asserts it is refused
	}
	copy(a[:16], s.pre[:])
	return a
}
func (s nsStore) out(a [32]byte) [32]byte {
	for i := 0; i < 16; i++ {
		a[i] = a[31]
	}
	return a
}
func (s nsStore) Put(ctx context.Context, k capture.Key, d []byte) error {
	k.AnchorID = s.in(k.AnchorID)
	return s.inner.Put(ctx, k, d)
}
func (s nsStore) Get(ctx context.Context, k capture.Key) ([]byte, bool, error) {
	k.AnchorID = s.in(k.AnchorID)
	return s.inner.Get(ctx, k)
}
func (s nsStore) ListByAnchor(ctx context.Context, chain uint64, a [32]byte) ([]capture.Key, error) {
	ks, err := s.inner.ListByAnchor(ctx, chain, s.in(a))
	for i := range ks {
		ks[i].AnchorID = s.out(ks[i].AnchorID)
	}
	return ks, err
}
func (s nsStore) ListByBlock(ctx context.Context, chain uint64, a, b [32]byte) ([]capture.Row, error) {
	rs, err := s.inner.ListByBlock(ctx, chain, s.in(a), b)
	for i := range rs {
		rs[i].AnchorID = s.out(rs[i].AnchorID)
	}
	return rs, err
}

// The production store passes the SAME conformance suite as the in-memory one (storetest.Run), on PostgreSQL.
func TestIdentityCaptureStorePassesTheConformanceSuite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) capture.Store {
		var pre [16]byte
		if _, err := rand.Read(pre[:]); err != nil {
			t.Fatal(err)
		}
		return nsStore{inner: NewIdentityCaptureStore(NewClientFromDB(testDB)), pre: pre}
	})
}

func execRaw(t *testing.T, q string, args ...any) error {
	t.Helper()
	_, err := testDB.Exec(q, args...)
	return err
}

// The tables refuse UPDATE, DELETE and TRUNCATE whoever the writer (trigger, SQLSTATE 23001), and the guard function pins its search_path
// (defect class 4): a schema a caller controls cannot shadow what it calls.
func TestIdentityTablesAreInsertOnlyAndTheGuardPinsItsSearchPath(t *testing.T) {
	st := NewIdentityCaptureStore(NewClientFromDB(testDB))
	var anchor, blk [32]byte
	_, _ = rand.Read(anchor[:])
	_, _ = rand.Read(blk[:])
	k := capture.Key{Chain: 77, AnchorID: anchor, BlockHash: blk, Item: "settle/proof"}
	if err := st.Put(context.Background(), k, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// a row must exist for the row trigger to fire
	var sh [32]byte
	copy(sh[:], bytes.Repeat([]byte{0x55}, 32))
	sl, sc := idContainer(t, 11155111, 55, 0x55, statedPart("state_unavailable", sh, 55), statedPart("state_unavailable", sh, 55))
	if _, _, err := NewContractIdentityRepository(NewClientFromDB(testDB)).Append(context.Background(), uuid.NewString(), 11155111, sl, sc, ci.DigestOf(11155111, 55, sl.Hash, sc)); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE proof_identity_capture SET bytes = '\x00' WHERE chain = 77`,
		`DELETE FROM proof_identity_capture WHERE chain = 77`,
		`TRUNCATE proof_identity_capture`,
		`UPDATE proof_contract_identity SET digest = digest`,
		`DELETE FROM proof_contract_identity`,
		`TRUNCATE proof_contract_identity`,
	} {
		if pgCode(execRaw(t, q)) != "23001" {
			t.Fatalf("%s must be refused with SQLSTATE 23001, got %v", q, execRaw(t, q))
		}
	}
	var cfg []string
	if err := testDB.QueryRow(`SELECT proconfig FROM pg_proc WHERE proname = 'proof_identity_guard'`).Scan(pq.Array(&cfg)); err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 1 || cfg[0] != "search_path=pg_catalog, pg_temp" {
		t.Fatalf("the guard function must pin search_path=pg_catalog, pg_temp, got %v", cfg)
	}
}

// ---- the container repository ----

func idContainer(t *testing.T, chain, number uint64, hash byte, settle, attest ci.Part) (ci.BlockRef, []byte) {
	t.Helper()
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{hash}, 32))
	leg := ci.BlockRef{Number: number, Hash: h}
	return leg, ci.EncodeUnvalidated(&ci.Container{Chain: chain, Leg: leg, Settle: settle, Attest: attest})
}

func statedPart(reason string, h [32]byte, n uint64) ci.Part {
	return ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: n, JudgedHash: h}}
}

func TestContractIdentityRepositoryAppendsInsertOnlyWithAGreatestSeq(t *testing.T) {
	ctx := context.Background()
	repo := NewContractIdentityRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{0x22}, 32))
	leg, c1 := idContainer(t, 11155111, 1000, 0x22, statedPart("capture_not_attempted_in_window", h, 1000), statedPart("attest_block_state_unavailable", h, 1000))
	d1 := ci.DigestOf(11155111, leg.Number, leg.Hash, c1)

	if _, ok, err := repo.Latest(ctx, pid); err != nil || ok {
		t.Fatalf("a proof without a container: %v %v", ok, err)
	}
	seq, appended, err := repo.Append(ctx, pid, 11155111, leg, c1, d1)
	if err != nil || !appended || seq != 1 {
		t.Fatalf("first append: %d %v %v", seq, appended, err)
	}
	// the same bytes again are an idempotent no-op that names the stored seq (seven validators share one Postgres)
	seq, appended, err = repo.Append(ctx, pid, 11155111, leg, c1, d1)
	if err != nil || appended || seq != 1 {
		t.Fatalf("duplicate append must be a no-op naming seq 1: %d %v %v", seq, appended, err)
	}
	got, ok, err := repo.Latest(ctx, pid)
	if err != nil || !ok || got.Seq != 1 || !bytes.Equal(got.Evidence, c1) || got.Digest != d1 || got.Chain != 11155111 || got.BlockNumber != 1000 || got.BlockHash != leg.Hash {
		t.Fatalf("latest: %+v %v %v", got, ok, err)
	}
	// a digest that is not the container's is a storage inconsistency, never stored
	var bad [32]byte
	if _, _, err := repo.Append(ctx, pid, 11155111, leg, c1, bad); !errors.Is(err, ErrContractIdentityDigest) {
		t.Fatalf("wrong digest must be ErrContractIdentityDigest, got %v", err)
	}
}

// A Stated container is refused when a captured one exists (better_present); a captured container after a Stated one is a NEW row seq+1.
func TestContractIdentityRepositoryRefusesAStatedContainerWhenACapturedOneExists(t *testing.T) {
	ctx := context.Background()
	repo := NewContractIdentityRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{0x33}, 32))
	stated := statedPart("capture_not_attempted_in_window", h, 5)
	leg, cs := idContainer(t, 84532, 5, 0x33, stated, stated)
	if seq, ok, err := repo.Append(ctx, pid, 84532, leg, cs, ci.DigestOf(84532, 5, leg.Hash, cs)); err != nil || !ok || seq != 1 {
		t.Fatalf("stated first: %d %v %v", seq, ok, err)
	}
	captured := ci.Part{Tag: ci.TagCaptured}
	_, cc := idContainer(t, 84532, 5, 0x33, captured, stated)
	if seq, ok, err := repo.Append(ctx, pid, 84532, leg, cc, ci.DigestOf(84532, 5, leg.Hash, cc)); err != nil || !ok || seq != 2 {
		t.Fatalf("a better capture is a new row: %d %v %v", seq, ok, err)
	}
	if _, _, err := repo.Append(ctx, pid, 84532, leg, cs, ci.DigestOf(84532, 5, leg.Hash, cs)); !errors.Is(err, ErrContractIdentityBetterPresent) {
		t.Fatalf("stated after captured must be better_present, got %v", err)
	}
}

// The size guard is EXACT: MaxContractIdentityBytes passes, one more byte is refused and nothing is stored.
func TestContractIdentityRepositorySizeGuardIsExact(t *testing.T) {
	ctx := context.Background()
	repo := NewContractIdentityRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	leg := ci.BlockRef{Number: 9, Hash: [32]byte{9}}
	big := bytes.Repeat([]byte{7}, ci.MaxContractIdentityBytes+1)
	if _, _, err := repo.Append(ctx, pid, 421614, leg, big, ci.DigestOf(421614, 9, leg.Hash, big)); !errors.Is(err, ErrContractIdentityTooLarge) {
		t.Fatalf("N+1 must be ErrContractIdentityTooLarge, got %v", err)
	}
	if _, ok, err := repo.Latest(ctx, pid); err != nil || ok {
		t.Fatalf("nothing is stored for a refused container: %v %v", ok, err)
	}
	if err := execRaw(t, `INSERT INTO proof_contract_identity (proof_id, seq, chain, block_number, block_hash, evidence, evidence_sha256, digest)
		VALUES ($1, 1, 421614, 9, $2, $3, $4, $4)`, pid, leg.Hash[:], big, make([]byte, 32)); err == nil {
		t.Fatal("the table itself must refuse an evidence over MaxContractIdentityBytes")
	}
}

// Seven validators append the same container at once: exactly one row, every caller sees seq 1.
func TestContractIdentityRepositoryConcurrentIdenticalAppendsMakeOneRow(t *testing.T) {
	ctx := context.Background()
	repo := NewContractIdentityRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	var h [32]byte
	copy(h[:], bytes.Repeat([]byte{0x44}, 32))
	st := statedPart("state_unavailable", h, 77)
	leg, c := idContainer(t, 2017, 77, 0x44, st, st)
	d := ci.DigestOf(2017, 77, leg.Hash, c)
	type res struct {
		seq uint64
		err error
	}
	out := make(chan res, 7)
	for i := 0; i < 7; i++ {
		go func() { s, _, err := repo.Append(ctx, pid, 2017, leg, c, d); out <- res{s, err} }()
	}
	for i := 0; i < 7; i++ {
		if r := <-out; r.err != nil || r.seq != 1 {
			t.Fatalf("%+v", r)
		}
	}
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM proof_contract_identity WHERE proof_id = $1`, pid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d %v", n, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/s8shape/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var _ = sql.ErrNoRows
