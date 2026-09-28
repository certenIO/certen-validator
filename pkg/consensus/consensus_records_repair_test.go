package consensus

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
)

type fakeCommitReader struct {
	quorum      map[int64]*commitQuorum
	times       map[int64]time.Time
	unavailable map[int64]bool
	batches     map[int64]map[uuid.UUID]bool
}

func (f *fakeCommitReader) BatchIDsAt(_ context.Context, h int64) (map[uuid.UUID]bool, error) {
	if f.unavailable[h] {
		return nil, errCommittedBlockUnavailable
	}
	b, ok := f.batches[h]
	if !ok {
		// A height this fake does not hold: another suite's row in the shared test database, left alone.
		return nil, errors.New("height not in this fake block store")
	}
	return b, nil
}

func (f *fakeCommitReader) CommitQuorum(_ context.Context, h int64) (*commitQuorum, error) {
	if f.unavailable[h] {
		return nil, errCommittedBlockUnavailable
	}
	if q, ok := f.quorum[h]; ok {
		return q, nil
	}
	return nil, errors.New("no commit")
}

func (f *fakeCommitReader) BlockTime(_ context.Context, h int64) (time.Time, error) {
	return f.times[h], nil
}

func consensusRepairDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := testdb.PackageURL("consensus")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := (schema.Runner{DB: db}).Up(context.Background(), "consensus-test-suite"); err != nil {
		t.Fatal(err)
	}
	return db
}

// RB3-F138: an entry written by the old mapping is restated from the commit that committed its height, the
// unverified validity of its batch's signature row is withdrawn, each with a correction record; an anchor
// batch's verified rows are untouched; a second run has nothing to do.
func TestConsensusRecordsAreRestatedFromTheirCommit(t *testing.T) {
	db := consensusRepairDB(t)
	ctx := context.Background()
	height := time.Now().UnixNano() % 1_000_000_000
	entry, batch := uuid.New(), uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO consensus_entries (entry_id, batch_id, merkle_root, block_number, tx_count, state, attestation_count,
		                               required_count, quorum_fraction, aggregate_signature, aggregate_pubkey, start_time, last_update, result_json)
		VALUES ($1, $2, '\xaa', $3, 1, 'quorum_met', 1, 5, 0.1429, '\xbbbb', '\xcccc', NOW(), NOW(), '{"governance_level":"G1"}')`,
		entry, batch, height); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO batch_attestations (batch_id, validator_id, evm_address, voting_power, merkle_root, bls_signature,
		                                bls_public_key, tx_count, block_height, attestation_time, signature_valid)
		VALUES ($1, 'certen-testnet', 'certen-testnet', 1, '\xaa', '\xbbbb', '\xcccc', 1, $2, NOW(), TRUE)`, batch, height); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM evidence_corrections WHERE record_id IN ($1, $2)`, entry.String(), batch.String())
		_, _ = db.ExecContext(bg, `DELETE FROM batch_attestations WHERE batch_id = $1`, batch)
		_, _ = db.ExecContext(bg, `DELETE FROM consensus_entries WHERE entry_id = $1`, entry)
	})

	blockTime := time.Unix(1_790_000_000, 0).UTC()
	commits := &fakeCommitReader{quorum: map[int64]*commitQuorum{height: {Signers: 6, Validators: 7, SignedPower: 6, TotalPower: 7}},
		times: map[int64]time.Time{height: blockTime}, unavailable: map[int64]bool{},
		batches: map[int64]map[uuid.UUID]bool{height: {batch: true}}}
	repair := database.NewEvidenceRepair(database.NewClientFromDB(db))

	// Other tests' stale entries share the database; this one is judged by its own rows.
	if _, err := RepairConsensusRecords(ctx, repair, commits, "validator-test", true); err != nil {
		t.Fatal(err)
	}
	var state string
	var signers, required int
	var fraction float64
	var completed time.Time
	var agg []byte
	var result string
	if err := db.QueryRow(`SELECT state, attestation_count, required_count, quorum_fraction::float8, completed_at, aggregate_signature, result_json::text
		FROM consensus_entries WHERE entry_id = $1`, entry).Scan(&state, &signers, &required, &fraction, &completed, &agg, &result); err != nil {
		t.Fatal(err)
	}
	if state != "completed" || signers != 6 || required != 5 || fraction < 0.857 || fraction > 0.858 || !completed.Equal(blockTime) || len(agg) != 0 {
		t.Fatalf("entry: state=%s signers=%d required=%d fraction=%v completed=%v aggregate=%x", state, signers, required, fraction, completed, agg)
	}
	if !strings.Contains(result, `"commit"`) || !strings.Contains(result, `"verified": false`) || !strings.Contains(result, "bbbb") {
		t.Fatalf("result does not state the commit and the unverified signature: %s", result)
	}
	var valid sql.NullBool
	if err := db.QueryRow(`SELECT signature_valid FROM batch_attestations WHERE batch_id = $1`, batch).Scan(&valid); err != nil || valid.Valid {
		t.Fatalf("signature_valid = %v (%v); want NULL - nothing verified it", valid, err)
	}
	var records int
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence_corrections WHERE record_id IN ($1, $2)`, entry.String(), batch.String()).Scan(&records); err != nil || records != 2 {
		t.Fatalf("%d correction records, want 2 (%v)", records, err)
	}
	// A second run finds nothing to restate for this entry.
	if _, err := RepairConsensusRecords(ctx, repair, commits, "validator-test", true); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence_corrections WHERE record_id IN ($1, $2)`, entry.String(), batch.String()).Scan(&records); err != nil || records != 2 {
		t.Fatalf("not idempotent: %d correction records", records)
	}
}

// A height the block store no longer holds is reported, never guessed.
func TestAConsensusRecordWithoutItsCommitIsNotRestated(t *testing.T) {
	db := consensusRepairDB(t)
	ctx := context.Background()
	height := time.Now().UnixNano()%1_000_000_000 + 1
	entry := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO consensus_entries (entry_id, batch_id, merkle_root, block_number, tx_count, state, attestation_count,
		                               required_count, quorum_fraction, start_time, last_update, result_json)
		VALUES ($1, $2, '\xaa', $3, 1, 'collecting', 1, 5, 0.1429, NOW(), NOW(), '{}')`, entry, uuid.New(), height); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM consensus_entries WHERE entry_id = $1`, entry)
	})
	commits := &fakeCommitReader{quorum: map[int64]*commitQuorum{}, times: map[int64]time.Time{}, unavailable: map[int64]bool{height: true}}
	report, err := RepairConsensusRecords(ctx, database.NewEvidenceRepair(database.NewClientFromDB(db)), commits, "validator-test", true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range report.Unavailable {
		found = found || strings.Contains(u, entry.String())
	}
	var state string
	_ = db.QueryRow(`SELECT state FROM consensus_entries WHERE entry_id = $1`, entry).Scan(&state)
	if !found || state != "collecting" {
		t.Fatalf("unavailable=%v state=%s; want it reported and unchanged", report.Unavailable, state)
	}
}

// The chain has restarted, and heights began again at 1: an entry whose height now holds other blocks was
// committed by an earlier incarnation. It is restated as committed at its own block time with its counts
// unknown - never from the commit of the block that now has its height.
func TestAnEarlierIncarnationsEntryIsNotRestatedFromAnotherBlocksCommit(t *testing.T) {
	db := consensusRepairDB(t)
	ctx := context.Background()
	height := time.Now().UnixNano()%1_000_000_000 + 2
	entry, batch := uuid.New(), uuid.New()
	blockTime := time.Unix(1_770_000_000, 0).UTC()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO consensus_entries (entry_id, batch_id, merkle_root, block_number, tx_count, state, attestation_count,
		                               required_count, quorum_fraction, aggregate_signature, start_time, last_update, result_json)
		VALUES ($1, $2, 'ª', $3, 1, 'quorum_met', 1, 5, 0.1429, '»bb', $4, NOW(), '{}')`, entry, batch, height, blockTime); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM evidence_corrections WHERE record_id IN ($1, $2)`, entry.String(), batch.String())
		_, _ = db.ExecContext(bg, `DELETE FROM consensus_entries WHERE entry_id = $1`, entry)
	})
	commits := &fakeCommitReader{
		quorum:  map[int64]*commitQuorum{height: {Signers: 7, Validators: 7, SignedPower: 7, TotalPower: 7}},
		times:   map[int64]time.Time{height: time.Unix(1_790_000_000, 0).UTC()},
		batches: map[int64]map[uuid.UUID]bool{height: {uuid.New(): true}}, // another block's
	}
	if _, err := RepairConsensusRecords(ctx, database.NewEvidenceRepair(database.NewClientFromDB(db)), commits, "validator-test", true); err != nil {
		t.Fatal(err)
	}
	var state string
	var signers sql.NullInt64
	var completed time.Time
	var result string
	if err := db.QueryRow(`SELECT state, attestation_count, completed_at, result_json::text FROM consensus_entries WHERE entry_id = $1`, entry).
		Scan(&state, &signers, &completed, &result); err != nil {
		t.Fatal(err)
	}
	if state != "completed" || signers.Valid || !completed.Equal(blockTime) || !strings.Contains(result, "commit_unavailable") {
		t.Fatalf("state=%s signers=%v completed=%v result=%s; want completed at its own block time, counts unknown", state, signers, completed, result)
	}
}
