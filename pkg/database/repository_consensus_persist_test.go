package database

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for committed-block consensus persistence (off the ABCI Commit path). They run
// against CERTEN_TEST_DB (see TestMain) with every embedded migration applied.

var migrateConsensusOnce sync.Once

func consensusRepoForTest(t *testing.T) *ConsensusRepository {
	t.Helper()
	if testDB == nil {
		t.Skip("Test database not configured")
	}
	client := NewClientFromDB(testDB)
	var migErr error
	migrateConsensusOnce.Do(func() { migErr = applyMigrationFilesDirectly(client) })
	if migErr != nil {
		t.Fatalf("migrations: %v", migErr)
	}
	return NewConsensusRepository(client)
}

// applyMigrationFilesDirectly brings an empty test database to the fleet's migration state by executing each
// embedded migration file in order, outside a wrapping transaction.
//
// The embedded migrations cannot build a database from empty — a pre-existing limit unrelated to this
// change: 005_intent_metadata carries its own BEGIN/COMMIT (which ends MigrateUp's transaction) and
// 010_backfill_leg_progress references a column no earlier migration creates. The fleet's database was
// built incrementally. So a migration unrelated to the consensus tables may fail here; every migration is
// then recorded as applied, as on the fleet. The migrations these tests depend on — 001 (consensus_entries,
// batch_attestations, schema_migrations) and 017 — must apply cleanly.
func applyMigrationFilesDirectly(client *Client) error {
	ms, err := client.getMigrations()
	if err != nil {
		return err
	}
	required := map[string]bool{"001_initial_schema": true, "017_consensus_persistence_progress": true}
	for _, m := range ms {
		if _, err := testDB.Exec(m.SQL); err != nil && required[m.Version] {
			return fmt.Errorf("%s: %w", m.Version, err)
		}
		// Some older migrations do not record themselves; record every one as the fleet has it. 017 is left
		// to record itself (TestMigration017AppliesThroughMigrateUpAndRegistersItself checks that it does).
		if m.Version == "017_consensus_persistence_progress" {
			continue
		}
		if _, err := testDB.Exec(`INSERT INTO schema_migrations (version, description) VALUES ($1, 'test fixture') ON CONFLICT (version) DO NOTHING`, m.Version); err != nil {
			return fmt.Errorf("record %s: %w", m.Version, err)
		}
	}
	return nil
}

// The production upgrade path: a database at 016 runs MigrateUp on the new binary. Exactly 017 applies,
// registers itself, and the next start applies nothing.
func TestMigration017AppliesThroughMigrateUpAndRegistersItself(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	client := repo.client

	// Rewind to the fleet's state before this change.
	if _, err := testDB.Exec(`DROP TABLE IF EXISTS consensus_persistence_progress;
		DELETE FROM schema_migrations WHERE version = '017_consensus_persistence_progress'`); err != nil {
		t.Fatal(err)
	}
	applied, err := client.getAppliedMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := client.getMigrations()
	for _, m := range all {
		if m.Version != "017_consensus_persistence_progress" && !applied[m.Version] {
			t.Fatalf("fixture: %s is not registered, so MigrateUp would re-apply it", m.Version)
		}
	}

	if err := client.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp from 016: %v", err)
	}
	applied, _ = client.getAppliedMigrations(ctx)
	if !applied["017_consensus_persistence_progress"] {
		t.Fatal("017 did not register itself in schema_migrations; it would re-run on every start")
	}
	if _, err := repo.PersistCommittedBlock(ctx, writerForTest(), &CommittedConsensusRecords{Height: 1}); err != nil {
		t.Fatalf("table not usable after MigrateUp: %v", err)
	}
	if err := client.MigrateUp(ctx); err != nil {
		t.Fatalf("second MigrateUp: %v", err)
	}
}

func committedRecordsForTest(height int64, blockTime time.Time, state string) (*CommittedConsensusRecords, uuid.UUID) {
	batch := uuid.New()
	valid := true
	completed := blockTime
	return &CommittedConsensusRecords{
		Height: height,
		Entries: []CommittedConsensusEntry{{
			NewConsensusEntry: NewConsensusEntry{
				BatchID: batch, MerkleRoot: []byte{0xaa, 0xbb}, AnchorTxHash: "0xfictional", BlockNumber: height,
				TxCount: 0, State: state, AttestationCount: 1, RequiredCount: 5, QuorumFraction: 1.0 / 7,
				AggregateSignature: []byte{0x01}, AggregatePubKey: []byte{0x02}, StartTime: blockTime,
				ResultJSON: map[string]interface{}{"bundle_id": "0xfictional-" + batch.String()},
			},
			CompletedAt: &completed,
		}},
		Attestations: []NewBatchAttestation{{
			BatchID: batch, ValidatorID: "validator-fictional", MerkleRoot: []byte{0xaa, 0xbb},
			BLSSignature: []byte{0x01}, BLSPublicKey: []byte{0x02}, TxCount: 0, BlockHeight: height,
			AttestationTime: blockTime, SignatureValid: &valid,
		}},
	}, batch
}

func writerForTest() string { return "writer-fictional-" + uuid.NewString() }

func TestPersistCommittedBlockInsertsOnceAndNeverRewrites(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()
	bt := time.Date(2026, 9, 15, 15, 47, 55, 0, time.UTC)

	rec, batch := committedRecordsForTest(2185, bt, "completed")
	if _, err := repo.PersistCommittedBlock(ctx, writer, rec); err != nil {
		t.Fatal(err)
	}
	first, err := repo.GetConsensusEntry(ctx, batch)
	if err != nil || first == nil {
		t.Fatalf("entry not stored: %v", err)
	}
	if first.CompletedAt == nil || !first.CompletedAt.Equal(bt) {
		t.Fatalf("completed_at = %v, want the block time %v", first.CompletedAt, bt)
	}

	// A second writer persisting the same block with different mutable values changes nothing.
	again, _ := committedRecordsForTest(2185, bt.Add(time.Hour), "collecting")
	again.Entries[0].BatchID = batch
	again.Attestations[0].BatchID = batch
	again.Entries[0].ResultJSON = map[string]interface{}{"rewritten": true}
	if _, err := repo.PersistCommittedBlock(ctx, writerForTest(), again); err != nil {
		t.Fatal(err)
	}
	second, _ := repo.GetConsensusEntry(ctx, batch)
	if second.State != "completed" || !second.CompletedAt.Equal(bt) || string(second.ResultJSON) != string(first.ResultJSON) || !second.LastUpdate.Equal(first.LastUpdate) {
		t.Fatalf("persisted row was rewritten: state=%s completed=%v json=%s", second.State, second.CompletedAt, second.ResultJSON)
	}
	if n, _ := repo.CountBatchAttestations(ctx, batch); n != 1 {
		t.Fatalf("attestations = %d, want 1", n)
	}
}

// A later update of the mutable columns (the quorum columns and the verification flag) must survive the
// same block being persisted again; the removed upsert reset them on every Commit.
//
// The quorum columns are set here directly rather than through a repository method: the only writer of
// them was the retired shadow coordinator, and this test is about what PersistCommittedBlock must not
// overwrite, whoever wrote it.
func TestPersistCommittedBlockPreservesQuorumMetAndVerification(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()
	bt := time.Date(2026, 9, 15, 16, 0, 0, 0, time.UTC)

	rec, batch := committedRecordsForTest(3000, bt, "completed")
	if _, err := repo.PersistCommittedBlock(ctx, writer, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		UPDATE consensus_entries
		   SET state = 'quorum_met', aggregate_signature = $2, aggregate_pubkey = $3,
		       attestation_count = 6, result_json = $4, completed_at = NOW(), last_update = NOW()
		 WHERE batch_id = $1`,
		batch, []byte{0xde, 0xad}, []byte{0xbe, 0xef}, `{"quorum":"fictional"}`); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkBatchAttestationVerifiedByBatchAndValidator(ctx, batch, "validator-fictional", false); err != nil {
		t.Fatal(err)
	}
	marked, _ := repo.GetConsensusEntry(ctx, batch)

	rec.Height = 3001 // the same block re-offered (a later rebuild), watermark moving on
	if _, err := repo.PersistCommittedBlock(ctx, writer, rec); err != nil {
		t.Fatal(err)
	}
	after, _ := repo.GetConsensusEntry(ctx, batch)
	if after.State != "quorum_met" || after.AttestationCount != 6 || string(after.AggregateSignature) != string([]byte{0xde, 0xad}) ||
		!after.CompletedAt.Equal(*marked.CompletedAt) || string(after.ResultJSON) != string(marked.ResultJSON) {
		t.Fatalf("quorum_met overwritten: state=%s count=%d sig=%x", after.State, after.AttestationCount, after.AggregateSignature)
	}
	atts, _ := repo.GetBatchAttestations(ctx, batch)
	if len(atts) != 1 || atts[0].SignatureValid == nil || *atts[0].SignatureValid {
		t.Fatalf("attestation verification flag overwritten: %+v", atts)
	}
}

func TestPersistedHeightOnlyMovesForward(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()

	if _, found, err := repo.LoadPersistedHeight(ctx, writer); err != nil || found {
		t.Fatalf("new writer: found=%v err=%v, want not found", found, err)
	}
	for _, h := range []int64{10, 12, 5} {
		if _, err := repo.PersistCommittedBlock(ctx, writer, &CommittedConsensusRecords{Height: h}); err != nil {
			t.Fatal(err)
		}
	}
	if h, found, err := repo.LoadPersistedHeight(ctx, writer); err != nil || !found || h != 12 {
		t.Fatalf("watermark = %d found=%v err=%v, want 12", h, found, err)
	}
	other := writerForTest()
	if _, err := repo.PersistCommittedBlock(ctx, other, &CommittedConsensusRecords{Height: 3}); err != nil {
		t.Fatal(err)
	}
	if h, _, _ := repo.LoadPersistedHeight(ctx, writer); h != 12 {
		t.Fatalf("another writer moved this writer's watermark to %d", h)
	}
}

// One invalid row aborts the block's transaction entirely: no partial rows, no watermark advance.
func TestPersistCommittedBlockIsAtomic(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()
	if _, err := repo.PersistCommittedBlock(ctx, writer, &CommittedConsensusRecords{Height: 40}); err != nil {
		t.Fatal(err)
	}

	// A failure that is not a content rejection (here the watermark update: writer_id is VARCHAR(256), and a
	// class-22 error outside a row savepoint aborts the block) rolls everything back.
	rec, batch := committedRecordsForTest(41, time.Now().UTC(), "completed")
	longWriter := strings.Repeat("w", 300)
	if _, err := repo.PersistCommittedBlock(ctx, longWriter, rec); err == nil || !strings.Contains(err.Error(), "advance watermark") {
		t.Fatalf("err = %v, want the watermark update to fail", err)
	}
	if e, _ := repo.GetConsensusEntry(ctx, batch); e != nil {
		t.Fatal("consensus entry committed despite the failed block transaction")
	}
	if h, _, _ := repo.LoadPersistedHeight(ctx, writer); h != 40 {
		t.Fatalf("watermark = %d after a failed block, want 40", h)
	}
	if h, found, _ := repo.LoadPersistedHeight(ctx, longWriter[:256]); found {
		t.Fatalf("a truncated watermark row exists at %d", h)
	}
}

// A row refused on its content is skipped and reported; the rest of the block and the watermark commit.
// The previous writer logged and skipped such rows too; a writer that retried them would stall forever.
func TestPersistCommittedBlockSkipsRowsRefusedOnContent(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()

	rec, good := committedRecordsForTest(50, time.Now().UTC(), "completed")
	bad, badBatch := committedRecordsForTest(50, time.Now().UTC(), "not-a-consensus-state") // valid_consensus_state: 23514
	tooLong, longBatch := committedRecordsForTest(50, time.Now().UTC(), "completed")
	tooLong.Entries[0].AnchorTxHash = "0x" + strings.Repeat("f", 80) // anchor_tx_hash VARCHAR(66): 22001
	rec.Entries = append(rec.Entries, bad.Entries[0], tooLong.Entries[0])

	rejected, err := repo.PersistCommittedBlock(ctx, writer, rec)
	if err != nil {
		t.Fatalf("content rejections must not fail the block: %v", err)
	}
	// Rows are written in batch-id order (PersistCommittedBlock sorts them so concurrent writers cannot
	// deadlock), and the ids are random uuids — so which refusal is reported first is not fixed. Assert
	// the SET of refused rows, never their order.
	rejectedIDs := map[uuid.UUID]bool{}
	for _, r := range rejected {
		rejectedIDs[r.BatchID] = true
	}
	if len(rejected) != 2 || !rejectedIDs[badBatch] || !rejectedIDs[longBatch] {
		t.Fatalf("rejected = %+v, want the invalid-state and over-long rows", rejected)
	}
	if e, _ := repo.GetConsensusEntry(ctx, good); e == nil {
		t.Fatal("the valid row was not committed")
	}
	if e, _ := repo.GetConsensusEntry(ctx, badBatch); e != nil {
		t.Fatal("a refused row was committed")
	}
	if n, _ := repo.CountBatchAttestations(ctx, good); n != 1 {
		t.Fatalf("attestations for the valid row = %d, want 1", n)
	}
	if h, _, _ := repo.LoadPersistedHeight(ctx, writer); h != 50 {
		t.Fatalf("watermark = %d, want 50", h)
	}
}

func TestPersistCommittedBlockRejectsInvalidInput(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	if _, err := repo.PersistCommittedBlock(ctx, "", &CommittedConsensusRecords{Height: 1}); err == nil {
		t.Fatal("empty writer accepted")
	}
	if _, err := repo.PersistCommittedBlock(ctx, writerForTest(), &CommittedConsensusRecords{Height: 0}); err == nil {
		t.Fatal("height 0 accepted")
	}
	if _, err := repo.PersistCommittedBlock(ctx, writerForTest(), nil); err == nil {
		t.Fatal("nil records accepted")
	}
}

func TestResetPersistedHeightMovesTheWatermarkBackwards(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	writer := writerForTest()
	if _, err := repo.PersistCommittedBlock(ctx, writer, &CommittedConsensusRecords{Height: 5000}); err != nil {
		t.Fatal(err)
	}
	if err := repo.ResetPersistedHeight(ctx, writer, 0); err != nil {
		t.Fatal(err)
	}
	if h, found, _ := repo.LoadPersistedHeight(ctx, writer); !found || h != 0 {
		t.Fatalf("watermark = %d found=%v, want 0", h, found)
	}
	if _, err := repo.PersistCommittedBlock(ctx, writer, &CommittedConsensusRecords{Height: 1}); err != nil {
		t.Fatal(err)
	}
	if h, _, _ := repo.LoadPersistedHeight(ctx, writer); h != 1 {
		t.Fatalf("watermark = %d after the rewound chain's first block, want 1", h)
	}
	if err := repo.ResetPersistedHeight(ctx, writer, -1); err == nil {
		t.Fatal("negative height accepted")
	}
}

// Validators that start together must all get through migration 017; before the advisory lock six of seven
// failed with a pg_type unique violation and MigrateUp stopped there.
func TestMigration017SurvivesSevenValidatorsStartingTogether(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	for round := 0; round < 3; round++ {
		if _, err := testDB.Exec(`DROP TABLE IF EXISTS consensus_persistence_progress;
			DELETE FROM schema_migrations WHERE version = '017_consensus_persistence_progress'`); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 7)
		var wg sync.WaitGroup
		for i := 0; i < 7; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- repo.client.MigrateUp(ctx)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: concurrent MigrateUp failed: %v", round, err)
			}
		}
	}
}

// Where MigrateUp never reaches 017, the writer creates the table itself — concurrently and repeatedly.
func TestEnsurePersistenceProgressTableIsConcurrentAndIdempotent(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	if _, err := testDB.Exec(`DROP TABLE IF EXISTS consensus_persistence_progress`); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 7)
	var wg sync.WaitGroup
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- repo.EnsurePersistenceProgressTable(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ensure failed: %v", err)
		}
	}
	if err := repo.EnsurePersistenceProgressTable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PersistCommittedBlock(ctx, writerForTest(), &CommittedConsensusRecords{Height: 1}); err != nil {
		t.Fatalf("table unusable: %v", err)
	}
}

// Writers persisting the same block in different record orders must not deadlock.
func TestWritersPersistingOneBlockInDifferentOrdersDoNotDeadlock(t *testing.T) {
	repo := consensusRepoForTest(t)
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		base, _ := committedRecordsForTest(int64(100+round), time.Now().UTC(), "completed")
		for i := 0; i < 5; i++ {
			more, _ := committedRecordsForTest(base.Height, time.Now().UTC(), "completed")
			base.Entries = append(base.Entries, more.Entries...)
			base.Attestations = append(base.Attestations, more.Attestations...)
		}
		errs := make(chan error, 7)
		var wg sync.WaitGroup
		for w := 0; w < 7; w++ {
			rec := *base
			rec.Entries = append([]CommittedConsensusEntry(nil), base.Entries...)
			rec.Attestations = append([]NewBatchAttestation(nil), base.Attestations...)
			if w%2 == 1 { // reversed order on half the writers
				for i, j := 0, len(rec.Entries)-1; i < j; i, j = i+1, j-1 {
					rec.Entries[i], rec.Entries[j] = rec.Entries[j], rec.Entries[i]
					rec.Attestations[i], rec.Attestations[j] = rec.Attestations[j], rec.Attestations[i]
				}
			}
			wg.Add(1)
			go func(r CommittedConsensusRecords) {
				defer wg.Done()
				_, err := repo.PersistCommittedBlock(ctx, writerForTest(), &r)
				errs <- err
			}(rec)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
}
