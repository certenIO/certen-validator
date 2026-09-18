package batch

// The batch path's Certen anchor proofs, against the shared schema: the processor stores one beside each
// proof artifact, and the confirmation tracker keeps its anchor confirmations current.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/merkle"
)

func openBatchTestDB(t *testing.T) (*sql.DB, *database.Repositories) {
	t.Helper()
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CERTEN_TEST_DB is required in CI")
		}
		t.Skip("CERTEN_TEST_DB not set — the batch proof records need PostgreSQL")
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := (schema.Runner{DB: db}).Up(context.Background(), "batch-test"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, database.NewRepositories(database.NewClientFromDB(db))
}

type fixedBlocks struct{ latest int64 }

func (b fixedBlocks) GetLatestBlockNumber(context.Context) (int64, error) { return b.latest, nil }
func (b fixedBlocks) GetBlockHash(context.Context, int64) (string, error) {
	return "0xanchorblock", nil
}
func (b fixedBlocks) GetBlockTimestamp(context.Context, int64) (time.Time, error) {
	return time.Now().UTC(), nil
}

// batchWithAnchor writes a batch, one member transaction, its anchor record and its proof artifact.
func batchWithAnchor(t *testing.T, db *sql.DB, repos *database.Repositories) (*ClosedBatchResult, *database.BatchTransaction, uuid.UUID, *BatchAnchorResult, *database.ProofArtifact) {
	t.Helper()
	ctx := context.Background()
	batchID, anchorID := uuid.New(), uuid.New()
	accumTx := "batch-proof-" + uuid.NewString()
	leaf := sha256.Sum256([]byte(accumTx))
	anchorTx := "0x" + uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO anchor_batches (id, merkle_root) VALUES ($1, $2)`, batchID, leaf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash, chained_proof, governance_proof, governance_level, governance_valid)
		VALUES ($1, $2, 'acc://batch.acme/tokens', 0, $3, '{"layers":3}', '{"level":"G1"}', 'G1', TRUE)`, batchID, accumTx, leaf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_records (anchor_id, batch_id, target_chain, anchor_tx_hash, anchor_block_number)
		VALUES ($1, $2, 'ethereum', $3, 100)`, anchorID, batchID, anchorTx); err != nil {
		t.Fatal(err)
	}
	artifact, err := repos.ProofArtifacts.CreateProofArtifact(ctx, &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: accumTx, AccountURL: "acc://batch.acme/tokens",
		BatchID: &batchID, ProofClass: database.ProofClassOnCadence, ValidatorID: "batch-test", ArtifactJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM certen_anchor_proofs WHERE batch_id = $1`, batchID)
		_, _ = db.ExecContext(bg, `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
		_, _ = db.ExecContext(bg, `DELETE FROM anchor_records WHERE anchor_id = $1`, anchorID)
		_, _ = db.ExecContext(bg, `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	txs, err := repos.Batches.GetTransactionsInBatch(ctx, batchID)
	if err != nil || len(txs) != 1 {
		t.Fatalf("batch transactions: %v %v", txs, err)
	}
	result := &ClosedBatchResult{BatchID: batchID, MerkleRoot: leaf[:]}
	anchor := &BatchAnchorResult{AnchorID: anchorID, BatchID: batchID, TxHash: anchorTx, BlockNumber: 100, BlockHash: "0xanchorblock"}
	return result, txs[0], anchorID, anchor, artifact
}

func TestProcessorStoresTheCertenProofBesideTheArtifact(t *testing.T) {
	db, repos := openBatchTestDB(t)
	result, tx, anchorID, anchor, artifact := batchWithAnchor(t, db, repos)
	p := &Processor{repos: repos, validatorID: "batch-test", targetChain: "ethereum", logger: log.New(io.Discard, "", 0)}
	_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)

	// The processor's own path: it creates the artifact, then the Certen proof beside it.
	result.Proofs = []*merkle.InclusionProof{{LeafIndex: 0}}
	if err := p.createProofs(context.Background(), result, anchorID, anchor); err != nil {
		t.Fatalf("createProofs: %v", err)
	}
	created, err := repos.ProofArtifacts.GetProofByTxHash(context.Background(), tx.AccumTxHash)
	if err != nil || created == nil {
		t.Fatalf("artifact from createProofs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, created.ProofID)
	})
	proof, err := repos.Proofs.GetProofByArtifactID(context.Background(), created.ProofID)
	if err != nil {
		t.Fatalf("certen proof: %v", err)
	}
	if proof.AnchorTxHash != anchor.TxHash || !proof.AnchorID.Valid || proof.AnchorID.UUID != anchorID ||
		!proof.BatchID.Valid || proof.BatchID.UUID != result.BatchID || !proof.VerifyProofHash() ||
		!proof.GovValid || proof.TransactionID.Int64 != tx.ID {
		t.Fatalf("certen proof = %+v", proof)
	}
}

func TestConfirmationTrackerCarriesConfirmationsToTheCertenProofs(t *testing.T) {
	db, repos := openBatchTestDB(t)
	ctx := context.Background()
	result, tx, anchorID, anchor, artifact := batchWithAnchor(t, db, repos)
	p := &Processor{repos: repos, validatorID: "batch-test", targetChain: "ethereum", logger: log.New(io.Discard, "", 0)}
	p.createCertenProof(ctx, tx, result, anchorID, anchor, &merkle.InclusionProof{}, nil, database.GovLevelG1, artifact.ProofID)

	tracker, err := NewConfirmationTracker(repos, fixedBlocks{latest: 104}, &ConfirmationTrackerConfig{
		PollInterval: time.Hour, RequiredConfirmations: 12, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := repos.Anchors.GetAnchor(ctx, anchorID)
	if err != nil {
		t.Fatal(err)
	}
	tracker.processAnchor(ctx, record, 104)

	proof, err := repos.Proofs.GetProofByArtifactID(ctx, artifact.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if proof.AnchorConfirms != 5 || proof.AnchorBlockHash.String != "0xanchorblock" {
		t.Fatalf("certen proof confirmations = %d, block %q", proof.AnchorConfirms, proof.AnchorBlockHash.String)
	}
}
