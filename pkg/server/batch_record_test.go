// Copyright 2026 Certen Protocol

package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
)

// RB4-F29/F31: the batch endpoints read the row the quorum path writes. /api/batches/{id} scanned validator_id
// (NULL on every quorum row) into a string and failed on every batch the validators record; the stats query at
// /api/v1/batches/{id}/stats could never run (an untyped $1), and would have answered zero counts for a batch
// that does not exist.
func TestBatchEndpointsReadTheQuorumRow(t *testing.T) {
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Fatal("CERTEN_TEST_DB is required (a skipped gate is not a green gate)")
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err := (schema.Runner{DB: db}).Up(ctx, "server-test"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	id := uuid.New()
	sum := sha256.Sum256([]byte("quorum-row-" + id.String()))
	createTx := "0x" + hex.EncodeToString(sum[:])
	// The columns RecordAnchorQuorum writes (repository_anchor_quorum.go), validator_id NULL as it writes it.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, validator_id, transaction_count, tx_count,
			chain_id, bundle_id, anchor_create_tx, anchor_tx_hash, anchor_block_num, quorum_reached, attestation_count,
			signed_voting_power, total_voting_power, evidence_source, lane, proof_data_included, anchored_at, confirmed_at, closed_at)
		VALUES ($1, 'on_demand', 'confirmed', $2, 'ethereum', NULL, 1, 1, 11155111, $3, $4, $4, 900, TRUE, 5, 5, 7,
			'chain_event', 'on_demand', TRUE, now(), now(), now())`, id, sum[:], "bundle-"+id.String()[:8], createTx); err != nil {
		t.Fatal(err)
	}
	repos := database.NewRepositories(database.NewClientFromDB(db))

	rr := httptest.NewRecorder()
	NewBatchHandlers(repos, "t", nil).HandleBatchStatus(rr, httptest.NewRequest(http.MethodGet, "/api/batches/"+id.String(), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/batches/{id}: status %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		BatchID        string  `json:"batch_id"`
		ValidatorID    *string `json:"validator_id"`
		ChainID        int64   `json:"chain_id"`
		MerkleRoot     string  `json:"merkle_root"`
		AnchorCreateTx string  `json:"anchor_create_tx"`
		QuorumReached  bool    `json:"quorum_reached"`
		Attestations   int     `json:"attestation_count"`
		SignedPower    string  `json:"signed_voting_power"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.BatchID != id.String() || got.ValidatorID != nil || got.ChainID != 11155111 || got.MerkleRoot != hex.EncodeToString(sum[:]) ||
		got.AnchorCreateTx != createTx || !got.QuorumReached || got.Attestations != 5 || got.SignedPower != "5" {
		t.Fatalf("/api/batches/{id}: not the record as written: %s", rr.Body.String())
	}

	proofs := NewProofHandlers(repos, "t", nil)
	rr = httptest.NewRecorder()
	proofs.HandleGetBatchStats(rr, httptest.NewRequest(http.MethodGet, "/api/v1/batches/"+id.String()+"/stats", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/v1/batches/{id}/stats: status %d: %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	proofs.HandleGetBatchStats(rr, httptest.NewRequest(http.MethodGet, "/api/v1/batches/"+uuid.NewString()+"/stats", nil))
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if rr.Code != http.StatusNotFound || e.Error.Code != "BATCH_NOT_FOUND" {
		t.Fatalf("stats of a batch that does not exist: want 404 BATCH_NOT_FOUND, got %d %s", rr.Code, rr.Body.String())
	}
}
