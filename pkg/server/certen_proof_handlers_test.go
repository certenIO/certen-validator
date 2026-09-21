package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
)

func TestCertenProofEndpoints(t *testing.T) {
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CERTEN_TEST_DB is required in CI")
		}
		t.Skip("CERTEN_TEST_DB not set — the Certen proof endpoints need PostgreSQL")
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
	repos := database.NewRepositories(database.NewClientFromDB(db))

	account := "acc://endpoints-" + uuid.NewString() + ".acme/tokens"
	accumTx := "endpoints-" + uuid.NewString()
	artifact, err := repos.ProofArtifacts.CreateProofArtifact(ctx, &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: accumTx, AccountURL: account,
		ProofClass: database.ProofClassOnDemand, ValidatorID: "server-test", ArtifactJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	root := sha256.Sum256([]byte(accumTx))
	proof, err := repos.Proofs.CreateProof(ctx, &database.NewCertenAnchorProof{
		ProofArtifactID: artifact.ProofID, AccumTxHash: accumTx, AccountURL: account, MerkleRoot: root[:],
		AnchorChain: "base-sepolia", AnchorTxHash: "0x" + uuid.NewString(), AnchorBlockNumber: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
	})

	h := NewBatchHandlers(repos, "server-test", log.New(io.Discard, "", 0))
	get := func(handler http.HandlerFunc, path string) (int, map[string]json.RawMessage) {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var body map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	wantProof := func(name string, code int, body map[string]json.RawMessage) {
		t.Helper()
		var id uuid.UUID
		_ = json.Unmarshal(body["proof_id"], &id)
		if code != http.StatusOK || id != proof.ProofID || string(body["proof_hash_verified"]) != "true" {
			t.Fatalf("%s: %d %v", name, code, body)
		}
	}

	code, body := get(h.HandleGetCertenProof, "/api/certen-proofs/"+proof.ProofID.String())
	wantProof("by id", code, body)
	if string(body["corrections"]) != "[]" {
		t.Fatalf("an uncorrected proof lists corrections: %s", body["corrections"])
	}
	// A corrected proof carries its correction, which keeps the proof as it was published.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO evidence_corrections (record_type, record_id, reason, previous, corrected, chain_evidence, corrected_by)
		VALUES ('certen_anchor_proof', $1, 'test', '{"proof_hash":"00"}', '{"proof_hash":"11"}', '{}', 'server-test')`,
		proof.ProofID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM evidence_corrections WHERE record_id = $1`, proof.ProofID.String())
	})
	code, body = get(h.HandleGetCertenProof, "/api/certen-proofs/"+proof.ProofID.String())
	var corrections []database.EvidenceCorrection
	if err := json.Unmarshal(body["corrections"], &corrections); code != http.StatusOK || err != nil || len(corrections) != 1 ||
		string(corrections[0].Previous) != `{"proof_hash":"00"}` {
		t.Fatalf("corrections: %d %s %v", code, body["corrections"], err)
	}
	code, body = get(h.HandleGetCertenProofByArtifact, "/api/certen-proofs/by-artifact/"+artifact.ProofID.String())
	wantProof("by artifact", code, body)
	code, body = get(h.HandleGetCertenProofByTxHash, "/api/certen-proofs/by-tx/"+accumTx)
	wantProof("by tx", code, body)
	code, body = get(h.HandleGetCertenProofsByAccount, "/api/certen-proofs/by-account/"+url.PathEscape(account))
	if code != http.StatusOK || string(body["count"]) != "1" {
		t.Fatalf("by account: %d %v", code, body)
	}

	if code, _ := get(h.HandleGetCertenProof, "/api/certen-proofs/"+uuid.NewString()); code != http.StatusNotFound {
		t.Fatalf("a missing proof answered %d", code)
	}
	if code, _ := get(h.HandleGetCertenProof, "/api/certen-proofs/not-a-uuid"); code != http.StatusBadRequest {
		t.Fatalf("a malformed id answered %d", code)
	}
	if code, _ := get(h.HandleGetCertenProof, "/api/certen-proofs/"); code != http.StatusBadRequest {
		t.Fatalf("an empty id answered %d", code)
	}
}
