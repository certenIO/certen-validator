// Copyright 2026 Certen Protocol

package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F120: a database that cannot answer is a server error, never "not found". A 404 tells a client the
// proof or bundle does not exist - a false statement about evidence - when the lookup simply failed.

func unreachableRepos(t *testing.T) *database.Repositories {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return database.NewRepositories(database.NewClientFromDB(db))
}

func status(h http.HandlerFunc, path string) int {
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr.Code
}

func TestAFailedLookupIsNotReportedAsNotFound(t *testing.T) {
	repos := unreachableRepos(t)
	batch := NewBatchHandlers(repos, "t", nil)
	bundles := NewBundleHandlers(repos, nil, nil, nil, nil)
	id := uuid.NewString()
	for name, code := range map[string]int{
		"batch proof by id":   status(batch.HandleGetProof, "/api/proofs/"+id),
		"batch proof by tx":   status(batch.HandleGetProofByTxHash, "/api/proofs/by-tx/abc"),
		"batch status":        status(batch.HandleBatchStatus, "/api/batches/"+id),
		"anchor":              status(batch.HandleGetAnchor, "/api/anchors/"+id),
		"anchor by batch":     status(batch.HandleGetAnchorByBatch, "/api/anchors/by-batch/"+id),
		"bundle verify":       status(bundles.HandleVerifyBundle, "/api/v1/proofs/"+id+"/bundle/verify"),
		"bundle download (1)": status(bundles.HandleDownloadBundle, "/api/v1/proofs/"+id+"/bundle"),
	} {
		if code != http.StatusInternalServerError {
			t.Errorf("%s: status %d on a failed lookup, want 500", name, code)
		}
	}
}

// The bundle download's second lookup (the proof, when no bundle is stored) fails on its own: a schema
// holding only the bundles table makes the first lookup answer "none" and the second one fail.
func TestABundleDownloadWhoseProofLookupFailsIsNotNotFound(t *testing.T) {
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Fatal("CERTEN_TEST_DB is required (a skipped gate is not a green gate)")
	}
	admin, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	ctx := context.Background()
	if err := (schema.Runner{DB: admin}).Up(ctx, "server-test"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	name := "f120_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+name+"; CREATE TABLE "+name+".proof_bundles (LIKE public.proof_bundles INCLUDING ALL)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec("DROP SCHEMA " + name + " CASCADE") })

	sep := "?"
	if strings.Contains(conn, "?") {
		sep = "&"
	}
	db, err := sql.Open("postgres", conn+sep+"search_path="+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	bundles := NewBundleHandlers(database.NewRepositories(database.NewClientFromDB(db)), nil, nil, nil, nil)
	if code := status(bundles.HandleDownloadBundle, "/api/v1/proofs/"+uuid.NewString()+"/bundle"); code != http.StatusInternalServerError {
		t.Fatalf("status %d when the proof lookup failed, want 500", code)
	}

	// Absent really is 404: the full schema, a proof that does not exist.
	full := NewBundleHandlers(database.NewRepositories(database.NewClientFromDB(admin)), nil, nil, nil, nil)
	if code := status(full.HandleDownloadBundle, "/api/v1/proofs/"+uuid.NewString()+"/bundle"); code != http.StatusNotFound {
		t.Fatalf("status %d for a proof that does not exist, want 404", code)
	}
	batch := NewBatchHandlers(database.NewRepositories(database.NewClientFromDB(admin)), "t", nil)
	for path, h := range map[string]http.HandlerFunc{
		"/api/proofs/" + uuid.NewString():           batch.HandleGetProof,
		"/api/batches/" + uuid.NewString():          batch.HandleBatchStatus,
		"/api/anchors/" + uuid.NewString():          batch.HandleGetAnchor,
		"/api/anchors/by-batch/" + uuid.NewString(): batch.HandleGetAnchorByBatch,
	} {
		if code := status(h, path); code != http.StatusNotFound {
			t.Fatalf("%s: status %d for a record that does not exist, want 404", path, code)
		}
	}
}
