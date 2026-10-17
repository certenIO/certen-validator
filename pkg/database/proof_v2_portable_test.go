// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"strings"
	"testing"
)

// The portable proof v2 document is stored beside the evidence (RB7b-F30): the part that belongs to one proof, the shared spine once,
// and the govRoot v3 inputs whenever the intent's certificate gets built.
func TestPortableDocumentStore(t *testing.T) {
	ctx := context.Background()
	r := NewProofV2ShadowRepository(NewClientFromDB(testDB))
	id := "portable-" + strings.ReplaceAll(t.Name(), "/", "-")
	t.Cleanup(func() { _, _ = testDB.Exec(`DELETE FROM proof_v2_portable WHERE intent_id = $1`, id) })

	// the certificate's inputs can arrive before the document: they wait as a row with no document
	if err := r.RecordGovRootInputs(ctx, id, []byte(`{"g0Hash":"aa"}`)); err != nil {
		t.Fatal(err)
	}
	var doc, inputs string
	var majors int
	read := func() {
		t.Helper()
		if err := testDB.QueryRow(`SELECT document, majors, COALESCE(govroot_v3_inputs, '') FROM proof_v2_portable WHERE intent_id = $1`, id).Scan(&doc, &majors, &inputs); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if doc != "" || inputs != `{"g0Hash":"aa"}` {
		t.Fatalf("waiting row: document %q inputs %q", doc, inputs)
	}

	// the document, when it is built, keeps them; a rebuild replaces the document and keeps them again
	if err := r.SavePortable(ctx, id, []byte(`{"format":"x","majors":[]}`), 491); err != nil {
		t.Fatal(err)
	}
	read()
	if doc != `{"format":"x","majors":[]}` || majors != 491 || inputs != `{"g0Hash":"aa"}` {
		t.Fatalf("after save: %q %d %q", doc, majors, inputs)
	}
	if err := r.SavePortable(ctx, id, []byte(`{"format":"y","majors":[]}`), 492); err != nil {
		t.Fatal(err)
	}
	read()
	if doc != `{"format":"y","majors":[]}` || majors != 492 || inputs != `{"g0Hash":"aa"}` {
		t.Fatalf("after rebuild: %q %d %q", doc, majors, inputs)
	}
	if err := r.SavePortable(ctx, id, []byte(`{}`), 0); err == nil {
		t.Fatal("a document that needs no major block was stored")
	}
}

func TestPortableSpineIsWrittenOnceAndNeverChanges(t *testing.T) {
	ctx := context.Background()
	r := NewProofV2ShadowRepository(NewClientFromDB(testDB))
	_, _ = testDB.Exec(`DELETE FROM proof_v2_spine_json`)
	t.Cleanup(func() { _, _ = testDB.Exec(`DELETE FROM proof_v2_spine_json`) })

	if err := r.SaveSpineJSON(ctx, 1, [][]byte{[]byte(`{"index":1}`), []byte(`{"index":2}`)}); err != nil {
		t.Fatal(err)
	}
	// the same records again are fine (a restart re-walks the spine)
	if err := r.SaveSpineJSON(ctx, 1, [][]byte{[]byte(`{"index":1}`)}); err != nil {
		t.Fatalf("a record stored again unchanged: %v", err)
	}
	// a different record for a stored major block is refused by name
	err := r.SaveSpineJSON(ctx, 2, [][]byte{[]byte(`{"index":"forged"}`)})
	if err == nil || !strings.Contains(err.Error(), "major block 2") {
		t.Fatalf("a changed record was accepted: %v", err)
	}
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM proof_v2_spine_json`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("stored %d records (%v)", n, err)
	}
}
