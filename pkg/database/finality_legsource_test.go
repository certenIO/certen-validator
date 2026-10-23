// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// The leg source reads what production writes: a summary-only proof_artifacts.artifact_json and the full bundle in
// proof_bundles.bundle_data (gzip). These tests pin that source, and every named state the source has for a bundle it cannot
// use. The seeding is finalitytest's production shape, never a shape the source's author assumed.

// leg is one stored proof of a real settlement, with its bundle not yet stored.
type leg struct {
	id   string
	s    finality.Settlement
	exec map[string]any
}

// newLeg stores the proof_artifacts row (settlement columns set) of a real settled leg and no bundle.
func newLeg(t *testing.T, fixture string) leg {
	t.Helper()
	s := finalitytest.Settlement(t, fixture)
	exec := finalitytest.ProductionExecutionProof(t, s)
	id := finalitytest.StoreProductionArtifact(t, testDB, s.Chain, exec["tx_hash"].(string), exec["block_number"].(uint64))
	return leg{id: id, s: s, exec: exec}
}

// storeBundleAt stores a proof_bundles row created at the given time.
func storeBundleAt(t *testing.T, id string, data []byte, at time.Time) {
	t.Helper()
	if _, err := testDB.Exec(`INSERT INTO proof_bundles (proof_id, bundle_format, bundle_version, bundle_data, bundle_hash, bundle_size_bytes, created_at)
		VALUES ($1::uuid, 'certen_v1', '1.0', $2, $3, $4, $5)`, id, data, make([]byte, 32), len(data), at); err != nil {
		t.Fatal(err)
	}
}

// listed pages through every leg the source lists and returns them by proof id.
func listed(t *testing.T, repo *FinalityAddendaRepository) map[string]finality.LegRef {
	t.Helper()
	out := map[string]finality.LegRef{}
	after := ""
	for {
		page, err := repo.SettledLegs(context.Background(), after, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			return out
		}
		after = page[len(page)-1].ProofID
		for _, r := range page {
			out[r.ProofID] = r
		}
	}
}

// wantState asserts err is the named state code, and that field (when non-empty) holds value.
func wantState(t *testing.T, what string, err error, code, field, value string) {
	t.Helper()
	n, ok := finality.AsNamed(err)
	if !ok || n.Code != code {
		t.Fatalf("%s: want the named state %s, got %v", what, code, err)
	}
	if field != "" && fmt.Sprint(n.Fields[field]) != value {
		t.Fatalf("%s: %s carries %s=%v, want %s", what, code, field, n.Fields[field], value)
	}
}

func gzipOf(t *testing.T, doc []byte) []byte {
	t.Helper()
	return finalitytest.Gzip(doc)
}

// A bundle is a proof_bundles row; proof_components inside artifact_json is not a source, however it got there.
func TestFinalityLegSourceDoesNotReadProofComponentsFromTheSummary(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	l := newLeg(t, "base_sepolia_47368146")
	// the shape the source's first version assumed: the component inside artifact_json
	inline, _ := json.Marshal(map[string]any{"chain_id": "84532", "proof_components": map[string]any{"5_execution_proof": l.exec}})
	if _, err := testDB.Exec(`UPDATE proof_artifacts SET artifact_json = $2::jsonb WHERE proof_id = $1::uuid`, l.id, string(inline)); err != nil {
		t.Fatal(err)
	}
	if _, ok := listed(t, repo)[l.id]; ok {
		t.Fatal("a proof with no bundle row is listed because its artifact_json names a component")
	}
	wantState(t, "LegSettlement", errOf(repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})),
		finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
	wantState(t, "LegRef", errOf(repo.LegRef(ctx, l.id)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))

	// with a bundle row that carries no component 5, the inline copy still counts for nothing
	storeBundleAt(t, l.id, gzipOf(t, finalitytest.ProductionBundleJSON(nil)), time.Now())
	wantState(t, "LegSettlement beside a bundle without component 5", errOf(repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})),
		finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
}

func errOf[T any](_ T, err error) error { return err }

// Listing is the cheap prefilter: a bundle row and a settlement block. A leg with either missing is not listed.
func TestFinalityLegSourceListsOnlyLegsWithABundleAndASettlementBlock(t *testing.T) {
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	full := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, full.id, gzipOf(t, finalitytest.ProductionBundleJSON(full.exec)), time.Now())

	noBundle := newLeg(t, "base_sepolia_47368146")

	noBlock := finalitytest.StoreProductionArtifact(t, testDB, full.s.Chain, "", 0)
	storeBundleAt(t, noBlock, gzipOf(t, finalitytest.ProductionBundleJSON(full.exec)), time.Now())

	got := listed(t, repo)
	if ref, ok := got[full.id]; !ok || ref.Chain != finality.ChainBaseSepolia {
		t.Fatalf("the settled leg is not listed with its chain: %+v %v", ref, ok)
	}
	if _, ok := got[noBundle.id]; ok {
		t.Fatal("a proof without a bundle row is listed")
	}
	if _, ok := got[noBlock]; ok {
		t.Fatal("a proof without a settlement block is listed")
	}
}

// A bundle that holds no execution proof, or one with no block header, is the named finality_included_unavailable state: it
// has no settlement (yet), which is not an error and not a refusal.
func TestFinalityLegSourceNamesABundleWithoutASettlement(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	base := newLeg(t, "base_sepolia_47368146")
	for name, build := range map[string]func() map[string]any{
		"no component 5": func() map[string]any { return nil },
		"no block_header_rlp": func() map[string]any {
			e := cloneExec(base.exec)
			delete(e, "block_header_rlp")
			return e
		},
		"empty block_header_rlp": func() map[string]any {
			e := cloneExec(base.exec)
			e["block_header_rlp"] = ""
			return e
		},
		"null block_header_rlp": func() map[string]any {
			e := cloneExec(base.exec)
			e["block_header_rlp"] = nil
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := newLeg(t, "base_sepolia_47368146")
			storeBundleAt(t, l.id, gzipOf(t, finalitytest.ProductionBundleJSON(build())), time.Now())
			ref, ok := listed(t, repo)[l.id]
			if !ok {
				t.Fatal("a settled leg with a bundle is listed, whatever the bundle holds: the prefilter cannot read gzip")
			}
			wantState(t, "LegSettlement", errOf(repo.LegSettlement(ctx, ref)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
			wantState(t, "LegRef", errOf(repo.LegRef(ctx, l.id)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
		})
	}
}

func cloneExec(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// A bundle the source cannot read is finality_included_invalid with its cause, never an empty settlement and never a pass: a
// truncated gzip, a gzip bomb (the decompressed size is bounded), bytes that are not gzip, a document that is not JSON, a
// component 5 that is not an object, a format other than certen_v1.
func TestFinalityLegSourceRefusesAnUnreadableBundleByName(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	good := newLeg(t, "base_sepolia_47368146")
	goodDoc := finalitytest.ProductionBundleJSON(good.exec)
	goodGzip := gzipOf(t, goodDoc)

	bomb := func(size int) []byte {
		var buf bytes.Buffer
		gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = gz.Write([]byte(`{"pad":"`))
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for n := 0; n < size; n += len(chunk) {
			_, _ = gz.Write(chunk)
		}
		_, _ = gz.Write([]byte(`"}`))
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	notAnObject := func() []byte {
		var doc map[string]any
		_ = json.Unmarshal(goodDoc, &doc)
		doc["proof_components"].(map[string]any)["5_execution_proof"] = "not an object"
		raw, _ := json.Marshal(doc)
		return gzipOf(t, raw)
	}

	cases := []struct {
		name   string
		data   []byte
		format string
		cause  string
	}{
		{"truncated gzip", goodGzip[:len(goodGzip)/2], "certen_v1", "gzip"},
		{"gzip bomb", bomb(256 << 20), "certen_v1", "16777216"},
		{"not gzip", goodDoc, "certen_v1", "gzip"},
		{"gzip of a document that is not JSON", gzipOf(t, []byte("not json")), "certen_v1", "bundle"},
		{"component 5 that is not an object", notAnObject(), "certen_v1", "execution proof"},
		{"a bundle format other than certen_v1", goodGzip, "json", "bundle_format"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLeg(t, "base_sepolia_47368146")
			if _, err := testDB.Exec(`INSERT INTO proof_bundles (proof_id, bundle_format, bundle_version, bundle_data, bundle_hash, bundle_size_bytes)
				VALUES ($1::uuid, $2, '1.0', $3, $4, $5)`, l.id, c.format, c.data, make([]byte, 32), len(c.data)); err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})
			runtime.ReadMemStats(&after)
			wantState(t, "LegSettlement", err, finality.CodeIncludedInvalid, "proof_id", l.id)
			n, _ := finality.AsNamed(err)
			if cause := fmt.Sprint(n.Fields["cause"]); !strings.Contains(cause, c.cause) {
				t.Fatalf("the cause %q does not name %q", cause, c.cause)
			}
			// a bomb is refused at the bound: nothing near its decompressed size is ever allocated
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 128<<20 {
				t.Fatalf("reading the bundle allocated %d MiB", grew>>20)
			}
			_, lerr := repo.LegRef(ctx, l.id)
			wantState(t, "LegRef", lerr, finality.CodeIncludedInvalid, "proof_id", l.id)
		})
	}
}

// The newest bundle of a proof is the one read (a proof can hold several: proof_bundles has no uniqueness on proof_id).
func TestFinalityLegSourceReadsTheNewestBundle(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	now := time.Now().UTC()
	withProof := func(l leg) []byte { return gzipOf(t, finalitytest.ProductionBundleJSON(l.exec)) }
	without := gzipOf(t, finalitytest.ProductionBundleJSON(nil))

	older := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, older.id, withProof(older), now.Add(-time.Hour))
	storeBundleAt(t, older.id, without, now)
	wantState(t, "newest bundle holds no execution proof", errOf(repo.LegSettlement(ctx, finality.LegRef{ProofID: older.id, Chain: older.s.Chain})),
		finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))

	newer := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, newer.id, without, now.Add(-time.Hour))
	storeBundleAt(t, newer.id, withProof(newer), now)
	got, err := repo.LegSettlement(ctx, finality.LegRef{ProofID: newer.id, Chain: newer.s.Chain})
	if err != nil || got.Subject != newer.s.Subject || got.Included == nil || got.Chain != finality.ChainBaseSepolia {
		t.Fatalf("the newest bundle was not read: %v %+v", err, got)
	}
}

// The leg's chain is the execution proof's own. The summary's chain_id is what listing reads; a bundle that disagrees with it
// is a named refusal, not a settlement judged on the wrong chain.
func TestFinalityLegSourceChainDisagreementIsNamed(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	exec := finalitytest.ProductionExecutionProof(t, s)
	// the summary says Sepolia, the bundle's execution proof says Base Sepolia
	id := finalitytest.StoreProductionArtifact(t, testDB, finality.ChainSepolia, exec["tx_hash"].(string), exec["block_number"].(uint64))
	storeBundleAt(t, id, gzipOf(t, finalitytest.ProductionBundleJSON(exec)), time.Now())

	ref, ok := listed(t, repo)[id]
	if !ok || ref.Chain != finality.ChainSepolia {
		t.Fatalf("listing reads the summary's chain: %+v %v", ref, ok)
	}
	_, err := repo.LegSettlement(ctx, ref)
	wantState(t, "LegSettlement", err, finality.CodeIncludedInvalid, "proof_id", id)
	if n, _ := finality.AsNamed(err); !strings.Contains(fmt.Sprint(n.Fields["cause"]), "chain") {
		t.Fatalf("the cause does not name the chain disagreement: %v", err)
	}
	// LegRef names the chain the bundle's execution proof settled on
	if got, err := repo.LegRef(ctx, id); err != nil || got.Chain != finality.ChainBaseSepolia {
		t.Fatalf("LegRef: %v %+v", err, got)
	}
	// a reference that names no chain takes the execution proof's
	got, err := repo.LegSettlement(ctx, finality.LegRef{ProofID: id})
	if err != nil || got.Chain != finality.ChainBaseSepolia {
		t.Fatalf("a reference without a chain: %v %+v", err, got)
	}
}

// A proof that does not exist is an ordinary not-found error, not a named state about a bundle.
func TestFinalityLegSourceUnknownProofIsNotAState(t *testing.T) {
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	id := uuid.NewString()
	if _, err := repo.LegRef(context.Background(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("LegRef of an unknown proof: %v", err)
	}
	if _, err := repo.LegSettlement(context.Background(), finality.LegRef{ProofID: id, Chain: finality.ChainBaseSepolia}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("LegSettlement of an unknown proof: %v", err)
	}
}

// Listing is newest first, by the proof's creation time then its id, so a backlog of old legs never starves a new one; the
// cursor is the last proof id returned, and it holds under inserts between pages: nothing is repeated and nothing older is
// skipped, the new leg is seen by the next listing, and a cursor that names no proof is a refusal, not an empty page.
func TestFinalityLegSourceListsNewestFirstWithAStableCursor(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	// later than every proof the database already holds, whatever earlier runs and other tests stored
	var base time.Time
	if err := testDB.QueryRow(`SELECT date_trunc('hour', COALESCE(max(created_at), now())) + interval '1 hour' FROM proof_artifacts`).Scan(&base); err != nil {
		t.Fatal(err)
	}
	mk := func(at time.Time) string {
		l := newLeg(t, "base_sepolia_47368146")
		storeBundleAt(t, l.id, gzipOf(t, finalitytest.ProductionBundleJSON(l.exec)), time.Now())
		if _, err := testDB.Exec(`UPDATE proof_artifacts SET created_at = $2 WHERE proof_id = $1::uuid`, l.id, at); err != nil {
			t.Fatal(err)
		}
		return l.id
	}
	oldest := mk(base)
	tieA, tieB := mk(base.Add(time.Hour)), mk(base.Add(time.Hour))
	newest := mk(base.Add(2 * time.Hour))
	hi, lo := tieA, tieB
	if lo > hi {
		hi, lo = lo, hi
	}
	want := []string{newest, hi, lo, oldest} // a tie on the time is broken by the proof id, descending

	page := func(after string, limit int) []finality.LegRef {
		t.Helper()
		p, err := repo.SettledLegs(ctx, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	ids := func(refs []finality.LegRef) []string {
		var out []string
		for _, r := range refs {
			out = append(out, r.ProofID)
		}
		return out
	}

	first := page("", 2)
	if got := ids(first); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("first page %v, want %v", got, want[:2])
	}
	// a leg stored between the two pages is newer than the cursor, so this walk does not see it and does not lose or repeat anything
	arrived := mk(base.Add(3 * time.Hour))
	second := page(first[1].ProofID, 2)
	if got := ids(second); len(got) != 2 || got[0] != want[2] || got[1] != want[3] {
		t.Fatalf("second page %v, want %v", got, want[2:])
	}
	// the next listing starts at the leg that arrived
	if got := ids(page("", 1)); len(got) != 1 || got[0] != arrived {
		t.Fatalf("the next listing starts at %v, want the leg that arrived (%s)", got, arrived)
	}

	// a whole walk by pages of 3: every leg once, strictly descending by (created_at, proof_id)
	var all []string
	after := ""
	for {
		p := page(after, 3)
		if len(p) == 0 {
			break
		}
		all = append(all, ids(p)...)
		after = p[len(p)-1].ProofID
	}
	rows, err := testDB.Query(`SELECT proof_id::text, created_at FROM proof_artifacts WHERE proof_id = ANY($1::uuid[])`, pq.Array(all))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	at := map[string]time.Time{}
	for rows.Next() {
		var id string
		var c time.Time
		if err := rows.Scan(&id, &c); err != nil {
			t.Fatal(err)
		}
		at[id] = c
	}
	for i := 1; i < len(all); i++ {
		prev, cur := all[i-1], all[i]
		if prev == cur {
			t.Fatalf("%s is listed twice", cur)
		}
		if at[prev].Before(at[cur]) || (at[prev].Equal(at[cur]) && prev < cur) {
			t.Fatalf("%s (%s) is listed before %s (%s)", prev, at[prev], cur, at[cur])
		}
	}

	if _, err := repo.SettledLegs(ctx, uuid.NewString(), 5); err == nil {
		t.Fatal("a cursor that names no proof listed an (empty) page")
	}
}
