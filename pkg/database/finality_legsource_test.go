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

// storeProductionBundle stores l's production bundle (gzip) under proof id.
func storeProductionBundle(t *testing.T, id string, l leg) {
	t.Helper()
	storeBundleAt(t, id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(id, l.exec)), time.Now())
}

// bundleDoc is l's production bundle document (the one stored under l's own id) after mutate changed it, as raw JSON.
func bundleDoc(t *testing.T, l leg, mutate func(doc map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(finalitytest.ProductionBundleJSON(l.id, l.exec)))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(doc)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func components(doc map[string]any) map[string]any { return doc["proof_components"].(map[string]any) }
func comp5(doc map[string]any) map[string]any {
	return components(doc)["5_execution_proof"].(map[string]any)
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

// wantInvalid asserts err is finality_included_invalid for the proof with a cause naming every want.
func wantInvalid(t *testing.T, what, proofID string, err error, causeHas ...string) {
	t.Helper()
	wantState(t, what, err, finality.CodeIncludedInvalid, "proof_id", proofID)
	n, _ := finality.AsNamed(err)
	cause := fmt.Sprint(n.Fields["cause"])
	for _, w := range causeHas {
		if !strings.Contains(cause, w) {
			t.Fatalf("%s: the cause %q does not name %q", what, cause, w)
		}
	}
}

func errOf[T any](_ T, err error) error { return err }

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
	storeBundleAt(t, l.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(l.id, nil)), time.Now())
	wantState(t, "LegSettlement beside a bundle without component 5", errOf(repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})),
		finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
}

// Every proof with a bundle is listed, whatever its settlement columns say or its bundle holds: a filter that can drop a settled
// leg is below the claim that every settled leg gets its evidence. Each leg carries its newest bundle's id, LegSettlement reads
// exactly that bundle, and a proof row that does not record its settlement yet is served marked Unrecorded.
func TestFinalityLegSourceListsEveryProofWithABundleAndNamesItsNewestBundle(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	bundleIDs := func(proofID string) (ids []string) {
		rows, err := testDB.Query(`SELECT bundle_id::text FROM proof_bundles WHERE proof_id = $1::uuid ORDER BY created_at, bundle_id`, proofID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		return ids
	}

	full := newLeg(t, "base_sepolia_47368146")
	storeProductionBundle(t, full.id, full)

	noBundle := newLeg(t, "base_sepolia_47368146")

	// component 5 exists but the proof row's settlement columns are still NULL: listed, and served marked Unrecorded
	unrecorded := newLeg(t, "base_sepolia_47368146")
	if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = NULL, settlement_block_number = NULL WHERE proof_id = $1::uuid`, unrecorded.id); err != nil {
		t.Fatal(err)
	}
	storeProductionBundle(t, unrecorded.id, unrecorded)

	// a bundle with no component 5 and NULL columns (the live anchor-only shape) is listed too, and named unavailable
	anchorOnly := finalitytest.StoreProductionArtifact(t, testDB, full.s.Chain, "", 0)
	storeBundleAt(t, anchorOnly, finalitytest.Gzip(finalitytest.ProductionBundleJSON(anchorOnly, nil)), time.Now())

	// two bundles: the newest is named, and the older one is still readable by its own id
	two := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, two.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(two.id, nil)), time.Now().Add(-time.Hour))
	storeBundleAt(t, two.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(two.id, two.exec)), time.Now())

	got := listed(t, repo)
	if ref, ok := got[full.id]; !ok || ref.Chain != finality.ChainBaseSepolia || ref.BundleID != bundleIDs(full.id)[0] {
		t.Fatalf("the settled leg is not listed with its chain and bundle: %+v %v", ref, ok)
	}
	if _, ok := got[noBundle.id]; ok {
		t.Fatal("a proof without a bundle row is listed")
	}
	settled, err := repo.LegSettlement(ctx, got[full.id])
	if err != nil || settled.Unrecorded || settled.Subject != full.s.Subject {
		t.Fatalf("a recorded settlement: %v %+v", err, settled)
	}

	ref, ok := got[unrecorded.id]
	if !ok {
		t.Fatal("a proof whose bundle holds component 5 is not listed because its settlement columns are NULL")
	}
	settled, err = repo.LegSettlement(ctx, ref)
	if err != nil || !settled.Unrecorded || settled.Subject != unrecorded.s.Subject || settled.Included == nil {
		t.Fatalf("component 5 with NULL settlement columns must be served, marked Unrecorded: %v %+v", err, settled)
	}

	ref, ok = got[anchorOnly]
	if !ok {
		t.Fatal("a bundle-bearing proof with NULL settlement columns is not listed")
	}
	wantState(t, "anchor-only bundle", errOf(repo.LegSettlement(ctx, ref)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))

	ids := bundleIDs(two.id)
	if len(ids) != 2 || got[two.id].BundleID != ids[1] {
		t.Fatalf("the newest of two bundles is not the one named: %v %+v", ids, got[two.id])
	}
	// LegSettlement reads the bundle the reference names: the newest holds component 5, the older one does not
	if s, err := repo.LegSettlement(ctx, got[two.id]); err != nil || s.Subject != two.s.Subject {
		t.Fatalf("the named (newest) bundle: %v %+v", err, s)
	}
	older := got[two.id]
	older.BundleID = ids[0]
	wantState(t, "the older bundle", errOf(repo.LegSettlement(ctx, older)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
	// a bundle id that is not this proof's is no bundle of it
	other := got[two.id]
	other.BundleID = bundleIDs(full.id)[0]
	wantState(t, "another proof's bundle", errOf(repo.LegSettlement(ctx, other)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
}

// Unavailable is exactly: no bundle, or a bundle whose component 5 is absent, null or {}. Nothing is wrong and nothing was served.
func TestFinalityLegSourceNamesABundleWithoutASettlement(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	for name, mutate := range map[string]func(doc map[string]any){
		"no component 5":      func(doc map[string]any) { delete(components(doc), "5_execution_proof") },
		"component 5 is null": func(doc map[string]any) { components(doc)["5_execution_proof"] = nil },
		"component 5 is {}":   func(doc map[string]any) { components(doc)["5_execution_proof"] = map[string]any{} },
	} {
		t.Run(name, func(t *testing.T) {
			l := newLeg(t, "base_sepolia_47368146")
			storeBundleAt(t, l.id, finalitytest.Gzip(bundleDoc(t, l, mutate)), time.Now())
			ref, ok := listed(t, repo)[l.id]
			if !ok {
				t.Fatal("a settled leg with a bundle is listed, whatever the bundle holds: the prefilter cannot read gzip")
			}
			wantState(t, "LegSettlement", errOf(repo.LegSettlement(ctx, ref)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
			wantState(t, "LegRef", errOf(repo.LegRef(ctx, l.id)), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))
		})
	}
}

func gzipBomb(t *testing.T, size int) []byte {
	t.Helper()
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

// A bundle the source cannot use is finality_included_invalid with its cause, never an empty settlement and never a pass, and
// never the quiet unavailable state: a truncated gzip, a gzip bomb (the decompressed size is bounded), a stored value over the
// size bound (refused before its bytes are fetched), bytes that are not gzip, a document that is not JSON or is JSON null, a
// bundle written for another proof, a non-empty component 5 that is not an object or has no block header or no usable chain,
// a format other than certen_v1.
func TestFinalityLegSourceRefusesAnUnusableBundleByName(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	gz := func(l leg, mutate func(doc map[string]any)) []byte { return finalitytest.Gzip(bundleDoc(t, l, mutate)) }

	cases := []struct {
		name   string
		format string
		data   func(l leg) []byte
		cause  []string
		maxMiB uint64 // allocation allowed while reading
	}{
		{"truncated gzip", "certen_v1", func(l leg) []byte { g := gz(l, nil); return g[:len(g)/2] }, []string{"gzip"}, 128},
		{"gzip bomb", "certen_v1", func(leg) []byte { return gzipBomb(t, 256<<20) }, []string{"16777216"}, 128},
		{"stored over the size bound", "certen_v1", func(leg) []byte { return make([]byte, 40<<20) }, []string{"bound"}, 16},
		{"not gzip", "certen_v1", func(l leg) []byte { return bundleDoc(t, l, nil) }, []string{"gzip"}, 128},
		{"gzip of a document that is not JSON", "certen_v1", func(leg) []byte { return finalitytest.Gzip([]byte("not json")) }, []string{"bundle"}, 128},
		{"a bundle that is JSON null", "certen_v1", func(leg) []byte { return finalitytest.Gzip([]byte("null")) }, []string{"null"}, 128},
		{"a bundle that is a JSON array", "certen_v1", func(leg) []byte { return finalitytest.Gzip([]byte("[]")) }, []string{"bundle"}, 128},
		{"a bundle format other than certen_v1", "json", func(l leg) []byte { return gz(l, nil) }, []string{"bundle_format"}, 128},
		{"a bundle with no bundle_integrity", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { delete(doc, "bundle_integrity") })
		}, []string{"custody_chain_hash"}, 128},
		{"an empty custody_chain_hash", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { doc["bundle_integrity"].(map[string]any)["custody_chain_hash"] = "" })
		}, []string{"custody_chain_hash"}, 128},
		{"a bundle written for another proof", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) {
				doc["bundle_integrity"].(map[string]any)["custody_chain_hash"] = strings.ReplaceAll(uuid.NewString(), "-", "")
			})
		}, []string{"not this proof's"}, 128},
		{"component 5 that is a string", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { components(doc)["5_execution_proof"] = "not an object" })
		}, []string{"not a JSON object"}, 128},
		{"component 5 that is an array", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { components(doc)["5_execution_proof"] = []any{1} })
		}, []string{"not a JSON object"}, 128},
		{"evidence without a block_header_rlp", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { delete(comp5(doc), "block_header_rlp") })
		}, []string{"block_header_rlp"}, 128},
		{"evidence with an empty block_header_rlp", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["block_header_rlp"] = "" })
		}, []string{"block_header_rlp"}, 128},
		{"evidence with a null block_header_rlp", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["block_header_rlp"] = nil })
		}, []string{"block_header_rlp"}, 128},
		{"a block_header_rlp that is a number", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["block_header_rlp"] = 5 })
		}, []string{"block_header_rlp"}, 128},
		{"a component 5 with no chain_id", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { delete(comp5(doc), "chain_id") })
		}, []string{"chain_id"}, 128},
		{"an empty chain_id", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["chain_id"] = "" })
		}, []string{"chain_id"}, 128},
		{"a chain_id that is a name", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["chain_id"] = "base" })
		}, []string{"chain_id", "base"}, 128},
		{"a chain_id past uint64", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["chain_id"] = "99999999999999999999999" })
		}, []string{"chain_id"}, 128},
		{"a chain_id that is a number", "certen_v1", func(l leg) []byte {
			return gz(l, func(doc map[string]any) { comp5(doc)["chain_id"] = 84532 })
		}, []string{"chain_id"}, 128},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLeg(t, "base_sepolia_47368146")
			data := c.data(l)
			if _, err := testDB.Exec(`INSERT INTO proof_bundles (proof_id, bundle_format, bundle_version, bundle_data, bundle_hash, bundle_size_bytes)
				VALUES ($1::uuid, $2, '1.0', $3, $4, $5)`, l.id, c.format, data, make([]byte, 32), len(data)); err != nil {
				t.Fatal(err)
			}
			data = nil
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})
			runtime.ReadMemStats(&after)
			wantInvalid(t, "LegSettlement", l.id, err, c.cause...)
			// a bomb is refused at the bound: nothing near its decompressed size is ever allocated
			if grew := after.TotalAlloc - before.TotalAlloc; grew > c.maxMiB<<20 {
				t.Fatalf("reading the bundle allocated %d MiB, the case allows %d", grew>>20, c.maxMiB)
			}
			_, lerr := repo.LegRef(ctx, l.id)
			wantInvalid(t, "LegRef", l.id, lerr, c.cause...)
		})
	}
}

// The newest bundle of a proof is the one read (a proof can hold several: proof_bundles has no uniqueness on proof_id).
func TestFinalityLegSourceReadsTheNewestBundle(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	now := time.Now().UTC()
	withProof := func(l leg) []byte { return finalitytest.Gzip(finalitytest.ProductionBundleJSON(l.id, l.exec)) }
	without := func(l leg) []byte { return finalitytest.Gzip(finalitytest.ProductionBundleJSON(l.id, nil)) }

	older := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, older.id, withProof(older), now.Add(-time.Hour))
	storeBundleAt(t, older.id, without(older), now)
	wantState(t, "newest bundle holds no execution proof", errOf(repo.LegSettlement(ctx, finality.LegRef{ProofID: older.id, Chain: older.s.Chain})),
		finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoExecutionProof))

	newer := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, newer.id, without(newer), now.Add(-time.Hour))
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
	storeBundleAt(t, id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(id, exec)), time.Now())

	ref, ok := listed(t, repo)[id]
	if !ok || ref.Chain != finality.ChainSepolia {
		t.Fatalf("listing reads the summary's chain: %+v %v", ref, ok)
	}
	_, err := repo.LegSettlement(ctx, ref)
	wantInvalid(t, "LegSettlement", id, err, "chain")
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

// The evidence served for a proof is for THAT proof: the bundle names it (custody_chain_hash is the proof id the writer sets) and
// proves the settlement the proof row records (settlement_tx_hash, settlement_block_number). Anything else is a named refusal
// carrying both values; it must never become another transaction's finality.
func TestFinalityLegSourceServesEvidenceOnlyForTheProofItIsStoredUnder(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	settle := func(l leg) (finality.Settlement, error) {
		return repo.LegSettlement(ctx, finality.LegRef{ProofID: l.id, Chain: l.s.Chain})
	}
	setColumns := func(id string, tx any, block any) {
		t.Helper()
		if _, err := testDB.Exec(`UPDATE proof_artifacts SET settlement_tx_hash = $2, settlement_block_number = $3 WHERE proof_id = $1::uuid`, id, tx, block); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("the recorded settlement matches: served, however the hash is written", func(t *testing.T) {
		l := newLeg(t, "base_sepolia_47368146")
		storeProductionBundle(t, l.id, l)
		if got, err := settle(l); err != nil || got.Subject != l.s.Subject {
			t.Fatalf("%v %+v", err, got)
		}
		tx := l.exec["tx_hash"].(string)
		setColumns(l.id, strings.ToUpper(strings.TrimPrefix(tx, "0x")), int64(l.exec["block_number"].(uint64)))
		if _, err := settle(l); err != nil {
			t.Fatalf("an upper-case hash without 0x is the same hash: %v", err)
		}
	})
	t.Run("a proof with no recorded settlement is not bound by one", func(t *testing.T) {
		l := newLeg(t, "base_sepolia_47368146")
		storeProductionBundle(t, l.id, l)
		setColumns(l.id, nil, nil)
		if _, err := settle(l); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another transaction than the recorded settlement is refused, naming both", func(t *testing.T) {
		l := newLeg(t, "base_sepolia_47368146")
		storeProductionBundle(t, l.id, l)
		wrong := "0x" + strings.Repeat("ab", 32)
		setColumns(l.id, wrong, int64(l.exec["block_number"].(uint64)))
		_, err := settle(l)
		wantInvalid(t, "wrong tx", l.id, err, wrong, l.exec["tx_hash"].(string))
	})
	t.Run("another block than the recorded settlement is refused, naming both", func(t *testing.T) {
		l := newLeg(t, "base_sepolia_47368146")
		storeProductionBundle(t, l.id, l)
		setColumns(l.id, l.exec["tx_hash"], int64(12345))
		_, err := settle(l)
		wantInvalid(t, "wrong block", l.id, err, "12345", fmt.Sprint(l.exec["block_number"]))
	})
	t.Run("the bundle of another proof stored under this one is refused even when the recorded settlement matches", func(t *testing.T) {
		a := newLeg(t, "base_sepolia_47368146")
		b := newLeg(t, "base_sepolia_47368146") // the same real settlement: tx and block equal b's columns
		storeProductionBundle(t, a.id, a)       // a's bundle, written for a
		storeBundleAt(t, b.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(a.id, a.exec)), time.Now())
		_, err := settle(b)
		wantInvalid(t, "wrong proof", b.id, err, strings.ReplaceAll(a.id, "-", ""))
	})
	t.Run("the custody hash is compared without case or dashes", func(t *testing.T) {
		l := newLeg(t, "base_sepolia_47368146")
		storeBundleAt(t, l.id, finalitytest.Gzip(bundleDoc(t, l, func(doc map[string]any) {
			doc["bundle_integrity"].(map[string]any)["custody_chain_hash"] = strings.ToUpper(l.id)
		})), time.Now())
		if _, err := settle(l); err != nil {
			t.Fatal(err)
		}
	})
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
		storeProductionBundle(t, l.id, l)
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
