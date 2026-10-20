// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// fakeKind stands in for a chain package's Kind (RB11-C..F register the real ones).
type fakeKind struct {
	chain uint64
	name  string
	level finality.Level
}

func (f fakeKind) Name() string          { return f.name }
func (f fakeKind) Chain() uint64         { return f.chain }
func (f fakeKind) Level() finality.Level { return f.level }
func (f fakeKind) Verify(*finality.Pins, finality.BlockRef, []byte) (finality.Verdict, error) {
	return finality.Verdict{Level: f.level, Kind: f.name}, nil
}

const (
	kindL1  = "base-sepolia/l1_posted/v1"
	kindFin = "base-sepolia/finalized/v1"
)

var baseKinds = map[finality.Level]string{finality.LevelL1Posted: kindL1, finality.LevelFinalized: kindFin}

func baseRegistry() *finality.Registry {
	reg := finality.NewRegistry()
	for l, k := range baseKinds {
		if err := reg.RegisterKind(fakeKind{finality.ChainBaseSepolia, k, l}); err != nil {
			panic(err)
		}
	}
	return reg
}

// chainFor builds the stored chain of a real block's leg, bound to d0, with one addendum per requested level.
func chainFor(t *testing.T, s finality.Settlement, proofID uuid.UUID, d0 [32]byte, levels ...finality.Level) []finality.Addendum {
	t.Helper()
	block := s.Block()
	var out []finality.Addendum
	for _, l := range levels {
		ev, err := finality.Container{Header: finality.ContainerHeader{Kind: baseKinds[l], Chain: block.Chain, Level: l, BlockNumber: block.Number, BlockHash: block.Hash}, Body: []byte("b")}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		a, err := finality.NewAddendum(d0, proofID, out, block.Chain, l, baseKinds[l], ev)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func writeDoc(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func verifyFile(t *testing.T, path string) (int, string) {
	t.Helper()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := reportFinalityFile(&out, path, finality.Default, pins)
	return code, out.String()
}

// The portable document does not carry the leg's Settlement, so an offline verifier cannot recompute D0 from the file alone:
// until RB11-B2B wires a Settlement source it judges no level and says so by name. It never takes D0 from the file.
func TestFinalityFileNamesWhyItJudgesNothingAndNeverTakesD0FromTheFile(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	pid := uuid.New()
	chain := chainFor(t, s, pid, finality.LegBindingOf(s.Block()), finality.LevelFinalized)
	section := finality.NewSection(s.Block(), chain)
	doc, _ := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": section})

	t.Run("a finality section is reported by name, not judged", func(t *testing.T) {
		code, out := verifyFile(t, writeDoc(t, doc))
		if code != exitSummaryOnly || !strings.Contains(out, finality.CodeIncludedUnavailable) || !strings.Contains(out, "D0 cannot be recomputed") || !strings.Contains(out, "1 addenda are not judged") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if strings.Contains(out, "VERIFIED") {
			t.Fatalf("a file with no Settlement was reported verified:\n%s", out)
		}
	})
	t.Run("no finality section is summary-only", func(t *testing.T) {
		if code, out := verifyFile(t, writeDoc(t, []byte(`{"format":"certen-proof-v2-accumulate-portable/1"}`))); code != exitSummaryOnly || !strings.Contains(out, "no finality section") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("the old flat array and a malformed section fail", func(t *testing.T) {
		old, _ := json.Marshal(map[string]any{"finality": section.Addenda})
		if code, out := verifyFile(t, writeDoc(t, old)); code != exitFailed {
			t.Fatalf("the old array form: exit %d\n%s", code, out)
		}
		bad, _ := json.Marshal(map[string]any{"finality": map[string]any{"format": "certen-finality-addenda/1", "originalProofDigest": "00", "addenda": []any{}}})
		if code, out := verifyFile(t, writeDoc(t, bad)); code != exitFailed {
			t.Fatalf("a section with the withdrawn originalProofDigest member: exit %d\n%s", code, out)
		}
		if code, out := verifyFile(t, writeDoc(t, []byte(`[1,2]`))); code != exitFailed {
			t.Fatalf("not a document: exit %d\n%s", code, out)
		}
	})
}

// The stored-proof path: the bundle's L6 Settlement is verified (level 1 is derived, never stored), D0 is recomputed from its
// block, and a stored chain is judged against it.
func TestFinalityOfAStoredProof(t *testing.T) {
	url, err := testdb.PackageURL("proofverify")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(context.Background(), "proofverify-test"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}

	store := func(fixture string) (uuid.UUID, finality.Settlement) {
		s := finalitytest.Settlement(t, fixture)
		exec := map[string]any{}
		raw, _ := json.Marshal(s.Included)
		_ = json.Unmarshal(raw, &exec)
		exec["chain_id"] = "84532"
		artifact, _ := json.Marshal(map[string]any{"proof_components": map[string]any{"5_execution_proof": exec}})
		created, err := database.NewProofArtifactRepository(db).CreateProofArtifact(ctx, &database.NewProofArtifact{
			ProofType: database.ProofTypeCertenAnchor, AccumTxHash: "fin_" + uuid.NewString()[:8], AccountURL: "acc://finality-test.acme/tokens",
			ProofClass: database.ProofClassOnCadence, ValidatorID: "test-validator-1", ArtifactJSON: artifact,
		})
		if err != nil {
			t.Fatal(err)
		}
		return created.ProofID, s
	}
	run := func(reg *finality.Registry, id uuid.UUID) (int, string) {
		var out bytes.Buffer
		code := reportFinality(ctx, &out, db, id, reg, pins)
		return code, out.String()
	}

	id, s := store("base_sepolia_47368146")
	if code, out := run(finality.NewRegistry(), id); code != exitVerified || !strings.Contains(out, "level reached: included") || !strings.Contains(out, "no_evidence_in_file") {
		t.Fatalf("no addendum yet: exit %d\n%s", code, out)
	}

	// finalized first, then l1_posted: any order, and level 1 is never stored
	for _, a := range chainFor(t, s, id, finality.LegBindingOf(s.Block()), finality.LevelFinalized, finality.LevelL1Posted) {
		if err := repo.Append(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := run(baseRegistry(), id); code != exitVerified || !strings.Contains(out, "level reached: finalized") || !strings.Contains(out, "finalized_block") {
		t.Fatalf("stored chain: exit %d\n%s", code, out)
	}
	if code, out := run(finality.NewRegistry(), id); code != exitSummaryOnly || !strings.Contains(out, finality.CodeEvidenceUnrecognised) {
		t.Fatalf("a verifier without the kinds: exit %d\n%s", code, out)
	}

	// a chain bound to another block than the proof's bundle proves is refused (own_hash at seq 1), never judged
	id2, s2 := store("base_sepolia_47368146")
	other := s2.Block()
	other.Number++
	for _, a := range chainFor(t, s2, id2, finality.LegBindingOf(other), finality.LevelFinalized) {
		if err := repo.Append(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := run(baseRegistry(), id2); code != exitFailed || !strings.Contains(out, finality.CheckOwnHash) {
		t.Fatalf("wrong binding: exit %d\n%s", code, out)
	}

	// a proof whose bundle has no settlement evidence has nothing for finality to attach to
	bare, err := database.NewProofArtifactRepository(db).CreateProofArtifact(ctx, &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: "bare_" + uuid.NewString()[:8], AccountURL: "acc://finality-test.acme/tokens",
		ProofClass: database.ProofClassOnCadence, ValidatorID: "test-validator-1", ArtifactJSON: json.RawMessage(`{"proof_components":{}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, out := run(finality.NewRegistry(), bare.ProofID); code != exitSummaryOnly || !strings.Contains(out, "no settlement evidence") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
