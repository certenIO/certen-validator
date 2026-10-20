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

// fakeLevel stands in for a chain package's verifier of a higher level (RB11-C..F register the real ones).
type fakeLevel struct {
	chain uint64
	kind  string
	level finality.Level
}

func (f fakeLevel) Chain() uint64            { return f.chain }
func (f fakeLevel) Kind() string             { return f.kind }
func (f fakeLevel) MaxLevel() finality.Level { return finality.LevelFinalized }
func (f fakeLevel) Verify(finality.Settlement, finality.Evidence, *finality.Pins) (finality.Level, error) {
	return f.level, nil
}

var digest = [32]byte{0xD1, 0x6E}

// chainFor builds an included addendum from a real block's L6 evidence, and optionally a finalized one of a given kind.
func chainFor(t *testing.T, fixture, proofID, finalKind string) (finality.Settlement, []finality.Addendum) {
	t.Helper()
	s := finalitytest.Settlement(t, fixture)
	ev, _, err := finality.IncludedProver{ChainID: s.Chain}.Build(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	first, err := finality.NewAddendum(digest, proofID, nil, s.Chain, finality.LevelIncluded, ev)
	if err != nil {
		t.Fatal(err)
	}
	out := []finality.Addendum{first}
	if finalKind != "" {
		second, err := finality.NewAddendum(digest, proofID, &first, s.Chain, finality.LevelFinalized, finality.NewEvidence(finalKind, s, []byte("f")))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, second)
	}
	return s, out
}

func writeDoc(t *testing.T, section []finality.Addendum, bare bool) string {
	t.Helper()
	raw, err := finality.DocumentSection(digest, section)
	if err != nil {
		t.Fatal(err)
	}
	var doc []byte
	if bare {
		doc, _ = json.Marshal(raw)
	} else {
		doc, _ = json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": raw})
	}
	p := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(p, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func registryWith(chain uint64, kind string, level finality.Level) *finality.Registry {
	reg := finality.NewRegistry()
	if kind != "" {
		if err := reg.RegisterVerifier(fakeLevel{chain, kind, level}); err != nil {
			panic(err)
		}
	}
	return reg
}

func verify(t *testing.T, reg *finality.Registry, path string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := reportFinalityFile(&out, path, reg, finality.NewPins())
	return code, out.String()
}

func TestFinalityFileReportsEveryLevelAndExitsWithTheToolsCodes(t *testing.T) {
	t.Run("included then finalized verifies", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "t.fin/v1")
		code, out := verify(t, registryWith(finality.ChainBaseSepolia, "t.fin/v1", finality.LevelFinalized), writeDoc(t, chain, false))
		if code != exitVerified || !strings.Contains(out, "level reached: finalized") || strings.Contains(out, "finality_pending") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		// l1_posted is a level base has; no addendum carries it, and finalized supersedes it: not reported as pending
		if strings.Contains(out, "l1_posted  not evidenced") {
			t.Fatalf("a level below the reached one is reported as missing:\n%s", out)
		}
	})
	t.Run("included only is verified at included and names what is pending", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "")
		code, out := verify(t, finality.NewRegistry(), writeDoc(t, chain, true)) // a bare list of addenda is accepted too
		if code != exitVerified || !strings.Contains(out, "level reached: included") ||
			!strings.Contains(out, "finality_pending{") || !strings.Contains(out, "next_level=l1_posted") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("adiri names l1_posted as not applicable", func(t *testing.T) {
		_, chain := chainFor(t, "telcoin_adiri_498759", "p1", "")
		code, out := verify(t, finality.NewRegistry(), writeDoc(t, chain, false))
		if code != exitVerified || !strings.Contains(out, "level_not_applicable{") || !strings.Contains(out, "no L1 settlement") ||
			!strings.Contains(out, "next_level=finalized") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("an addendum of a kind this verifier does not know is summary-only, below it still verified", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "t.unknown/v1")
		code, out := verify(t, finality.NewRegistry(), writeDoc(t, chain, false))
		if code != exitSummaryOnly || !strings.Contains(out, "finality_kind_unknown") || !strings.Contains(out, "level reached: included") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("tampered evidence fails", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "")
		chain[0].Evidence = append([]byte(nil), chain[0].Evidence...)
		chain[0].Evidence[len(chain[0].Evidence)-1] ^= 1
		code, out := verify(t, finality.NewRegistry(), writeDoc(t, chain, false))
		if code != exitFailed || !strings.Contains(out, "level reached: none") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("re-hashed evidence that does not verify fails and reaches no level", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "")
		ev, _ := finality.DecodeEvidence(chain[0].Evidence)
		ev.Body = append([]byte(nil), ev.Body...)
		ev.Body[10] ^= 1 // a bit of the header
		enc, _ := ev.Encode()
		chain[0].Evidence = enc
		chain[0].OwnHash = chain[0].ComputeHash(digest)
		code, out := verify(t, finality.NewRegistry(), writeDoc(t, chain, false))
		if code != exitFailed || !strings.Contains(out, "level reached: none") || !strings.Contains(out, "finality_included_invalid") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a level claimed above the evidence fails", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "t.weak/v1")
		code, out := verify(t, registryWith(finality.ChainBaseSepolia, "t.weak/v1", finality.LevelL1Posted), writeDoc(t, chain, false))
		if code != exitFailed || !strings.Contains(out, "finality_level_mismatch") && !strings.Contains(out, "finality_level_exceeds_evidence") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if !strings.Contains(out, "level reached: included") {
			t.Fatalf("the level reached must stay at what verified:\n%s", out)
		}
	})
	t.Run("addenda of one proof that state different original digests fail", func(t *testing.T) {
		_, chain := chainFor(t, "base_sepolia_47368146", "p1", "t.fin/v1")
		raw, _ := finality.DocumentSection(digest, chain)
		var second finality.Addendum
		_ = json.Unmarshal(raw[1], &second)
		second.OriginalDigest[0] ^= 1
		raw[1], _ = json.Marshal(second)
		doc, _ := json.Marshal(map[string]any{"finality": raw})
		p := filepath.Join(t.TempDir(), "doc.json")
		_ = os.WriteFile(p, doc, 0o600)
		if code, out := verify(t, registryWith(finality.ChainBaseSepolia, "t.fin/v1", finality.LevelFinalized), p); code != exitFailed {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("no finality section is summary-only, not verified", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "doc.json")
		_ = os.WriteFile(p, []byte(`{"format":"certen-proof-v2-accumulate-portable/1"}`), 0o600)
		if code, out := verify(t, finality.NewRegistry(), p); code != exitSummaryOnly {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

// The stored-proof path: the bundle's L6 evidence is level 1 on its own, a stored chain is judged against the proof's
// original digest, and a chain about another settlement than the bundle's fails.
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

	store := func(fixture string) (uuid.UUID, [32]byte, finality.Settlement) {
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
		var d [32]byte
		copy(d[:], created.ArtifactHash)
		return created.ProofID, d, s
	}
	run := func(reg *finality.Registry, id uuid.UUID) (int, string) {
		var out bytes.Buffer
		code := reportFinality(ctx, &out, db, id, reg, finality.NewPins())
		return code, out.String()
	}

	id, d, s := store("base_sepolia_47368146")
	if code, out := run(finality.NewRegistry(), id); code != exitVerified || !strings.Contains(out, "judged as level 1") || !strings.Contains(out, "level reached: included") {
		t.Fatalf("no addendum yet: exit %d\n%s", code, out)
	}

	ev, _, _ := finality.IncludedProver{ChainID: s.Chain}.Build(ctx, s)
	first, _ := finality.NewAddendum(d, id.String(), nil, s.Chain, finality.LevelIncluded, ev)
	second, _ := finality.NewAddendum(d, id.String(), &first, s.Chain, finality.LevelFinalized, finality.NewEvidence("t.fin/v1", s, []byte("f")))
	for _, a := range []finality.Addendum{first, second} {
		if err := repo.Append(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := run(registryWith(s.Chain, "t.fin/v1", finality.LevelFinalized), id); code != exitVerified || !strings.Contains(out, "level reached: finalized") {
		t.Fatalf("stored chain: exit %d\n%s", code, out)
	}
	if code, out := run(finality.NewRegistry(), id); code != exitSummaryOnly || !strings.Contains(out, "finality_kind_unknown") {
		t.Fatalf("a verifier without the finalized kind: exit %d\n%s", code, out)
	}

	// a chain about another settlement than the proof's bundle proves is refused
	id2, d2, s2 := store("base_sepolia_47368146")
	other := s2
	other.TxHash[0] ^= 0xFF
	f1, _ := finality.NewAddendum(d2, id2.String(), nil, s2.Chain, finality.LevelFinalized, finality.NewEvidence("t.fin/v1", other, []byte("f")))
	if err := repo.Append(ctx, f1); err != nil {
		t.Fatal(err)
	}
	if code, out := run(registryWith(s2.Chain, "t.fin/v1", finality.LevelFinalized), id2); code != exitFailed || !strings.Contains(out, "bundle proves") {
		t.Fatalf("wrong settlement: exit %d\n%s", code, out)
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
