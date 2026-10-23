// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	"github.com/certen/independant-validator/pkg/proof"
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

// appendFor is the request of one level of a stored proof's leg, verified by the fake base kinds.
func appendFor(t *testing.T, proofID uuid.UUID, s finality.Settlement, l finality.Level) finality.AppendRequest {
	t.Helper()
	block := s.Block()
	ev, err := finality.Container{Header: finality.ContainerHeader{Kind: baseKinds[l], Chain: block.Chain, Level: l, BlockNumber: block.Number, BlockHash: block.Hash}, Body: []byte("b")}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return finality.AppendRequest{ProofID: proofID, Chain: block.Chain, Settlement: s.Included, Level: l, Kind: baseKinds[l], Evidence: ev, Registry: baseRegistry()}
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
	return verifyFileWith(t, path, finality.Default, nil)
}

// verifyFileWith judges a file against a Settlement source (nil = none given) with the registry reg.
func verifyFileWith(t *testing.T, path string, reg *finality.Registry, leg *legSettlement) (int, string) {
	t.Helper()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := reportFinalityFile(&out, path, reg, pins, leg)
	return code, out.String()
}

// The portable document does not carry the leg's Settlement, so an offline verifier cannot recompute D0 from the file alone:
// with no Settlement source named it judges no level and says so by name. It never takes D0 from the file.
func TestFinalityFileNamesWhyItJudgesNothingAndNeverTakesD0FromTheFile(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	pid := uuid.New()
	chain := chainFor(t, s, pid, finality.LegBindingOf(s.Block()), finality.LevelFinalized)
	section := finality.NewSection(s.Block(), chain)
	doc, _ := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": section})

	t.Run("a finality section is reported by name, not judged", func(t *testing.T) {
		code, out := verifyFile(t, writeDoc(t, doc))
		if code != exitSummaryOnly || !strings.Contains(out, finality.CodeIncludedUnavailable) || !strings.Contains(out, string(finality.IncludedSettlementNotJudged)) || !strings.Contains(out, "1 addenda are not judged") {
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
		return uuid.MustParse(finalitytest.StoreProductionLeg(t, db, s)), s
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
	for _, l := range []finality.Level{finality.LevelFinalized, finality.LevelL1Posted} {
		if _, err := repo.Append(ctx, appendFor(t, id, s, l)); err != nil {
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
		// a writer that is not the repository (the repository would refuse to extend or form this chain)
		if _, err := db.ExecContext(ctx, `INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id2.String(), int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:]); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := run(baseRegistry(), id2); code != exitFailed || !strings.Contains(out, finality.CheckOwnHash) {
		t.Fatalf("wrong binding: exit %d\n%s", code, out)
	}

	// a proof whose bundle has no settlement evidence has nothing for finality to attach to
	bare := uuid.MustParse(finalitytest.StoreProductionArtifact(t, db, finality.ChainBaseSepolia, "", 0))
	if code, out := run(finality.NewRegistry(), bare); code != exitSummaryOnly || !strings.Contains(out, "no settlement evidence") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// the same when the proof has a bundle that holds no execution proof
	finalitytest.StoreBundleRow(t, db, bare.String(), finalitytest.Gzip(finalitytest.ProductionBundleJSON(bare.String(), nil)))
	if code, out := run(finality.NewRegistry(), bare); code != exitSummaryOnly || !strings.Contains(out, "no settlement evidence") {
		t.Fatalf("a bundle without component 5: exit %d\n%s", code, out)
	}
}

// The bundle the production writer (pkg/proof CertenProofBundle.ToCompressedJSON) produces is read by the stored-proof path: the
// test document of finalitytest is not trusted to be the writer's shape, the writer's own output is.
func TestFinalityReadsTheBundleTheProductionWriterWrites(t *testing.T) {
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
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	rawExec, err := json.Marshal(finalitytest.ProductionExecutionProof(t, s))
	if err != nil {
		t.Fatal(err)
	}
	var exec proof.ExecutionProof
	if err := json.Unmarshal(rawExec, &exec); err != nil {
		t.Fatal(err)
	}
	id := finalitytest.StoreProductionArtifact(t, db, s.Chain, exec.TxHash, exec.BlockNumber)
	// the writer (pkg/execution generateAndPersistBundle) sets bundle_integrity.custody_chain_hash to the proof id as hex
	bundle := &proof.CertenProofBundle{Schema: proof.BundleSchemaURL, BundleVersion: proof.BundleVersion, BundleID: "bundle-writer-test",
		BundleIntegrity: proof.BundleIntegrity{CustodyChainHash: strings.ReplaceAll(id, "-", ""), SignerID: "validator-test"}}
	bundle.SetExecutionProof(&exec)
	if bundle.ProofComponents.ExecutionProof == nil {
		t.Fatal("the writer did not attach component 5")
	}
	gz, err := bundle.ToCompressedJSON()
	if err != nil {
		t.Fatal(err)
	}
	finalitytest.StoreBundleRow(t, db, id, gz)

	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	ref, err := repo.LegRef(context.Background(), id)
	if err != nil || ref.Chain != s.Chain {
		t.Fatalf("LegRef: %v %+v", err, ref)
	}
	got, err := repo.LegSettlement(context.Background(), ref)
	if err != nil || got.Subject != s.Subject || got.Chain != s.Chain || got.Included == nil {
		t.Fatalf("LegSettlement: %v %+v", err, got)
	}
}

// With a Settlement source the file is judged exactly as a stored leg: D0 from the Settlement's block, the carried leg compared
// with it, the chain recomputed, each addendum judged by its Kind. The Settlement is a REAL captured Base block.
func TestFinalityFileIsJudgedAgainstTheNamedSettlement(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	pid := uuid.New()
	leg := &legSettlement{chain: finality.ChainBaseSepolia, s: s.Included, source: "test"}
	doc := func(section any) string {
		raw, _ := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": section})
		return writeDoc(t, raw)
	}
	good := finality.NewSection(s.Block(), chainFor(t, s, pid, finality.LegBindingOf(s.Block()), finality.LevelL1Posted, finality.LevelFinalized))

	t.Run("a chain bound to the Settlement's block verifies to the level reached", func(t *testing.T) {
		code, out := verifyFileWith(t, doc(good), baseRegistry(), leg)
		if code != exitVerified || !strings.Contains(out, "level reached: finalized") || !strings.Contains(out, "finalized_block") || !strings.Contains(out, "Settlement source: test") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if strings.Contains(out, finality.CodeIncludedUnavailable) {
			t.Fatalf("the summary-only path survived a given Settlement:\n%s", out)
		}
	})
	t.Run("one level present: the other is pending in the file, the headline is the level present", func(t *testing.T) {
		one := finality.NewSection(s.Block(), chainFor(t, s, pid, finality.LegBindingOf(s.Block()), finality.LevelL1Posted))
		code, out := verifyFileWith(t, doc(one), baseRegistry(), leg)
		if code != exitVerified || !strings.Contains(out, "level reached: l1_posted") || !strings.Contains(out, "no_evidence_in_file") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("an altered leg member is finality_chain_broken{leg_binding} and nothing else is judged", func(t *testing.T) {
		bad := good
		bad.Leg.BlockNumber++
		code, out := verifyFileWith(t, doc(bad), baseRegistry(), leg)
		if code != exitFailed || !strings.Contains(out, finality.CheckLegBinding) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a chain forged under another D0 (a digest taken from the file) is refused at own_hash", func(t *testing.T) {
		other := s.Block()
		other.Number++
		forged := finality.NewSection(s.Block(), chainFor(t, s, pid, finality.LegBindingOf(other), finality.LevelFinalized))
		code, out := verifyFileWith(t, doc(forged), baseRegistry(), leg)
		if code != exitFailed || !strings.Contains(out, finality.CheckOwnHash) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a verifier that does not know the kinds is summary-only by name, not failed", func(t *testing.T) {
		code, out := verifyFileWith(t, doc(good), finality.NewRegistry(), leg)
		if code != exitSummaryOnly || !strings.Contains(out, finality.CodeEvidenceUnrecognised) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a Settlement of another block than the file's leg is a leg_binding failure", func(t *testing.T) {
		other := finalitytest.Settlement(t, "telcoin_adiri_498759")
		code, out := verifyFileWith(t, doc(good), baseRegistry(), &legSettlement{chain: finality.ChainBaseSepolia, s: other.Included, source: "test"})
		if code != exitFailed || !strings.Contains(out, finality.CheckLegBinding) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

// The exported outcome evidence is a Settlement source: the block that holds the recorded outcome, proven offline.
func TestFinalityFileSettlementFromAnExportedOutcomeEvidenceFile(t *testing.T) {
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatalf("the outcome evidence's block does not verify as the included level: %v", err)
	}
	ev := loadFixture(t, 84532)
	if leg.chain != 84532 || block.Number != ev.Record.BlockNumber || "0x"+fmt.Sprintf("%x", block.Hash) != strings.ToLower(ev.Record.BlockHash) {
		t.Fatalf("%+v vs the record's block %d %s", block, ev.Record.BlockNumber, ev.Record.BlockHash)
	}
	pid := uuid.New()
	s := finality.Settlement{Chain: leg.chain, Included: leg.s}
	s.Subject, _ = finality.SubjectOfSettlement(leg.s)
	section := finality.NewSection(block, chainFor(t, s, pid, finality.LegBindingOf(block), finality.LevelL1Posted))
	raw, _ := json.Marshal(map[string]any{"finality": section})
	code, out := verifyFileWith(t, writeDoc(t, raw), baseRegistry(), leg)
	if code != exitVerified || !strings.Contains(out, "level reached: l1_posted") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// a header other than the one the record names, and a transaction other than the recorded one, are not a Settlement
	tampered := loadFixture(t, 84532)
	tampered.Record.Inclusion.Header[len(tampered.Record.Inclusion.Header)-1] ^= 1
	if _, err := settlementFromOutcomeFile(writeEvidence(t, tampered)); err == nil || !strings.Contains(err.Error(), "header hashes to") {
		t.Fatalf("a tampered outcome header was accepted as a Settlement: %v", err)
	}
	swapped := loadFixture(t, 84532)
	swapped.Record.Tx = swapped.Record.BlockHash
	if _, err := settlementFromOutcomeFile(writeEvidence(t, swapped)); err == nil || !strings.Contains(err.Error(), "transaction hashes to") {
		t.Fatalf("a transaction other than the recorded one was accepted: %v", err)
	}
	if _, err := settlementFromOutcomeFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("an absent file was accepted")
	}
}

// A stored proof whose row has not recorded its settlement yet (settlement_tx_hash / settlement_block_number NULL) is judged as
// before, and the report says that the bundle was bound to the proof by its custody hash only. The portable section is untouched.
func TestFinalityReportSaysWhenTheSettlementColumnsAreNotRecorded(t *testing.T) {
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
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	id := uuid.MustParse(finalitytest.StoreProductionLeg(t, db, s))
	run := func() (int, string) {
		var out bytes.Buffer
		code := reportFinality(ctx, &out, db, id, finality.NewRegistry(), pins)
		return code, out.String()
	}
	const note = "settlement columns not recorded: the bundle is bound to the proof by its custody hash, tx/block not cross-checked"
	recordedCode, out := run()
	if strings.Contains(out, note) {
		t.Fatalf("a recorded settlement carries the note:\n%s", out)
	}
	if _, err := db.ExecContext(ctx, `UPDATE proof_artifacts SET settlement_tx_hash = NULL, settlement_block_number = NULL WHERE proof_id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	code, out := run()
	if !strings.Contains(out, note) || code != recordedCode {
		t.Fatalf("exit %d (recorded: %d)\n%s", code, recordedCode, out)
	}
}
