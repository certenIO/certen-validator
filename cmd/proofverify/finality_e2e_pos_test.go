// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// RB11-E2E-POS: the positive end to end of every S7 kind through the real database path.
//
// For the leg of a PUBLISHED vector's valid case, the recorded valid evidence goes through finality.AppendRequest and
// database.FinalityAddendaRepository.Append (locked, verified: the registered REAL Kind judges the evidence inside the append)
// against the leg's real Settlement (cmd/finalitye2erecord: the tx and receipt of the vector's real leg block, read from agreeing
// public providers and proven into the header's roots; the published sets carry only the header). The stored chain is composed
// into the portable `finality` section (ComposeSection) and judged by proofverify's finality report, offline, against the
// Settlement read from the stored bundle (--proof-id), and the headline and the per-level verdict must equal the vector's own
// canonical verdict, byte for byte.
//
// What is real: the Kind (pkg/finality/<kind>), the pins (the vector's own pins file, exactly as the vector is judged), the
// evidence bytes, the Settlement, the database, Append, ComposeSection, the registry and reportFinalityFile. What is a test
// double, and only where a chain has two levels and the published sets hold no second level for the SAME block: the sibling
// level's Kind (fakeKind) accepts any container whose header names the leg; it is used to prove the any-order append through
// the database, never to prove a verdict of the sibling level.

const e2eData = "testdata/finality_e2e_pos1"

type e2eLeg struct {
	name   string // row name
	settle string // recorded Settlement file (name when empty): a second row may judge the same block with other evidence
	// embeddedVerifies: the evidence is anchored at the root pin the EMBEDDED pins hold, so it verifies under them as well.
	embeddedVerifies bool
	kind             string
	level            finality.Level
	chain            uint64
	register         func(*finality.Registry) error
	pins             *finality.Pins
	evidence         []byte
	expect           string // the vector's own canonical verdict text
	render           func(finality.Verdict) string
	legHash          string // the vector's leg block hash
	sibling          finality.Level
	siblingKnd       string
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func readFileT(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// baseRender and basefinalRender are the canonical verdict text of the Base kinds ({"fields":...,"result":"ok"}).
func baseRender(v finality.Verdict) string { return string(baseposted.CanonicalVerdict(v, nil)) }

func basefinalRender(v finality.Verdict) string { return string(basefinal.CanonicalVerdict(v, nil)) }

// verifiedRender is the canonical verdict text of the kinds whose cases write {"code":"verified","fields":{...,kind,level}}.
func verifiedRender(v finality.Verdict) string {
	f := map[string]any{}
	for k, x := range v.Fields {
		f[k] = x
	}
	f["kind"] = v.Kind
	f["level"] = v.Level
	return string((&finality.StateError{Code: "verified", Fields: f}).Canonical())
}

// finalizedRender is the canonical verdict text of arb-sepolia/finalized/v1 (code "finalized", the Result fields).
func finalizedRender(v finality.Verdict) string {
	var kv []any
	for k, val := range v.Fields {
		kv = append(kv, k, val)
	}
	return string(finality.NewState("finalized", kv...).Canonical())
}

func baseExpect(raw json.RawMessage) string {
	var e baseposted.Expect
	if err := json.Unmarshal(raw, &e); err != nil {
		panic(err)
	}
	return string(baseposted.ExpectBytes(e))
}

func basefinalExpect(raw json.RawMessage) string {
	var e basefinal.Expect
	if err := json.Unmarshal(raw, &e); err != nil {
		panic(err)
	}
	return string(basefinal.ExpectBytes(e))
}

// baseFamilyCase loads one valid case of finality_base_posted1 / finality_base_final1 (cases/<id>.json).
func baseFamilyCase(t *testing.T, set, id string, expect func(json.RawMessage) string) (pins *finality.Pins, evidence []byte, want, legHash string) {
	t.Helper()
	dir := repoPath("pkg", "finality", set)
	var c struct {
		Pins     string          `json:"pins"`
		Leg      string          `json:"leg"`
		Evidence string          `json:"evidence"`
		Splice   json.RawMessage `json:"splice"`
		Expect   json.RawMessage `json:"expect"`
	}
	if err := json.Unmarshal(readFileT(t, filepath.Join(dir, "cases", id+".json")), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Splice) != 0 && string(c.Splice) != "null" {
		t.Fatalf("%s is not the unmodified recorded evidence", id)
	}
	var leg struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(readFileT(t, filepath.Join(dir, c.Leg)), &leg); err != nil {
		t.Fatal(err)
	}
	pinsRaw := readFileT(t, filepath.Join(dir, c.Pins))
	if strings.HasPrefix(set, "baseposted/") {
		// the published l1_posted set predates the Granite pins; the harness supplies them explicitly (baseposted.PublishedSetPinSupply)
		var err error
		if pinsRaw, err = baseposted.SupplyBaseSepoliaPins(pinsRaw, baseposted.PublishedSetPinSupply); err != nil {
			t.Fatal(err)
		}
	}
	p, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	return p, readFileT(t, filepath.Join(dir, c.Evidence)), expect(c.Expect), leg.Hash
}

// rawCase loads a case of finality_arb_posted1 / finality_eth_sepolia1 ({pins, leg, evidence_base, evidence_patch(es), expect_canonical}).
func rawCase(t *testing.T, set, id string) (pins *finality.Pins, evidence []byte, want, legHash string) {
	t.Helper()
	dir := repoPath("pkg", "finality", set)
	var c struct {
		Pins string `json:"pins"`
		Leg  struct {
			Hash string `json:"hash"`
		} `json:"leg"`
		Base  string `json:"evidence_base"`
		Patch *struct {
			At  uint64 `json:"at"`
			Del uint64 `json:"del"`
			Ins string `json:"ins"`
		} `json:"evidence_patch"`
		Patches json.RawMessage `json:"evidence_patches"`
		Expect  string          `json:"expect_canonical"`
	}
	if err := json.Unmarshal(readFileT(t, filepath.Join(dir, "cases", id+".json")), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Patches) != 0 && string(c.Patches) != "null" && string(c.Patches) != "[]" {
		t.Fatalf("%s carries evidence patches", id)
	}
	if c.Patch != nil && (c.Patch.Del != 0 || strings.TrimPrefix(c.Patch.Ins, "0x") != "") {
		t.Fatalf("%s alters the recorded evidence", id)
	}
	p, err := finality.ParsePinsOverride(readFileT(t, filepath.Join(dir, c.Pins)))
	if err != nil {
		t.Fatal(err)
	}
	return p, readFileT(t, filepath.Join(dir, c.Base)), c.Expect, c.Leg.Hash
}

func e2eLegs(t *testing.T) []e2eLeg {
	t.Helper()
	var out []e2eLeg
	for _, c := range []struct{ id, name string }{{"valid_a", "base_posted_a"}, {"valid_b", "base_posted_b"}} {
		p, ev, ex, h := baseFamilyCase(t, "baseposted/testdata/finality_base_posted1", c.id, baseExpect)
		out = append(out, e2eLeg{name: c.name, kind: baseposted.KindName, level: finality.LevelL1Posted, chain: finality.ChainBaseSepolia, register: baseposted.Register,
			pins: p, evidence: ev, expect: ex, render: baseRender, legHash: h, sibling: finality.LevelFinalized, siblingKnd: basefinal.KindName})
	}
	for _, c := range []struct{ id, name string }{{"valid_leg_47604755", "base_final_47604755"}, {"valid_leg_47898494", "base_final_47898494"}} {
		p, ev, ex, h := baseFamilyCase(t, "basefinal/testdata/finality_base_final1", c.id, basefinalExpect)
		out = append(out, e2eLeg{name: c.name, kind: basefinal.KindName, level: finality.LevelFinalized, chain: finality.ChainBaseSepolia, register: basefinal.Register,
			pins: p, evidence: ev, expect: ex, render: basefinalRender, legHash: h, sibling: finality.LevelL1Posted, siblingKnd: baseposted.KindName})
	}
	{
		p, ev, ex, h := rawCase(t, "arbposted/testdata/finality_arb_posted1", "valid_live")
		out = append(out, e2eLeg{name: "arb_posted", kind: arbposted.KindName, level: finality.LevelL1Posted, chain: finality.ChainArbitrumSepolia, register: arbposted.Register,
			pins: p, evidence: ev, expect: ex, render: verifiedRender, legHash: h, sibling: finality.LevelFinalized, siblingKnd: arbfinal.KindName})
	}
	{
		// finality_arb_final1: vectors.json, the `live` group's real_valid (the other valid vectors judge synthetic L2 blocks that no chain holds)
		dir := repoPath("pkg", "finality", "arbfinal", "testdata", "finality_arb_final1")
		var set struct {
			Vectors []struct {
				Name  string `json:"name"`
				Group string `json:"group"`
				Leg   struct {
					Hash string `json:"hash"`
				} `json:"leg"`
				Pins     string `json:"pins"`
				Evidence string `json:"evidence"`
				Expect   string `json:"expect"`
			} `json:"vectors"`
		}
		if err := json.Unmarshal(readFileT(t, filepath.Join(dir, "vectors.json")), &set); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range set.Vectors {
			if v.Name != "real_valid" {
				continue
			}
			if v.Group != "live" || v.Evidence == "" {
				t.Fatalf("real_valid is %+v", v)
			}
			p, err := finality.ParsePinsOverride(readFileT(t, filepath.Join(dir, "pins", v.Pins)))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, e2eLeg{name: "arb_final_real", kind: arbfinal.KindName, level: finality.LevelFinalized, chain: finality.ChainArbitrumSepolia, register: arbfinal.Register,
				pins: p, evidence: readFileT(t, filepath.Join(dir, "evidence", v.Evidence)), expect: v.Expect, render: finalizedRender, legHash: v.Leg.Hash,
				sibling: finality.LevelL1Posted, siblingKnd: arbposted.KindName})
			found = true
		}
		if !found {
			t.Fatal("finality_arb_final1 has no real_valid vector")
		}
	}
	for _, c := range []struct{ id, name string }{{"valid_gloas_latest", "eth_gloas_latest"}, {"valid_gloas_period", "eth_gloas_period"}, {"valid_legacy", "eth_legacy"}} {
		p, ev, ex, h := rawCase(t, "ethsepolia/testdata/finality_eth_sepolia1", c.id)
		out = append(out, e2eLeg{name: c.name, kind: ethsepolia.Name, level: finality.LevelFinalized, chain: finality.ChainSepolia, register: ethsepolia.Register,
			pins: p, evidence: ev, expect: ex, render: verifiedRender, legHash: h, embeddedVerifies: c.name == "eth_legacy"})
	}
	// RB11-C2: the same three leg blocks with evidence ANCHORED AT THE ROOT PIN with in-evidence links (finality_eth_sepolia2, judged under
	// the embedded pins): the production shape, which verifies under the embedded pins, through the database path as well.
	for _, c := range []struct{ id, name string }{{"valid_gloas_latest", "eth_gloas_latest"}, {"valid_gloas_period", "eth_gloas_period"}, {"valid_legacy", "eth_legacy"}} {
		p, ev, ex, h := rawCase(t, "ethsepolia/testdata/finality_eth_sepolia2", c.id)
		out = append(out, e2eLeg{name: c.name + "_root_anchored", settle: c.name, kind: ethsepolia.Name, level: finality.LevelFinalized, chain: finality.ChainSepolia, register: ethsepolia.Register,
			pins: p, evidence: ev, expect: ex, render: verifiedRender, legHash: h, embeddedVerifies: true})
	}
	return out
}

// settlementOf reads the recorded Settlement of a leg and binds it to the vector's leg block.
func settlementOf(t *testing.T, l e2eLeg) finality.Settlement {
	t.Helper()
	file := l.settle
	if file == "" {
		file = l.name
	}
	raw := readFileT(t, filepath.Join(e2eData, file+".json"))
	var manifest map[string]string
	if err := json.Unmarshal(readFileT(t, filepath.Join(e2eData, "MANIFEST.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); manifest[file+".json"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("%s.json is not the recorded file (MANIFEST.json sha256 differs)", l.name)
	}
	var f struct {
		Chain      int64                `json:"chain"`
		Settlement *ethproof.Settlement `json:"settlement"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	subj, err := finality.SubjectOfSettlement(f.Settlement)
	if err != nil {
		t.Fatalf("%s: the recorded Settlement does not verify: %v", l.name, err)
	}
	s := finality.Settlement{Chain: uint64(f.Chain), Subject: subj, Included: f.Settlement}
	if s.Chain != l.chain {
		t.Fatalf("%s: Settlement of chain %d, leg of chain %d", l.name, s.Chain, l.chain)
	}
	if got := "0x" + hex.EncodeToString(s.BlockHash[:]); got != l.legHash {
		t.Fatalf("%s: the Settlement proves block %s, the vector's leg is %s", l.name, got, l.legHash)
	}
	return s
}

func newProofFor(t *testing.T, db *sql.DB, s finality.Settlement) uuid.UUID {
	t.Helper()
	exec := map[string]any{}
	raw, err := json.Marshal(s.Included)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &exec); err != nil {
		t.Fatal(err)
	}
	exec["chain_id"] = strconv.FormatUint(s.Chain, 10)
	artifact, _ := json.Marshal(map[string]any{"proof_components": map[string]any{"5_execution_proof": exec}})
	created, err := database.NewProofArtifactRepository(db).CreateProofArtifact(context.Background(), &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: "e2e_" + uuid.NewString()[:8], AccountURL: "acc://finality-e2e.acme/tokens",
		ProofClass: database.ProofClassOnCadence, ValidatorID: "test-validator-1", ArtifactJSON: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.ProofID
}

func request(l e2eLeg, id uuid.UUID, s finality.Settlement, level finality.Level, kind string, evidence []byte, reg *finality.Registry) finality.AppendRequest {
	return finality.AppendRequest{ProofID: id, Chain: s.Chain, Settlement: s.Included, Level: level, Kind: kind, Evidence: evidence, Registry: reg, Pins: l.pins}
}

// realRegistry registers the leg's REAL kind and, where the chain has a second level, the sibling's test double.
func realRegistry(t *testing.T, l e2eLeg) *finality.Registry {
	t.Helper()
	reg := finality.NewRegistry()
	if err := l.register(reg); err != nil {
		t.Fatal(err)
	}
	if l.sibling != finality.LevelNone {
		if err := reg.RegisterKind(fakeKind{l.chain, l.siblingKnd, l.sibling}); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func doubleEvidence(t *testing.T, s finality.Settlement, level finality.Level, kind string) []byte {
	t.Helper()
	b := s.Block()
	ev, err := finality.Container{Header: finality.ContainerHeader{Kind: kind, Chain: b.Chain, Level: level, BlockNumber: b.Number, BlockHash: b.Hash}, Body: []byte("sibling-double")}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type e2eRow struct {
	leg, kind, level string
	evidence, stored int
	headline         string
	verdict          string
	mutations        string
	embedded         string
}

func TestFinalityE2EPositiveEveryKindThroughTheDatabase(t *testing.T) {
	url, err := testdb.PackageURL("proofverify")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(context.Background(), "proofverify-e2e"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	var rows []e2eRow
	t.Cleanup(func() {
		for _, r := range rows {
			t.Logf("E2E-ROW leg=%s kind=%s level=%s evidence_bytes=%d stored_bytes=%d headline=%s verdict=%s mutated_byte_refusals=%s embedded_pins=%s result=PASS",
				r.leg, r.kind, r.level, r.evidence, r.stored, r.headline, r.verdict, r.mutations, r.embedded)
		}
	})

	for _, l := range e2eLegs(t) {
		l := l
		t.Run(l.name, func(t *testing.T) {
			s := settlementOf(t, l)
			d0 := finality.LegBindingOf(s.Block())
			row := e2eRow{leg: l.name, kind: l.kind, level: l.level.String(), evidence: len(l.evidence)}

			// --- single level: the recorded valid evidence, then the portable section, then proofverify's report ---
			id := newProofFor(t, db, s)
			reg := realRegistry(t, l)

			// (3c) a mutated evidence byte is refused by the append with a named state and stores nothing
			var codes []string
			for _, off := range []int{len(l.evidence) / 2, len(l.evidence) - 1, 100} {
				bad := append([]byte(nil), l.evidence...)
				bad[off] ^= 0x01
				_, err := repo.Append(ctx, request(l, id, s, l.level, l.kind, bad, reg))
				n, named := finality.AsNamed(err)
				if err == nil || !named {
					t.Fatalf("a flipped byte at %d: want a named refusal, got %v", off, err)
				}
				if n.Code == finality.CodeAppendConflict || n.Code == finality.CodeLevelAlreadyPresent {
					t.Fatalf("a flipped byte at %d is reported as %s, not as a refusal of the evidence", off, n.Code)
				}
				codes = append(codes, n.Code)
				if chain, err := repo.Chain(ctx, id.String()); err != nil || len(chain) != 0 {
					t.Fatalf("a refused append stored %d addenda (%v)", len(chain), err)
				}
			}
			row.mutations = strings.Join(codes, ",")

			// (2)+(3a) the valid evidence is verified inside the locked append and stored under the right D0
			a, err := repo.Append(ctx, request(l, id, s, l.level, l.kind, l.evidence, reg))
			if err != nil {
				t.Fatalf("the vector's valid evidence is refused through the database path: %v", err)
			}
			if a.Seq != 1 || a.Level != l.level || a.Kind != l.kind || a.Chain != l.chain || !bytes.Equal(a.Evidence, l.evidence) {
				t.Fatalf("stored addendum %d/%s/%s/%d", a.Seq, a.Level, a.Kind, a.Chain)
			}
			chain, err := repo.Chain(ctx, id.String())
			if err != nil || len(chain) != 1 {
				t.Fatalf("%v %d", err, len(chain))
			}
			if !bytes.Equal(chain[0].Evidence, l.evidence) {
				t.Fatal("the evidence read back from the database is not the evidence that was appended")
			}
			if err := finality.VerifyChain(d0, chain); err != nil {
				t.Fatalf("the stored chain does not verify under the Settlement's own D0: %v", err)
			}
			other := s.Block()
			other.Number++
			if err := finality.VerifyChain(finality.LegBindingOf(other), chain); err == nil {
				t.Fatal("the stored chain verifies under another leg's D0")
			}
			row.stored = len(chain[0].Evidence)
			if _, err := repo.Append(ctx, request(l, id, s, l.level, l.kind, l.evidence, reg)); err == nil {
				t.Fatal("a second append of the same level was accepted")
			}

			// (4) the portable section, composed from the repository
			section, err := finality.ComposeSection(ctx, repo, id.String())
			if err != nil || section == nil {
				t.Fatalf("compose: %v", err)
			}
			docRaw, err := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": section})
			if err != nil {
				t.Fatal(err)
			}
			doc := writeDoc(t, docRaw)

			// (5) proofverify's finality report, offline, against the Settlement of the stored bundle, with the REAL kind
			leg, err := settlementFromDB(ctx, url, id.String())
			if err != nil {
				t.Fatalf("the Settlement of the stored bundle: %v", err)
			}
			realOnly := finality.NewRegistry()
			if err := l.register(realOnly); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code := reportFinalityFile(&out, doc, realOnly, l.pins, leg)
			if code != exitVerified || !strings.Contains(out.String(), "level reached: "+l.level.String()) || !strings.Contains(out.String(), "VERIFIED (finality)") {
				t.Fatalf("proofverify: exit %d\n%s", code, out.String())
			}
			parsed, err := finality.ParseSection(mustJSON(t, section))
			if err != nil {
				t.Fatal(err)
			}
			carried, err := parsed.Leg.Ref()
			if err != nil {
				t.Fatal(err)
			}
			rep := realOnly.Verify(leg.chain, leg.s, carried, parsed.Addenda, l.pins)
			if rep.Headline != l.level || rep.Broken != nil {
				t.Fatalf("headline %s broken %v", rep.Headline, rep.Broken)
			}
			st := rep.Levels[l.level]
			if st.Status != finality.StatusVerified || st.Verdict == nil {
				t.Fatalf("level %s: %+v", l.level, st)
			}
			got := l.render(*st.Verdict)
			if got != l.expect {
				t.Fatalf("the verdict through the database and proofverify differs from the vector's canonical verdict\n got: %.600s\nwant: %.600s", got, l.expect)
			}
			row.headline, row.verdict = rep.Headline.String(), "equals the vector's expect ("+strconv.Itoa(len(got))+" B canonical)"
			emb, perr := finality.EmbeddedPins()
			if perr != nil {
				t.Fatal(perr)
			}
			repE := realOnly.Verify(leg.chain, leg.s, carried, parsed.Addenda, emb)
			// The same evidence under the EMBEDDED pins (what the proofverify command always uses): the embedded Sepolia ledger holds the
			// root pin (period 1378) only, so evidence anchored beyond it is not established and is the named finality_ledger_behind,
			// never a weaker level; evidence anchored at the root pin (eth_legacy) verifies, with the vector's own verdict.
			if es := repE.Levels[l.level]; l.embeddedVerifies {
				if es.Status != finality.StatusVerified || es.Verdict == nil || l.render(*es.Verdict) != l.expect || repE.Headline != l.level {
					t.Fatalf("%s under the embedded pins: headline %s %+v", l.name, repE.Headline, es)
				}
				row.embedded = "verified (anchored at the root pin 1378), verdict equals the vector's"
			} else {
				if es.Status != finality.StatusRefused || es.State == nil || !strings.Contains(es.State.Error(), "finality_ledger_behind") || repE.Headline != finality.LevelIncluded {
					t.Fatalf("%s under the embedded pins: want the named finality_ledger_behind, got headline %s %+v", l.name, repE.Headline, es)
				}
				row.embedded = es.State.Error()
			}
			rows = append(rows, row)

			// --- a second level, in either order, on its own stored proof of the same Settlement ---
			if l.sibling == finality.LevelNone {
				return
			}
			sib := doubleEvidence(t, s, l.sibling, l.siblingKnd)
			for _, order := range [][]finality.Level{{l.level, l.sibling}, {l.sibling, l.level}} {
				pid := newProofFor(t, db, s)
				for _, lv := range order {
					ev, kn := l.evidence, l.kind
					if lv == l.sibling {
						ev, kn = sib, l.siblingKnd
					}
					if _, err := repo.Append(ctx, request(l, pid, s, lv, kn, ev, reg)); err != nil {
						t.Fatalf("order %v: appending %s: %v", order, lv, err)
					}
				}
				two, err := repo.Chain(ctx, pid.String())
				if err != nil || len(two) != 2 || two[0].Level != order[0] || two[1].Level != order[1] {
					t.Fatalf("order %v: stored %d addenda, err %v", order, len(two), err)
				}
				if err := finality.VerifyChain(d0, two); err != nil {
					t.Fatalf("order %v: %v", order, err)
				}
				// the report judges both: the real level by its real Kind, the sibling by the double
				rep := reg.VerifyLeg(s.Block(), s.Block(), two, l.pins)
				if rep.Broken != nil || rep.Headline != finality.LevelFinalized || rep.Levels[l.level].Status != finality.StatusVerified || rep.Levels[l.sibling].Status != finality.StatusVerified {
					t.Fatalf("order %v: headline %s broken %v l1=%s fin=%s", order, rep.Headline, rep.Broken,
						rep.Levels[finality.LevelL1Posted].Status, rep.Levels[finality.LevelFinalized].Status)
				}
				if got := l.render(*rep.Levels[l.level].Verdict); got != l.expect {
					t.Fatalf("order %v: the real level's verdict changed beside a second level\n got: %.400s\nwant: %.400s", order, got, l.expect)
				}
			}
			// a flipped byte of the real evidence is refused on a leg that already holds the other level, and stores nothing
			bad := append([]byte(nil), l.evidence...)
			bad[len(bad)/2] ^= 0x01
			p3 := newProofFor(t, db, s)
			if _, err := repo.Append(ctx, request(l, p3, s, l.sibling, l.siblingKnd, sib, reg)); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Append(ctx, request(l, p3, s, l.level, l.kind, bad, reg)); err == nil {
				t.Fatal("a flipped byte was appended beside the sibling level")
			}
			if c3, _ := repo.Chain(ctx, p3.String()); len(c3) != 1 {
				t.Fatalf("a refused append changed the stored chain: %d", len(c3))
			}
		})
	}
}
