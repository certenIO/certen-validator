package consensus

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-E: the app-level test J2-F1 asked for. Each fixture in testdata/g1_live is a LIVE Kermit intent captured by cmd/g1fixture - its
// L1-L4 chained proof, G0-G2, the G1 vote record and its evidence, each built by the production prover (the chained proof generator, the
// signing key page resolver and the governance proof CLI, driven as the BFT stage drives them), and the evidence 2.1 document built from the
// validators' own capture of the same transaction, with the Directory's major records it builds on. The facts the binding binds the
// document to are therefore NOT derived from the document under test.
//
// The test goes through BuildIntentCertificate and VerifyIntentCertificate with no verifier named, i.e. the production path: the real
// evidence 2.1 verifier against the chain's spine, the real binding (BindProofV21) to the intent's own vote evidence, and govRoot v4.

// g1LiveFixture is cmd/g1fixture's file.
type g1LiveFixture struct {
	intentFixture
	Format  string          `json:"format"`
	Name    string          `json:"name"`
	Account string          `json:"account"`
	TxHash  string          `json:"tx_hash"`
	KeyBook string          `json:"key_book"`
	KeyPage string          `json:"key_page"`
	ProofV2 json.RawMessage `json:"proof_v2"`
	Archive json.RawMessage `json:"archive"`
	Report  json.RawMessage `json:"report"`
}

type g1LiveCase struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	SHA256     string   `json:"sha256"`
	IntentID   string   `json:"intentId"`
	TxHash     string   `json:"txHash"`
	Principal  string   `json:"principal"`
	Partitions []string `json:"partitions"` // the partitions the proven pages live on, sorted
	Pages      int      `json:"pages"`
	Delegators int      `json:"delegators,omitempty"`
	Note       string   `json:"note,omitempty"`
}

type g1LiveManifest struct {
	Format        string       `json:"format"`
	Prover        string       `json:"prover,omitempty"` // which build produced the G0-G2 of the fixtures, when it is not the deployed one
	Archive       string       `json:"archive"`          // the Directory major records every fixture builds on, gzip JSON
	ArchiveSHA256 string       `json:"archiveSha256"`
	Cases         []g1LiveCase `json:"cases"`
}

// g1LiveDirs are the two suites: g1_live holds intents the deployed build's provers can certify (the base build's G1 and G2 produced their
// facts); g1_live_fixedprover holds the intents it cannot (delegation through an authority book, a foreign vote that completes the approval:
// findings C5-F6 and C5-F7), whose G0-G2 were produced by the govproof of the two fix branches (see the manifest's "prover").
var g1LiveDirs = []string{"testdata/g1_live", "testdata/g1_live_fixedprover"}

func loadG1LiveManifest(t *testing.T, dir string) *g1LiveManifest {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mb)
	if got := hex.EncodeToString(sum[:]); !strings.HasPrefix(strings.TrimSpace(string(want)), got) {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %s of manifest.json", strings.TrimSpace(string(want)), got)
	}
	m := new(g1LiveManifest)
	if err := json.Unmarshal(mb, m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-g1live/1" || len(m.Cases) == 0 {
		t.Fatalf("manifest format %q with %d cases", m.Format, len(m.Cases))
	}
	return m
}

// loadG1LiveArchive reads the suite's shared major records, checked against the manifest's hash.
func loadG1LiveArchive(t *testing.T, dir string) json.RawMessage {
	t.Helper()
	m := loadG1LiveManifest(t, dir)
	gz, err := os.ReadFile(filepath.Join(dir, m.Archive))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz)
	if got := hex.EncodeToString(sum[:]); got != m.ArchiveSHA256 {
		t.Fatalf("%s hashes to %s, the manifest says %s", m.Archive, got, m.ArchiveSHA256)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadG1LiveCase(t *testing.T, dir string, c g1LiveCase) *g1LiveFixture {
	t.Helper()
	gz, err := os.ReadFile(filepath.Join(dir, c.File))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz)
	if got := hex.EncodeToString(sum[:]); got != c.SHA256 {
		t.Fatalf("%s: the file hashes to %s, the manifest says %s", c.File, got, c.SHA256)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	f := new(g1LiveFixture)
	if err := json.Unmarshal(b, f); err != nil {
		t.Fatal(err)
	}
	if len(f.Archive) == 0 { // the Directory's major records are stored once for the suite (cmd/g1fixture -shared-archive)
		f.Archive = loadG1LiveArchive(t, dir)
	}
	if f.Format != "certen-g1fixture/1" || f.ChainedProof == nil || len(f.ProofV2) == 0 || len(f.Archive) == 0 || len(f.VoteEvidence) == 0 {
		t.Fatalf("%s: not a complete g1 fixture", c.File)
	}
	if !strings.EqualFold(f.TxHash, c.TxHash) || f.Name != c.Name {
		t.Fatalf("%s: the fixture is %s/%s, the manifest says %s/%s", c.File, f.Name, f.TxHash, c.Name, c.TxHash)
	}
	return f
}

// g1LiveSpine is the spine the chain holds after verifying the fixture's major records from Kermit's genesis (as v3Spine, for this fixture).
func g1LiveSpine(t *testing.T, f *g1LiveFixture) *ledger.AccumulateSpineLog {
	t.Helper()
	return v3Spine(t, &intentFixtureV3{intentFixture: f.intentFixture, ProofV2: f.ProofV2, Archive: f.Archive})
}

func g1LiveBlock(t *testing.T, f *g1LiveFixture, validatorID string) *ValidatorBlock {
	t.Helper()
	return v3Block(t, &intentFixtureV3{intentFixture: f.intentFixture, ProofV2: f.ProofV2, Archive: f.Archive}, validatorID)
}

func g1LiveEvidence(t *testing.T, f *g1LiveFixture) *proofv2.Evidence {
	t.Helper()
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(f.ProofV2, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

var g1LiveActivation = &ledger.G1ActivationRecord{Version: 1, Height: 100, ID: "g1-activation:rb9-e-live"}

// Every live case: a certificate over its evidence 2.1 is built and verified with the real verifier, binding and govRoot v4; it survives the
// block's JSON; it is refused as not-in-force before the activation; and a certificate carrying no proof v2 at all cannot be built on a chain that requires v3. (That a 2.0 document is refused once the activation is in force, ErrIntentProofV21Missing, is proved on real documents in g1_gate_test.go and g1_real21_test.go.)
func TestG1LiveEvidence21IsCertifiedAndVerifiedThroughTheAppWithTheRealVerifier(t *testing.T) {
	for _, dir := range g1LiveDirs {
		m := loadG1LiveManifest(t, dir)
		for _, c := range m.Cases {
			t.Run(filepath.Base(dir)+"/"+c.Name, func(t *testing.T) {
				f := loadG1LiveCase(t, dir, c)
				rf, reg := intentRegistry(t)
				spine := g1LiveSpine(t, f)
				if !ProofV3Required(spine, reg) {
					t.Fatal("the spine does not require v3")
				}
				ev := g1LiveEvidence(t, f)
				if ev.Version != proofv2.Version21 {
					t.Fatalf("the fixture's proof v2 is version %q, not %q", ev.Version, proofv2.Version21)
				}
				parts := map[string]bool{}
				for _, p := range ev.Pages {
					parts[strings.ToLower(p.Partition)] = true
				}
				var got []string
				for p := range parts {
					got = append(got, p)
				}
				if len(got) != len(c.Partitions) {
					t.Fatalf("the document proves pages on %v, the manifest says %v", got, c.Partitions)
				}
				for _, want := range c.Partitions {
					if !parts[strings.ToLower(want)] {
						t.Fatalf("the manifest names partition %s, the document proves pages on %v", want, got)
					}
				}
				if len(ev.Pages) != c.Pages {
					t.Fatalf("the document proves %d pages, the manifest says %d", len(ev.Pages), c.Pages)
				}

				vb := g1LiveBlock(t, f, "validator-1")
				rec := f.record(t)
				if err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, rec, f.VoteEvidence, f.ChainedProof,
					spine, g1LiveActivation, ev); err != nil {
					t.Fatalf("building the certificate over the live evidence 2.1: %v", err)
				}
				cert := vb.IntentCertificate
				if cert.ProofV2 == nil || cert.ProofV2.Version != proofv2.Version21 || cert.GovRootV3 == "" || cert.GovRootV2 != "" {
					t.Fatalf("not a certificate over evidence 2.1: proof v2 %v, root %q, govRoot v2 %q", cert.ProofV2 != nil, cert.GovRootV3, cert.GovRootV2)
				}
				b, err := json.Marshal(vb)
				if err != nil {
					t.Fatal(err)
				}
				var back ValidatorBlock
				if err := json.Unmarshal(b, &back); err != nil {
					t.Fatal(err)
				}
				if _, err := VerifyIntentCertificate(&back, intentChain, reg, spine, g1LiveActivation); err != nil {
					t.Fatalf("after a JSON round trip, with the activation in force: %v", err)
				}
				t.Logf("%s: %d bytes of block JSON, pages on %v, govRoot (v4) %s", c.Name, len(b), c.Partitions, cert.GovRootV3)

				// before the activation the chain does not accept evidence 2.1
				if _, err := VerifyIntentCertificate(&back, intentChain, reg, spine, nil); !errors.Is(err, ErrIntentProofV21NotInForce) {
					t.Fatalf("evidence 2.1 before the activation: %v", err)
				}
			})
		}
	}
}

// What the binding refuses, on the live documents: it is the intent's own vote evidence and G1 that the document is bound to, not the
// document's own claims.
func TestG1LiveEvidence21RefusesWhatTheLiveFactsDoNotSupport(t *testing.T) {
	dir := g1LiveDirs[0]
	m := loadG1LiveManifest(t, dir)
	c := m.Cases[0]
	f := loadG1LiveCase(t, dir, c)
	rf, reg := intentRegistry(t)
	spine := g1LiveSpine(t, f)
	built := func(t *testing.T) *ValidatorBlock {
		vb := g1LiveBlock(t, f, "validator-1")
		if err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, f.record(t), f.VoteEvidence, f.ChainedProof,
			spine, g1LiveActivation, g1LiveEvidence(t, f)); err != nil {
			t.Fatal(err)
		}
		return vb
	}
	for _, tc := range []struct {
		name string
		edit func(vb *ValidatorBlock)
		want error
	}{
		{"a dropped proof v2", func(vb *ValidatorBlock) { vb.IntentCertificate.ProofV2 = nil }, ErrIntentProofV2Missing},
		{"a key page the proof did not prove", func(vb *ValidatorBlock) {
			vb.IntentCertificate.KeyPageURL = "acc://someone-else.acme/book/1"
		}, ErrIntentProofV2Invalid},
		{"a claimed govRoot", func(vb *ValidatorBlock) { vb.IntentCertificate.GovRootV3 = "0x" + strings.Repeat("11", 32) }, ErrIntentGovRootMismatch},
		{"levels about another block", func(vb *ValidatorBlock) { vb.GovernanceProof.G0Proof.ExecMBI++ }, ErrIntentProofV2Invalid},
		{"vote evidence that is not the intent's", func(vb *ValidatorBlock) { vb.IntentCertificate.VoteEvidence = json.RawMessage(`{}`) }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vb := built(t)
			tc.edit(vb)
			_, err := VerifyIntentCertificate(vb, intentChain, reg, spine, g1LiveActivation)
			switch {
			case err == nil:
				t.Fatal("the edited block was accepted")
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// a certificate with no proof v2 evidence on a chain that requires v3
	vb := g1LiveBlock(t, f, "validator-1")
	if err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, f.record(t), f.VoteEvidence, f.ChainedProof,
		spine, nil, nil); err == nil {
		t.Fatal("a certificate with no proof v2 was built on a chain that requires v3")
	}
}
