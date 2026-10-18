package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F5 package F5-4 (V-E A4): the budget constants of pkg/proof/v2/xbudget.go, derived from the 19 LIVE intents' ANCHORED evidence (the form
// AnchorEvidence builds from Kermit's recorded link answers, testdata/g1_live_anchored) and from the rest of the transaction R measured on
// the same intents. FixedEvidenceBytes is the anchored document without its pages, votes and transaction; R is the ValidatorBlock without
// its proof_v2 member (everything CertificateReserve is for). The cap is MaxEvidenceBytes.

// genesisLinkAllowance is the genesis link (V-E A1b) in bytes: the recorded live answer (testdata/certify1-live/links.json, label genesis) is 1,864 hex
// characters, plus the member's key and quotes.
const genesisLinkAllowance = 1_880

// budgetLiveSample is what one live intent measures.
type budgetLiveSample struct {
	Name         string
	Pages        int
	Votes        int
	Records      int // signature-bearing records of the fixed part: certify runs, hops and anchors
	Anchored     int // the encoded anchored evidence
	Fixed        int // the anchored evidence without Pages, Votes and Transaction
	Pagesvotes   int // the encoded pages and votes
	VoteEvidence int // the vote_evidence member of the intent certificate
	Rest         int // the encoded ValidatorBlock without proof_v2
}

// measureLiveBudget builds, for each of the 19 live fixtures, the anchored evidence and the certificate around it.
func measureLiveBudget(t *testing.T) []budgetLiveSample {
	t.Helper()
	links := loadAnchoredLiveLinks(t)
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	activation := &ledger.G1ActivationRecord{Version: 1, Height: 100, ID: "g1-activation:rb9-f5-budget"}
	var out []budgetLiveSample
	for _, dir := range []string{"testdata/g1_live", "testdata/g1_live_fixedprover"} {
		var m struct {
			Archive string `json:"archive"`
			Cases   []struct {
				Name   string `json:"name"`
				File   string `json:"file"`
				SHA256 string `json:"sha256"`
			} `json:"cases"`
		}
		mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(mb, &m); err != nil {
			t.Fatal(err)
		}
		shared := gunzipFile(t, filepath.Join(dir, m.Archive))
		for _, c := range m.Cases {
			gz, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(gz); hex.EncodeToString(sum[:]) != c.SHA256 {
				t.Fatalf("%s does not hash to the manifest's value", c.File)
			}
			f := new(anchoredLiveFixture)
			if err := json.Unmarshal(gunzipFile(t, filepath.Join(dir, c.File)), f); err != nil {
				t.Fatal(err)
			}
			if len(f.Archive) == 0 {
				f.Archive = shared
			}
			fx := &intentFixtureV3{intentFixture: f.intentFixture, ProofV2: f.ProofV2, Archive: f.Archive}
			ar, err := proofv2.UnmarshalArchive(f.Archive)
			if err != nil {
				t.Fatal(err)
			}
			anchored, err := proofv2.AnchorEvidence(context.Background(), v3Evidence(t, fx), ar, ir.Inputs, links)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			enc := func(v any) int {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return len(b)
			}
			s := budgetLiveSample{Name: c.Name, Pages: len(anchored.Pages), Votes: len(anchored.Votes), Anchored: enc(anchored)}
			s.Pagesvotes = enc(anchored.Pages) + enc(anchored.Votes)
			bare := *anchored
			bare.Pages, bare.Votes, bare.Transaction = nil, nil, ""
			s.Fixed = enc(&bare)
			if bare.GenesisLink == "" {
				s.Fixed += genesisLinkAllowance // the document predates the genesis link (V-E A1b); the real answer is measured below
			}
			s.Records = len(anchored.Certify) + len(anchored.Check.Hops) + max(1, len(anchored.Anchors))
			s.VoteEvidence = len(f.VoteEvidence)

			rf, reg := intentRegistry(t)
			spine := v3Spine(t, fx)
			vb := v3Block(t, fx, "validator-1")
			if err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, fx.record(t), f.VoteEvidence, f.ChainedProof,
				spine, activation, anchored); err != nil {
				t.Fatalf("%s: building the certificate: %v", c.Name, err)
			}
			vb.IntentCertificate.ProofV2 = nil
			s.Rest = enc(vb)
			out = append(out, s)
		}
	}
	if len(out) != 19 {
		t.Fatalf("%d live fixtures, want 19", len(out))
	}
	return out
}

func TestBudgetLiveAnchoredMeasured(t *testing.T) {
	samples := measureLiveBudget(t)
	var maxFixed, maxAnch, maxRest, maxVE, maxPV, maxRecords, maxRestFlat int
	maxVEPerPage := 0
	for _, s := range samples {
		t.Logf("%-18s pages=%d votes=%d records=%d anchored=%d fixed=%d pages+votes=%d vote_evidence=%d R=%d", s.Name, s.Pages, s.Votes, s.Records, s.Anchored, s.Fixed, s.Pagesvotes, s.VoteEvidence, s.Rest)
		maxFixed, maxAnch, maxRest, maxVE, maxPV = max(maxFixed, s.Fixed), max(maxAnch, s.Anchored), max(maxRest, s.Rest), max(maxVE, s.VoteEvidence), max(maxPV, s.Pagesvotes)
		maxRecords, maxRestFlat = max(maxRecords, s.Records), max(maxRestFlat, s.Rest-s.VoteEvidence)
		maxVEPerPage = max(maxVEPerPage, (s.VoteEvidence+s.Pages-1)/s.Pages)
		// The whole certificate is inside the path limit, and the model of R (flat part + vote evidence per closure page) covers the measured R.
		if s.Anchored+s.Rest > proofv2.ConsensusTxLimit {
			t.Errorf("%s: anchored evidence %d + R %d is over the transaction limit %d", s.Name, s.Anchored, s.Rest, proofv2.ConsensusTxLimit)
		}
		if model := proofv2.CertificateEstimate(0, s.Pages); s.Rest > model {
			t.Errorf("%s: R is %d bytes, over the model's %d for %d pages", s.Name, s.Rest, model, s.Pages)
		}
		if err := proofv2.CheckCertificateFits(s.Anchored, s.Pages, s.Name); err != nil {
			t.Errorf("%s: the real certificate is refused before signing: %v", s.Name, err)
		}
		if s.Anchored > proofv2.MaxEvidenceBytes {
			t.Errorf("%s: anchored evidence %d is over MaxEvidenceBytes %d", s.Name, s.Anchored, proofv2.MaxEvidenceBytes)
		}
		if s.Fixed > proofv2.FixedEvidenceBytes {
			t.Errorf("%s: the anchored form's fixed part is %d bytes, over FixedEvidenceBytes (%d)", s.Name, s.Fixed, proofv2.FixedEvidenceBytes)
		}
	}
	t.Logf("MEASURED over 19 live intents (anchored form): max fixed=%d (records %d) max anchored=%d max pages+votes=%d max vote_evidence=%d max R=%d max R without vote evidence=%d max vote evidence per page=%d "+
		"(CertificateReserve %d, MaxEvidenceBytes %d, FixedEvidenceBytes %d, RestFlatBytes %d, VoteEvidenceBytesPerPage %d)",
		maxFixed, maxRecords, maxAnch, maxPV, maxVE, maxRest, maxRestFlat, maxVEPerPage,
		proofv2.CertificateReserve, proofv2.MaxEvidenceBytes, proofv2.FixedEvidenceBytes, proofv2.RestFlatBytes, proofv2.VoteEvidenceBytesPerPage)
	if proofv2.VoteEvidenceBytesPerPage < maxVEPerPage || proofv2.RestFlatBytes < maxRestFlat {
		t.Fatalf("the R model (flat %d, per page %d) is under the measurement (flat %d, per page %d)", proofv2.RestFlatBytes, proofv2.VoteEvidenceBytesPerPage, maxRestFlat, maxVEPerPage)
	}
	// FixedEvidenceBytes is derived, not guessed: the largest measured fixed part plus the signature entries of every record it holds at
	// BudgetedValidators instead of the measured validator set, rounded up to 5,000, and no more.
	derived := maxFixed + maxRecords*proofv2.ValidatorSignatureBytes*(proofv2.BudgetedValidators-proofv2.MeasuredValidators)
	derived = (derived + 4999) / 5000 * 5000
	if proofv2.FixedEvidenceBytes != derived {
		t.Fatalf("FixedEvidenceBytes is %d, the derivation from the anchored fixtures gives exactly %d (max fixed %d incl. the genesis link + %d records x %d x (%d-%d) validators, rounded up to 5,000)",
			proofv2.FixedEvidenceBytes, derived, maxFixed, maxRecords, proofv2.ValidatorSignatureBytes, proofv2.BudgetedValidators, proofv2.MeasuredValidators)
	}
}

// The certificate is judged whole before it is signed: where R is known (the block as it will be broadcast, with the roots and signature filled after the check counted at their final length: json.Marshal of the
// ValidatorBlock), a block carrying evidence 2.1 that is over the transaction path limit is refused by certificate_budget{size,limit}, with
// nothing signed and no certificate left on the block.
func TestBudgetBuildIntentCertificateRefusesAnOversizeBlockBeforeSigning(t *testing.T) {
	links := loadAnchoredLiveLinks(t)
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	dir := "testdata/g1_live"
	var m struct {
		Archive string `json:"archive"`
		Cases   []struct {
			Name string `json:"name"`
			File string `json:"file"`
		} `json:"cases"`
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	f := new(anchoredLiveFixture)
	if err := json.Unmarshal(gunzipFile(t, filepath.Join(dir, m.Cases[0].File)), f); err != nil {
		t.Fatal(err)
	}
	f.Archive = gunzipFile(t, filepath.Join(dir, m.Archive))
	fx := &intentFixtureV3{intentFixture: f.intentFixture, ProofV2: f.ProofV2, Archive: f.Archive}
	ar, err := proofv2.UnmarshalArchive(f.Archive)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := proofv2.AnchorEvidence(context.Background(), v3Evidence(t, fx), ar, ir.Inputs, links)
	if err != nil {
		t.Fatal(err)
	}
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, fx)
	activation := &ledger.G1ActivationRecord{Version: 1, Height: 100, ID: "g1-activation:rb9-f5-budget"}

	vb := v3Block(t, fx, strings.Repeat("v", proofv2.ConsensusTxLimit))
	err = BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, fx.record(t), f.VoteEvidence, f.ChainedProof, spine, activation, anchored)
	var cs *proofv2.CertifyState
	if !errors.As(err, &cs) || cs.Code != proofv2.StateCertificateBudget || len(cs.Fields) != 2 {
		t.Fatalf("a block over the path limit: %v, want certificate_budget{size,limit}", err)
	}
	if cs.Fields[1] != strconv.Itoa(proofv2.ConsensusTxLimit) {
		t.Fatalf("the limit field is %s, want %d", cs.Fields[1], proofv2.ConsensusTxLimit)
	}
	if size, _ := strconv.Atoi(cs.Fields[0]); size <= proofv2.ConsensusTxLimit {
		t.Fatalf("the size field %s is not over the limit", cs.Fields[0])
	}
	if vb.IntentCertificate != nil {
		t.Fatal("a refused block keeps its intent certificate")
	}
}
