package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// RB9-F5 package F5-2: the anchored certify form on the 19 LIVE intents of RB9-E (testdata/g1_live, testdata/g1_live_fixedprover; the data is
// byte-identical to pv2/rb9-e-live's). For each, the continuous document and the document AnchorEvidence builds from Kermit's recorded link
// answers (testdata/g1_live_anchored/links.json, recorded by cmd/proofv2linkprobe -g1, pinned by MANIFEST.sha256) are judged through the
// production functions: the evidence 2.1 verifier against the chain's spine gives the SAME report, and BuildIntentCertificate /
// VerifyIntentCertificate give the SAME govRoot (v4); the anchored document is smaller; and a dropped link is refused by name.

type anchoredLiveLink struct {
	Prev        string `json:"prev"`
	Height      uint64 `json:"height"`
	Receipt     string `json:"receipt"`
	NotAnchored string `json:"notAnchored"`
}

type anchoredLiveLinks struct{ Links []anchoredLiveLink }

func (s *anchoredLiveLinks) Link(_ context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	p := hex.EncodeToString(prev[:])
	for _, l := range s.Links {
		if l.Prev == p && l.Height == height {
			if l.Receipt == "" {
				return nil, fmt.Errorf("%w: %s", proofv2.ErrLinkNotAnchored, l.NotAnchored)
			}
			raw, err := hex.DecodeString(l.Receipt)
			if err != nil {
				return nil, err
			}
			r := new(merkle.Receipt)
			return r, r.UnmarshalBinary(raw)
		}
	}
	return nil, fmt.Errorf("no recorded answer for prev %s height %d", p, height)
}

func loadAnchoredLiveLinks(t *testing.T) *anchoredLiveLinks {
	t.Helper()
	raw, err := os.ReadFile("testdata/g1_live_anchored/links.json")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile("testdata/g1_live_anchored/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); !strings.HasPrefix(strings.TrimSpace(string(pin)), got) {
		t.Fatalf("links.json hashes to %s, the manifest pins %s", got, strings.TrimSpace(string(pin)))
	}
	l := new(anchoredLiveLinks)
	if err := json.Unmarshal(raw, l); err != nil {
		t.Fatal(err)
	}
	return l
}

type anchoredLiveFixture struct {
	intentFixture
	Name    string          `json:"name"`
	KeyBook string          `json:"key_book"`
	KeyPage string          `json:"key_page"`
	ProofV2 json.RawMessage `json:"proof_v2"`
	Archive json.RawMessage `json:"archive"`
}

func TestG1LiveAnchored(t *testing.T) {
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
	activation := &ledger.G1ActivationRecord{Version: 1, Height: 100, ID: "g1-activation:rb9-f5-anchored"}
	reportJSON := func(r *proofv2.Report) string {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	cases := 0
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
			cases++
			t.Run(filepath.Base(dir)+"/"+c.Name, func(t *testing.T) {
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
				cont := v3Evidence(t, fx)

				// V-E A9, on this fixture: the height a link is asked at is the anchor's RootChainIndex, which is the end of the root proof.
				for i, h := range append(append([]string{}, cont.Certify...), cont.Check.Hops...) {
					end, err := proofv2.RunRootProofEnd(h)
					if err != nil {
						t.Fatal(err)
					}
					idx, _, err := proofv2.RunAnchor(h)
					if err != nil {
						t.Fatal(err)
					}
					if end != idx {
						t.Fatalf("run %d: the root proof ends at height %d, the RootChainIndex is %d", i, end, idx)
					}
				}

				anchored, err := proofv2.AnchorEvidence(context.Background(), cont, ar, ir.Inputs, links)
				if err != nil {
					t.Fatal(err)
				}
				if len(anchored.Links) == 0 {
					t.Fatal("the anchored document carries no link")
				}
				cb, _ := json.Marshal(cont)
				ab, _ := json.Marshal(anchored)
				if len(ab) >= len(cb) {
					t.Fatalf("the anchored document (%d bytes) is not smaller than the continuous one (%d)", len(ab), len(cb))
				}

				rf, reg := intentRegistry(t)
				spine := v3Spine(t, fx)
				contRep, err := proofv2.VerifyEvidence21FromSpine(cont, spine, ir.Incarnation)
				if err != nil {
					t.Fatalf("continuous: %v", err)
				}
				anchRep, err := proofv2.VerifyEvidence21FromSpine(anchored, spine, ir.Incarnation)
				if err != nil {
					t.Fatalf("anchored: %v", err)
				}
				if reportJSON(contRep) != reportJSON(anchRep) {
					t.Fatalf("the reports differ:\n continuous %s\n anchored   %s", reportJSON(contRep), reportJSON(anchRep))
				}

				root := func(ev *proofv2.Evidence) string {
					vb := v3Block(t, fx, "validator-1")
					if err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, fx.record(t), f.VoteEvidence, f.ChainedProof,
						spine, activation, ev); err != nil {
						t.Fatalf("building the certificate: %v", err)
					}
					b, err := json.Marshal(vb)
					if err != nil {
						t.Fatal(err)
					}
					var back ValidatorBlock
					if err := json.Unmarshal(b, &back); err != nil {
						t.Fatal(err)
					}
					if _, err := VerifyIntentCertificate(&back, intentChain, reg, spine, activation); err != nil {
						t.Fatalf("verifying the certificate after a JSON round trip: %v", err)
					}
					return vb.IntentCertificate.GovRootV3
				}
				cr, ar2 := root(cont), root(anchored)
				if cr == "" || cr != ar2 {
					t.Fatalf("govRoot (v4): continuous %q, anchored %q", cr, ar2)
				}

				// A link dropped from the anchored document is refused by name, through the same production path.
				broken := *anchored
				broken.Links = broken.Links[:len(broken.Links)-1]
				_, err = proofv2.VerifyEvidence21FromSpine(&broken, spine, ir.Incarnation)
				var cs *proofv2.CertifyState
				if err == nil || !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyLinkMissing {
					t.Fatalf("a document with a link dropped: %v, want certify_link_missing", err)
				}
				t.Logf("%s: continuous %d bytes, anchored %d bytes, %d links, govRoot v4 %s", c.Name, len(cb), len(ab), len(anchored.Links), cr)
			})
		}
	}
	if cases != 19 {
		t.Fatalf("%d live fixtures, want 19", cases)
	}
}
