// Copyright 2026 Certen Protocol

// An external test package, so the suite can compute govRoot v3 through pkg/intentcert, which imports this package.
package proofv2_test

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/certen/independant-validator/pkg/intentcert"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The govRoot v3 pkg/intentcert's golden test pins for the same proof and inputs (goldenGovRootV3 there): the
// manifest must carry exactly it, so the cross-language fixture and the Go golden vector cannot drift apart.
const goldenGovRootV3 = "0477ea2c8f1d2ad8d3a84a5dc3f87f241e57efc97688016f88cb4001521dcee2"

func gunzipConformance(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifyPortableJSON reads a case as another language's verifier does and verifies it, returning the evidence read
// back with the report, for govRoot v3.
func verifyPortableJSON(j []byte) (*proofv2.Portable, *proofv2.Evidence, *proofv2.Report, error) {
	p := new(proofv2.Portable)
	if err := json.Unmarshal(j, p); err != nil {
		return nil, nil, nil, err
	}
	ev, ar, in, pin, err := proofv2.Import(p)
	if err != nil {
		return nil, nil, nil, err
	}
	rep, err := proofv2.VerifyFromGenesis(ev, ar, in, pin)
	return p, ev, rep, err
}

// The cross-language conformance suite (cmd/proofv2conformance). The TypeScript verifier in certen-sdk runs the same
// files and must reach the same verdict on every case, and the same report on the valid one, govRoot v3 included.
func TestConformanceSuite(t *testing.T) {
	var m struct {
		Format string `json:"format"`
		Base   string `json:"base"`
		Cases  []struct {
			Name   string         `json:"name"`
			Expect string         `json:"expect"`
			Patch  []proofv2.Op   `json:"patch"`
			Report map[string]any `json:"report"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile("testdata/conformance/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != proofv2.PortableFormat || len(m.Cases) < 2 {
		t.Fatalf("manifest format %q with %d cases", m.Format, len(m.Cases))
	}
	base := gunzipConformance(t, "testdata/conformance/"+m.Base)
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(base, &doc); err != nil {
				t.Fatal(err)
			}
			if err := proofv2.ApplyPatch(doc, c.Patch); err != nil {
				t.Fatal(err)
			}
			j, _ := json.Marshal(doc)
			p, ev, rep, err := verifyPortableJSON(j)
			switch c.Expect {
			case "verified":
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				// govRoot v3 through the same exported path production uses, from the verified report and the
				// proof's govRootV3Inputs.
				root, _, err := intentcert.GovRootV3FromPortable(rep, ev, p.GovRootV3Inputs)
				if err != nil {
					t.Fatalf("govRoot v3: %v", err)
				}
				got := map[string]any{
					"incarnation": fmt.Sprintf("%x", rep.Incarnation), "majors": float64(rep.Majors),
					"certifiedBlock": float64(rep.CertifiedBlock), "certifiedRoot": fmt.Sprintf("%x", rep.CertifiedRoot),
					"checkBlock": float64(rep.CheckBlock), "setVerdict": string(rep.SetVerdict),
					"validators": float64(rep.Validators), "threshold": float64(rep.Threshold),
					"partition": rep.Partition, "anchorBlock": float64(rep.AnchorBlock), "pages": float64(len(rep.Pages)),
					"govRootV3": fmt.Sprintf("%x", root),
				}
				if len(got) != len(c.Report) {
					t.Fatalf("the manifest reports %d fields, the verifier %d", len(c.Report), len(got))
				}
				for k, v := range got {
					if c.Report[k] != v {
						t.Fatalf("%s: got %v, manifest %v", k, v, c.Report[k])
					}
				}
				if c.Report["govRootV3"] != goldenGovRootV3 {
					t.Fatalf("the manifest's govRoot v3 %v is not the golden %s", c.Report["govRootV3"], goldenGovRootV3)
				}
				// One changed govRoot v3 input leaves the proof verified and changes the root.
				alt := *p.GovRootV3Inputs
				alt.OperationID = fmt.Sprintf("%064x", 8)
				other, _, err := intentcert.GovRootV3FromPortable(rep, ev, &alt)
				if err != nil || other == root {
					t.Fatalf("a changed operation id gave %x (%v), the same root", other, err)
				}
			case "refused":
				if err == nil {
					t.Fatal("verified a tampered proof")
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}
}
