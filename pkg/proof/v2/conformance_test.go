// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// The cross-language conformance suite (cmd/proofv2conformance). The TypeScript verifier in certen-sdk runs the same
// files and must reach the same verdict on every case, and the same report on the valid one.
func TestConformanceSuite(t *testing.T) {
	var m struct {
		Format string `json:"format"`
		Base   string `json:"base"`
		Cases  []struct {
			Name   string         `json:"name"`
			Expect string         `json:"expect"`
			Patch  []Op           `json:"patch"`
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
	if m.Format != PortableFormat || len(m.Cases) < 2 {
		t.Fatalf("manifest format %q with %d cases", m.Format, len(m.Cases))
	}
	base := gunzip(t, "testdata/conformance/"+m.Base)
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(base, &doc); err != nil {
				t.Fatal(err)
			}
			if err := ApplyPatch(doc, c.Patch); err != nil {
				t.Fatal(err)
			}
			j, _ := json.Marshal(doc)
			p := new(Portable)
			var rep *Report
			if err = json.Unmarshal(j, p); err == nil {
				rep, err = VerifyPortable(p)
			}
			switch c.Expect {
			case "verified":
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				got := map[string]any{
					"incarnation": fmt.Sprintf("%x", rep.Incarnation), "majors": float64(rep.Majors),
					"certifiedBlock": float64(rep.CertifiedBlock), "certifiedRoot": fmt.Sprintf("%x", rep.CertifiedRoot),
					"checkBlock": float64(rep.CheckBlock), "setVerdict": string(rep.SetVerdict),
					"validators": float64(rep.Validators), "threshold": float64(rep.Threshold),
					"partition": rep.Partition, "anchorBlock": float64(rep.AnchorBlock), "pages": float64(len(rep.Pages)),
				}
				if len(got) != len(c.Report) {
					t.Fatalf("the manifest reports %d fields, the verifier %d", len(c.Report), len(got))
				}
				for k, v := range got {
					if c.Report[k] != v {
						t.Fatalf("%s: got %v, manifest %v", k, v, c.Report[k])
					}
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
