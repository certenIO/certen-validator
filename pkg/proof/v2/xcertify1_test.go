// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	jm "github.com/certen/independant-validator/internal/jsonmutate"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// names is testdata/certify1/names.json.
type certifyNames struct {
	Format string `json:"format"`
	Names  []struct {
		Name   string   `json:"name"`
		Fields []string `json:"fields"`
		Side   string   `json:"side"`
		Detail string   `json:"detail"`
	} `json:"names"`
}

func loadCertifyNames(t *testing.T) (certifyNames, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/certify1/names.json")
	if err != nil {
		t.Fatal(err)
	}
	var n certifyNames
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	return n, raw
}

// The anchored-certify vectors (RB9-F5; testdata/certify1, written by `go run ./cmd/proofv2conformance -certify1 ...`) are what the
// TypeScript verifier consumes byte for byte: the manifest's hash, names.json's hash, every file's hash, and the verdict of every document -
// verified with its report, or refused with the exact text, and for a certify state its name and fields (the text is name{fields}: detail
// of names.json). A document is judged ten times: the verdict is a function of the document, and a document that crashes the verifier is a
// failure of this test, not of the process.
func TestCertify1SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/certify1/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/certify1/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mj)
	if string(hf) != hex.EncodeToString(sum[:])+"  manifest.json\n" {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %x of manifest.json", hf, sum)
	}
	attrs, err := os.ReadFile("testdata/certify1/.gitattributes")
	if err != nil || !strings.Contains(string(attrs), "* -text") {
		t.Fatalf("the suite's .gitattributes must keep the bytes as they are (* -text): %q (%v)", attrs, err)
	}
	names, nraw := loadCertifyNames(t)
	nsum := sha256.Sum256(nraw)
	var m struct {
		Format      string `json:"format"`
		Domain      string `json:"domain"`
		NamesSHA256 string `json:"namesSha256"`
		Cases       []struct {
			Name         string          `json:"name"`
			File         string          `json:"file"`
			SHA256       string          `json:"sha256"`
			Expect       string          `json:"expect"`
			State        string          `json:"state"`
			Fields       []string        `json:"fields"`
			Wording      string          `json:"wording"`
			Prefix       string          `json:"prefix"`
			SameReportAs string          `json:"sameReportAs"`
			Report       json.RawMessage `json:"report"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-certify1-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) < 25 {
		t.Fatalf("manifest %q %q with %d cases", m.Format, m.Domain, len(m.Cases))
	}
	if m.NamesSHA256 != hex.EncodeToString(nsum[:]) {
		t.Fatalf("names.json hashes to %x, the manifest pins %s", nsum, m.NamesSHA256)
	}
	details := map[string]string{}
	for _, e := range names.Names {
		details[e.Name] = e.Detail
	}
	reports := map[string]string{}
	for _, c := range m.Cases {
		reports[c.Name] = string(c.Report)
	}
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc, err := os.ReadFile("testdata/certify1/" + c.File)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(doc)
			if hex.EncodeToString(h[:]) != c.SHA256 {
				t.Fatalf("%s does not hash to the manifest's %s", c.File, c.SHA256)
			}
			if c.SameReportAs != "" && string(c.Report) != reports[c.SameReportAs] {
				t.Fatalf("the manifest's report of %s is not the report of %s", c.Name, c.SameReportAs)
			}
			if c.State != "" {
				if want := c.State + "{" + strings.Join(c.Fields, ",") + "}: " + details[c.State]; c.Wording != want || details[c.State] == "" {
					t.Fatalf("the manifest's wording %q is not %q (names.json)", c.Wording, want)
				}
			}
			for run := 0; run < 10; run++ {
				var rep *proofv2.Report
				var verr error
				if v := jm.Guard(func() jm.Verdict {
					p := new(proofv2.Portable)
					if err := json.Unmarshal(doc, p); err != nil {
						t.Fatal(err)
					}
					rep, verr = proofv2.VerifyPortable(p)
					return jm.Verdict{}
				}); v.Panicked != "" {
					t.Fatalf("run %d: the verifier panicked: %s", run, v.Panicked)
				}
				switch c.Expect {
				case "verified":
					if verr != nil {
						t.Fatalf("run %d refused a document the manifest says is verified: %v", run, verr)
					}
					var want struct {
						Version       string `json:"version"`
						Tag           string `json:"tag"`
						Partition     string `json:"partition"`
						AnchorBlock   uint64 `json:"anchorBlock"`
						CertifiedRoot string `json:"certifiedRoot"`
						CheckBlock    uint64 `json:"checkBlock"`
						SetVerdict    string `json:"setVerdict"`
					}
					if err := json.Unmarshal(c.Report, &want); err != nil {
						t.Fatal(err)
					}
					if rep.Version != want.Version || rep.Tag != want.Tag || rep.Partition != want.Partition || rep.AnchorBlock != want.AnchorBlock ||
						hex.EncodeToString(rep.CertifiedRoot[:]) != want.CertifiedRoot || rep.CheckBlock != want.CheckBlock || string(rep.SetVerdict) != want.SetVerdict {
						t.Fatalf("run %d: the report is %+v, the manifest says %+v", run, rep, want)
					}
				case "refused":
					if verr == nil {
						t.Fatalf("run %d verified a document the manifest says is refused", run)
					}
					if c.Prefix != c.Wording { // the part another verifier reproduces when the rest is a hash
						if !strings.HasPrefix(verr.Error(), c.Prefix) {
							t.Fatalf("run %d refused with %q, which does not begin with the manifest's prefix %q", run, verr.Error(), c.Prefix)
						}
					} else if verr.Error() != c.Wording {
						t.Fatalf("run %d refused with %q, the manifest says %q", run, verr.Error(), c.Wording)
					}
				default:
					t.Fatalf("expect %q", c.Expect)
				}
			}
		})
	}
}
