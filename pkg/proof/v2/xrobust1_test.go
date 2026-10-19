// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	jm "github.com/certen/independant-validator/internal/jsonmutate"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The robustness vectors (RB9-L) (testdata/robust1, written by `go run ./cmd/proofv2conformance -robust1 ...`) are what the TypeScript verifier
// consumes byte for byte: the manifest's hash, every file's hash, and the verdict of every document - a refusal, the named state with its
// partition and block when it is one, the refusal's exact text, and the part of it another verifier must reproduce. A document is judged ten
// times: the refusal is a function of the document, whatever order a map happens to be walked in, and a document that crashes the verifier
// is a failure of this test, not of the process.
func TestRobust1SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/robust1/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/robust1/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mj)
	if string(hf) != hex.EncodeToString(sum[:])+"  manifest.json\n" {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %x of manifest.json", hf, sum)
	}
	attrs, err := os.ReadFile("testdata/robust1/.gitattributes")
	if err != nil || !strings.Contains(string(attrs), "* -text") {
		t.Fatalf("the suite's .gitattributes must keep the bytes as they are (* -text): %q (%v)", attrs, err)
	}
	var m struct {
		Format string `json:"format"`
		Domain string `json:"domain"`
		Cases  []struct {
			Name      string `json:"name"`
			Base      string `json:"base"`
			File      string `json:"file"`
			SHA256    string `json:"sha256"`
			Expect    string `json:"expect"`
			State     string `json:"state"`
			Partition string `json:"partition"`
			Block     uint64 `json:"block"`
			Wording   string `json:"wording"`
			Prefix    string `json:"prefix"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-robust1-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) < 18 {
		t.Fatalf("manifest %q %q with %d cases", m.Format, m.Domain, len(m.Cases))
	}
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc, err := os.ReadFile("testdata/robust1/" + c.File)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(doc)
			if hex.EncodeToString(h[:]) != c.SHA256 {
				t.Fatalf("%s does not hash to the manifest's %s", c.File, c.SHA256)
			}
			if c.Expect != "refused" {
				t.Fatalf("expect %q", c.Expect)
			}
			for run := 0; run < 10; run++ {
				var verr error
				if v := jm.Guard(func() jm.Verdict {
					p := new(proofv2.Portable)
					if err := json.Unmarshal(doc, p); err != nil {
						t.Fatal(err)
					}
					_, verr = proofv2.VerifyPortable(p)
					return jm.Verdict{}
				}); v.Panicked != "" {
					t.Fatalf("run %d: the verifier panicked: %s", run, v.Panicked)
				}
				if verr == nil {
					t.Fatalf("run %d verified a document the manifest says is refused", run)
				}
				var ns *proofv2.NamedState
				named := errors.As(verr, &ns)
				if c.State == "" && named {
					t.Fatalf("run %d refused with the named state %v, the manifest names none", run, ns)
				}
				if c.State != "" && (!named || ns.Code != c.State || ns.Partition != c.Partition || ns.Block != c.Block) {
					t.Fatalf("run %d refused with %v, the manifest says %s{%s,%d}", run, verr, c.State, c.Partition, c.Block)
				}
				if verr.Error() != c.Wording {
					t.Fatalf("run %d refused with %q, the manifest says %q", run, verr.Error(), c.Wording)
				}
				if c.Prefix == "" || !strings.HasPrefix(verr.Error(), c.Prefix) {
					t.Fatalf("run %d refused with %q, which does not begin with the manifest's prefix %q", run, verr.Error(), c.Prefix)
				}
			}
		})
	}
}
