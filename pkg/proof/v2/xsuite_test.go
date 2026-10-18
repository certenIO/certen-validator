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

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The shared evidence 2.1 vectors (testdata/xpartition2, written by `go run ./cmd/proofv2conformance -xpartition2 ...`) are what
// the TypeScript verifier will consume byte for byte. This is the Go side of the same contract: the manifest's hash, every
// file's hash, and every document's verdict - the report a verified case must produce, the named state (with its partition and
// block) a refusal must carry - as another language's verifier reads the file.
func TestXPartition2SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/xpartition2/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/xpartition2/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mj)
	if !strings.HasPrefix(string(hf), hex.EncodeToString(sum[:])+"  manifest.json") {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %x of manifest.json", hf, sum)
	}
	var m struct {
		Format         string `json:"format"`
		Domain         string `json:"domain"`
		PortableFormat string `json:"portableFormat"`
		Cases          []struct {
			Name      string `json:"name"`
			File      string `json:"file"`
			SHA256    string `json:"sha256"`
			Expect    string `json:"expect"`
			State     string `json:"state"`
			Partition string `json:"partition"`
			Block     uint64 `json:"block"`
			Report    *struct {
				Version       string `json:"version"`
				Tag           string `json:"tag"`
				Partition     string `json:"partition"`
				AnchorBlock   uint64 `json:"anchorBlock"`
				CertifiedRoot string `json:"certifiedRoot"`
				CheckBlock    uint64 `json:"checkBlock"`
				SetVerdict    string `json:"setVerdict"`
				RoutingHeight uint64 `json:"routingHeight"`
				PagesBound    int    `json:"pagesBound"`
				Unproven      []string
				Proven        []struct {
					URL       string   `json:"url"`
					Partition string   `json:"partition"`
					Block     uint64   `json:"block"`
					Roles     []string `json:"roles"`
					Declared  []string `json:"declared"`
				} `json:"proven"`
			} `json:"report"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-xpartition2-conformance/1" || m.Domain != proofv2.DomainG1V4 || m.PortableFormat != proofv2.PortableFormat || len(m.Cases) < 20 {
		t.Fatalf("manifest %q %q %q with %d cases", m.Format, m.Domain, m.PortableFormat, len(m.Cases))
	}
	verified, refused := 0, 0
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc, err := os.ReadFile("testdata/xpartition2/" + c.File)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(doc) // the file's exact bytes
			if hex.EncodeToString(h[:]) != c.SHA256 {
				t.Fatalf("%s does not hash to the manifest's %s", c.File, c.SHA256)
			}
			p := new(proofv2.Portable)
			if err := json.Unmarshal(doc, p); err != nil {
				t.Fatal(err)
			}
			rep, err := proofv2.VerifyPortable(p)
			switch c.Expect {
			case "refused":
				refused++
				if err == nil {
					t.Fatal("a refused case was accepted")
				}
				var ns *proofv2.NamedState
				switch {
				case c.State == "" && errors.As(err, &ns):
					t.Fatalf("refused with the named state %v, the manifest names none", ns)
				case c.State != "" && (!errors.As(err, &ns) || ns.Code != c.State || ns.Partition != c.Partition || ns.Block != c.Block):
					t.Fatalf("refused with %v, the manifest says %s{%s,%d}", err, c.State, c.Partition, c.Block)
				}
			case "verified":
				verified++
				if err != nil {
					t.Fatal(err)
				}
				r := c.Report
				if rep.Version != r.Version || rep.Tag != r.Tag || rep.Partition != r.Partition || rep.AnchorBlock != r.AnchorBlock || rep.CheckBlock != r.CheckBlock ||
					hex.EncodeToString(rep.CertifiedRoot[:]) != r.CertifiedRoot || string(rep.SetVerdict) != r.SetVerdict || rep.RoutingHeight != r.RoutingHeight {
					t.Fatalf("report header differs from the manifest's: %+v", rep)
				}
				if len(rep.Proven) != len(r.Proven) {
					t.Fatalf("%d proven pages, the manifest says %d", len(rep.Proven), len(r.Proven))
				}
				bound := 0
				for i, g := range rep.Proven {
					w := r.Proven[i]
					var roles, decl []string
					for _, x := range g.Roles {
						roles = append(roles, string(x))
					}
					for _, x := range g.Declared {
						decl = append(decl, string(x))
					}
					if g.URL != w.URL || g.Partition != w.Partition || g.Block != w.Block || strings.Join(roles, ",") != strings.Join(w.Roles, ",") || strings.Join(decl, ",") != strings.Join(w.Declared, ",") {
						t.Fatalf("proven page %d is %+v, the manifest says %+v", i, g, w)
					}
					if rep.PageChains[i].Bound {
						bound++
					}
				}
				var un []string
				for _, u := range rep.Unproven {
					un = append(un, u.Code)
				}
				if bound != r.PagesBound || strings.Join(un, ",") != strings.Join(r.Unproven, ",") {
					t.Fatalf("bound %d (manifest %d), unproven %v (manifest %v)", bound, r.PagesBound, un, r.Unproven)
				}
			default:
				t.Fatalf("expect %q", c.Expect)
			}
		})
	}
	if verified < 4 || refused < 15 {
		t.Fatalf("%d verified and %d refused cases", verified, refused)
	}
}
