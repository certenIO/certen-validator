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

// The roles, executor-version and budget vectors (RB9 Phase C1b-2) (testdata/xpartition4, written by `go run ./cmd/proofv2conformance -xpartition4 ...`) are what
// the TypeScript verifier consumes byte for byte: the manifest's hash, every file's hash, every document's verdict - the report a
// verified case must produce (the derived arrival blocks and the authorization mode included), the named state with its partition
// and block a refusal must carry.
func TestXPartition4SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/xpartition4/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/xpartition4/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mj)
	if !strings.HasPrefix(string(hf), hex.EncodeToString(sum[:])+"  manifest.json") {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %x of manifest.json", hf, sum)
	}
	var m struct {
		Format string `json:"format"`
		Domain string `json:"domain"`
		Cases  []struct {
			Name      string `json:"name"`
			File      string `json:"file"`
			SHA256    string `json:"sha256"`
			Expect    string `json:"expect"`
			State     string `json:"state"`
			Partition string `json:"partition"`
			Block     uint64 `json:"block"`
			Report    *struct {
				Version           string   `json:"version"`
				Tag               string   `json:"tag"`
				Unproven          []string `json:"unproven"`
				AuthorizationMode string   `json:"authorizationMode"`
				Disclosures       []string `json:"disclosures"`
				Proven            []struct {
					URL       string   `json:"url"`
					Partition string   `json:"partition"`
					Block     uint64   `json:"block"`
					Roles     []string `json:"roles"`
					Declared  []string `json:"declared"`
				} `json:"proven"`
				Arrivals []struct {
					Kind    string `json:"kind"`
					Account string `json:"account"`
					Block   uint64 `json:"block"`
				} `json:"arrivals"`
			} `json:"report"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-xpartition4-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) < 18 {
		t.Fatalf("manifest %q %q with %d cases", m.Format, m.Domain, len(m.Cases))
	}
	verified, refused := 0, 0
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc, err := os.ReadFile("testdata/xpartition4/" + c.File)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(doc)
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
				var ns *proofv2.NamedState
				if err == nil || !errors.As(err, &ns) || ns.Code != c.State || ns.Partition != c.Partition || ns.Block != c.Block {
					t.Fatalf("refused with %v, the manifest says %s{%s,%d}", err, c.State, c.Partition, c.Block)
				}
			case "verified":
				verified++
				if err != nil {
					t.Fatal(err)
				}
				r := c.Report
				var un []string
				for _, u := range rep.Unproven {
					un = append(un, u.Code)
				}
				if rep.Version != r.Version || rep.Tag != r.Tag || strings.Join(un, ",") != strings.Join(r.Unproven, ",") {
					t.Fatalf("report %s %s unproven %v differs from the manifest's %+v", rep.Version, rep.Tag, un, r)
				}
				var disc []string
				for _, d := range rep.Disclosures {
					disc = append(disc, d.Code)
				}
				if strings.Join(disc, ",") != strings.Join(r.Disclosures, ",") {
					t.Fatalf("disclosures %v, the manifest says %v", disc, r.Disclosures)
				}
				if rep.AuthorizationMode != r.AuthorizationMode || len(rep.Arrivals) != len(r.Arrivals) {
					t.Fatalf("mode %q, %d arrivals; the manifest says %q, %d", rep.AuthorizationMode, len(rep.Arrivals), r.AuthorizationMode, len(r.Arrivals))
				}
				if len(rep.Proven) != len(r.Proven) {
					t.Fatalf("%d proven pages, the manifest says %d", len(rep.Proven), len(r.Proven))
				}
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
						t.Fatalf("proven page %d is %+v (roles %v, declared %v), the manifest says %+v", i, g, roles, decl, w)
					}
				}
				for i, a := range rep.Arrivals {
					w := r.Arrivals[i]
					if a.Kind != w.Kind || a.Account != w.Account || a.Block != w.Block {
						t.Fatalf("arrival %d is %+v, the manifest says %+v", i, a, w)
					}
				}
			default:
				t.Fatalf("expect %q", c.Expect)
			}
		})
	}
	if verified < 8 || refused < 10 {
		t.Fatalf("%d verified and %d refused cases", verified, refused)
	}
}
