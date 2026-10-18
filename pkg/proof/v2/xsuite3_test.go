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
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// The three-way partition vectors (testdata/xpartition3, written by `go run ./cmd/proofv2conformance -xpartition3 ...`): D2a (block
// validator to block validator), D2b (a governing book on the Directory) and D2c (the principal on the Directory), each with the
// anchor kind checked per partition kind. This is the Go side of the contract the TypeScript verifier consumes byte for byte.
func TestXPartition3SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/xpartition3/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/xpartition3/MANIFEST.sha256")
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
				Version     string   `json:"version"`
				Tag         string   `json:"tag"`
				Partition   string   `json:"partition"`
				AnchorBlock uint64   `json:"anchorBlock"`
				Unproven    []string `json:"unproven"`
				Proven      []struct {
					URL       string `json:"url"`
					Partition string `json:"partition"`
					Block     uint64 `json:"block"`
				} `json:"proven"`
			} `json:"report"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "certen-xpartition3-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) < 12 {
		t.Fatalf("manifest %q %q with %d cases", m.Format, m.Domain, len(m.Cases))
	}
	verified, refused := 0, 0
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc, err := os.ReadFile("testdata/xpartition3/" + c.File)
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
				if rep.Version != r.Version || rep.Tag != r.Tag || rep.Partition != r.Partition || rep.AnchorBlock != r.AnchorBlock || strings.Join(un, ",") != strings.Join(r.Unproven, ",") {
					t.Fatalf("report %s %s %s %d unproven %v differs from the manifest's %+v", rep.Version, rep.Tag, rep.Partition, rep.AnchorBlock, un, r)
				}
				if len(rep.Proven) != len(r.Proven) {
					t.Fatalf("%d proven pages, the manifest says %d", len(rep.Proven), len(r.Proven))
				}
				for i, g := range rep.Proven {
					w := r.Proven[i]
					if g.URL != w.URL || g.Partition != w.Partition || g.Block != w.Block {
						t.Fatalf("proven page %d is %+v, the manifest says %+v", i, g, w)
					}
				}
			default:
				t.Fatalf("expect %q", c.Expect)
			}
		})
	}
	if verified < 3 || refused < 9 {
		t.Fatalf("%d verified and %d refused cases", verified, refused)
	}
}

// Every case of the suite reaches its verdict as built (not as read back from a committed file), and the three valid documents
// prove pages on the partitions their layout puts them on.
func TestXPartition3CasesReachTheirVerdicts(t *testing.T) {
	want := map[string]map[string]string{ // case -> page -> partition
		"d2a-bvn-to-bvn-valid":          {xworld.Principal: xworld.PartBVN1, xworld.BankPage1: xworld.PartBVN2, xworld.DelePage1: xworld.PartBVN3},
		"d2b-directory-authority-valid": {xworld.Principal: xworld.PartBVN1, xworld.DNBook: xworld.DirPartition, xworld.DNPage1: xworld.DirPartition, xworld.DelePage1: xworld.PartBVN3},
		"d2c-directory-principal-valid": {xworld.DNPrincipal: xworld.DirPartition, xworld.BankPage1: xworld.PartBVN2, xworld.DelePage1: xworld.PartBVN3},
	}
	for _, c := range xworld.Cases3() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			_, p, err := c.Document()
			if err != nil {
				t.Fatal(err)
			}
			rep, err := proofv2.VerifyPortable(p)
			if c.Expect == "refused" {
				var ns *proofv2.NamedState
				if err == nil || !errors.As(err, &ns) || ns.Code != c.State || ns.Partition != c.Partition || ns.Block != c.Block {
					t.Fatalf("refused with %v, the case says %s{%s,%d}", err, c.State, c.Partition, c.Block)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for page, part := range want[c.Name] {
				found := false
				for _, g := range rep.Proven {
					if strings.EqualFold(g.URL, page) {
						found = true
						if g.Partition != part {
							t.Fatalf("%s is proven on %s, want %s", page, g.Partition, part)
						}
					}
				}
				if !found {
					t.Fatalf("%s is not among the proven pages", page)
				}
			}
		})
	}
}

// The anchor kind is checked per partition kind: a Directory slot that holds a BlockValidatorAnchor, a transaction partition on the
// Directory that does, and a block validator slot that holds a DirectoryAnchor, are all refused by name even though each anchor is
// proven into the certified root. A 2.0 document keeps refusing a DirectoryAnchor as the transaction's anchor, byte for byte as before.
func TestXPartition3AnchorKindIsCheckedPerPartitionKind(t *testing.T) {
	for _, c := range []struct {
		name string
		opts xworld.Options
		part string
		blk  uint64
	}{
		{"directory slot, BlockValidatorAnchor", xworld.Options{Layout: xworld.LayoutDirectoryAuthority, SwapAnchorKind: 2}, "Directory", xworld.BlockDN},
		{"transaction slot on the Directory, BlockValidatorAnchor", xworld.Options{Layout: xworld.LayoutDirectoryPrincipal, SwapAnchorKind: 1}, "Directory", xworld.BlockDNTx},
		{"block validator slot, DirectoryAnchor", xworld.Options{SwapAnchorKind: 2}, "BVN2", xworld.BlockBVN2},
	} {
		b, err := xworld.Build(c.opts)
		if err != nil {
			t.Fatal(err)
		}
		p, err := b.Portable()
		if err != nil {
			t.Fatal(err)
		}
		_, err = proofv2.VerifyPortable(p)
		var ns *proofv2.NamedState
		if !errors.As(err, &ns) || ns.Code != proofv2.StateForeignPartitionMismatch || ns.Partition != c.part || ns.Block != c.blk {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	b, err := xworld.Build(xworld.Options{Layout: xworld.LayoutDirectoryPrincipal})
	if err != nil {
		t.Fatal(err)
	}
	ev := *b.Evidence
	ev.Version = proofv2.Version
	ev.Anchors, ev.Votes, ev.Check.Routing = nil, nil, nil
	for i := range ev.Pages {
		ev.Pages[i].Partition, ev.Pages[i].Roles = "", nil
	}
	if _, err := proofv2.VerifyFromGenesis(&ev, b.Archive, b.Inputs, b.Pin); err == nil || !strings.Contains(err.Error(), "not a block validator anchor") {
		t.Fatalf("a 2.0 document with a DirectoryAnchor: %v", err)
	}
}
