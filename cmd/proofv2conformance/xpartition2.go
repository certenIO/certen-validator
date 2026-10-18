package main

// The evidence 2.1 (cross-partition) conformance suite, RB9 Phase C1a: whole portable documents built by pkg/proof/v2/xworld,
// one per case, each with the verdict every verifier must reach - verified with the report it must produce, or refused with the
// named state (and the partition and block it was judged at) when it is one. New files under their own directory with their own
// domain tag (certen:g1:v4); the 2.0 suite (testdata/conformance) is never rewritten by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition2 pkg/proof/v2/testdata/xpartition2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// XPageReport is one proven page of a verified case's report.
type XPageReport struct {
	URL       string   `json:"url"`
	Partition string   `json:"partition"`
	Block     uint64   `json:"block"`
	Roles     []string `json:"roles"`
	Declared  []string `json:"declared,omitempty"`
}

// XReport is what a verifier must report for a verified 2.1 case.
type XReport struct {
	Version       string        `json:"version"`
	Tag           string        `json:"tag"`
	Partition     string        `json:"partition"`
	AnchorBlock   uint64        `json:"anchorBlock"`
	CertifiedRoot string        `json:"certifiedRoot"`
	CheckBlock    uint64        `json:"checkBlock"`
	SetVerdict    string        `json:"setVerdict"`
	RoutingHeight uint64        `json:"routingHeight"`
	Proven        []XPageReport `json:"proven"`
	PagesBound    int           `json:"pagesBound"`
	Unproven      []string      `json:"unproven"`
}

// XCase is one manifest entry.
type XCase struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	SHA256      string   `json:"sha256"`
	Expect      string   `json:"expect"` // "verified" or "refused"
	State       string   `json:"state,omitempty"`
	Partition   string   `json:"partition,omitempty"`
	Block       uint64   `json:"block,omitempty"`
	Report      *XReport `json:"report,omitempty"`
}

// XManifest lists the suite. Its own hash is the content of MANIFEST.sha256, beside it.
type XManifest struct {
	Format         string  `json:"format"`
	Domain         string  `json:"domain"`
	PortableFormat string  `json:"portableFormat"`
	Cases          []XCase `json:"cases"`
}

const XManifestFormat = "certen-xpartition2-conformance/1"

func roleStrings(rs []proofv2.PageRole) []string {
	var out []string
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}

// xreport is the report a verifier must produce, in the form the manifest pins.
func xreport(rep *proofv2.Report) *XReport {
	out := &XReport{Version: rep.Version, Tag: rep.Tag, Partition: rep.Partition, AnchorBlock: rep.AnchorBlock, CertifiedRoot: hex.EncodeToString(rep.CertifiedRoot[:]),
		CheckBlock: rep.CheckBlock, SetVerdict: string(rep.SetVerdict), RoutingHeight: rep.RoutingHeight}
	for i, p := range rep.Proven {
		out.Proven = append(out.Proven, XPageReport{URL: p.URL, Partition: p.Partition, Block: p.Block, Roles: roleStrings(p.Roles), Declared: roleStrings(p.Declared)})
		if rep.PageChains[i].Bound {
			out.PagesBound++
		}
	}
	for _, u := range rep.Unproven {
		out.Unproven = append(out.Unproven, u.Code)
	}
	return out
}

// writeXPartition2 writes the suite into out and refuses to write a case the Go verifier does not judge as the manifest says.
func writeXPartition2(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	m := XManifest{Format: XManifestFormat, Domain: proofv2.DomainG1V4, PortableFormat: proofv2.PortableFormat}
	for _, c := range xworld.Cases() {
		_, p, err := c.Document()
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		doc, err := json.Marshal(p)
		if err != nil {
			return err
		}
		// The verdict, as another language's verifier reads the file.
		back := new(proofv2.Portable)
		if err := json.Unmarshal(doc, back); err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		rep, verr := proofv2.VerifyPortable(back)
		xc := XCase{Name: c.Name, Description: c.Description, File: c.Name + ".json", Expect: c.Expect, State: c.State, Partition: c.Partition, Block: c.Block}
		switch c.Expect {
		case "verified":
			if verr != nil {
				return fmt.Errorf("%s: the Go verifier refused a verified case: %w", c.Name, verr)
			}
			xc.Report = xreport(rep)
			if fmt.Sprint(xc.Report.Unproven) != fmt.Sprint(c.Unproven) {
				return fmt.Errorf("%s: unproven %v, the case says %v", c.Name, xc.Report.Unproven, c.Unproven)
			}
		case "refused":
			if verr == nil {
				return fmt.Errorf("%s: the Go verifier accepted a refused case", c.Name)
			}
			var ns *proofv2.NamedState
			switch {
			case c.State == "":
				if errors.As(verr, &ns) {
					return fmt.Errorf("%s: refused with the named state %v, the case names none", c.Name, ns)
				}
			case !errors.As(verr, &ns) || ns.Code != c.State || ns.Partition != c.Partition || ns.Block != c.Block:
				return fmt.Errorf("%s: refused with %v, the case says %s{%s,%d}", c.Name, verr, c.State, c.Partition, c.Block)
			}
		default:
			return fmt.Errorf("%s: expect %q", c.Name, c.Expect)
		}
		doc = append(doc, 0x0a)
		sum := sha256.Sum256(doc) // the hash of the file's exact bytes
		xc.SHA256 = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(out, xc.File), doc, 0o644); err != nil {
			return err
		}
		m.Cases = append(m.Cases, xc)
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), mj, 0o644); err != nil {
		return err
	}
	h := sha256.Sum256(mj)
	return os.WriteFile(filepath.Join(out, "MANIFEST.sha256"), []byte(hex.EncodeToString(h[:])+"  manifest.json\n"), 0o644)
}
