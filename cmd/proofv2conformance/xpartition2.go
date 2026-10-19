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
	"reflect"

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

	// The certified timeline (suite xpartition2b); absent from the first suite, whose reports have none.
	AuthorizationMode string `json:"authorizationMode,omitempty"`
	// Disclosures (suite xpartition4): the codes of Report.Disclosures; absent from the earlier suites.
	Disclosures []string   `json:"disclosures,omitempty"`
	Arrivals    []XArrival `json:"arrivals,omitempty"`
}

// XArrival is one counted signature (or a vote's production) and the block the verifier derived for it.
type XArrival struct {
	Kind    string `json:"kind"`
	Account string `json:"account"`
	Block   uint64 `json:"block"`
}

// XCase is one manifest entry.
type XCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Expect      string `json:"expect"` // "verified" or "refused"
	State       string `json:"state,omitempty"`
	// Fields are the fields of a refusal that is a certify state (certify_link_missing{genesis}, names.json of the certify1 suite); empty for a
	// named G1 state, which carries Partition and Block instead. Note says why a frozen document is refused when it was not (RB9-F6).
	Fields    []string `json:"fields,omitempty"`
	Partition string   `json:"partition,omitempty"`
	Block     uint64   `json:"block,omitempty"`
	Note      string   `json:"note,omitempty"`
	Report    *XReport `json:"report,omitempty"`
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
	out.AuthorizationMode = rep.AuthorizationMode
	for _, a := range rep.Arrivals {
		out.Arrivals = append(out.Arrivals, XArrival{Kind: a.Kind, Account: a.Account, Block: a.Block})
	}
	return out
}

// writeXPartition2 writes the suite into out and refuses to write a case the Go verifier does not judge as the manifest says.
func writeXPartition2(out string) error {
	return writeXSuite(out, XManifestFormat, xworld.GenesisRequired(xworld.Cases()))
}

// XManifestFormat2b names the certified-timeline suite (RB9 Phase C1b-1): new files, their own manifest and hash.
const XManifestFormat2b = "certen-xpartition2b-conformance/1"

// writeXPartition2b writes the certified-timeline suite; the first suite's files and manifest are never touched.
func writeXPartition2b(out string) error {
	return writeXSuite(out, XManifestFormat2b, xworld.GenesisRequired(xworld.Cases2()))
}

func writeXSuite(out, format string, cases []xworld.Case) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	m := XManifest{Format: format, Domain: proofv2.DomainG1V4, PortableFormat: proofv2.PortableFormat}
	for _, c := range cases {
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
		xc := XCase{Name: c.Name, Description: c.Description, File: c.Name + ".json", Expect: c.Expect, State: c.State, Fields: c.Fields, Partition: c.Partition, Block: c.Block, Note: c.Note}
		switch c.Expect {
		case "verified":
			if verr != nil {
				return fmt.Errorf("%s: the Go verifier refused a verified case: %w", c.Name, verr)
			}
			xc.Report = xreport(rep)
			if format == XManifestFormat4 || format == XManifestFormat6 {
				for _, d := range rep.Disclosures {
					xc.Report.Disclosures = append(xc.Report.Disclosures, d.Code)
				}
				if fmt.Sprint(xc.Report.Disclosures) != fmt.Sprint(c.Disclosures) && (len(xc.Report.Disclosures)+len(c.Disclosures) > 0) {
					return fmt.Errorf("%s: disclosures %v, the case says %v", c.Name, xc.Report.Disclosures, c.Disclosures)
				}
			}
			if fmt.Sprint(xc.Report.Unproven) != fmt.Sprint(c.Unproven) {
				return fmt.Errorf("%s: unproven %v, the case says %v", c.Name, xc.Report.Unproven, c.Unproven)
			}
		case "refused":
			if verr == nil {
				return fmt.Errorf("%s: the Go verifier accepted a refused case", c.Name)
			}
			var ns *proofv2.NamedState
			var cs *proofv2.CertifyState
			switch {
			case len(c.Fields) > 0: // a certify state (RB9-F6: certify_link_missing{genesis})
				if !errors.As(verr, &cs) || cs.Code != c.State || !reflect.DeepEqual(cs.Fields, c.Fields) {
					return fmt.Errorf("%s: refused with %v, the case says %s%v", c.Name, verr, c.State, c.Fields)
				}
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
