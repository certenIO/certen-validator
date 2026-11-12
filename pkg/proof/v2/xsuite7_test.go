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

// The non-voting initiator vectors (DAX-1G, G-83) (testdata/xpartition7, written by `go run ./cmd/proofv2conformance -xpartition7 ...`) are what the
// TypeScript verifier consumes byte for byte. This test runs the real verifier on every committed file and checks the verdict EXACTLY: the file's
// hash, the manifest's hash, and against a table written here from the semantics of the member (not read from the manifest) the expectation, the
// named state with its partition and block for a refusal, and for a verified document the whole report - what is left unproven, the block the
// document is judged at, every proven page with its roles (initiator-signer PROVEN, never declared, for the member-carried documents).
var xs7Want = map[string]struct {
	expect    string
	state     string
	partition string
	block     uint64
	unproven  string // comma separated; verified only
}{
	"initiator-nonvoting-carried":                   {expect: "verified"},
	"initiator-nonvoting-key-removed-after-arrival": {expect: "verified"},
	"initiator-nonvoting-delegated-carried":         {expect: "verified"},
	"initiator-signature-tampered":                  {expect: "refused", state: "g1_signature_invalid", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-signature-other-transaction":         {expect: "refused", state: "g1_block_before_signature", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-signature-signs-another-transaction": {expect: "refused", state: "g1_signature_invalid", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-signature-other-page":                {expect: "refused", state: "g1_block_before_signature", partition: "BVN2", block: xworld.ProvenBlockBVN2},
	"initiator-signature-recorded-on-another-page":  {expect: "refused", state: "g1_signature_invalid", partition: "BVN2", block: xworld.ProvenBlockBVN2},
	"initiator-member-absent":                       {expect: "verified", unproven: "g1_initiator_signature_not_carried"},
	"initiator-member-page-records-no-role":         {expect: "refused", state: "g1_role_mismatch", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-not-the-initiator":            {expect: "refused", state: "g1_role_mismatch", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-key-not-held":                        {expect: "refused", state: "g1_initiator_key_not_held", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-no-history":                   {expect: "refused", state: "g1_history_unavailable", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-arrival-altered":              {expect: "refused", state: "g1_arrival_unproven", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-receipt-altered":              {expect: "refused", state: "g1_block_before_signature", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-header-names-no-initiator":    {expect: "refused", state: "g1_role_mismatch", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-without-transaction":          {expect: "refused", state: "g1_transaction_mismatch", partition: "BVN1", block: xworld.ProvenBlockBVN1},
	"initiator-member-is-an-authority-signature":    {expect: "refused", state: "g1_signature_invalid", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-member-no-arrival-proof":             {expect: "refused", state: "g1_arrival_unproven", partition: "BVN3", block: xworld.ProvenBlockBVN3},
	"initiator-delegator-not-a-proven-page":         {expect: "refused", state: "g1_initiator_page_unproven", partition: "BVN1", block: xworld.ProvenBlockBVN1},
	"initiator-member-in-20-document":               {expect: "refused"},
}

// The pages a verified member-carried document proves initiator-signer on (the payer, and the delegator of a delegated signature).
var xs7Initiators = map[string][]string{
	"initiator-nonvoting-carried":                   {xworld.ErpPage1},
	"initiator-nonvoting-key-removed-after-arrival": {xworld.ErpPage1},
	"initiator-nonvoting-delegated-carried":         {xworld.ErpPage1, xworld.DelePage1},
}

func TestXPartition7SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/xpartition7/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/xpartition7/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mj)
	if string(hf) != hex.EncodeToString(sum[:])+"  manifest.json\n" {
		t.Fatalf("MANIFEST.sha256 %q is not the hash %x of manifest.json", hf, sum)
	}
	var m struct {
		Format string `json:"format"`
		Domain string `json:"domain"`
		Cases  []struct {
			Name      string   `json:"name"`
			File      string   `json:"file"`
			SHA256    string   `json:"sha256"`
			Expect    string   `json:"expect"`
			State     string   `json:"state"`
			Fields    []string `json:"fields"`
			Partition string   `json:"partition"`
			Block     uint64   `json:"block"`
			Report    *struct {
				Version     string   `json:"version"`
				Tag         string   `json:"tag"`
				Partition   string   `json:"partition"`
				AnchorBlock uint64   `json:"anchorBlock"`
				SetVerdict  string   `json:"setVerdict"`
				Unproven    []string `json:"unproven"`
				Proven      []struct {
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
	if m.Format != "certen-xpartition7-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) != len(xs7Want) {
		t.Fatalf("manifest %q %q with %d cases, want %d (the table's)", m.Format, m.Domain, len(m.Cases), len(xs7Want))
	}
	if len(xworld.Cases7()) != len(xs7Want) {
		t.Fatalf("the suite generator holds %d cases, the table %d", len(xworld.Cases7()), len(xs7Want))
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		w, ok := xs7Want[c.Name]
		if !ok || seen[c.Name] || len(c.Fields) > 0 {
			t.Fatalf("case %q is not in the table, or listed twice, or a frozen moved entry", c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			if c.Expect != w.expect || c.State != w.state || c.Partition != w.partition || c.Block != w.block {
				t.Fatalf("the manifest says %s %s{%s,%d}; the member's semantics (this table) say %s %s{%s,%d}", c.Expect, c.State, c.Partition, c.Block, w.expect, w.state, w.partition, w.block)
			}
			doc, err := os.ReadFile("testdata/xpartition7/" + c.File)
			if err != nil {
				t.Fatal(err)
			}
			if h := sha256.Sum256(doc); hex.EncodeToString(h[:]) != c.SHA256 {
				t.Fatalf("%s does not hash to the manifest's %s", c.File, c.SHA256)
			}
			p := new(proofv2.Portable)
			if err := json.Unmarshal(doc, p); err != nil {
				t.Fatal(err)
			}
			rep, err := proofv2.VerifyPortable(p)
			if w.expect == "refused" {
				if w.state == "" {
					var ns *proofv2.NamedState
					if err == nil || errors.As(err, &ns) {
						t.Fatalf("refused with %v, want a refusal with no named state", err)
					}
					return
				}
				var ns *proofv2.NamedState
				if err == nil || !errors.As(err, &ns) || ns.Code != w.state || ns.Partition != w.partition || ns.Block != w.block {
					t.Fatalf("refused with %v, want %s{%s,%d}", err, w.state, w.partition, w.block)
				}
				if c.Report != nil {
					t.Fatal("a refused case carries a report")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r := c.Report
			if r == nil {
				t.Fatal("a verified case carries no report")
			}
			var un []string
			for _, u := range rep.Unproven {
				un = append(un, u.Code)
			}
			if strings.Join(un, ",") != w.unproven || strings.Join(r.Unproven, ",") != w.unproven {
				t.Fatalf("unproven: the verifier says %v, the manifest %v, the table %q", un, r.Unproven, w.unproven)
			}
			if rep.Version != r.Version || rep.Tag != r.Tag || rep.Tag != proofv2.DomainG1V4 || rep.Partition != r.Partition || rep.AnchorBlock != r.AnchorBlock || string(rep.SetVerdict) != r.SetVerdict {
				t.Fatalf("report %s %s %s block %d %s differs from the manifest's %+v", rep.Version, rep.Tag, rep.Partition, rep.AnchorBlock, rep.SetVerdict, r)
			}
			if rep.AnchorBlock != xworld.ProvenBlockBVN1 || rep.Partition != "acc://bvn-BVN1.acme" {
				t.Fatalf("judged at %s block %d: the principal's partition and the block the executor-activation table proves", rep.Partition, rep.AnchorBlock)
			}
			if len(rep.Proven) != len(r.Proven) {
				t.Fatalf("%d proven pages, the manifest says %d", len(rep.Proven), len(r.Proven))
			}
			for i, g := range rep.Proven {
				x := r.Proven[i]
				var roles, decl []string
				for _, y := range g.Roles {
					roles = append(roles, string(y))
				}
				for _, y := range g.Declared {
					decl = append(decl, string(y))
				}
				if g.URL != x.URL || g.Partition != x.Partition || g.Block != x.Block || strings.Join(roles, ",") != strings.Join(x.Roles, ",") || strings.Join(decl, ",") != strings.Join(x.Declared, ",") {
					t.Fatalf("proven page %d is %+v (roles %v, declared %v), the manifest says %+v", i, g, roles, decl, x)
				}
			}
			// The role, from the table: PROVEN on exactly the pages the member makes initiator-signers, DECLARED (and unproven) where the member is absent.
			want := xs7Initiators[c.Name]
			for _, g := range rep.Proven {
				isWant := false
				for _, u := range want {
					isWant = isWant || strings.EqualFold(u, g.URL)
				}
				proven, declared := hasRole(g.Roles, proofv2.RoleInitiatorSigner), hasRole(g.Declared, proofv2.RoleInitiatorSigner)
				switch {
				case isWant && (!proven || declared):
					t.Fatalf("%s: initiator-signer must be proven (roles %v declared %v)", g.URL, g.Roles, g.Declared)
				case !isWant && proven:
					t.Fatalf("%s: initiator-signer proven on a page the member does not make an initiator-signer", g.URL)
				case !isWant && w.unproven != "" && strings.EqualFold(g.URL, xworld.ErpPage1) && (proven || !declared):
					t.Fatalf("%s: with no member the role must be declared and not proven (roles %v declared %v)", g.URL, g.Roles, g.Declared)
				}
			}
		})
	}
	for name := range xs7Want {
		if !seen[name] {
			t.Fatalf("the vector %q is missing from the manifest", name)
		}
	}
}
