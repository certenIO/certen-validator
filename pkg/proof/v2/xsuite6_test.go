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

// The two-voter UpdateAccountAuth vectors (RB9-K-F1) (testdata/xpartition6, written by `go run ./cmd/proofv2conformance -xpartition6 ...`) are what
// the TypeScript verifier consumes byte for byte. This test runs the real verifier on every committed file and checks the verdict EXACTLY:
// the file's hash, the manifest's hash, and against a table written here from the executor's semantics (not read from the manifest) the
// expectation, the named state with its partition and block for a refusal, and for a verified document the whole report - the version and
// tag, the partition and block it was judged at, the certified root, the set verdict, the routing height, every proven page with its roles,
// the authorization mode, every derived arrival and what is left unproven.
var xs6Want = map[string]struct {
	expect    string
	state     string
	partition string
	block     uint64
	unproven  string // comma separated; verified only
	arrivals  int
}{
	"add-op-added-authority-voted":                               {expect: "verified", unproven: "", arrivals: 4},
	"add-op-added-authority-voted-first":                         {expect: "verified", unproven: "g1_vote_held,g1_vote_held", arrivals: 2},
	"add-op-votes-listed-in-the-other-order":                     {expect: "verified", unproven: "g1_vote_held,g1_vote_held", arrivals: 2},
	"add-op-added-authority-page-threshold-two-voted":            {expect: "verified", unproven: "g1_vote_held,g1_vote_held", arrivals: 3},
	"enable-op-both-authorities-voted":                           {expect: "verified", unproven: "g1_vote_held,g1_vote_held", arrivals: 2},
	"disable-op-both-authorities-voted":                          {expect: "verified", unproven: "g1_vote_held,g1_vote_held", arrivals: 2},
	"add-op-only-the-added-authority-voted":                      {expect: "refused", state: proofv2.StateAuthorityNotReady, partition: "BVN1", block: 50},
	"add-op-added-authority-voted-reject":                        {expect: "refused", state: proofv2.StateAuthorityNotReady, partition: "BVN1", block: 50},
	"add-op-added-authority-page-below-threshold":                {expect: "refused", state: proofv2.StateVoteNotReproduced, partition: "BVN1", block: 50},
	"update-account-auth-voter-neither-listed-nor-added":         {expect: "refused", state: proofv2.StateVoteNotReproduced, partition: "BVN1", block: 50},
	"disable-op-every-authority-disabled-one-voted":              {expect: "refused", state: proofv2.StateAuthorityNotReady, partition: "BVN1", block: 50},
	"disable-op-voter-outside-the-list-every-authority-disabled": {expect: "refused", state: proofv2.StateVoteNotReproduced, partition: "BVN1", block: 50},
	"add-op-first-authorities-both-added-both-voted":             {expect: "refused", state: proofv2.StateExecutorOverrideUnsupported, partition: "BVN1", block: 50},
	"add-op-second-voter-page-at-another-block":                  {expect: "refused", state: proofv2.StatePageBlockMismatch, partition: "BVN3", block: 90},
	"add-op-second-voter-history-tampered":                       {expect: "refused", state: proofv2.StateHistoryFoldMismatch, partition: "BVN3", block: 90},
	"add-op-second-voter-key-added-after-arrival":                {expect: "refused", state: proofv2.StateVoteNotReproduced, partition: "BVN1", block: 50},
	"add-op-second-vote-not-in-the-principal-chain":              {expect: "refused", state: proofv2.StateBlockBeforeArrival, partition: "BVN1", block: 50},
}

// xs6Verified is the number of table cases that verify: each has a frozen entry (refused certify_link_missing{genesis}) and a -g sibling that verifies.
func xs6Verified() int {
	n := 0
	for _, w := range xs6Want {
		if w.expect == "verified" {
			n++
		}
	}
	return n
}

func TestXPartition6SharedVectors(t *testing.T) {
	mj, err := os.ReadFile("testdata/xpartition6/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	hf, err := os.ReadFile("testdata/xpartition6/MANIFEST.sha256")
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
			Note      string   `json:"note"`
			Partition string   `json:"partition"`
			Block     uint64   `json:"block"`
			Report    *struct {
				Version           string   `json:"version"`
				Tag               string   `json:"tag"`
				Partition         string   `json:"partition"`
				AnchorBlock       uint64   `json:"anchorBlock"`
				CertifiedRoot     string   `json:"certifiedRoot"`
				CheckBlock        uint64   `json:"checkBlock"`
				SetVerdict        string   `json:"setVerdict"`
				RoutingHeight     uint64   `json:"routingHeight"`
				PagesBound        int      `json:"pagesBound"`
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
	if m.Format != "certen-xpartition6-conformance/1" || m.Domain != proofv2.DomainG1V4 || len(m.Cases) != len(xs6Want)+xs6Verified() {
		t.Fatalf("manifest %q %q with %d cases, want %d (the table's, and a -g sibling of each that verified: F-VE-2 (b))", m.Format, m.Domain, len(m.Cases), len(xs6Want)+xs6Verified())
	}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		base := strings.TrimSuffix(c.Name, xworld.GenesisSiblingSuffix) // a -g sibling is judged as the case it is the sibling of
		w, ok := xs6Want[base]
		if ok && strings.HasSuffix(c.Name, xworld.GenesisSiblingSuffix) && w.expect != "verified" {
			ok = false // only a case that verified has a sibling
		}
		if !ok || seen[c.Name] {
			t.Fatalf("case %q is not in the table, or listed twice", c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			if len(c.Fields) > 0 { // F-VE-2 (b): the frozen document of a case that verified, refused for the missing genesis link
				if w.expect != "verified" || c.Expect != "refused" || c.Report != nil {
					t.Fatalf("a frozen moved entry for a case the table says %s: %+v", w.expect, c)
				}
				doc, err := os.ReadFile("testdata/xpartition6/" + c.File)
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
				_, err = proofv2.VerifyPortable(p)
				wantMovedByGenesis(t, err, c.State, c.Fields, c.Note)
				return
			}
			if c.Expect != w.expect || c.State != w.state || c.Partition != w.partition || c.Block != w.block {
				t.Fatalf("the manifest says %s %s{%s,%d}; the executor semantics (this table) say %s %s{%s,%d}",
					c.Expect, c.State, c.Partition, c.Block, w.expect, w.state, w.partition, w.block)
			}
			doc, err := os.ReadFile("testdata/xpartition6/" + c.File)
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
			if w.expect == "refused" {
				var ns *proofv2.NamedState
				if err == nil || !errors.As(err, &ns) || ns.Code != w.state || ns.Partition != w.partition || ns.Block != w.block {
					t.Fatalf("refused with %v, want %s{%s,%d}", err, w.state, w.partition, w.block)
				}
				if c.Report != nil {
					t.Fatalf("a refused case carries a report")
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
			if rep.Version != r.Version || rep.Tag != r.Tag || rep.Tag != proofv2.DomainG1V4 || rep.Partition != r.Partition || rep.AnchorBlock != r.AnchorBlock ||
				hex.EncodeToString(rep.CertifiedRoot[:]) != r.CertifiedRoot || rep.CheckBlock != r.CheckBlock || string(rep.SetVerdict) != r.SetVerdict ||
				rep.RoutingHeight != r.RoutingHeight {
				t.Fatalf("report %s %s %s block %d root %x check %d %s routing %d differs from the manifest's %+v", rep.Version, rep.Tag, rep.Partition, rep.AnchorBlock,
					rep.CertifiedRoot, rep.CheckBlock, rep.SetVerdict, rep.RoutingHeight, r)
			}
			if rep.AnchorBlock != 50 || rep.Partition != "acc://bvn-BVN1.acme" || rep.RoutingHeight != 1 {
				t.Fatalf("judged at %s block %d, routing height %d: the principal's partition and block, the routing table of genesis", rep.Partition, rep.AnchorBlock, rep.RoutingHeight)
			}
			if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired || r.AuthorizationMode != proofv2.ModeAuthoritiesRequired {
				t.Fatalf("mode %q (manifest %q): UpdateAccountAuth requires every authority, disabled or not", rep.AuthorizationMode, r.AuthorizationMode)
			}
			var disc []string
			for _, d := range rep.Disclosures {
				disc = append(disc, d.Code)
			}
			if len(disc) != 0 || len(r.Disclosures) != 0 {
				t.Fatalf("disclosures %v / %v", disc, r.Disclosures)
			}
			bound := 0
			for _, pc := range rep.PageChains {
				if pc.Bound {
					bound++
				}
			}
			if bound != r.PagesBound {
				t.Fatalf("%d pages bound, the manifest says %d", bound, r.PagesBound)
			}
			if len(rep.Arrivals) != w.arrivals || len(r.Arrivals) != w.arrivals {
				t.Fatalf("%d arrivals (manifest %d), the table says %d", len(rep.Arrivals), len(r.Arrivals), w.arrivals)
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
			for i, a := range rep.Arrivals {
				x := r.Arrivals[i]
				if a.Kind != x.Kind || a.Account != x.Account || a.Block != x.Block {
					t.Fatalf("arrival %d is %+v, the manifest says %+v", i, a, x)
				}
			}
		})
	}
	for name := range xs6Want {
		if !seen[name] {
			t.Fatalf("the vector %q is missing from the manifest", name)
		}
	}
}
