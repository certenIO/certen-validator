// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func compact(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A 2.0 evidence document, stored before evidence 2.1 existed, decodes into the 2.1 types and re-encodes to exactly the
// bytes it was stored as: every field 2.1 adds is omitted when empty.
func TestEvidence20ReencodesByteIdentical(t *testing.T) {
	raw := gunzipConformance(t, "testdata/evidence_3cfb04cf.json.gz")
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	if ev.Version != proofv2.Version || ev.Anchors != nil || ev.Votes != nil || ev.Check.Routing != nil {
		t.Fatalf("a 2.0 document decoded with 2.1 members: version %q anchors %v votes %v routing %v", ev.Version, ev.Anchors, ev.Votes, ev.Check.Routing)
	}
	for _, p := range ev.Pages {
		if p.Partition != "" || p.Roles != nil {
			t.Fatalf("2.0 page %s decoded with a partition or roles", p.URL)
		}
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, compact(t, raw)) {
		t.Fatalf("the 2.0 evidence re-encodes to %d bytes that differ from the %d stored", len(got), len(compact(t, raw)))
	}
}

// Every 2.0 portable document of the conformance suite (the valid case's base and the synthetic documents) decodes and
// re-encodes byte for byte, and imports to evidence that exports back to the same evidence section.
func TestPortable20ReencodesByteIdentical(t *testing.T) {
	var m struct {
		Base      string `json:"base"`
		Documents []struct {
			File string `json:"file"`
		} `json:"documents"`
	}
	raw, err := readFile("testdata/conformance/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	files := []string{m.Base}
	for _, d := range m.Documents {
		files = append(files, d.File)
	}
	if len(files) < 2 {
		t.Fatalf("only %d conformance documents", len(files))
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			doc := gunzipConformance(t, "testdata/conformance/"+f)
			p := new(proofv2.Portable)
			if err := json.Unmarshal(doc, p); err != nil {
				t.Fatal(err)
			}
			if p.Evidence.Anchors != nil || p.Evidence.Votes != nil || p.Evidence.Check.Routing != nil {
				t.Fatal("a 2.0 portable document decoded with 2.1 members")
			}
			// The whole document, field for field.
			again, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, compact(t, doc)) {
				t.Fatalf("the document re-encodes to %d bytes that differ from the %d stored", len(again), len(compact(t, doc)))
			}
			// Imported and exported again, its evidence section is the stored one.
			ev, _, in, pin, err := proofv2.Import(p)
			if err != nil {
				t.Fatal(err)
			}
			back, err := proofv2.ExportDocument(ev, in, pin)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := json.Marshal(p.Evidence)
			got, _ := json.Marshal(back.Evidence)
			if !bytes.Equal(got, want) {
				t.Fatalf("import then export changed the evidence section (%d bytes, was %d)", len(got), len(want))
			}
		})
	}
}

// An evidence 2.1 document (anchors for two partitions, votes, a routing proof, page partitions and roles) survives the
// portable form unchanged, and the 2.0 verifier refuses it by version: no 2.0 verdict can be reached for a 2.1 document.
func TestEvidence21PortableRoundTripAndTwoZeroRefusal(t *testing.T) {
	fx := loadFixture(t)
	ev := fx.ev
	ev.Version = proofv2.Version21

	// Anchors for the transaction's partition and a foreign one: the same anchor message and receipt are enough to
	// exercise the encoding (the verification of 2.1 is RB9 Phase C).
	ev.Anchors = map[string]proofv2.PartitionAnchor{
		"acc://bvn-BVN1.acme": ev.Anchor,
		"acc://bvn-BVN2.acme": ev.Anchor,
	}
	roles, err := proofv2.CanonicalRoles([]proofv2.PageRole{proofv2.RoleVoter, proofv2.RoleAuthorityPage, proofv2.RoleVoter})
	if err != nil {
		t.Fatal(err)
	}
	ev.Pages[0].Partition, ev.Pages[0].Roles = "acc://bvn-BVN1.acme", roles
	ev.Pages[1].Partition, ev.Pages[1].Roles = "acc://bvn-BVN2.acme", []proofv2.PageRole{proofv2.RoleDelegateBook}
	ev.Votes = []proofv2.Vote{{
		Authority: "acc://fdb-risk-tcl1.acme/book", Origin: "acc://fdb-risk-tcl1.acme/book/2", Vote: "accept",
		Delegators: []string{"acc://b.acme/book/1"}, Cause: "acc://" + strings.Repeat("ab", 32) + "@fdb-risk-tcl1.acme/book/2",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportSequenced, Source: "acc://bvn-BVN2.acme", Destination: "acc://bvn-BVN1.acme", Number: 6280},
		Message:   strings.Repeat("cd", 32), Receipt: ev.Receipt,
	}, {
		Authority: "acc://harbor-mfg-tcl1.acme/book", Origin: "acc://harbor-mfg-tcl1.acme/book/2", Vote: "accept",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}, Message: strings.Repeat("ef", 32), Receipt: ev.Receipt,
	}}
	ev.Check.Routing = routingProof(t)

	doc, err := proofv2.ExportDocument(ev, fx.in, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := new(proofv2.Portable)
	if err := json.Unmarshal(j, p); err != nil {
		t.Fatal(err)
	}
	if again, _ := json.Marshal(p); !bytes.Equal(again, j) {
		t.Fatal("the 2.1 portable document does not re-encode to itself")
	}
	back, _, _, _, err := proofv2.Import(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Anchors, ev.Anchors) || !reflect.DeepEqual(back.Votes, ev.Votes) {
		t.Fatal("anchors or votes changed through the portable form")
	}
	if back.Pages[0].Partition != "acc://bvn-BVN1.acme" || !reflect.DeepEqual(back.Pages[0].Roles, roles) || back.Pages[1].Roles[0] != proofv2.RoleDelegateBook {
		t.Fatalf("page partitions or roles changed: %+v %+v", back.Pages[0], back.Pages[1])
	}
	if back.Check.Routing == nil || back.Check.Routing.AccountURL != ev.Check.Routing.AccountURL || back.Check.Routing.AccountState != ev.Check.Routing.AccountState {
		t.Fatal("the routing proof changed through the portable form")
	}
	// The 2.0 verifier does not reach a verdict for 2.1.
	if _, err := proofv2.Verify(ev, fx.ar, fx.inc, fx.pinBytes); err == nil {
		t.Fatal("the 2.0 verifier accepted a 2.1 document")
	}
}

func TestCanonicalRolesOrderDedupeAndRefusal(t *testing.T) {
	got, err := proofv2.CanonicalRoles([]proofv2.PageRole{proofv2.RoleInitiatorSigner, proofv2.RolePrincipalChain, proofv2.RoleVoter, proofv2.RolePrincipalChain})
	if err != nil {
		t.Fatal(err)
	}
	want := []proofv2.PageRole{proofv2.RolePrincipalChain, proofv2.RoleVoter, proofv2.RoleInitiatorSigner}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if _, err := proofv2.CanonicalRoles([]proofv2.PageRole{"owner"}); err == nil {
		t.Fatal("an unknown role was accepted")
	}
}

func TestNamedStateCarriesWhereItWasJudged(t *testing.T) {
	var err error = &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: "BVN2", Block: 14004595, Detail: "retained [1, 2]"}
	if got := err.Error(); got != "g1_historical_unavailable{BVN2,14004595}: retained [1, 2]" {
		t.Fatal(got)
	}
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Block != 14004595 {
		t.Fatal("not recoverable by errors.As")
	}
	if (&proofv2.NamedState{Code: proofv2.StateAuthorityMissing}).Error() != "g1_authority_missing" {
		t.Fatal("bare state")
	}
}

// The 2.1 domain tags are new: they are not a v3 tag, and the contracts package's v3 tags are untouched.
func TestDomainTagsAreNewNotV3(t *testing.T) {
	if proofv2.DomainG1V4 != "certen:g1:v4" || proofv2.DomainGovRootV4 != "certen:govroot:v4" {
		t.Fatal("2.1 domain tags changed")
	}
	if proofv2.DomainG1V4 == contracts.GovRootV3TagG1 || proofv2.DomainGovRootV4 == contracts.GovRootV3Domain {
		t.Fatal("a v4 tag reuses a v3 tag")
	}
	if contracts.GovRootV3TagG1 != "certen:g1:v3" || contracts.GovRootV3Domain != "certen:govroot:v3" {
		t.Fatal("a v3 tag moved")
	}
}

// routingProof is a one-entry data account in the shape a routing proof has: the account's state with the routing table
// as its single entry. (Its proof into a state root is RB9 Phase C; this is the encoding.)
func routingProof(t *testing.T) *proof.AccountStateProof {
	t.Helper()
	tbl := &protocol.RoutingTable{Routes: []protocol.Route{{Length: 1, Value: 0, Partition: "BVN1"}, {Length: 2, Value: 2, Partition: "BVN2"}, {Length: 2, Value: 3, Partition: "BVN3"}}}
	rb, err := tbl.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	da := &protocol.DataAccount{Url: url.MustParse("acc://dn.acme/routing"), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{rb}}}
	st, err := da.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &proof.AccountStateProof{AccountURL: "acc://dn.acme/routing", AccountState: hex.EncodeToString(st)}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

type xfixture struct {
	ev       *proofv2.Evidence
	ar       *proofv2.Archive
	inc      *proof.IncarnationEvidence
	in       proof.IncarnationInputs
	pin      [32]byte
	pinBytes [32]byte
}

func loadFixture(t *testing.T) xfixture {
	t.Helper()
	var fx xfixture
	var err error
	if fx.ar, err = proofv2.UnmarshalArchive(gunzipConformance(t, "testdata/archive.json.gz")); err != nil {
		t.Fatal(err)
	}
	fx.ev = new(proofv2.Evidence)
	if err := json.Unmarshal(gunzipConformance(t, "testdata/evidence_3cfb04cf.json.gz"), fx.ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	fx.inc = new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, fx.inc); err != nil {
		t.Fatal(err)
	}
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fx.in = ir.Inputs
	b, _ := hex.DecodeString("cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0")
	copy(fx.pin[:], b)
	fx.pinBytes = fx.pin
	return fx
}
