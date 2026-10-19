// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Real data (Kermit, captured 2026-10-17): the foreign-page vector (fdb-compliance-tcl1.acme/book/2 with the BlockValidatorAnchor the
// Directory executed for its block and the receipt into a Directory root) and the full production capture of
// certen-protocol.acme/billing-receipts at the same BVN1 block 14699674 (five pages with their chains). BVN2 and BVN3 were idle
// during the capture (RB9-B-F7), so every real page is on BVN1; the cross-partition document is the synthetic xworld one.

type realCapture struct {
	Principal  string `json:"principal"`
	Partitions map[string]struct {
		Block     uint64 `json:"block"`
		StateRoot string `json:"stateRoot"`
	} `json:"partitions"`
	Pages []PageState `json:"pages"`
}

func loadRealCapture(t *testing.T) *realCapture {
	t.Helper()
	c := new(realCapture)
	if err := json.Unmarshal(gunzip(t, "../../proofv2shadow/testdata/capture_billing_receipts_bvn1_14699674.json.gz"), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// The real anchor is verified as a 2.1 partition anchor: its partition is derived from its Source, it is a BlockValidatorAnchor
// delivered to the Directory, and its receipt is proven into the root the certified chain would end at. A claimed partition that
// is not its Source, and a root it does not end at, are refused by name.
func TestRealAnchorIsDerivedAndRefusesAWrongKey(t *testing.T) {
	v := loadVector(t, "bvn1-fdb-compliance-book2.json.gz")
	r, err := decodeReceipt(v.Anchor.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	xa, err := verifyAnchor21("acc://bvn-BVN1.acme", v.Anchor, r.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	if xa.id != "BVN1" || xa.block != v.Block || hex.EncodeToString(xa.stateRoot) != v.StateRoot {
		t.Fatalf("derived %s block %d root %x, the vector names BVN1 %d %s", xa.id, xa.block, xa.stateRoot, v.Block, v.StateRoot)
	}
	_, err = verifyAnchor21("acc://bvn-BVN2.acme", v.Anchor, r.Anchor)
	if ns, ok := err.(*NamedState); !ok || ns.Code != StateForeignPartitionMismatch || ns.Partition != "BVN1" {
		t.Fatalf("a key that is not the anchor's source: %v", err)
	}
	wrong := append([]byte(nil), r.Anchor...)
	wrong[0] ^= 1
	_, err = verifyAnchor21("acc://bvn-BVN1.acme", v.Anchor, wrong)
	if ns, ok := err.(*NamedState); !ok || ns.Code != StatePartitionAnchorUnavailable || ns.Block != v.Block {
		t.Fatalf("an anchor not proven into the certified root: %v", err)
	}
	// The later root the vector also holds a receipt to is a longer path to a different root, equally an anchor proof.
	r2, _ := decodeReceipt(v.AnchorAtH.Receipt)
	if _, err := verifyAnchor21("acc://bvn-BVN1.acme", v.AnchorAtH, r2.Anchor); err != nil {
		t.Fatal(err)
	}
	// The real routing table the vector captured sends the real page to the partition its anchor names.
	tbl := new(protocol.RoutingTable)
	if err := json.Unmarshal(v.Routing, tbl); err != nil {
		t.Fatal(err)
	}
	if id, err := proof.RoutePartition(tbl, v.Page); err != nil || id != xa.id {
		t.Fatalf("the routing table sends %s to (%q, %v), its anchor names %s", v.Page, id, err, xa.id)
	}
}

// The real pages verify under the 2.1 verifier through the real anchor: every page against the partition's state root at its
// block, the chains bound, the governing set RE-DERIVED from the proven states (principal chain through the ADI, the authority
// book and both of its pages) equal to what the production capture recorded, and the real page of an unrelated identity (the
// initiator/payer case of R9 section 3) proven beside them under a declared role.
func TestRealCaptureVerifiesAsEvidence21(t *testing.T) {
	v := loadVector(t, "bvn1-fdb-compliance-book2.json.gz")
	c := loadRealCapture(t)
	r, err := decodeReceipt(v.Anchor.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	body, seq, _, err := anchorBody(v.Anchor.Message)
	if err != nil {
		t.Fatal(err)
	}
	bvn1 := c.Partitions["BVN1"]
	if hex.EncodeToString(body.StateTreeAnchor[:]) != bvn1.StateRoot || body.MinorBlockIndex != bvn1.Block {
		t.Fatalf("the capture and the vector are not the same BVN1 block: %x/%d vs %s/%d", body.StateTreeAnchor, body.MinorBlockIndex, bvn1.StateRoot, bvn1.Block)
	}
	var pages []PageState
	for _, p := range c.Pages {
		tp, err := trimPage(&p, body.StateTreeAnchor[:])
		if err != nil {
			t.Fatal(err)
		}
		// The vote's receipts are added when the evidence is built; the capture holds none, so the voter role (justified by the
		// vote's origin) is not asserted here, and the roles the header and certificate would justify stay declared.
		var roles []PageRole
		for _, role := range tp.Roles {
			if role != RoleVoter {
				roles = append(roles, role)
			}
		}
		tp.Roles = roles
		pages = append(pages, *tp)
	}
	foreign := v.PageState
	foreign.Partition, foreign.Roles = seq.Source.String(), []PageRole{RoleCertifiedKeyPage}
	pages = append(pages, foreign)

	ev := &Evidence{Version: Version21, Account: c.Principal, Anchor: v.Anchor, Pages: pages}
	rep := &Report{}
	in := xIn{certRoot: append([]byte(nil), r.Anchor...)}
	in.x.source, in.x.id, in.x.block, in.x.stateRoot = seq.Source.String(), "BVN1", body.MinorBlockIndex, append([]byte(nil), body.StateTreeAnchor[:]...)
	if err := verify21(ev, rep, in); err != nil {
		t.Fatal(err)
	}
	if len(rep.Proven) != 6 {
		t.Fatalf("%d proven pages", len(rep.Proven))
	}
	for i, p := range rep.Proven {
		if p.Partition != "acc://bvn-BVN1.acme" || p.Block != 14699674 || !rep.PageChains[i].Bound {
			t.Fatalf("proven page %+v chain %+v", p, rep.PageChains[i])
		}
	}
	var book2, other *ProvenPage
	for i := range rep.Proven {
		switch strings.ToLower(rep.Proven[i].URL) {
		case "acc://certen-protocol.acme/book/2":
			book2 = &rep.Proven[i]
		case "acc://fdb-compliance-tcl1.acme/book/2":
			other = &rep.Proven[i]
		}
	}
	if book2 == nil || len(book2.Roles) != 1 || book2.Roles[0] != RoleAuthorityPage || len(book2.Declared) != 2 {
		t.Fatalf("the certified page: %+v", book2)
	}
	if other == nil || len(other.Roles) != 0 || len(other.Declared) != 1 || other.Declared[0] != RoleCertifiedKeyPage {
		t.Fatalf("the unrelated identity's page: %+v", other)
	}
	// No routing proof was carried and the votes were not re-evaluated: both are named.
	if len(rep.Unproven) != 2 || rep.Unproven[0].Code != StateRoutingUnproven || rep.Unproven[1].Code != StateCompletenessUnproven {
		t.Fatalf("unproven: %+v", rep.Unproven)
	}

	// Attacks on the real data. The real book's second page removed: the book proves PageCount 2.
	short := &Evidence{Version: Version21, Account: c.Principal, Anchor: v.Anchor}
	for _, p := range pages {
		if !strings.EqualFold(p.URL, "acc://certen-protocol.acme/book/2") {
			short.Pages = append(short.Pages, p)
		}
	}
	err = verify21(short, &Report{}, in)
	if ns, ok := err.(*NamedState); !ok || ns.Code != StateBookPageCountUnproven || !strings.Contains(ns.Detail, "certen-protocol.acme/book/2") {
		t.Fatalf("a real book with its second page omitted: %v", err)
	}
	// The same state under a flipped byte does not hash to the receipt's start.
	forged := &Evidence{Version: Version21, Account: c.Principal, Anchor: v.Anchor, Pages: append([]PageState(nil), pages...)}
	forged.Pages[2].State = flipHexByte(forged.Pages[2].State, len(forged.Pages[2].State)/2-2)
	if err := verify21(forged, &Report{}, in); err == nil {
		t.Fatal("a real page with a changed byte was verified")
	}
	// A real page claimed for a block the anchor is not for: the real receipt of the vector page against another root.
	moved := in
	moved.x.stateRoot = bytes.Repeat([]byte{9}, 32)
	moved.x.block++
	err = verify21(ev, &Report{}, moved)
	if ns, ok := err.(*NamedState); !ok || ns.Code != StatePageBlockMismatch || ns.Block != moved.x.block {
		t.Fatalf("real pages against another block's root: %v", err)
	}
}

// The routing account of the real Kermit Directory, read and proven by BuildRoutingProofAt on 2026-10-17 into the state tree root of
// a DirectoryAnchor inside the node's retained range (go test -tags live -run TestLiveRoutingProof, PV2_WRITE_ROUTING_VECTOR):
// verified offline here against the certified root, never rewritten since genesis, and routing the pages of the real vectors to the
// partitions that served them.
func TestRealRoutingProofVectorVerifies(t *testing.T) {
	raw, err := os.ReadFile("testdata/xpartition/dn-routing-proof-live.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Format    string                  `json:"format"`
		DNBlock   uint64                  `json:"dnBlock"`
		StateRoot string                  `json:"stateRoot"`
		Proof     proof.AccountStateProof `json:"proof"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Format != "certen-routing-vector/1" || v.DNBlock == 0 {
		t.Fatalf("vector %q block %d", v.Format, v.DNBlock)
	}
	table, height, err := proof.VerifyRoutingProof(&v.Proof, v.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if height != 1 {
		t.Fatalf("main chain height %d", height)
	}
	pv := loadVector(t, "bvn1-fdb-compliance-book2.json.gz")
	if id, err := proof.RoutePartition(table, pv.Page); err != nil || id != pv.Partition {
		t.Fatalf("the proven table sends %s to (%q, %v), the node served it from %s", pv.Page, id, err, pv.Partition)
	}
	if _, _, err := proof.VerifyRoutingProof(&v.Proof, strings.Repeat("00", 32)); err == nil {
		t.Fatal("the routing proof verified against a root it is not proven into")
	}
}
