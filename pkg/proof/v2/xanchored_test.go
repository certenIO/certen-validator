// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The anchored certify form (RB9-F5): Spine.AdvanceAnchored and the evidence 2.1 verifier's use of it, on the synthetic chains of
// xworld.Chain. The shared vectors (testdata/certify1) pin the verdicts across languages; these tests pin the function and its invariants.

func orc(anchored bool) xworld.ChainItem {
	return xworld.ChainItem{Anchored: anchored, Update: xworld.UpdateOracle}
}

// eff is an item with an effect: a write to the globals account that the walk applies and records. An anchored item that is not the last
// of its sequence must have one (a transaction the walk does not apply, as orc carries, has none).
func eff(anchored bool) xworld.ChainItem {
	return xworld.ChainItem{Anchored: anchored, Update: xworld.UpdateGenesisGlobals}
}

func buildChain(t *testing.T, c *xworld.Chain) *xworld.Built {
	t.Helper()
	b, err := xworld.Build(xworld.Options{Chain: c})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spineAt1 is the spine after the first major block, as the verifier stands before the certification, and the world's records and links.
func spineAt1(t *testing.T, b *xworld.Built) (*proofv2.Spine, []*api.MinorRootRecord, []*merkle.Receipt) {
	t.Helper()
	def, glob := new(protocol.NetworkDefinition), new(protocol.NetworkGlobals)
	if err := def.UnmarshalBinary(b.Inputs.NetworkRecord); err != nil {
		t.Fatal(err)
	}
	if err := glob.UnmarshalBinary(b.Inputs.GlobalsRecord); err != nil {
		t.Fatal(err)
	}
	sp, err := proofv2.NewSpine(&network.GlobalValues{Network: def, Globals: glob, Oracle: new(protocol.AcmeOracle), Routing: new(protocol.RoutingTable)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Advance(b.Archive.Majors[0]); err != nil {
		t.Fatal(err)
	}
	var recs []*api.MinorRootRecord
	for _, h := range b.Evidence.Certify {
		raw, _ := hex.DecodeString(h)
		r := new(api.MinorRootRecord)
		if err := r.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	var links []*merkle.Receipt
	for _, h := range b.Evidence.Links {
		raw, _ := hex.DecodeString(h)
		l := new(merkle.Receipt)
		if err := l.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		links = append(links, l)
	}
	return sp, recs, links
}

func copyReceipt(r *merkle.Receipt) *merkle.Receipt {
	c := *r
	c.Start = append([]byte(nil), r.Start...)
	c.Anchor = append([]byte(nil), r.Anchor...)
	c.Entries = nil
	for _, e := range r.Entries {
		x := *e
		x.Hash = append([]byte(nil), e.Hash...)
		c.Entries = append(c.Entries, &x)
	}
	return &c
}

func wantCertifyState(t *testing.T, err error, code string, fields ...string) {
	t.Helper()
	var cs *proofv2.CertifyState
	if !errors.As(err, &cs) || cs.Code != code || !reflect.DeepEqual(cs.Fields, fields) {
		t.Fatalf("refused with %v, want %s%v", err, code, fields)
	}
}

func TestAdvanceAnchoredAcceptsALinkedRecord(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{orc(true)}, Final: xworld.ChainItem{Anchored: true}})
	sp, recs, links := spineAt1(t, b)
	if len(recs) != 2 || len(links) != 2 {
		t.Fatalf("%d records and %d links", len(recs), len(links))
	}
	for i := range recs {
		if err := sp.AdvanceAnchored(recs[i], links[i]); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if !bytes.Equal(sp.RootChainAnchor[:], links[i].Anchor) {
			t.Fatalf("record %d: the spine stands at %x, not the link's end %x", i, sp.RootChainAnchor, links[i].Anchor)
		}
	}
	if sp.LastMinorBlock != 300 {
		t.Fatalf("the spine stands at DN %d, not 300", sp.LastMinorBlock)
	}
}

func TestAdvanceAnchoredRefusesEachLinkDefectAndDoesNotAdvance(t *testing.T) {
	flip := func(h []byte) { h[0] ^= 0xff }
	cases := []struct {
		name   string
		mutate func(rec *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt)
		code   string // a certify state, or
		text   string // a plain refusal
	}{
		{"no link", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) { return r, nil }, proofv2.StateCertifyLinkMissing, ""},
		{"start altered", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			l = copyReceipt(l)
			flip(l.Start)
			return r, l
		}, proofv2.StateCertifyLinkStart, ""},
		{"end altered", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			l = copyReceipt(l)
			flip(l.Anchor)
			return r, l
		}, proofv2.StateCertifyLinkEnd, ""},
		{"step altered", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			l = copyReceipt(l)
			flip(l.Entries[0].Hash)
			return r, l
		}, proofv2.StateCertifyLinkInvalid, ""},
		{"null step", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			l = copyReceipt(l)
			l.Entries[0] = nil
			return r, l
		}, proofv2.StateCertifyLinkInvalid, ""},
		{"a root proof as well", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			c := *r
			c.RootProof = &merkle.ReceiptList{}
			return &c, l
		}, "", "an anchored record carries no root proof"},
		{"no anchor", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) {
			c := *r
			c.Anchor = nil
			return &c, l
		}, "", "incomplete minor root record"},
		{"no record", func(r *api.MinorRootRecord, l *merkle.Receipt) (*api.MinorRootRecord, *merkle.Receipt) { return nil, l }, "", "incomplete minor root record"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
			sp, recs, links := spineAt1(t, b)
			before := sp.Clone()
			rec, link := c.mutate(recs[0], links[0])
			err := sp.AdvanceAnchored(rec, link)
			switch {
			case err == nil:
				t.Fatal("accepted")
			case c.code != "":
				wantCertifyState(t, err, c.code, "0")
			case !strings.Contains(err.Error(), c.text):
				t.Fatalf("refused with %q, want %q", err, c.text)
			}
			if sp.RootChainAnchor != before.RootChainAnchor || sp.LastMinorBlock != before.LastMinorBlock || len(sp.Applied) != len(before.Applied) {
				t.Fatal("a refused record moved the spine")
			}
		})
	}
}

func TestAdvanceAnchoredRefusesABlockThatDoesNotAdvance(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateOracle, Block: 130}, {Anchored: true, Update: xworld.UpdateOracle, Block: 120}}, Final: xworld.ChainItem{Anchored: true}})
	sp, recs, links := spineAt1(t, b)
	if err := sp.AdvanceAnchored(recs[0], links[0]); err != nil {
		t.Fatal(err)
	}
	err := sp.AdvanceAnchored(recs[1], links[1])
	if err == nil || !strings.Contains(err.Error(), "anchor for minor block 120 does not advance past 130") {
		t.Fatalf("got %v", err)
	}
}

func TestAdvanceAnchoredRefusesAReplayedUpdate(t *testing.T) {
	g := xworld.ChainItem{Anchored: true, Update: xworld.UpdateGlobals}
	t.Run("twice in one record", func(t *testing.T) {
		g2 := g
		g2.Repeat = 2
		b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{g2}, Final: xworld.ChainItem{Anchored: true}})
		sp, recs, links := spineAt1(t, b)
		wantCertifyState(t, sp.AdvanceAnchored(recs[0], links[0]), proofv2.StateCertifyUpdateReplayed, xworld.UpdateTxHash(xworld.UpdateGlobals, b.Inputs.GlobalsRecord))
		if len(sp.Applied) != 0 {
			t.Fatal("a refused record moved the spine")
		}
	})
	t.Run("in a later record", func(t *testing.T) {
		b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{g, g}, Final: xworld.ChainItem{Anchored: true}})
		sp, recs, links := spineAt1(t, b)
		if err := sp.AdvanceAnchored(recs[0], links[0]); err != nil {
			t.Fatal(err)
		}
		wantCertifyState(t, sp.AdvanceAnchored(recs[1], links[1]), proofv2.StateCertifyUpdateReplayed, xworld.UpdateTxHash(xworld.UpdateGlobals, b.Inputs.GlobalsRecord))
		if len(sp.Applied) != 1 {
			t.Fatalf("%d updates applied", len(sp.Applied))
		}
	})
}

// A spine that is not walked for evidence 2.1 behaves as it always did: AdvanceEpoch still refuses a record without a root proof by its old
// name, and still accepts the same update twice (the evidence 2.0 verifier counts on neither changing).
func TestVerify20KeepsItsSpineBehaviour(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	sp, recs, _ := spineAt1(t, b)
	err := sp.AdvanceEpoch(recs[0])
	var cs *proofv2.CertifyState
	if err == nil || err.Error() != "incomplete minor root record" || errors.As(err, &cs) {
		t.Fatalf("AdvanceEpoch of an anchored record: %v", err)
	}

	g2 := xworld.ChainItem{Update: xworld.UpdateGlobals, Repeat: 2}
	b = buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{g2}})
	sp, recs, _ = spineAt1(t, b)
	if err := sp.AdvanceEpoch(recs[0]); err != nil {
		t.Fatalf("AdvanceEpoch of a continuous record with a repeated update: %v", err)
	}
	if len(sp.Applied) != 2 {
		t.Fatalf("%d updates applied, the 2.0 walk records both", len(sp.Applied))
	}
}

func conformance20(t *testing.T) map[string]any {
	t.Helper()
	f, err := os.Open("testdata/conformance/network-update.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func verifyDoc(t *testing.T, doc map[string]any) (*proofv2.Report, error) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := new(proofv2.Portable)
	if err := json.Unmarshal(raw, p); err != nil {
		t.Fatal(err)
	}
	return proofv2.VerifyPortable(p)
}

func TestVerify20RefusesAnchored(t *testing.T) {
	doc := conformance20(t)
	evd := doc["evidence"].(map[string]any)
	if evd["version"] != "2.0" {
		t.Fatalf("the base document is %v", evd["version"])
	}
	rec := evd["certify"].([]any)[0].(map[string]any)
	if _, ok := rec["rootProof"]; !ok {
		t.Fatal("the base document's first record has no root proof")
	}
	delete(rec, "rootProof")
	_, err := verifyDoc(t, doc)
	var cs *proofv2.CertifyState
	if err == nil || err.Error() != "certify run 0: incomplete minor root record" || errors.As(err, &cs) {
		t.Fatalf("an anchored record in a 2.0 document: %v", err)
	}
	// A links member is not read in a 2.0 document, whatever it holds: the verdict is the unedited document's.
	base, baseErr := verifyDoc(t, conformance20(t))
	d2 := conformance20(t)
	d2["evidence"].(map[string]any)["links"] = []any{map[string]any{"start": "00", "anchor": "00"}, 7, nil}
	got, gotErr := verifyDoc(t, d2)
	if (baseErr == nil) != (gotErr == nil) || (baseErr != nil && baseErr.Error() != gotErr.Error()) || !reflect.DeepEqual(base, got) {
		t.Fatalf("a links member changed the verdict of a 2.0 document: %v / %v", gotErr, baseErr)
	}
}

func TestVerify21AnchoredFormsGiveTheSameReport(t *testing.T) {
	verify := func(c *xworld.Chain) *proofv2.Report {
		t.Helper()
		b := buildChain(t, c)
		rep, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	cont := verify(&xworld.Chain{Items: []xworld.ChainItem{eff(false), eff(false)}})
	anch := verify(&xworld.Chain{Items: []xworld.ChainItem{eff(true), eff(true)}, Final: xworld.ChainItem{Anchored: true}})
	mixed := verify(&xworld.Chain{Items: []xworld.ChainItem{eff(true), eff(false)}, Final: xworld.ChainItem{Anchored: true}})
	js := func(r *proofv2.Report) string {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if js(cont) != js(anch) || js(cont) != js(mixed) {
		t.Fatalf("the reports differ:\n continuous %+v\n anchored   %+v\n mixed      %+v", cont, anch, mixed)
	}
}

func TestVerify21AnchoredHopsAndLinkOrdinals(t *testing.T) {
	c := func() *xworld.Chain {
		return &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{eff(true), {Anchored: true}}}
	}
	b := buildChain(t, c())
	if len(b.Evidence.Links) != 3 {
		t.Fatalf("%d links", len(b.Evidence.Links))
	}
	rep, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	if err != nil || rep.CheckBlock != 320 {
		t.Fatalf("hops: %v, check block %v", err, rep)
	}

	b = buildChain(t, c())
	b.Evidence.Links = b.Evidence.Links[:2] // the last hop has no link: the ordinal runs on across certify and hops
	_, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "2")

	b = buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{{Anchored: true}, {Anchored: true}}})
	_, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyItemWithoutEffect, "1", "310")
}

// The canonical form is about effect: an anchored item that is not the last of its sequence and carries only updates the walk does not apply
// (here a write to the oracle account, whose receipt is valid) changes nothing and is refused like one without updates (V-F N1).
func TestVerify21AnchoredRefusesAnItemWhoseOnlyUpdateIsNotApplied(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{orc(true)}, Final: xworld.ChainItem{Anchored: true}})
	_, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyItemWithoutEffect, "0", "110")

	// the same padding repeated is still no effect
	b = buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateOracle, Repeat: 3}}, Final: xworld.ChainItem{Anchored: true}})
	_, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyItemWithoutEffect, "0", "110")

	// in the set check's hops the item is numbered across certify and hops
	b = buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{orc(true), {Anchored: true}}})
	_, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyItemWithoutEffect, "1", "310")

	// an update the walk applies is an effect, whether or not it changes the globals
	b = buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{eff(true)}, Final: xworld.ChainItem{Anchored: true}})
	if _, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin); err != nil {
		t.Fatal(err)
	}
}

func TestVerify21AnchoredRefusesAnUnusedLink(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	b.Evidence.Links = append(b.Evidence.Links, b.Evidence.Links[0])
	_, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyLinkInvalid, "1")
	// an undecodable link is named at its ordinal too
	b = buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	b.Evidence.Links = []string{"zz"}
	_, err = proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyLinkInvalid, "0")
}

func TestAnchoredRefusesGenuineAnchorOfAnotherChain(t *testing.T) {
	// A record of another chain, signed by the genesis set (its signatures are intact) with the link that is valid in that chain: the
	// link does not start at the root the verifier stands at.
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	sp, _, _ := spineAt1(t, b)
	rec, link := foreign(t, nil, false)
	wantCertifyState(t, sp.AdvanceAnchored(rec, link), proofv2.StateCertifyLinkStart, "0")

	// The same record linked from the verified root: the walk takes it (the genesis set signed it) and the transaction's receipt, which
	// ends at the world's own root, is what refuses the document.
	rec, link = foreign(t, xworld.GenesisRoot(), false)
	b = buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	b.Evidence.Certify = []string{recHex(t, rec)}
	b.Evidence.Links = []string{receiptHexOf(t, link)}
	_, err := proofv2.Verify21FromGenesis(b.Evidence, b.Archive, b.Inputs, b.Pin)
	if err == nil || !strings.HasPrefix(err.Error(), "receipt ends at ") {
		t.Fatalf("got %v", err)
	}

	// Another incarnation's validators signed it: not the set in force.
	sp, _, _ = spineAt1(t, b)
	rec, link = foreign(t, xworld.GenesisRoot(), true)
	if err := sp.AdvanceAnchored(rec, link); err == nil || !strings.Contains(err.Error(), "signer is not an active directory validator") {
		t.Fatalf("got %v", err)
	}
}

func foreign(t *testing.T, start []byte, otherSet bool) (*api.MinorRootRecord, *merkle.Receipt) {
	t.Helper()
	rh, lh := xworld.ForeignItem(start, 110, otherSet)
	raw, _ := hex.DecodeString(rh)
	rec := new(api.MinorRootRecord)
	if err := rec.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	raw, _ = hex.DecodeString(lh)
	link := new(merkle.Receipt)
	if err := link.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	return rec, link
}

func recHex(t *testing.T, r *api.MinorRootRecord) string {
	t.Helper()
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func receiptHexOf(t *testing.T, r *merkle.Receipt) string {
	t.Helper()
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
