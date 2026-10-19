// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// RB9-F6, F-VE-2 option (b) (owner decision 2026-10-19): the genesis link (Evidence.GenesisLink, V-E A1b) is required of EVERY evidence 2.1
// document the offline walk (verifyFromGenesis: Verify21FromGenesis, VerifyPortable, the builder's own check, the execution recheck,
// proofverify --offline) judges, the continuous form included. Before this a 2.1 document with no `links` needed none, so an offline
// continuous document built from a complete chain of ANOTHER incarnation (same genesis records, same genesis set, its own root chain) passed the
// pin. The spine-log entry point (VerifyEvidence21FromSpine, the one consensus calls) requires it too, and judges it in the same place (last), so
// consensus accepts as a certificate's proof exactly the documents an independent auditor can verify offline.

// plainWorld is the world every earlier suite is made of: one continuous item, no links, no genesis link.
func plainWorld(t *testing.T) *xworld.Built {
	t.Helper()
	b, err := xworld.Build(xworld.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Evidence.Links) != 0 || b.Evidence.GenesisLink != "" {
		t.Fatalf("the plain world carries %d links and genesis link %q", len(b.Evidence.Links), b.Evidence.GenesisLink)
	}
	return b
}

// An offline continuous 2.1 document with no genesis link ends certify_link_missing{genesis}, by every offline entry point.
func TestContinuousEvidence21WithoutAGenesisLinkIsRefusedOffline(t *testing.T) {
	b := plainWorld(t)
	_, err := verify21(t, b)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")

	p, err := b.Portable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = proofv2.VerifyPortable(p)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")
}

// The same chain WITH the link verifies, in the continuous form (no links), and removing the link is the refusal. The continuous chain worlds
// carry the link by construction.
func TestContinuousEvidence21WithAGenesisLinkVerifies(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{eff(false), eff(false)}})
	if len(b.Evidence.Links) != 0 || b.Evidence.GenesisLink == "" {
		t.Fatalf("not a continuous document with a genesis link: %d links, genesis link %q", len(b.Evidence.Links), b.Evidence.GenesisLink)
	}
	if _, err := verify21(t, b); err != nil {
		t.Fatalf("a continuous 2.1 document with its genesis link: %v", err)
	}
	b.Evidence.GenesisLink = ""
	_, err := verify21(t, b)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")
}

// The pin (V-J N1): a continuous document built from a COMPLETE chain of another incarnation - the pinned genesis records and genesis set,
// validly signed, a root chain of its own. Without a link it used to pass; it is refused by name. With its own, self-consistent genesis link
// it is refused because that link does not start at the pinned genesis root chain anchor; with the link's start forged to the pinned root the
// receipt no longer recomputes.
func TestContinuousCompleteChainOfAnotherIncarnationIsRefused(t *testing.T) {
	foreignChain := func() *xworld.Chain {
		return &xworld.Chain{Items: []xworld.ChainItem{eff(false), eff(false)}, Start: xworld.ForeignGenesis()}
	}
	b := buildChain(t, foreignChain())
	if len(b.Evidence.Links) != 0 || b.Evidence.GenesisLink == "" {
		t.Fatalf("not a continuous document with a genesis link: %d links", len(b.Evidence.Links))
	}

	// its own, self-consistent genesis link: valid, ends at the certified root, starts at the other chain's root
	_, err := verify21(t, b)
	wantCertifyState(t, err, proofv2.StateCertifyLinkStart, "genesis")

	// no genesis link at all: the residual of F-VE-2
	none := buildChain(t, foreignChain())
	none.Evidence.GenesisLink = ""
	_, err = verify21(t, none)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")

	// the link's start forged to the pinned genesis root chain anchor: self-consistent no longer, its path does not recompute
	forged := buildChain(t, foreignChain())
	raw, err := hex.DecodeString(forged.Evidence.GenesisLink)
	if err != nil {
		t.Fatal(err)
	}
	l := new(merkle.Receipt)
	if err := l.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	l.Start = append([]byte(nil), forged.Inputs.GenesisRootChainAnchor[:]...)
	fb, err := l.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	forged.Evidence.GenesisLink = hex.EncodeToString(fb)
	_, err = verify21(t, forged)
	wantCertifyState(t, err, proofv2.StateCertifyLinkInvalid, "genesis")
}

// Evidence 2.0 is not asked for a genesis link and its verdict does not move: the committed 2.0 vector that verifies still verifies by the
// offline entry point, with no genesis link and no 2.1 members.
func TestEvidence20IsNotAskedForAGenesisLink(t *testing.T) {
	_, ev, rep, err := verifyPortableJSON(gunzipConformance(t, "testdata/conformance/valid.json.gz"))
	if err != nil {
		t.Fatalf("the 2.0 vector that verified: %v", err)
	}
	if ev.Version != proofv2.Version || ev.GenesisLink != "" || len(ev.Links) != 0 {
		t.Fatalf("the 2.0 vector is %q with %d links and genesis link %q", ev.Version, len(ev.Links), ev.GenesisLink)
	}
	if rep.Version != "" || rep.Tag != "" {
		t.Fatalf("version %q tag %q: not an evidence 2.0 report", rep.Version, rep.Tag)
	}
	// the entry point of a 2.0 document is VerifyPortable's too: the same bytes through it give the same verdict
	if _, err := proofv2.VerifyPortable(mustPortable(t, gunzipConformance(t, "testdata/conformance/valid.json.gz"))); err != nil {
		t.Fatalf("VerifyPortable: %v", err)
	}
}

func mustPortable(t *testing.T, j []byte) *proofv2.Portable {
	t.Helper()
	p := new(proofv2.Portable)
	if err := json.Unmarshal(j, p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The consensus-callable entry point (VerifyEvidence21FromSpine) refuses the continuous form without the link exactly as the offline walk does -
// by the same name, after everything else (a document refused for another reason keeps that refusal) - and accepts the same document with it,
// with the report the offline walk gives. Consensus accepts as a certificate's proof exactly the documents an independent auditor can verify
// offline.
func TestSpineEntryPointRequiresTheGenesisLikeTheOfflineWalk(t *testing.T) {
	spine := func(b *xworld.Built) *ledger.AccumulateSpineLog {
		g, set, err := proofv2.AcceptSpineGenesis(b.Inputs, b.Pin, 1)
		if err != nil {
			t.Fatal(err)
		}
		l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
		cps, sets, err := proofv2.ExtendSpine(l, b.Archive.Majors, 2)
		if err != nil {
			t.Fatal(err)
		}
		l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
		return l
	}
	b := plainWorld(t)
	_, err := proofv2.VerifyEvidence21FromSpine(b.Evidence, spine(b), b.Pin)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")
	_, offline := verify21(t, b)
	wantCertifyState(t, offline, proofv2.StateCertifyLinkMissing, "genesis")

	// refused for another reason, it keeps that refusal in both: the genesis link is judged last
	other := plainWorld(t)
	other.Evidence.Pages[0].State = other.Evidence.Pages[1].State
	_, errSpine := proofv2.VerifyEvidence21FromSpine(other.Evidence, spine(other), other.Pin)
	_, errOffline := verify21(t, other)
	if errSpine == nil || errOffline == nil || errSpine.Error() != errOffline.Error() {
		t.Fatalf("a document refused for another reason: spine %v, offline %v", errSpine, errOffline)
	}
	var cs *proofv2.CertifyState
	if errors.As(errSpine, &cs) {
		t.Fatalf("the genesis link was judged before the page: %v", errSpine)
	}

	// with the link, both accept, with the same report
	linked, err := xworld.Build(xworld.Options{GenesisLinked: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := proofv2.VerifyEvidence21FromSpine(linked.Evidence, spine(linked), linked.Pin)
	if err != nil {
		t.Fatalf("the spine entry point refused the continuous document with its genesis link: %v", err)
	}
	want, err := verify21(t, linked)
	if err != nil {
		t.Fatal(err)
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Fatal("the spine entry point's report differs from the offline walk's")
	}
}

// onlyTheGenesisIsAnchored serves the genesis question and answers every other link question "not yet anchored": every kept run is emitted
// continuous, so the document has no link of its own.
type onlyTheGenesisIsAnchored struct {
	inner   proofv2.LinkSource
	genesis [32]byte
	height  uint64 // the certified anchor's RootChainIndex: the one height the genesis link is asked at
}

func (s onlyTheGenesisIsAnchored) Link(ctx context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	if prev == s.genesis && height == s.height {
		return s.inner.Link(ctx, prev, height)
	}
	return nil, proofv2.ErrLinkNotAnchored
}

// The builder never emits the document the offline walk refuses: a 2.1 document whose runs all had to be emitted continuous (no link served
// for any of them) still carries the genesis link.
func TestAnchorEvidenceGivesEvery21DocumentItsGenesisLink(t *testing.T) {
	world := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{eff(false)}, Final: xworld.ChainItem{}})
	sp, recs, _ := spineAt1(t, world)
	in := *world.Evidence
	in.GenesisLink = "" // the continuous document as the builder emitted it before the genesis link was required of every 2.1 document
	height, _, err := proofv2.RunAnchor(world.Evidence.Certify[len(world.Evidence.Certify)-1])
	if err != nil {
		t.Fatal(err)
	}
	src := onlyTheGenesisIsAnchored{inner: synthLinks{start: sp.RootChainAnchor[:], seqs: [][]*api.MinorRootRecord{recs}}, genesis: sp.RootChainAnchor, height: height}
	out, err := proofv2.AnchorEvidence(context.Background(), &in, world.Archive, world.Inputs, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Links) != 0 {
		t.Fatalf("%d links: the test wants a document with none", len(out.Links))
	}
	if out.GenesisLink == "" {
		t.Fatal("the built continuous 2.1 document has no genesis link: the offline walk refuses it")
	}
	if _, err := proofv2.Verify21FromGenesis(out, world.Archive, world.Inputs, world.Pin); err != nil {
		t.Fatalf("the built document does not verify: %v", err)
	}
}
