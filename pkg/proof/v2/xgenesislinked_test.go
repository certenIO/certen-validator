// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// RB9-F6: the plain world with the genesis link the offline walk now requires of every evidence 2.1 document (xworld.Options.GenesisLinked).
// It is the `-g` sibling of every vector of the earlier suites that verified: same world, its first major block's root pinned as the
// incarnation's genesis root chain anchor, the link from that root to the certified root.
func TestGenesisLinkedWorldVerifiesInTheContinuousForm(t *testing.T) {
	plain := plainWorld(t)
	b, err := xworld.Build(xworld.Options{GenesisLinked: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Evidence.Links) != 0 || b.Evidence.GenesisLink == "" || len(b.Evidence.Certify) != 1 {
		t.Fatalf("%d links, genesis link %q, %d certify runs: want the continuous form with the link", len(b.Evidence.Links), b.Evidence.GenesisLink, len(b.Evidence.Certify))
	}
	if b.Pin == plain.Pin {
		t.Fatal("the genesis-linked world has the plain world's pin: it pins a different genesis root chain anchor")
	}
	rep, err := verify21(t, b)
	if err != nil {
		t.Fatalf("the continuous 2.1 document with its genesis link: %v", err)
	}
	if rep.Version != proofv2.Version21 || rep.CertifiedBlock != 300 {
		t.Fatalf("version %q certified block %d", rep.Version, rep.CertifiedBlock)
	}
	p, err := b.Portable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proofv2.VerifyPortable(p); err != nil {
		t.Fatalf("VerifyPortable: %v", err)
	}
	// the consensus-callable entry point judges the same bytes the same way (a link it does not need is still judged)
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
	if _, err := proofv2.VerifyEvidence21FromSpine(b.Evidence, l, b.Pin); err != nil {
		t.Fatalf("the spine entry point refused the genesis-linked document: %v", err)
	}
}

// Each way of damaging the link of a continuous document is the named state at the index "genesis".
func TestGenesisLinkedWorldRefusesEachLinkDefect(t *testing.T) {
	build := func() *xworld.Built {
		b, err := xworld.Build(xworld.Options{GenesisLinked: true})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	absent := build()
	absent.Evidence.GenesisLink = ""
	_, err := verify21(t, absent)
	wantCertifyState(t, err, proofv2.StateCertifyLinkMissing, "genesis")

	garbage := build()
	garbage.Evidence.GenesisLink = "zz"
	_, err = verify21(t, garbage)
	wantCertifyState(t, err, proofv2.StateCertifyLinkInvalid, "genesis")

	// a link that starts somewhere other than the pinned genesis root chain anchor, whole and valid
	moved := build()
	moved.Inputs.GenesisRootChainAnchor[0] ^= 1
	if moved.Pin, err = proof.ComputeIncarnation(moved.Inputs); err != nil {
		t.Fatal(err)
	}
	_, err = verify21(t, moved)
	wantCertifyState(t, err, proofv2.StateCertifyLinkStart, "genesis")
}
