package consensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F6, F-VE-2 option (b) (owner decision 2026-10-19): the genesis link is required of every evidence 2.1 document by the OFFLINE walk
// (proofv2.Verify21FromGenesis, VerifyPortable, the builder's own check, proofverify --offline). Consensus judges a 2.1 certificate with
// proofv2.VerifyEvidence21FromSpine against the chain's own spine log, and its verdict does not change, before the rules v15 activation or after
// it: before it a 2.1 certificate is refused by the gate (intent_certificate.go, ErrIntentProofV21NotInForce) whatever the document holds, after it
// the real continuous document is accepted exactly as TestRulesV15AcceptsAVerifiedEvidence21 pins. This test drives the REAL stored continuous
// document, with no genesis link, through judgeProofV2 on both sides of the activation and shows the offline walk's refusal of the same bytes -
// and that attaching Kermit's recorded genesis answer changes neither consensus' report nor its govRoot v4.
func TestContinuousEvidence21IsJudgedByConsensusAsBeforeTheGenesisLinkWasRequired(t *testing.T) {
	w := loadReal21World(t)
	if len(w.ev.Links) != 0 || w.ev.GenesisLink != "" {
		t.Fatalf("the stored document is not in the continuous form without a link: %d links, genesis link %q", len(w.ev.Links), w.ev.GenesisLink)
	}
	c := real21CertificateFor(t, w, w.clone(t))

	// Before the activation: the gate refuses a 2.1 certificate by name, before the verifier is asked - the verdict of every earlier binary.
	if _, _, err := c.judge(w, nil); !errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("a continuous 2.1 document before the activation: %v, want ErrIntentProofV21NotInForce", err)
	}
	// After it: accepted, by the spine entry point, with no genesis link.
	root, rep, err := c.judge(w, g1Active)
	if err != nil {
		t.Fatalf("a continuous 2.1 document without a genesis link under the activation: %v", err)
	}
	if rep.Version != proofv2.Version21 || len(rep.Unproven) != 0 {
		t.Fatalf("version %q, %d unproven", rep.Version, len(rep.Unproven))
	}

	// The offline walk refuses the very same bytes by name.
	_, err = proofv2.Verify21FromGenesis(w.clone(t), w.ar, w.in, w.inc)
	var cs *proofv2.CertifyState
	if !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyLinkMissing || len(cs.Fields) != 1 || cs.Fields[0] != "genesis" {
		t.Fatalf("the offline walk on the continuous document without a genesis link: %v, want certify_link_missing{genesis}", err)
	}

	// With Kermit's recorded answer to the genesis question attached, the offline walk verifies and consensus judges the same report and root.
	linked := w.clone(t)
	linked.GenesisLink = recordedGenesisLink(t, w)
	offline, err := proofv2.Verify21FromGenesis(linked, w.ar, w.in, w.inc)
	if err != nil {
		t.Fatalf("the offline walk with the genesis link: %v", err)
	}
	cl := c
	cert := *c.cert
	cert.ProofV2 = linked
	cl.cert = &cert
	root2, rep2, err := cl.judge(w, g1Active)
	if err != nil {
		t.Fatalf("consensus on the document with the genesis link: %v", err)
	}
	if root2 != root {
		t.Fatalf("the genesis link changed the committed govRoot v4: %x -> %x", root, root2)
	}
	a, _ := json.Marshal(rep)
	b, _ := json.Marshal(rep2)
	o, _ := json.Marshal(offline)
	if string(a) != string(b) || string(a) != string(o) {
		t.Fatal("the report differs between consensus without the link, consensus with it and the offline walk")
	}
}

// recordedGenesisLink is Kermit's recorded answer to the genesis question for the stored document (testdata/certify1-live/links.json, label
// genesis): the receipt from the pinned genesis root chain anchor to the real certified root, hex.
func recordedGenesisLink(t *testing.T, w real21World) string {
	t.Helper()
	raw, err := os.ReadFile("../proof/v2/testdata/certify1-live/links.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Links []struct {
			Label   string `json:"label"`
			Prev    string `json:"prev"`
			Receipt string `json:"receipt"`
		} `json:"links"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	for _, l := range rec.Links {
		if l.Label == "genesis" {
			if l.Prev != hex.EncodeToString(w.in.GenesisRootChainAnchor[:]) || l.Receipt == "" {
				t.Fatalf("the recorded genesis answer starts at %s (want %x) or is a refusal", l.Prev, w.in.GenesisRootChainAnchor)
			}
			return l.Receipt
		}
	}
	t.Fatal("no recorded answer labelled genesis")
	return ""
}
