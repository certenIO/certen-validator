package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/intentcert"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F6, F-VE-2 option (b) (owner decision 2026-10-19), aligned for consensus (orchestrator, 2026-10-19): the genesis link is required of EVERY
// evidence 2.1 document by the offline walk (Verify21FromGenesis, VerifyPortable, proofverify --offline) AND by the spine-log walk consensus
// runs (VerifyEvidence21FromSpine through defaultProofV2Verifier), judged in the same place (last). Consensus must not accept as a certificate's
// proof a document no independent auditor can verify offline, and 2.1 is frozen at the activation. Before the activation nothing changes: the v15
// gate (intent_certificate.go, ErrIntentProofV21NotInForce) refuses a 2.1 certificate before any verifier is asked, linked or not.
//
// This drives the REAL stored continuous document (a live Kermit transaction) through judgeProofV2 with and without its genesis link (Kermit's
// recorded answer to the genesis question), on both sides of the activation, and through the offline walk.
func TestConsensusRequiresTheGenesisLinkOfEvery21DocumentAsTheOfflineWalkDoes(t *testing.T) {
	w := loadReal21World(t)
	if len(w.ev.Links) != 0 || w.ev.GenesisLink == "" || w.unlinked.GenesisLink != "" || len(w.unlinked.Links) != 0 {
		t.Fatalf("the world is not the continuous document with and without its link: %d links, link %q, unlinked link %q", len(w.ev.Links), w.ev.GenesisLink, w.unlinked.GenesisLink)
	}
	c := real21CertificateFor(t, w, w.clone(t))
	withoutLink := func() real21Cert {
		cu := c
		cert := *c.cert
		cert.ProofV2 = w.unlinked
		cu.cert = &cert
		return cu
	}()

	// Before the activation: the gate refuses a 2.1 certificate by name, before the verifier is asked, with or without the link.
	for name, cert := range map[string]real21Cert{"linked": c, "unlinked": withoutLink} {
		if _, _, err := cert.judge(w, nil); !errors.Is(err, ErrIntentProofV21NotInForce) {
			t.Fatalf("%s, before the activation: %v, want ErrIntentProofV21NotInForce", name, err)
		}
	}

	// After it: the document with its link is accepted, the very same document without it is refused certify_link_missing{genesis}.
	root, rep, err := c.judge(w, g1Active)
	if err != nil {
		t.Fatalf("the linked continuous document under the activation: %v", err)
	}
	if rep.Version != proofv2.Version21 || len(rep.Unproven) != 0 {
		t.Fatalf("version %q, %d unproven", rep.Version, len(rep.Unproven))
	}
	_, _, err = withoutLink.judge(w, g1Active)
	if !errors.Is(err, ErrIntentProofV2Invalid) || !strings.Contains(err.Error(), "certify_link_missing{genesis}") {
		t.Fatalf("the continuous document without a genesis link under the activation: %v, want ErrIntentProofV2Invalid with certify_link_missing{genesis}", err)
	}
	// ... by the verifier consensus runs, with the named state itself
	var cs *proofv2.CertifyState
	if _, err := proofv2.VerifyEvidence21FromSpine(w.unlinked, w.spine, w.inc); !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyLinkMissing || len(cs.Fields) != 1 || cs.Fields[0] != "genesis" {
		t.Fatalf("VerifyEvidence21FromSpine on the continuous document without a genesis link: %v", err)
	}
	// ... and it is the offline walk's verdict on the same bytes, and the same report with the link
	if _, err := proofv2.Verify21FromGenesis(w.unlinked, w.ar, w.in, w.inc); !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyLinkMissing {
		t.Fatalf("the offline walk on the continuous document without a genesis link: %v", err)
	}
	offline, err := proofv2.Verify21FromGenesis(w.ev, w.ar, w.in, w.inc)
	if err != nil {
		t.Fatalf("the offline walk with the genesis link: %v", err)
	}
	a, _ := json.Marshal(rep)
	o, _ := json.Marshal(offline)
	if string(a) != string(o) {
		t.Fatal("the report consensus judged differs from the offline walk's")
	}
	// the root is govRoot v4 over exactly this report and evidence
	want, _, err := intentcert.GovRootV4(intentcert.GovRootV4Inputs{Report: rep, Evidence: c.cert.ProofV2, G0: c.g0, G1: c.g1, G2: c.g2,
		KeyPageURL: c.cert.KeyPageURL, KeyBookURL: c.cert.KeyBookURL, OperationID: c.operationID})
	if err != nil || want != root {
		t.Fatalf("the judged root %x is not govRoot v4 %x (%v)", root, want, err)
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

// withRecordedGenesisLink is a stored continuous live document as the builder emits it since RB9-F6: with the genesis link every evidence 2.1
// document needs, taken from Kermit's recorded answers (testdata/g1_live_anchored/links.json), the very receipt AnchorEvidence puts in the
// anchored form of the same document. The stored fixture is unchanged.
func withRecordedGenesisLink(t *testing.T, ev *proofv2.Evidence, archive json.RawMessage) *proofv2.Evidence {
	t.Helper()
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	ar, err := proofv2.UnmarshalArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := proofv2.AnchorEvidence(context.Background(), ev, ar, ir.Inputs, loadAnchoredLiveLinks(t))
	if err != nil {
		t.Fatal(err)
	}
	linked := *ev
	linked.GenesisLink = anchored.GenesisLink
	return &linked
}
