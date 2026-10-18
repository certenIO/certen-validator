package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The activation record the gate tests judge by: accepted at height 12, so evidence 2.1 is required from 13.
var g1Active = &ledger.G1ActivationRecord{Version: 1, Height: 12, ID: "g1-activation:test"}

// relabelled21 is the production proof's evidence with its version named 2.1: enough to pass the version gate, not a
// document the verifier accepts (it carries none of 2.1's anchors, routing or votes).
func relabelled21(t *testing.T, f *intentFixtureV3) *proofv2.Evidence {
	t.Helper()
	ev := v3Evidence(t, f)
	ev.Version = proofv2.Version21
	return ev
}

// RB9-C, rules v15: the certificate a block carries is judged by the activation in force for its height. Without one
// (every block until the activation, and the activation's own block) a 2.0 certificate is judged exactly as v14 judged it and
// a certificate carrying 2.1 is refused by name; with one, a 2.0 certificate is refused by name and a 2.1 one is judged
// by the verifier (here the real one, which refuses a document that is not a verifiable 2.1).
func TestTheCertificateGateFollowsTheActivation(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)

	// Before the activation: unchanged. The 2.0 certificate builds and verifies with no activation in force.
	vb := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
		t.Fatalf("a 2.0 certificate before the activation: %v", err)
	}
	if _, err := VerifyIntentCertificate(vb, intentChain, reg, spine, nil); err != nil {
		t.Fatalf("verify, no activation: %v", err)
	}

	// A certificate carrying 2.1 before the activation is refused by its own name, not as an invalid proof.
	pre := v3Block(t, f, "validator-1")
	err := BuildIntentCertificate(pre, intentChain, reg, rf.keys[0], intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence,
		f.ChainedProof, spine, nil, relabelled21(t, f))
	if !errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("2.1 before the activation: %v", err)
	}
	carried := *vb
	cert := *vb.IntentCertificate
	cert.ProofV2 = relabelled21(t, f)
	carried.IntentCertificate = &cert
	if _, err := VerifyIntentCertificate(&carried, intentChain, reg, spine, nil); !errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("a block carrying 2.1 before the activation: %v", err)
	}

	// From the activation on, the 2.0 certificate is refused by name - on the verifier's side and on the proposer's.
	if _, err := VerifyIntentCertificate(vb, intentChain, reg, spine, g1Active); !errors.Is(err, ErrIntentProofV21Missing) ||
		!strings.Contains(err.Error(), `"2.0"`) {
		t.Fatalf("a 2.0 certificate under the activation: %v", err)
	}
	post := v3Block(t, f, "validator-1")
	if err := buildV3G1(t, f, post, reg, rf, spine, g1Active, v3Evidence(t, f)); !errors.Is(err, ErrIntentProofV21Missing) {
		t.Fatalf("building a 2.0 certificate under the activation: %v", err)
	}
	if post.IntentCertificate != nil {
		t.Fatal("a refused certificate was left on the block")
	}

	// A document of 2.1 passes the gate and reaches the verifier, which judges it: here it is not a valid 2.1 document.
	err = buildV3G1(t, f, v3Block(t, f, "validator-1"), reg, rf, spine, g1Active, relabelled21(t, f))
	if !errors.Is(err, ErrIntentProofV2Invalid) || errors.Is(err, ErrIntentProofV21Missing) || errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("2.1 under the activation reaches the verifier: %v", err)
	}

	// The gate is v3's: with no spine the chain requires no proof v2 at all, activation or not, and a v2 certificate
	// verifies under an activation record exactly as without one.
	v2 := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, v2, reg, rf, nil, nil); err != nil {
		t.Fatalf("building the v2 certificate: %v", err)
	}
	if _, err := VerifyIntentCertificate(v2, intentChain, reg, nil, g1Active); err != nil {
		t.Fatalf("a v2 certificate where v3 is not required, with an activation recorded: %v", err)
	}
	// And a block that carries a proof v2 where v3 is not required is refused for that, whatever its version.
	if _, err := VerifyIntentCertificate(&carried, intentChain, reg, nil, g1Active); !errors.Is(err, ErrIntentProofV3NotInForce) {
		t.Fatalf("a proof v2 where v3 is not required: %v", err)
	}
}

func buildV3G1(t *testing.T, f *intentFixtureV3, vb *ValidatorBlock, reg *ledger.BLSRegistryRecord, rf *registryFixture,
	spine *ledger.AccumulateSpineLog, g1 *ledger.G1ActivationRecord, ev *proofv2.Evidence) error {
	t.Helper()
	return BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence,
		f.ChainedProof, spine, g1, ev)
}

// The app's judgement of a block's certificate reads the activation by the block's height: at the activation's own block
// and before it, a 2.0 certificate is accepted as v14 accepted it and the first v15 verdict is not recorded; one block later it
// is refused (code 10) and that refusal is a v15 verdict.
func TestAppJudgesTheCertificateByTheActivationInForceAtItsHeight(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)
	vb := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
		t.Fatal(err)
	}

	app, store := rotationApp(t, newRotationFixture())
	app.cometChainID = intentChain
	r := *reg
	r.Height = 10
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{r}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccumulateSpine(spine); err != nil {
		t.Fatal(err)
	}
	judge := func(h uint64) (*uint32, string) {
		app.currentBlockHeight = h
		app.blockRulesV15Verdict = false
		res := app.judgeIntentCertificate(vb)
		if res == nil {
			return nil, ""
		}
		return &res.Code, res.Log
	}

	// No activation: accepted.
	if code, log := judge(12); code != nil {
		t.Fatalf("height 12 with no activation: code %d (%s)", *code, log)
	}
	if app.blockRulesV15Verdict {
		t.Fatal("an accepted 2.0 certificate was counted a v15 verdict")
	}
	if err := store.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{*g1Active}}); err != nil {
		t.Fatal(err)
	}
	// The activation's own block: still v14's verdict.
	if code, log := judge(12); code != nil {
		t.Fatalf("the activation's own block (12): code %d (%s)", *code, log)
	}
	// Below it: the same.
	if code, log := judge(11); code != nil {
		t.Fatalf("height 11: code %d (%s)", *code, log)
	}
	// The next block: refused by name, a v15 verdict.
	code, log := judge(13)
	if code == nil || *code != codeIntentCertificateRefused || !strings.Contains(log, ErrIntentProofV21Missing.Error()) {
		t.Fatalf("height 13 under the activation: %v %q", code, log)
	}
	if !app.blockRulesV15Verdict {
		t.Fatal("the refusal only v15 reaches was not counted a v15 verdict")
	}

	// A 2.1 certificate (as21Verifier: see its comment) is accepted by the app at 13, and is a v15 verdict; at the
	// activation's own block it is refused by name with the same code.
	app.proofVerifier = as21Verifier(t)
	vb21 := v3Block(t, f, "validator-1")
	if err := buildIntentCertificate(vb21, intentChain, reg, rf.keys[0], intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence,
		f.ChainedProof, spine, g1Active, evidence21(t, f, spine), app.proofVerifier); err != nil {
		t.Fatal(err)
	}
	app.currentBlockHeight, app.blockRulesV15Verdict = 13, false
	if res := app.judgeIntentCertificate(vb21); res != nil {
		t.Fatalf("a 2.1 certificate at height 13: %+v", res)
	}
	if !app.blockRulesV15Verdict {
		t.Fatal("an accepted 2.1 certificate was not counted a v15 verdict (v14 refused every such block)")
	}
	app.currentBlockHeight, app.blockRulesV15Verdict = 12, false
	if res := app.judgeIntentCertificate(vb21); res == nil || res.Code != codeIntentCertificateRefused ||
		!strings.Contains(res.Log, ErrIntentProofV21NotInForce.Error()) {
		t.Fatalf("a 2.1 certificate at the activation's own block: %+v", res)
	}
	if app.blockRulesV15Verdict {
		t.Fatal("a refusal v14 also returns was counted a v15 verdict")
	}
	app.proofVerifier = nil

	// A certificate carrying 2.1 before the activation is refused with the code v14 refused it with (10): v15's pre-activation
	// result for the block is v14's, and it records no verdict.
	if err := store.SaveG1Activation(&ledger.G1ActivationLog{}); err != nil {
		t.Fatal(err)
	}
	carried := *vb
	cert := *vb.IntentCertificate
	cert.ProofV2 = relabelled21(t, f)
	carried.IntentCertificate = &cert
	app.currentBlockHeight = 13
	app.blockRulesV15Verdict = false
	res := app.judgeIntentCertificate(&carried)
	if res == nil || res.Code != codeIntentCertificateRefused || !strings.Contains(res.Log, ErrIntentProofV21NotInForce.Error()) {
		t.Fatalf("2.1 before the activation: %+v", res)
	}
	if app.blockRulesV15Verdict {
		t.Fatal("a refusal v14 also returns (code 10) was counted a v15 verdict")
	}
	// What v14 returned for the same bytes: a document that is not a verifiable proof v2 was refused as an invalid proof,
	// with the same code (10), so the block's result is v14's.
	if _, err := proofv2.VerifyFromSpine(cert.ProofV2, spine, [32]byte{}); err == nil {
		t.Fatal("the verifier accepts a relabelled version-2.1 document")
	}
}

// as21Verifier is the proof verifier of the GATE tests of this file, a test seam for the one thing they cannot build: a 2.1 document
// for the production fixture's intent (that intent's pages are not captured in the 2.1 form, and Kermit no longer serves them). It
// runs the REAL VerifyFromSpine on the production proof (the 2.0 form of the same document: S1-S2, the receipt, the spine, the pages;
// the 2.1 members the gate tests add - votes, partitions, roles - are removed first because the 2.0 entry point refuses them) and
// presents the report it gives as that of a 2.1 document: every page is listed as proven on the transaction's partition at its
// anchor block, with every role. These tests therefore pin what the gate adds - the activation, BindProofV21 over the intent's own
// vote evidence, govRoot v4 and the message - and nothing of 2.1's own verification. That is TestRulesV15AcceptsAVerifiedEvidence21
// (g1_real21_test.go), which runs the real VerifyEvidence21FromSpine over the real stored 2.1 document; production never names a
// verifier (defaultProofV2Verifier).
func as21Verifier(t *testing.T) proofV2Verifier {
	t.Helper()
	return func(ev *proofv2.Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*proofv2.Report, error) {
		if ev.Version != proofv2.Version21 {
			return nil, errors.New("not a 2.1 document")
		}
		twoZero := *ev
		twoZero.Version = proofv2.Version
		twoZero.Votes = nil
		twoZero.Pages = append([]proofv2.PageState(nil), ev.Pages...)
		for i := range twoZero.Pages {
			twoZero.Pages[i].Partition, twoZero.Pages[i].Roles = "", nil
		}
		rep, err := proofv2.VerifyFromSpine(&twoZero, l, pinned)
		if err != nil {
			return nil, err
		}
		roles, err := proofv2.CanonicalRoles(proofv2.KnownRoles)
		if err != nil {
			return nil, err
		}
		rep.Proven = nil
		for _, a := range rep.Pages {
			rep.Proven = append(rep.Proven, proofv2.ProvenPage{URL: a.GetUrl().String(), Partition: rep.Partition, Block: rep.AnchorBlock, Roles: roles})
		}
		return rep, nil
	}
}

// evidence21 is the production proof's evidence as a 2.1 document: its version, and the proven votes of the intent's own
// vote evidence (a 2.1 document carries them; govRoot v4 commits them).
func evidence21(t *testing.T, f *intentFixtureV3, spine *ledger.AccumulateSpineLog) *proofv2.Evidence {
	t.Helper()
	ev := relabelled21(t, f)
	// Each page names the partition it is proven on and why it is there, as the report does (as21Verifier).
	inc, err := hex32("0x" + kermitIncarnationHex)
	if err != nil {
		t.Fatal(err)
	}
	base, err := proofv2.VerifyFromSpine(v3Evidence(t, f), spine, inc)
	if err != nil {
		t.Fatal(err)
	}
	roles, err := proofv2.CanonicalRoles(proofv2.KnownRoles)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ev.Pages {
		ev.Pages[i].Partition, ev.Pages[i].Roles = base.Partition, roles
	}
	var gev govvote.Evidence
	if err := json.Unmarshal(f.VoteEvidence, &gev); err != nil {
		t.Fatal(err)
	}
	if len(gev.Votes) == 0 {
		t.Fatal("the production vote evidence records no vote")
	}
	for _, v := range gev.Votes {
		ev.Votes = append(ev.Votes, proofv2.Vote{Authority: v.Fact.Authority, Origin: v.Fact.Origin, Vote: v.Fact.Vote.String(),
			Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}, Message: voteMessageOf(v.Fact.ID)})
	}
	return ev
}

// From the height after the activation a 2.1 certificate is accepted - bound to the intent's vote evidence, committed under
// govRoot v4 and a message over it - and it is not the certificate a 2.0 document gives: the two roots differ.
func TestACertificateOverEvidence21IsAcceptedFromTheNextHeight(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)
	verify := as21Verifier(t)

	vb := v3Block(t, f, "validator-1")
	err := buildIntentCertificate(vb, intentChain, reg, rf.keys[0], intentKeyPage, intentKeyBook, f.record(t), f.VoteEvidence,
		f.ChainedProof, spine, g1Active, evidence21(t, f, spine), verify)
	if err != nil {
		t.Fatalf("a 2.1 certificate under the activation: %v", err)
	}
	cert := vb.IntentCertificate
	if cert.ProofV2.Version != proofv2.Version21 || cert.GovRootV3 == "" {
		t.Fatalf("not a 2.1 certificate: %q %q", cert.ProofV2.Version, cert.GovRootV3)
	}
	msg, err := verifyIntentCertificate(vb, intentChain, reg, spine, g1Active, verify)
	if err != nil {
		t.Fatalf("verifying it: %v", err)
	}

	// Before the activation, the same block is refused by name; the activation's own block counts as before.
	if _, err := verifyIntentCertificate(vb, intentChain, reg, spine, nil, verify); !errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("2.1 before the activation: %v", err)
	}

	// Its govRoot is v4's: the 2.0 certificate of the same intent commits a different root and signs a different message.
	old := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, old, reg, rf, spine, v3Evidence(t, f)); err != nil {
		t.Fatal(err)
	}
	if old.IntentCertificate.GovRootV3 == cert.GovRootV3 || old.IntentCertificate.Message == cert.Message {
		t.Fatal("govRoot v3 and v4 of one intent are the same")
	}
	if !hexEquals(cert.Message, msg) {
		t.Fatalf("the verified message %x is not the certificate's %s", msg, cert.Message)
	}

	// What the 2.1 certificate commits is what the evidence says: another vote, or a page proven at another block, is another root
	// the signature does not cover.
	for name, edit := range map[string]func(c *IntentCertificateEvidence){
		"another vote":      func(c *IntentCertificateEvidence) { c.ProofV2.Votes[0].Vote = "reject" },
		"another transport": func(c *IntentCertificateEvidence) { c.ProofV2.Votes[0].Transport.Kind = proofv2.TransportSequenced },
		"a dropped vote":    func(c *IntentCertificateEvidence) { c.ProofV2.Votes = nil },
	} {
		c := *vb
		ce := *vb.IntentCertificate
		pv := *ce.ProofV2
		pv.Votes = append([]proofv2.Vote(nil), ce.ProofV2.Votes...)
		ce.ProofV2 = &pv
		c.IntentCertificate = &ce
		edit(&ce)
		if _, err := verifyIntentCertificate(&c, intentChain, reg, spine, g1Active, verify); err == nil {
			t.Errorf("%s: the certificate still verifies", name)
		}
	}

	// A 2.1 document that does not carry the pages the intent needs is refused by the binding, by name.
	short := func(ev *proofv2.Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*proofv2.Report, error) {
		rep, err := verify(ev, l, pinned)
		if err != nil {
			return nil, err
		}
		rep.Proven[0].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage}
		return rep, nil
	}
	if _, err := verifyIntentCertificate(vb, intentChain, reg, spine, g1Active, short); !errors.Is(err, ErrIntentProofV2Invalid) {
		t.Fatalf("a 2.1 report whose pages lack their roles: %v", err)
	}
}

// voteMessageOf is the vote's entry hash in the principal's signature chain as a 2.1 document records it (hex32). The gate tests'
// documents are built from the production vote evidence, which names the vote by its transaction id; govRoot v4 commits the message as
// bytes, so the stand-in document gives it the hash of that id.
func voteMessageOf(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}
