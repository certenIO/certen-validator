package execution

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// The fixture is real evidence captured from Kermit — the actual account
// encodings of acc://dn.acme/network and acc://dn.acme/globals, their actual BPT
// membership receipts, and the actual chain merkle states.
const vspFixture = "../proof/testdata/validator_set_proof_kermit.json"

func loadBinding(t *testing.T) *AccumulateBinding {
	t.Helper()
	raw, err := os.ReadFile(vspFixture)
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	vsp := new(certenproof.ValidatorSetProof)
	if err := json.Unmarshal(raw, vsp); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	root, err := AccumulateSetRoot(vsp)
	if err != nil {
		t.Fatalf("compute set root: %v", err)
	}
	return &AccumulateBinding{
		Incarnation:       vsp.Incarnation,
		ValidatorSetRoot:  root,
		ValidatorSetProof: vsp,
	}
}

func assertedFrom(t *testing.T, b *AccumulateBinding) ([]chained_proof.ValidatorKey, chained_proof.Rational) {
	t.Helper()
	set, thr, err := b.ValidatorSetProof.DerivedSet()
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return set, thr
}

// TestL5Ext_RootMatchesTheOnChainEncoding is the join between the two halves:
// the root computed from the artifact's evidence must be the one
// CertenAnchorV8_2's pre-exec message commits. If these ever diverge, the chain
// commits to something the artifact cannot expand — decoration that looks like
// coverage.
func TestL5Ext_RootMatchesTheOnChainEncoding(t *testing.T) {
	b := loadBinding(t)
	root, err := AccumulateSetRoot(b.ValidatorSetProof)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 64 {
		t.Fatalf("root is not 32 bytes of hex: %q", root)
	}
	if !strings.EqualFold(root, b.ValidatorSetRoot) {
		t.Fatalf("restated root %s != computed %s", b.ValidatorSetRoot, root)
	}
	t.Logf("accumulateValidatorSetRoot = %s", root)
	t.Logf("  (this is the value CertenAnchorV8_2's pre-exec message commits)")
}

// TestL5Ext_AbsentIsNotAFailure. Every proof issued to date has no extension.
// If a missing one were a failure, an evidence outage would become a
// governance-proof failure.
func TestL5Ext_AbsentIsNotAFailure(t *testing.T) {
	l5 := &Layer5{
		ChainID: 84532, Network: "base-sepolia", AnchorTx: "0xabc", BlockNumber: 7,
		BatchRoot: strings.Repeat("11", 32), LeafHash: strings.Repeat("11", 32),
	}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("a Layer5 with no extension must verify exactly as before: %v", err)
	}

	var b *AccumulateBinding
	res := b.Verify(nil, chained_proof.Rational{}, "", nil)
	if res.Present {
		t.Fatal("a nil binding must not report as present")
	}
	if res.Err != nil {
		t.Fatalf("a nil binding must not be an error: %v", res.Err)
	}
	if !strings.Contains(res.Claim(), "asserted") {
		t.Fatalf("the claim must say the set is asserted, got: %s", res.Claim())
	}
}

// TestL5Ext_VerdictsCarryThrough — the extension must surface the same ladder the
// ValidatorSetProof produces, never collapsing a weaker state into a pass.
func TestL5Ext_VerdictsCarryThrough(t *testing.T) {
	b := loadBinding(t)
	set, thr := assertedFrom(t, b)
	pin := b.Incarnation
	other := "672f89ffc3cc87cff9a7fea1529ec893ec775e49e0cf4da1ab9c927979176e17"

	cases := []struct {
		name  string
		bound string
		pin   *string
		want  certenproof.Verdict
	}{
		{"unbound — the normal state today", "", &pin, certenproof.VerdictValidatorSetUnbound},
		{"bound, no pin held", b.ValidatorSetProof.Network.StateReceipt.Anchor, nil,
			certenproof.VerdictIncarnationUnverified},
		{"bound and pinned", b.ValidatorSetProof.Network.StateReceipt.Anchor, &pin,
			certenproof.VerdictVerified},
		{"bound, pinned to a different chain", b.ValidatorSetProof.Network.StateReceipt.Anchor, &other,
			certenproof.VerdictForeignIncarnation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := b.Verify(set, thr, tc.bound, tc.pin)
			if res.Err != nil {
				t.Fatalf("weaker states must not be errors: %v", res.Err)
			}
			if !res.Present {
				t.Fatal("binding should be present")
			}
			if res.Verdict != tc.want {
				t.Fatalf("verdict %q, wanted %q", res.Verdict, tc.want)
			}
			if tc.want != certenproof.VerdictVerified && strings.Contains(res.Claim(), "was derived from chain state, bound to a") {
				t.Fatalf("a weaker verdict must not read as the full claim: %s", res.Claim())
			}
		})
	}
}

// TestL5Ext_RefusesInconsistentEvidence — present and wrong is an ERROR, which is
// a different thing from present and weak.
func TestL5Ext_RefusesInconsistentEvidence(t *testing.T) {
	cases := map[string]func(*AccumulateBinding){
		"restated root does not match the evidence": func(b *AccumulateBinding) {
			b.ValidatorSetRoot = strings.Repeat("ab", 32)
		},
		"binding and proof name different incarnations": func(b *AccumulateBinding) {
			b.Incarnation = "672f89ffc3cc87cff9a7fea1529ec893ec775e49e0cf4da1ab9c927979176e17"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := loadBinding(t)
			set, thr := assertedFrom(t, b)
			mutate(b)
			res := b.Verify(set, thr, "", nil)
			if res.Err == nil {
				t.Fatalf("accepted inconsistent evidence (%s); verdict %q", name, res.Verdict)
			}
			if !strings.Contains(res.Claim(), "does NOT check out") {
				t.Fatalf("the claim must report a failure, got: %s", res.Claim())
			}
			t.Logf("refused: %v", res.Err)
		})
	}
}

// TestL5Ext_ClaimNeverOverstates. The caveat shrinks only when the evidence is
// carried, and even then it must not assert the binding or the pin.
func TestL5Ext_ClaimNeverOverstates(t *testing.T) {
	l5 := &Layer5{
		ChainID: 84532, Network: "base-sepolia", AnchorTx: "0xabc", BlockNumber: 7,
		BatchRoot: strings.Repeat("11", 32), LeafHash: strings.Repeat("11", 32),
	}

	without := l5.ExternalClaim()
	if !strings.Contains(without, "NOT to whether the Accumulate validator set") {
		t.Fatalf("without the extension the original caveat must stand verbatim:\n%s", without)
	}

	l5.Accumulate = loadBinding(t)
	with := l5.ExternalClaim()
	if strings.Contains(with, "NOT to whether the Accumulate validator set") {
		t.Fatalf("with evidence carried the caveat should have narrowed:\n%s", with)
	}
	for _, must := range []string{"EVIDENCE", "does not say", "out-of-band pin"} {
		if !strings.Contains(with, must) {
			t.Fatalf("the narrowed claim must still bound itself (missing %q):\n%s", must, with)
		}
	}
	// It must never claim the strong thing.
	for _, forbidden := range []string{"is the legitimate", "proves the validator set"} {
		if strings.Contains(with, forbidden) {
			t.Fatalf("the claim overstates (%q):\n%s", forbidden, with)
		}
	}
	t.Logf("with evidence: %s", with)
}
