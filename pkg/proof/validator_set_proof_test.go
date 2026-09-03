package proof

import (
	"encoding/json"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// The fixture is REAL evidence captured from Kermit, not hand-built bytes: the
// actual account encodings of acc://dn.acme/network and acc://dn.acme/globals,
// their actual BPT membership receipts, and the actual chain DAG roots folded
// from the chain query's merkle state. A test built on synthetic bytes would
// prove the code self-consistent; this proves it works on what the network
// actually serves.
const fixture = "testdata/validator_set_proof_kermit.json"

func load(t *testing.T) *ValidatorSetProof {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p := new(ValidatorSetProof)
	if err := json.Unmarshal(raw, p); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return p
}

// goodInput builds the VerifyInput that a correct proof should satisfy, deriving
// the asserted set from the proof itself — which is what the real builder does,
// since layer4.go populates ValidatorSet from the same network.
func goodInput(t *testing.T, p *ValidatorSetProof) VerifyInput {
	t.Helper()
	set, thr, err := p.DerivedSet()
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return VerifyInput{
		AssertedSet:          set,
		AssertedThreshold:    thr,
		BoundStateTreeAnchor: p.Network.StateReceipt.Anchor,
	}
}

// TestVSP_DerivesTheRealSet is the headline: the validator set and the accept
// threshold both come out of chain bytes, with no assertion anywhere.
func TestVSP_DerivesTheRealSet(t *testing.T) {
	p := load(t)
	set, thr, err := p.DerivedSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set) == 0 {
		t.Fatal("derived an empty validator set")
	}
	if thr.Denominator == 0 || thr.Numerator == 0 {
		t.Fatalf("derived a nonsense threshold %d/%d", thr.Numerator, thr.Denominator)
	}
	height, ok := p.MainChainHeight()
	if !ok {
		t.Fatal("no main chain")
	}
	t.Logf("derived %d validators, threshold %d/%d, network main chain height %d",
		len(set), thr.Numerator, thr.Denominator, height)
	for _, v := range set {
		t.Logf("  %s active on %v", v.PublicKey[:16], v.ActiveOn)
	}
	if height == 1 {
		t.Logf("height 1 => only the genesis entry exists => this IS the genesis set " +
			"of this incarnation")
	}
}

// TestVSP_ChainHeightsAreBound is the Phase 6 defect-2 regression. The state
// hasher is [main, secondaryState, chains, pending], so the receipt's second
// step is H(chains||pending) and the chain roots ALONE cannot be checked. If
// this passes, MainChainHeight is proven rather than asserted.
func TestVSP_ChainHeightsAreBound(t *testing.T) {
	p := load(t)
	if err := p.Network.verifyChainBinding(); err != nil {
		t.Fatalf("network chain binding failed: %v", err)
	}
	if err := p.Globals.verifyChainBinding(); err != nil {
		t.Fatalf("globals chain binding failed: %v", err)
	}
}

// TestVSP_PendingHashIsRequired guards the same defect from the other side: an
// implementation that omitted PendingHash would have compiled, passed a naive
// test, and silently proved nothing.
func TestVSP_PendingHashIsRequired(t *testing.T) {
	p := load(t)
	p.Network.PendingHash = ""
	if _, err := p.Verify(goodInput(t, load(t))); err == nil {
		t.Fatal("accepted a proof with no pendingHash; the chain heights would be unbound")
	}
}

// TestVSP_VerdictLadder walks every outcome. The weaker states must never be
// reported as errors, and must never be reported as verified.
func TestVSP_VerdictLadder(t *testing.T) {
	pin := load(t).Incarnation
	other := "672f89ffc3cc87cff9a7fea1529ec893ec775e49e0cf4da1ab9c927979176e17" // MainNet's

	cases := []struct {
		name     string
		mutate   func(*ValidatorSetProof)
		mutateIn func(*VerifyInput)
		pinned   *string
		want     Verdict
	}{
		{"pinned and matching", nil, nil, &pin, VerdictVerified},
		{"no pin held", nil, nil, nil, VerdictIncarnationUnverified},
		{"pinned but different chain", nil, nil, &other, VerdictForeignIncarnation},
		{"artifact names no incarnation",
			func(p *ValidatorSetProof) { p.Incarnation = "" }, nil, &pin, VerdictIncarnationUnknown},
		{"derived but not bound to a signed anchor — the normal state today",
			nil, func(in *VerifyInput) { in.BoundStateTreeAnchor = "" }, &pin, VerdictValidatorSetUnbound},
		{"no network evidence at all",
			func(p *ValidatorSetProof) { p.Network.AccountState = "" }, nil, &pin, VerdictValidatorSetAsserted},
		{"membership without the denominator",
			func(p *ValidatorSetProof) { p.Globals.AccountState = "" }, nil, &pin, VerdictValidatorSetAsserted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := load(t)
			in := goodInput(t, load(t))
			if tc.mutate != nil {
				tc.mutate(p)
			}
			if tc.mutateIn != nil {
				tc.mutateIn(&in)
			}
			in.PinnedIncarnation = tc.pinned
			got, err := p.Verify(in)
			if err != nil {
				t.Fatalf("a weaker verdict must not be an error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("verdict %q, wanted %q", got, tc.want)
			}
			if got != VerdictVerified && !got.Weaker() {
				t.Fatalf("%q must report as weaker than verified", got)
			}
		})
	}
}

// TestVSP_RefusesTampering — these are PROVEN WRONG, so each must be an error
// rather than a weaker verdict. Confusing the two is the defect this project has
// removed twice: a capability limit reported as a governance rejection, or
// tampering reported as a capability limit.
func TestVSP_RefusesTampering(t *testing.T) {
	pin := load(t).Incarnation

	cases := map[string]func(*ValidatorSetProof, *VerifyInput){
		"account bytes changed": func(p *ValidatorSetProof, _ *VerifyInput) {
			b := []byte(p.Network.AccountState)
			b[len(b)-1] ^= 0x01
			p.Network.AccountState = string(b)
		},
		"receipt path step altered": func(p *ValidatorSetProof, _ *VerifyInput) {
			last := len(p.Network.StateReceipt.Entries) - 1
			h := []byte(p.Network.StateReceipt.Entries[last].Hash)
			if h[0] == 'a' {
				h[0] = 'b'
			} else {
				h[0] = 'a'
			}
			p.Network.StateReceipt.Entries[last].Hash = string(h)
		},
		// The DANGEROUS direction: understating the height makes an account whose
		// validator set has changed look like it still holds its genesis set, so
		// step 16's base case would fire on a set that is not the genesis set.
		"chain height DEFLATED to fake the base case": func(p *ValidatorSetProof, _ *VerifyInput) {
			for i := range p.Network.Chains {
				if p.Network.Chains[i].Name == "main-index" {
					p.Network.Chains[i].Count = 1
				}
			}
			for i := range p.Network.Chains {
				if p.Network.Chains[i].Name == "main" {
					p.Network.Chains[i].Count = 1
					// pretend a five-entry chain is a one-entry chain
					five := "0000000000000000000000000000000000000000000000000000000000000005"
					p.Network.Chains[i].Pending = []*string{nil, nil, &five}
				}
			}
		},
		"chain height inflated": func(p *ValidatorSetProof, _ *VerifyInput) {
			for i := range p.Network.Chains {
				if p.Network.Chains[i].Name == "main" {
					p.Network.Chains[i].Count = 99
				}
			}
		},
		"asserted set does not match the chain": func(_ *ValidatorSetProof, in *VerifyInput) {
			in.AssertedSet = append([]chained_proof.ValidatorKey{}, in.AssertedSet...)
			in.AssertedSet[0].PublicKey = "00" + in.AssertedSet[0].PublicKey[2:]
		},
		"asserted threshold does not match the chain": func(_ *ValidatorSetProof, in *VerifyInput) {
			in.AssertedThreshold.Numerator++
		},
		"BPT root not bound to a signed anchor": func(_ *ValidatorSetProof, in *VerifyInput) {
			in.BoundStateTreeAnchor = "00000000000000000000000000000000000000000000000000000000000000ff"
		},
		"the two accounts read at different blocks": func(p *ValidatorSetProof, _ *VerifyInput) {
			p.Globals.StateReceipt.Anchor = p.Globals.StateReceipt.Start
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := load(t)
			in := goodInput(t, load(t))
			in.PinnedIncarnation = &pin
			mutate(p, &in)
			verdict, err := p.Verify(in)
			if err == nil {
				t.Fatalf("accepted tampering (%s) with verdict %q", name, verdict)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestVSP_NilIsNotAFailure. Every proof issued before this type existed carries
// no ValidatorSetProof. Failing them would turn a capability limit into a
// governance rejection.
func TestVSP_NilIsNotAFailure(t *testing.T) {
	var p *ValidatorSetProof
	got, err := p.Verify(VerifyInput{})
	if err != nil {
		t.Fatalf("a nil proof must not be an error: %v", err)
	}
	if got != VerdictValidatorSetAsserted {
		t.Fatalf("verdict %q, wanted %q", got, VerdictValidatorSetAsserted)
	}
}
