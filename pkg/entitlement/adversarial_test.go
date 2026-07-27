package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// Adversarial suite for the entitlement verifier.
//
// The verifier decides whether CERTEN spends its own money on 14 chains, so the
// question is not "does it work" but "what does it refuse". Each test here is an
// attack an unpaid caller would actually try.
//
// Scope note: this file probes the VERIFIER, which is pure and self-contained.
// Whether the principal it is handed is trustworthy is a separate question, and
// a worse one — see TestPrincipalIsProposerAsserted in pkg/consensus.

const advNow = int64(1_800_000_000)

type advFixture struct {
	keys   KeySet
	priv   ed25519.PrivateKey
	keyID  string
	set    *Set
	header Header
}

func newAdvFixture(t *testing.T, leaves ...Leaf) *advFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "entitlement-v1"
	set := &Set{Leaves: leaves}
	setHash, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	hdr := Header{
		Epoch: 7, Root: set.Root(), SetHash: setHash,
		NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix:   advNow - 60, NotAfterUnix: advNow + 900,
		KeyID: keyID,
	}
	hdr.Signature = hex.EncodeToString(ed25519.Sign(priv, hdr.SigningBytes()))
	return &advFixture{keys: KeySet{keyID: pub}, priv: priv, keyID: keyID, set: set, header: hdr}
}

func (f *advFixture) evidence(t *testing.T, adi string) *Evidence {
	t.Helper()
	proof, leaf, ok := f.set.BuildProof(adi)
	if !ok {
		t.Fatalf("no proof for %s", adi)
	}
	return &Evidence{Header: f.header, Leaf: leaf, Proof: proof}
}

func (f *advFixture) reseal(ev *Evidence) {
	ev.Header.Signature = hex.EncodeToString(ed25519.Sign(f.priv, ev.Header.SigningBytes()))
}

func activeLeafA(adi string) Leaf {
	return Leaf{ADIURL: adi, Status: StatusActive,
		IntentCeilingMicroUSD: 25_000_000, EpochCeilingMicroUSD: 97_500_000}
}

func reasonOf2(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	if ve, ok := err.(*VerifyError); ok {
		return ve.Reason
	}
	return "UNTYPED:" + err.Error()
}

const payerA = "acc://payer-a.acme/data"
const payerB = "acc://payer-b.acme/data"

// ── Baseline ────────────────────────────────────────────────────────────────

func TestHonestEvidencePasses(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA), activeLeafA(payerB))
	if err := Verify(f.evidence(t, payerA), payerA, advNow, f.keys); err != nil {
		t.Fatalf("honest evidence rejected: %v", err)
	}
}

// ── Forgery of the signed header ────────────────────────────────────────────

// Signing with a key the fleet does not trust must fail, or anyone could mint
// entitlements.
func TestAttackerSignedEpochIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)

	ev := f.evidence(t, payerA)
	ev.Header.Signature = hex.EncodeToString(ed25519.Sign(attacker, ev.Header.SigningBytes()))

	if got := reasonOf2(t, Verify(ev, payerA, advNow, f.keys)); got != ReasonBadSignature {
		t.Fatalf("reason = %s, want %s", got, ReasonBadSignature)
	}
}

// Naming an unknown key id must fail closed rather than skip verification.
func TestUnknownKeyIDIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	ev := f.evidence(t, payerA)
	ev.Header.KeyID = "attacker-key"

	if got := reasonOf2(t, Verify(ev, payerA, advNow, f.keys)); got != ReasonUnknownKey {
		t.Fatalf("reason = %s, want %s", got, ReasonUnknownKey)
	}
}

// Every signed field must be covered, or the covered ones are decoration.
func TestTamperingWithAnySignedHeaderFieldIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"root", func(e *Evidence) { e.Header.Root = strings.Repeat("aa", 32) }},
		{"set hash", func(e *Evidence) { e.Header.SetHash = strings.Repeat("bb", 32) }},
		{"epoch", func(e *Evidence) { e.Header.Epoch = 9999 }},
		{"not after", func(e *Evidence) { e.Header.NotAfterUnix = advNow + 999999 }},
		{"issued at", func(e *Evidence) { e.Header.IssuedAtUnix = advNow }},
		{"native price", func(e *Evidence) { e.Header.NativeUSDMicro = 1 }},
		{"prev root", func(e *Evidence) { e.Header.PrevRoot = strings.Repeat("cc", 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdvFixture(t, activeLeafA(payerA))
			ev := f.evidence(t, payerA)
			tc.mutate(ev)
			if err := Verify(ev, payerA, advNow, f.keys); err == nil {
				t.Fatalf("tampering with %s was accepted", tc.name)
			}
		})
	}
}

// ── Freshness ───────────────────────────────────────────────────────────────

// An epoch past its expiry must be refused even though its signature is
// perfectly valid — otherwise killing the publisher grants unlimited free
// service on the last good epoch.
func TestExpiredEpochIsRefusedEvenWithAValidSignature(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	ev := f.evidence(t, payerA)

	if got := reasonOf2(t, Verify(ev, payerA, ev.Header.NotAfterUnix+1, f.keys)); got != ReasonStale {
		t.Fatalf("reason = %s, want %s", got, ReasonStale)
	}
	// Exactly at expiry is still valid; one second past is not.
	if err := Verify(ev, payerA, ev.Header.NotAfterUnix, f.keys); err != nil {
		t.Fatalf("epoch rejected exactly at its expiry: %v", err)
	}
}

// A publisher that signs epochs far in the future would otherwise be able to
// mint an entitlement that outlives any revocation.
func TestFutureDatedEpochIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	ev := f.evidence(t, payerA)
	ev.Header.IssuedAtUnix = advNow + 3600
	ev.Header.NotAfterUnix = advNow + 7200
	f.reseal(ev)

	if got := reasonOf2(t, Verify(ev, payerA, advNow, f.keys)); got != ReasonStale {
		t.Fatalf("reason = %s, want %s", got, ReasonStale)
	}
}

// A missing expiry must not mean "never expires".
func TestZeroNotAfterIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	ev := f.evidence(t, payerA)
	ev.Header.NotAfterUnix = 0
	f.reseal(ev)

	if got := reasonOf2(t, Verify(ev, payerA, advNow, f.keys)); got != ReasonStale {
		t.Fatalf("reason = %s, want %s", got, ReasonStale)
	}
}

// ── Principal binding ───────────────────────────────────────────────────────

// Presenting a legitimately entitled account's evidence for a DIFFERENT
// principal is the most obvious attack, and must fail.
func TestEvidenceForAnotherAccountIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA), activeLeafA(payerB))
	if got := reasonOf2(t, Verify(f.evidence(t, payerA), payerB, advNow, f.keys)); got != ReasonPrincipalMatch {
		t.Fatalf("reason = %s, want %s", got, ReasonPrincipalMatch)
	}
}

// Accumulate URLs are case-insensitive, so a case-only difference must not be
// exploitable in EITHER direction: not as a bypass, not as a false refusal.
func TestCaseVariantPrincipalStillMatches(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	upper := strings.ToUpper(payerA)
	if err := Verify(f.evidence(t, payerA), upper, advNow, f.keys); err != nil {
		t.Fatalf("case-variant principal was refused: %v", err)
	}
}

// A data account and its identity are DIFFERENT accounts. Treating them as one
// would let an entitlement for one authorise spending for the other.
func TestIdentityAndDataAccountAreNotInterchangeable(t *testing.T) {
	f := newAdvFixture(t, activeLeafA("acc://payer-a.acme/data"))
	if err := Verify(f.evidence(t, "acc://payer-a.acme/data"), "acc://payer-a.acme", advNow, f.keys); err == nil {
		t.Fatal("evidence for the data account authorised the bare identity")
	}
}

func TestEmptyPrincipalIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	if err := Verify(f.evidence(t, payerA), "", advNow, f.keys); err == nil {
		t.Fatal("an empty principal was accepted")
	}
}

// ── Inclusion proof ─────────────────────────────────────────────────────────

// Inventing a leaf that was never in the signed set must fail: this is minting
// an entitlement outright.
func TestFabricatedLeafIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	ev := f.evidence(t, payerA)
	ev.Leaf = activeLeafA("acc://attacker.acme/data")

	if err := Verify(ev, "acc://attacker.acme/data", advNow, f.keys); err == nil {
		t.Fatal("a fabricated leaf was accepted")
	}
}

// Upgrading your own leaf after the fact — raising a ceiling, flipping status —
// must break inclusion, since the leaf is hashed into the signed root.
func TestUpgradingYourOwnLeafIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Leaf)
	}{
		{"raise the intent ceiling", func(l *Leaf) { l.IntentCeilingMicroUSD = 1 << 40 }},
		{"raise the epoch ceiling", func(l *Leaf) { l.EpochCeilingMicroUSD = 1 << 40 }},
		{"flip status to active", func(l *Leaf) { l.Status = StatusActive }},
		{"change tier", func(l *Leaf) { l.Tier = "enterprise" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suspended := Leaf{ADIURL: payerA, Status: StatusSuspended, Tier: "starter"}
			f := newAdvFixture(t, suspended)
			ev := f.evidence(t, payerA)
			tc.mutate(&ev.Leaf)
			if err := Verify(ev, payerA, advNow, f.keys); err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
		})
	}
}

// Truncating or padding the proof path must not reach the root by accident.
func TestMutatedProofPathIsRefused(t *testing.T) {
	f := newAdvFixture(t,
		activeLeafA(payerA), activeLeafA(payerB),
		activeLeafA("acc://c.acme/data"), activeLeafA("acc://d.acme/data"))

	t.Run("truncated", func(t *testing.T) {
		ev := f.evidence(t, payerA)
		if len(ev.Proof) == 0 {
			t.Skip("proof has no steps to truncate")
		}
		ev.Proof = ev.Proof[:len(ev.Proof)-1]
		if err := Verify(ev, payerA, advNow, f.keys); err == nil {
			t.Fatal("a truncated proof was accepted")
		}
	})
	t.Run("flipped direction", func(t *testing.T) {
		ev := f.evidence(t, payerA)
		if len(ev.Proof) == 0 {
			t.Skip("proof has no steps to flip")
		}
		ev.Proof[0].Right = !ev.Proof[0].Right
		if err := Verify(ev, payerA, advNow, f.keys); err == nil {
			t.Fatal("a proof with a flipped sibling direction was accepted")
		}
	})
	t.Run("empty", func(t *testing.T) {
		ev := f.evidence(t, payerA)
		ev.Proof = nil
		if err := Verify(ev, payerA, advNow, f.keys); err == nil {
			t.Fatal("an empty proof was accepted for a multi-leaf set")
		}
	})
}

// Splicing a header from one epoch onto a leaf and proof from another must
// fail, or an account could be entitled by an epoch it was never in.
func TestCrossEpochSpliceIsRefused(t *testing.T) {
	old := newAdvFixture(t, activeLeafA(payerA))
	current := newAdvFixture(t, Leaf{ADIURL: payerA, Status: StatusSuspended})

	// The current, correctly signed header — with the old epoch's entitled leaf.
	spliced := old.evidence(t, payerA)
	spliced.Header = current.header

	if err := Verify(spliced, payerA, advNow, current.keys); err == nil {
		t.Fatal("a leaf from a previous epoch was accepted under the current header")
	}
}

// ── The entitlement predicate ───────────────────────────────────────────────

// Being in the set is not the same as being entitled. Suspended and closed
// accounts are published precisely so their state is provable.
func TestNonActiveStatusIsRefused(t *testing.T) {
	for _, status := range []Status{StatusSuspended, StatusClosed} {
		t.Run(string(status), func(t *testing.T) {
			f := newAdvFixture(t, Leaf{
				ADIURL: payerA, Status: status,
				IntentCeilingMicroUSD: 25_000_000,
			})
			if got := reasonOf2(t, Verify(f.evidence(t, payerA), payerA, advNow, f.keys)); got != ReasonNotEntitled {
				t.Fatalf("status %s: reason = %s, want %s", status, got, ReasonNotEntitled)
			}
		})
	}
}

// An active account with a zero ceiling can spend nothing. Treating zero as
// "unlimited" would be the classic sign-error bypass.
func TestActiveWithZeroCeilingIsRefused(t *testing.T) {
	f := newAdvFixture(t, Leaf{ADIURL: payerA, Status: StatusActive, IntentCeilingMicroUSD: 0})
	if got := reasonOf2(t, Verify(f.evidence(t, payerA), payerA, advNow, f.keys)); got != ReasonNotEntitled {
		t.Fatalf("reason = %s, want %s", got, ReasonNotEntitled)
	}
}

// ── Absence ─────────────────────────────────────────────────────────────────

// No evidence must never mean "assume entitled".
func TestNilEvidenceIsRefused(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	if got := reasonOf2(t, Verify(nil, payerA, advNow, f.keys)); got != ReasonNoEvidence {
		t.Fatalf("reason = %s, want %s", got, ReasonNoEvidence)
	}
}

// An empty trusted key set must refuse everything rather than skip the check.
func TestEmptyKeySetRefusesEverything(t *testing.T) {
	f := newAdvFixture(t, activeLeafA(payerA))
	if err := Verify(f.evidence(t, payerA), payerA, advNow, KeySet{}); err == nil {
		t.Fatal("an empty key set accepted evidence")
	}
}
