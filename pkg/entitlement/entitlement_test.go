package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This gate is the only thing standing between CERTEN and doing unbounded work
// for free. The positive path is easy; the tests that matter are the ones that
// try to get service without paying.

const (
	now       = int64(1_800_000_000)
	oneHour   = int64(3600)
	principal = "acc://payer.acme/data"
)

type fixture struct {
	set    *Set
	keys   KeySet
	priv   ed25519.PrivateKey
	keyID  string
	header Header
}

func newFixture(t *testing.T, leaves ...Leaf) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "test-key-1"
	set := &Set{Leaves: leaves}
	setHash, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		set:   set,
		keys:  KeySet{keyID: pub},
		priv:  priv,
		keyID: keyID,
	}
	f.header = f.sign(Header{
		Epoch:          7,
		Root:           set.Root(),
		SetHash:        setHash,
		NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix:   now - 60,
		NotAfterUnix:   now + oneHour,
		KeyID:          keyID,
	})
	return f
}

func (f *fixture) sign(h Header) Header {
	h.Signature = hex.EncodeToString(ed25519.Sign(f.priv, h.SigningBytes()))
	return h
}

// evidence builds well-formed evidence for an ADI in the set.
func (f *fixture) evidence(t *testing.T, adi string) *Evidence {
	t.Helper()
	proof, leaf, ok := f.set.BuildProof(adi)
	if !ok {
		t.Fatalf("%s is not in the set", adi)
	}
	return &Evidence{Header: f.header, Leaf: leaf, Proof: proof}
}

func activeLeaf(adi string) Leaf {
	return Leaf{ADIURL: adi, Status: StatusActive, Tier: "growth",
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 100_000_000}
}

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
	return ve.Reason
}

// ── The happy path ──────────────────────────────────────────────────────────

func TestFundedAccountIsServed(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	if err := Verify(f.evidence(t, principal), principal, now, f.keys); err != nil {
		t.Fatalf("a funded, active account must be served: %v", err)
	}
}

func TestWorksAcrossManySetSizes(t *testing.T) {
	// Merkle path construction is where off-by-ones live, especially with odd
	// node counts promoting unchanged. Exercise every size boundary.
	for n := 1; n <= 33; n++ {
		leaves := make([]Leaf, 0, n)
		for i := range n {
			leaves = append(leaves, activeLeaf(fmt.Sprintf("acc://payer%03d.acme/data", i)))
		}
		f := newFixture(t, leaves...)
		for i := range n {
			adi := fmt.Sprintf("acc://payer%03d.acme/data", i)
			if err := Verify(f.evidence(t, adi), adi, now, f.keys); err != nil {
				t.Fatalf("set size %d, member %d rejected: %v", n, i, err)
			}
		}
	}
}

// ── Refusals: the whole point ───────────────────────────────────────────────

func TestNoEvidenceIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	err := Verify(nil, principal, now, f.keys)
	if got := reasonOf(t, err); got != ReasonNoEvidence {
		t.Fatalf("absent evidence must fail closed, got %s", got)
	}
}

// The direct-submit bypass, exactly: a stranger writes an intent to Accumulate
// and has no entitlement. They cannot construct evidence, so they are refused.
func TestAccountAbsentFromSetCannotProveEntitlement(t *testing.T) {
	f := newFixture(t, activeLeaf("acc://someone-else.acme/data"))
	if _, _, ok := f.set.BuildProof(principal); ok {
		t.Fatal("built a proof for an account that is not in the set")
	}
	// The best a stranger can do is present a leaf they invented.
	forged := &Evidence{Header: f.header, Leaf: activeLeaf(principal), Proof: nil}
	if got := reasonOf(t, Verify(forged, principal, now, f.keys)); got != ReasonBadProof {
		t.Fatalf("an invented leaf must fail inclusion, got %s", got)
	}
}

func TestSuspendedAccountIsRefused(t *testing.T) {
	l := activeLeaf(principal)
	l.Status = StatusSuspended
	f := newFixture(t, l)
	if got := reasonOf(t, Verify(f.evidence(t, principal), principal, now, f.keys)); got != ReasonNotEntitled {
		t.Fatalf("suspended must refuse, got %s", got)
	}
}

func TestClosedAccountIsRefused(t *testing.T) {
	l := activeLeaf(principal)
	l.Status = StatusClosed
	f := newFixture(t, l)
	if got := reasonOf(t, Verify(f.evidence(t, principal), principal, now, f.keys)); got != ReasonNotEntitled {
		t.Fatalf("closed must refuse, got %s", got)
	}
}

func TestZeroCeilingIsRefused(t *testing.T) {
	// Active but broke. Status alone must not authorize spending.
	l := activeLeaf(principal)
	l.IntentCeilingMicroUSD = 0
	f := newFixture(t, l)
	if got := reasonOf(t, Verify(f.evidence(t, principal), principal, now, f.keys)); got != ReasonNotEntitled {
		t.Fatalf("a zero ceiling must refuse, got %s", got)
	}
}

// ── Forgery and substitution ────────────────────────────────────────────────

// The attack this design exists to stop: lifting a funded account's evidence
// onto your own intent.
func TestCannotUseAnotherAccountsEvidence(t *testing.T) {
	payer := "acc://payer.acme/data"
	freeloader := "acc://freeloader.acme/data"
	f := newFixture(t, activeLeaf(payer))

	ev := f.evidence(t, payer) // perfectly valid evidence...
	err := Verify(ev, freeloader, now, f.keys)
	if got := reasonOf(t, err); got != ReasonPrincipalMatch {
		t.Fatalf("evidence must be bound to the intent principal, got %s", got)
	}
}

func TestUnsignedHeaderIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	ev := f.evidence(t, principal)
	ev.Header.Signature = ""
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonBadSignature {
		t.Fatalf("unsigned header must refuse, got %s", got)
	}
}

func TestUnknownSigningKeyIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	ev := f.evidence(t, principal)
	ev.Header.KeyID = "some-key-we-never-pinned"
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonUnknownKey {
		t.Fatalf("an unpinned key must refuse, got %s", got)
	}
}

// Self-signing: an attacker generates their own keypair and signs a header
// granting themselves service. Must fail on the pinned key set.
func TestSelfSignedHeaderIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)

	ev := f.evidence(t, principal)
	ev.Header.Signature = hex.EncodeToString(ed25519.Sign(evilPriv, ev.Header.SigningBytes()))
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonBadSignature {
		t.Fatalf("a header signed by an unknown key must refuse, got %s", got)
	}
}

// Every signed field must actually be covered by the signature.
func TestEverySignedHeaderFieldIsTamperEvident(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	base := f.evidence(t, principal)

	mutations := map[string]func(*Header){
		"epoch":      func(h *Header) { h.Epoch++ },
		"root":       func(h *Header) { h.Root = strings.Repeat("ab", 32) },
		"set_hash":   func(h *Header) { h.SetHash = strings.Repeat("cd", 32) },
		"prev_root":  func(h *Header) { h.PrevRoot = strings.Repeat("ef", 32) },
		"native_usd": func(h *Header) { h.NativeUSDMicro *= 1000 },
		"issued_at":  func(h *Header) { h.IssuedAtUnix -= 10 },
		"not_after":  func(h *Header) { h.NotAfterUnix += 86400 },
	}
	for name, mutate := range mutations {
		ev := *base
		hdr := base.Header
		mutate(&hdr)
		ev.Header = hdr
		err := Verify(&ev, principal, now, f.keys)
		if err == nil {
			t.Fatalf("tampering with %q was not detected", name)
		}
		if got := reasonOf(t, err); got != ReasonBadSignature {
			t.Fatalf("tampering with %q should break the signature, got %s", name, got)
		}
	}
}

// Raising your own ceiling must invalidate the inclusion proof.
func TestTamperedLeafIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal), activeLeaf("acc://other.acme/data"))
	ev := f.evidence(t, principal)
	ev.Leaf.IntentCeilingMicroUSD = 999_999_999_999
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonBadProof {
		t.Fatalf("raising your own ceiling must break inclusion, got %s", got)
	}
}

func TestUpgradingOwnStatusIsRefused(t *testing.T) {
	l := activeLeaf(principal)
	l.Status = StatusSuspended
	f := newFixture(t, l, activeLeaf("acc://other.acme/data"))

	ev := f.evidence(t, principal)
	ev.Leaf.Status = StatusActive // "I'm active, honest"
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonBadProof {
		t.Fatalf("self-upgrading status must break inclusion, got %s", got)
	}
}

func TestGarbageProofIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal), activeLeaf("acc://other.acme/data"))
	for _, bad := range [][]ProofStep{
		{{Hash: "not-hex", Right: true}},
		{{Hash: "abcd", Right: true}},                    // too short
		{{Hash: strings.Repeat("11", 32), Right: true}},  // wrong sibling
		{{Hash: strings.Repeat("11", 32), Right: false}}, // wrong side
	} {
		ev := f.evidence(t, principal)
		ev.Proof = bad
		if err := Verify(ev, principal, now, f.keys); err == nil {
			t.Fatalf("garbage proof %v was accepted", bad)
		}
	}
}

// Swapping the sibling side must not still reach the root.
func TestProofSideIsChecked(t *testing.T) {
	f := newFixture(t, activeLeaf("acc://a.acme/data"), activeLeaf("acc://b.acme/data"))
	ev := f.evidence(t, "acc://a.acme/data")
	if len(ev.Proof) == 0 {
		t.Skip("no sibling to flip")
	}
	ev.Proof[0].Right = !ev.Proof[0].Right
	if err := Verify(ev, "acc://a.acme/data", now, f.keys); err == nil {
		t.Fatal("flipping the sibling side must invalidate the proof")
	}
}

// ── Staleness: killing the publisher must not grant free service ────────────

func TestExpiredEpochIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	ev := f.evidence(t, principal)
	// One second past expiry.
	if got := reasonOf(t, Verify(ev, principal, ev.Header.NotAfterUnix+1, f.keys)); got != ReasonStale {
		t.Fatalf("an expired epoch must refuse, got %s", got)
	}
}

func TestExactExpiryBoundaryIsStillValid(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	ev := f.evidence(t, principal)
	if err := Verify(ev, principal, ev.Header.NotAfterUnix, f.keys); err != nil {
		t.Fatalf("not_after should be inclusive: %v", err)
	}
}

func TestMissingExpiryIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	hdr := f.header
	hdr.NotAfterUnix = 0
	ev := f.evidence(t, principal)
	ev.Header = f.sign(hdr) // properly signed, but never expires
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonStale {
		t.Fatalf("an epoch with no expiry must refuse, got %s", got)
	}
}

func TestFutureEpochIsRefused(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	hdr := f.header
	hdr.IssuedAtUnix = now + 86400
	hdr.NotAfterUnix = now + 90000
	ev := f.evidence(t, principal)
	ev.Header = f.sign(hdr)
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonStale {
		t.Fatalf("an epoch from the future must refuse, got %s", got)
	}
}

func TestSmallClockSkewIsTolerated(t *testing.T) {
	f := newFixture(t, activeLeaf(principal))
	hdr := f.header
	hdr.IssuedAtUnix = now + 60 // 1 minute ahead
	ev := f.evidence(t, principal)
	ev.Header = f.sign(hdr)
	if err := Verify(ev, principal, now, f.keys); err != nil {
		t.Fatalf("ordinary skew must not refuse: %v", err)
	}
}

// ── Determinism: the property a consensus rule lives or dies by ─────────────

func TestVerifyIsDeterministic(t *testing.T) {
	f := newFixture(t, activeLeaf(principal), activeLeaf("acc://b.acme/data"))
	ev := f.evidence(t, principal)
	first := Verify(ev, principal, now, f.keys)
	for range 500 {
		if got := Verify(ev, principal, now, f.keys); (got == nil) != (first == nil) {
			t.Fatal("Verify is not deterministic; this would halt consensus")
		}
	}
}

func TestRootIsIndependentOfInputOrder(t *testing.T) {
	a, b, c := activeLeaf("acc://a.acme/d"), activeLeaf("acc://b.acme/d"), activeLeaf("acc://c.acme/d")
	s1 := &Set{Leaves: []Leaf{a, b, c}}
	s2 := &Set{Leaves: []Leaf{c, a, b}}
	if s1.Root() != s2.Root() {
		t.Fatal("root depends on input order; publishers would disagree")
	}
}

func TestDuplicateADIResolvesDeterministically(t *testing.T) {
	l1 := activeLeaf(principal)
	l2 := activeLeaf(principal)
	l2.IntentCeilingMicroUSD = 42
	s1 := &Set{Leaves: []Leaf{l1, l2}}
	s2 := &Set{Leaves: []Leaf{l1, l2}}
	if s1.Root() != s2.Root() {
		t.Fatal("duplicate handling is not deterministic")
	}
	if got, _ := s1.Lookup(principal); got.IntentCeilingMicroUSD != 42 {
		t.Fatal("expected the last occurrence to win, consistently")
	}
}

func TestLeafEncodingIsStable(t *testing.T) {
	// Every validator must compute this byte-for-byte identically, forever. If
	// this test fails after a struct change, the change is a breaking protocol
	// change and needs a version bump, not a test update.
	l := Leaf{ADIURL: "acc://x.acme/data", Status: StatusActive, Tier: "growth",
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 100_000_000}
	want := "v1\x1facc://x.acme/data\x1factive\x1fgrowth\x1f5000000\x1f100000000"
	if got := string(l.Canonical()); got != want {
		t.Fatalf("leaf encoding changed:\n got %q\nwant %q", got, want)
	}
}

func TestLeafAndInteriorHashesAreDomainSeparated(t *testing.T) {
	// Without domain separation a leaf could be reinterpreted as an interior
	// node, which is a classic second-preimage attack on Merkle trees.
	l := activeLeaf(principal)
	leafHash := l.Hash()
	interior := interiorHash(leafHash[:], leafHash[:])
	if hex.EncodeToString(leafHash[:]) == hex.EncodeToString(interior) {
		t.Fatal("leaf and interior hashes collide")
	}
}

// ── ADI comparison ──────────────────────────────────────────────────────────

func TestADIComparisonIsCaseAndWhitespaceInsensitive(t *testing.T) {
	f := newFixture(t, activeLeaf("acc://Payer.ACME/data"))
	if err := Verify(f.evidence(t, "acc://Payer.ACME/data"), "  acc://payer.acme/DATA  ", now, f.keys); err != nil {
		t.Fatalf("Accumulate URLs are case-insensitive: %v", err)
	}
}

// A data account and its identity are DIFFERENT accounts. Conflating them would
// let an entitlement for one authorize spending for the other.
func TestPathComponentsAreNotStripped(t *testing.T) {
	f := newFixture(t, activeLeaf("acc://payer.acme/data"))
	err := Verify(f.evidence(t, "acc://payer.acme/data"), "acc://payer.acme", now, f.keys)
	if got := reasonOf(t, err); got != ReasonPrincipalMatch {
		t.Fatalf("acc://payer.acme must not match acc://payer.acme/data, got %s", got)
	}
}

func TestEmptyPrincipalNeverMatches(t *testing.T) {
	f := newFixture(t, Leaf{ADIURL: "", Status: StatusActive, IntentCeilingMicroUSD: 1})
	ev := &Evidence{Header: f.header, Leaf: Leaf{ADIURL: "", Status: StatusActive, IntentCeilingMicroUSD: 1}}
	if err := Verify(ev, "", now, f.keys); err == nil {
		t.Fatal("an empty principal must never verify")
	}
}

// ── Set plumbing ────────────────────────────────────────────────────────────

func TestEmptySetHasNoRootAndGrantsNothing(t *testing.T) {
	s := &Set{}
	if s.Root() != "" {
		t.Fatalf("an empty set must not produce a usable root, got %q", s.Root())
	}
	if _, _, ok := s.BuildProof(principal); ok {
		t.Fatal("built a proof against an empty set")
	}
}

func TestSetHashDetectsAnyChange(t *testing.T) {
	s := &Set{Leaves: []Leaf{activeLeaf(principal)}}
	h1, err := s.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	s.Leaves[0].IntentCeilingMicroUSD++
	h2, _ := s.SetHash()
	if h1 == h2 {
		t.Fatal("set hash did not change; a tampered blob would verify")
	}
}

func TestNativeUSDRateRidesOnTheSignedHeader(t *testing.T) {
	// The validator needs a USD rate to enforce a cost ceiling. Carrying it on
	// the already-signed, already-fetched header avoids both a gateway
	// dependency and a non-deterministic local feed.
	f := newFixture(t, activeLeaf(principal))
	ev := f.evidence(t, principal)
	if err := Verify(ev, principal, now, f.keys); err != nil {
		t.Fatal(err)
	}
	if ev.Header.NativeUSDMicro != 3000*1_000_000 {
		t.Fatalf("rate not carried: %d", ev.Header.NativeUSDMicro)
	}
	// And it must be tamper-evident, or a cheap rate would raise every ceiling.
	ev.Header.NativeUSDMicro = 1
	if got := reasonOf(t, Verify(ev, principal, now, f.keys)); got != ReasonBadSignature {
		t.Fatalf("the rate must be signed, got %s", got)
	}
}
