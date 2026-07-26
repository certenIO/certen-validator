package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// The gate that decides whether CERTEN spends. These tests cover the wiring:
// mode selection, configuration safety, and the principal extraction that the
// whole decision keys on. The cryptography itself is covered exhaustively in
// pkg/entitlement.

const (
	gateNow   = int64(1_800_000_000)
	gatePayer = "acc://payer.acme/data"
)

func gateFixture(t *testing.T, leaves ...entitlement.Leaf) (EntitlementConfig, *entitlement.Evidence, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "k1"
	set := &entitlement.Set{Leaves: leaves}
	setHash, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	hdr := entitlement.Header{
		Epoch: 1, Root: set.Root(), SetHash: setHash,
		NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix:   gateNow - 60, NotAfterUnix: gateNow + 3600,
		KeyID: keyID,
	}
	hdr.Signature = hex.EncodeToString(ed25519.Sign(priv, hdr.SigningBytes()))

	var ev *entitlement.Evidence
	if proof, leaf, ok := set.BuildProof(gatePayer); ok {
		ev = &entitlement.Evidence{Header: hdr, Leaf: leaf, Proof: proof}
	}
	cfg := EntitlementConfig{Mode: EntitlementEnforce, Keys: entitlement.KeySet{keyID: pub}}
	return cfg, ev, priv, keyID
}

func activeLeaf(adi string) entitlement.Leaf {
	return entitlement.Leaf{
		ADIURL: adi, Status: entitlement.StatusActive,
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 100_000_000,
	}
}

func blockFor(principal string, ev *entitlement.Evidence) *ValidatorBlock {
	return &ValidatorBlock{
		BundleID:                  "bundle-1",
		AccumulateAnchorReference: AccumulateAnchorReference{AccountURL: principal},
		EntitlementEvidence:       ev,
	}
}

// ── Modes ───────────────────────────────────────────────────────────────────

func TestOffModeIgnoresEverything(t *testing.T) {
	cfg := EntitlementConfig{Mode: EntitlementOff}
	// No evidence at all, and it still passes: off is off.
	reason, err := VerifyEntitlement(blockFor(gatePayer, nil), gatePayer, gateNow, cfg)
	if err != nil || reason != "" {
		t.Fatalf("off mode must not gate: reason=%q err=%v", reason, err)
	}
}

func TestObserveModeReportsButNeverRejects(t *testing.T) {
	cfg, _, _, _ := gateFixture(t, activeLeaf("acc://someone-else.acme/data"))
	cfg.Mode = EntitlementObserve

	reason, err := VerifyEntitlement(blockFor(gatePayer, nil), gatePayer, gateNow, cfg)
	if err != nil {
		t.Fatalf("observe must never reject: %v", err)
	}
	if reason != entitlement.ReasonNoEvidence {
		t.Fatalf("observe must still report the reason, got %q", reason)
	}
}

func TestEnforceModeRejects(t *testing.T) {
	cfg, _, _, _ := gateFixture(t, activeLeaf("acc://someone-else.acme/data"))

	reason, err := VerifyEntitlement(blockFor(gatePayer, nil), gatePayer, gateNow, cfg)
	if err == nil {
		t.Fatal("enforce must reject a block with no entitlement evidence")
	}
	if reason != entitlement.ReasonNoEvidence {
		t.Fatalf("expected NO_ENTITLEMENT_EVIDENCE, got %q", reason)
	}
}

func TestEnforceModeAdmitsAFundedAccount(t *testing.T) {
	cfg, ev, _, _ := gateFixture(t, activeLeaf(gatePayer))
	if ev == nil {
		t.Fatal("fixture failed to build evidence")
	}
	reason, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, gateNow, cfg)
	if err != nil || reason != "" {
		t.Fatalf("a funded account must be admitted: reason=%q err=%v", reason, err)
	}
}

// ── Configuration safety ────────────────────────────────────────────────────

func TestConfigDefaultsToOff(t *testing.T) {
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "")
	t.Setenv("CERTEN_ENTITLEMENT_KEYS", "")
	cfg, err := EntitlementConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// A consensus rule must not switch itself on during an upgrade: a fleet
	// where some nodes enforce and others do not disagrees about validity.
	if cfg.Mode != EntitlementOff {
		t.Fatalf("must default to off, got %q", cfg.Mode)
	}
}

func TestEnforceWithoutKeysRefusesToStart(t *testing.T) {
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "enforce")
	t.Setenv("CERTEN_ENTITLEMENT_KEYS", "")
	if _, err := EntitlementConfigFromEnv(); err == nil {
		t.Fatal("enforcing with no trusted keys would reject every block; must refuse to start")
	}
}

func TestUnknownModeIsFatalNotGuessed(t *testing.T) {
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "enforceing") // typo
	t.Setenv("CERTEN_ENTITLEMENT_KEYS", "")
	if _, err := EntitlementConfigFromEnv(); err == nil {
		t.Fatal("a typo'd mode must be fatal; silently defaulting to off would look enforcing to the operator")
	}
}

func TestKeyParsing(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "enforce")
	t.Setenv("CERTEN_ENTITLEMENT_KEYS",
		"k1:"+hex.EncodeToString(pub1)+" , k2:"+hex.EncodeToString(pub2))

	cfg, err := EntitlementConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Keys) != 2 || cfg.Keys["k1"] == nil || cfg.Keys["k2"] == nil {
		t.Fatalf("expected two keys, got %d", len(cfg.Keys))
	}
}

func TestMalformedKeysAreFatal(t *testing.T) {
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "enforce")
	for _, bad := range []string{
		"no-colon-here",
		"k1:nothex",
		"k1:" + hex.EncodeToString([]byte("too-short")),
		":" + hex.EncodeToString(make([]byte, 32)),
	} {
		t.Setenv("CERTEN_ENTITLEMENT_KEYS", bad)
		if _, err := EntitlementConfigFromEnv(); err == nil {
			t.Fatalf("malformed key spec %q was accepted", bad)
		}
	}
}

// ── Principal extraction ────────────────────────────────────────────────────

// The whole decision keys on this one field. If it can be influenced by the
// submitter, the gate is decorative.
func TestPrincipalComesFromTheDiscoveredAccountURL(t *testing.T) {
	vb := blockFor("acc://real-principal.acme/data", nil)
	// A self-declared organization_adi claiming to be someone else must not win.
	vb.GovernanceProof.OrganizationADI = "acc://i-am-rich.acme"

	if got := PrincipalOf(vb); got != "acc://real-principal.acme/data" {
		t.Fatalf("principal must come from the discovered account URL, got %q", got)
	}
}

func TestMissingPrincipalFailsClosed(t *testing.T) {
	cfg, ev, _, _ := gateFixture(t, activeLeaf(gatePayer))
	vb := blockFor("", ev) // no account URL at all

	if got := PrincipalOf(vb); got != "" {
		t.Fatalf("expected empty principal, got %q", got)
	}
	if _, err := VerifyEntitlement(vb, PrincipalOf(vb), gateNow, cfg); err == nil {
		t.Fatal("a block with no identifiable principal must be refused")
	}
}

func TestPrincipalOfNilBlock(t *testing.T) {
	if got := PrincipalOf(nil); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// ── Determinism: a consensus rule lives or dies by this ─────────────────────

func TestGateIsDeterministic(t *testing.T) {
	cfg, ev, _, _ := gateFixture(t, activeLeaf(gatePayer), activeLeaf("acc://b.acme/data"))
	vb := blockFor(gatePayer, ev)

	first, firstErr := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
	for range 1000 {
		r, e := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
		if r != first || (e == nil) != (firstErr == nil) {
			t.Fatal("gate is not deterministic; this would halt consensus")
		}
	}
}

// Two validators handed the same block and the same BLOCK TIME must agree, even
// though their wall clocks differ. This is why nowUnix is a parameter.
func TestSameBlockTimeYieldsSameAnswerRegardlessOfWallClock(t *testing.T) {
	cfg, ev, _, _ := gateFixture(t, activeLeaf(gatePayer))
	vb := blockFor(gatePayer, ev)

	// Simulate two nodes evaluating the same block at the same block height.
	rA, eA := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
	rB, eB := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
	if rA != rB || (eA == nil) != (eB == nil) {
		t.Fatal("validators disagreed on identical input")
	}

	// And the answer MUST flip together once the epoch expires, at the same
	// block time — not at each node's local time.
	expired := ev.Header.NotAfterUnix + 1
	_, eA2 := VerifyEntitlement(vb, gatePayer, expired, cfg)
	_, eB2 := VerifyEntitlement(vb, gatePayer, expired, cfg)
	if (eA2 == nil) != (eB2 == nil) {
		t.Fatal("validators disagreed after expiry")
	}
	if eA2 == nil {
		t.Fatal("an expired epoch must be refused")
	}
}

// ── The bypass, end to end at this layer ────────────────────────────────────

// Acceptance condition #1, at the consensus-rule level: an unfunded party
// submitting directly to Accumulate produces a ValidatorBlock that cannot
// commit, so no TX1 is ever reached.
func TestUnfundedDirectSubmissionCannotCommit(t *testing.T) {
	// The fleet's entitlement set contains a paying customer, not the attacker.
	cfg, _, _, _ := gateFixture(t, activeLeaf("acc://paying-customer.acme/data"))

	attacker := "acc://freeloader.acme/data"
	vb := blockFor(attacker, nil) // nothing they can attach

	reason, err := VerifyEntitlement(vb, attacker, gateNow, cfg)
	if err == nil {
		t.Fatal("an unfunded direct submission must be rejected before any chain spend")
	}
	if reason != entitlement.ReasonNoEvidence {
		t.Fatalf("expected NO_ENTITLEMENT_EVIDENCE, got %q", reason)
	}
}

// Acceptance condition #2: a funded party submitting directly is served.
func TestFundedDirectSubmissionIsServed(t *testing.T) {
	cfg, ev, _, _ := gateFixture(t, activeLeaf(gatePayer))
	if _, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("a funded direct submission must be served: %v", err)
	}
}
