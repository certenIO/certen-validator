package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// reseal re-signs the header after a test mutates its timestamps. Without it
// the signature check fires first and the test proves nothing about freshness.
func reseal(ev *entitlement.Evidence, priv ed25519.PrivateKey) {
	ev.Header.Signature = hex.EncodeToString(ed25519.Sign(priv, ev.Header.SigningBytes()))
}

// The idle-chain deadlock, observed in production 2026-07-27.
//
// CheckTx used to judge epoch freshness against the LAST COMMITTED block time.
// Block time only advances when a ValidatorBlock commits, so on a quiet chain
// it falls arbitrarily far behind the wall clock the gateway stamps epochs
// with. Past the 300s tolerance every fresh epoch reads as "issued in the
// future", CheckTx refuses it as ENTITLEMENT_STALE, and the block it refuses is
// exactly the one that would have advanced the clock. Nothing recovers.
//
// Real numbers from the incident (intent a45ee049): epoch issued 1785146227,
// judged against block time 1785145745 — 482s ahead, 182s past tolerance.

// A freshly issued epoch must FAIL when judged against a stale block clock.
// This is the hazard itself; if this ever stops failing, the tolerance changed
// and the reasoning below needs revisiting.
func TestFreshEpochLooksFutureDatedAgainstStaleBlockClock(t *testing.T) {
	cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
	if ev == nil {
		t.Fatal("fixture built no evidence")
	}

	// Epoch issued "now"; the chain last committed 482 seconds ago.
	ev.Header.IssuedAtUnix = gateNow
	ev.Header.NotAfterUnix = gateNow + 900
	reseal(ev, priv)
	staleBlockClock := gateNow - 482

	reason, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, staleBlockClock, cfg)
	if err == nil {
		t.Fatal("expected the stale-clock rejection that deadlocked production")
	}
	if reason != entitlement.ReasonStale {
		t.Fatalf("reason = %q, want %q", reason, entitlement.ReasonStale)
	}
}

// The same evidence, judged against the wall clock CheckTx now uses, passes.
// That is the whole fix: the epoch was never invalid, only mis-measured.
func TestSameEpochPassesAgainstWallClock(t *testing.T) {
	cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
	if ev == nil {
		t.Fatal("fixture built no evidence")
	}

	ev.Header.IssuedAtUnix = gateNow
	ev.Header.NotAfterUnix = gateNow + 900
	reseal(ev, priv)

	reason, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, gateNow, cfg)
	if err != nil {
		t.Fatalf("entitled principal rejected against a current clock: %v (%s)", err, reason)
	}
	if reason != "" {
		t.Fatalf("unexpected reason %q", reason)
	}
}

// Idleness beyond the tolerance is the trigger, so pin where the edge sits.
// A chain quiet for four minutes still works; five and a half does not.
func TestStalenessEdgeIsTheIdlenessTolerance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		idleFor    int64
		wantReject bool
	}{
		{"quiet 60s", 60, false},
		{"quiet 240s", 240, false},
		{"quiet 299s", 299, false},
		{"quiet 301s", 301, true},
		{"quiet 482s (the incident)", 482, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
			ev.Header.IssuedAtUnix = gateNow
			ev.Header.NotAfterUnix = gateNow + 900
			reseal(ev, priv)

			_, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, gateNow-tc.idleFor, cfg)
			if got := err != nil; got != tc.wantReject {
				t.Fatalf("idle %ds: rejected=%v, want %v", tc.idleFor, got, tc.wantReject)
			}
		})
	}
}
