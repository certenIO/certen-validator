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

// THE IDLE-CHAIN CLOCK, and the two incidents it caused.
//
// This chain produces blocks only for real work, so block time advances only
// when work happens. After a quiet period it lags wall clock by an unbounded
// amount, while the gateway stamps epochs with wall clock. Any rule that treats
// "issued after block time" as suspicious therefore fires on perfectly good
// epochs, and the longer the chain is idle the worse it gets.
//
// It bit twice:
//
//  1. 2026-07-27, CheckTx. Freshness was judged against the LAST COMMITTED
//     block time, so after five idle minutes every epoch looked future-dated,
//     CheckTx refused it, and the block that would have advanced the clock was
//     the one being refused. Deadlock. Fixed by judging CheckTx against wall
//     time (35c894c) — safe there because CheckTx is a mempool filter, not
//     consensus.
//
//  2. 2026-07-28, FinalizeBlock. Same cause, consensus path. Block 22 carried
//     time 23:15:41 after an hour of quiet; the proposer attached an epoch
//     issued at 00:20; Verify refused it as future-dated and an ENTITLED
//     principal was rejected under enforcement. CheckTx had passed the very
//     same block. Fixed by removing the future-dated check entirely: on this
//     chain a fresh epoch ahead of block time is normal, not a fault.
//
// NotAfterUnix remains the bound, and it is inside the signed header — a
// publisher cannot extend an entitlement by moving issued_at.

// A fresh epoch judged against a badly lagging block clock must be ACCEPTED.
// This is the exact shape that refused paid work in production.
func TestFreshEpochOnALaggingBlockClockIsAccepted(t *testing.T) {
	cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
	if ev == nil {
		t.Fatal("fixture built no evidence")
	}

	// Epoch issued "now"; the chain last committed an hour ago.
	ev.Header.IssuedAtUnix = gateNow
	ev.Header.NotAfterUnix = gateNow + 900
	reseal(ev, priv)
	staleBlockClock := gateNow - 3600

	if reason, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, staleBlockClock, cfg); err != nil {
		t.Fatalf("a fresh epoch was refused on a lagging chain clock: %v (%s)", err, reason)
	}
}

// Idleness of any length must no longer cause a refusal. The old rule failed at
// 301 seconds; the incident ran to an hour.
func TestIdlenessOfAnyLengthNoLongerRefuses(t *testing.T) {
	for _, idleFor := range []int64{60, 299, 301, 482, 3600, 86400} {
		t.Run(idleName(idleFor), func(t *testing.T) {
			cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
			ev.Header.IssuedAtUnix = gateNow
			ev.Header.NotAfterUnix = gateNow + 900
			reseal(ev, priv)

			if _, err := VerifyEntitlement(
				blockFor(gatePayer, ev), gatePayer, gateNow-idleFor, cfg); err != nil {
				t.Fatalf("idle %ds: refused a fresh epoch: %v", idleFor, err)
			}
		})
	}
}

// Expiry is still enforced, and still against BLOCK time. Removing the
// future-dated check must not have removed the bound that matters.
func TestExpiryIsStillEnforcedAgainstBlockTime(t *testing.T) {
	cfg, ev, priv, _ := gateFixture(t, activeLeaf(gatePayer))
	ev.Header.IssuedAtUnix = gateNow - 1000
	ev.Header.NotAfterUnix = gateNow - 1 // expired as of this block
	reseal(ev, priv)

	reason, err := VerifyEntitlement(blockFor(gatePayer, ev), gatePayer, gateNow, cfg)
	if err == nil {
		t.Fatal("an expired epoch was accepted")
	}
	if reason != entitlement.ReasonStale {
		t.Fatalf("reason = %q, want %q", reason, entitlement.ReasonStale)
	}
}

func idleName(s int64) string {
	switch {
	case s < 300:
		return "under the old tolerance"
	case s < 600:
		return "just past the old tolerance"
	default:
		return "long idle"
	}
}
