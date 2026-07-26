package consensus

import (
	"context"
	"path/filepath"
	"testing"
)

// Replay protection has been written and unreachable since it was authored:
// ValidateNonce had no live caller, so a replayed intent — the same 4 blobs
// written to Accumulate a second time — was executed again at CERTEN's expense.
//
// Turning it on is only safe if it can tell a RETRY from a REPLAY. The validator
// legitimately re-processes the same intent (the on-demand chained-proof retry
// absorbs DN-anchoring latency, and a restart re-queues work). Replay protection
// that breaks the retry path is worse than none: it would fail on exactly the
// intents that needed patience.
//
// The distinction is ownership. A replay is the same nonce presented by a
// DIFFERENT Accumulate transaction; a retry is the same transaction again.

func newClaimStore(t *testing.T) *BboltReplayStore {
	t.Helper()
	s, err := NewBboltReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestFirstClaimSucceeds(t *testing.T) {
	s := newClaimStore(t)
	res, err := s.ClaimNonce(context.Background(), "n1", "tx-aaa", 1900000000)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Reclaimed {
		t.Fatalf("expected a fresh claim, got %+v", res)
	}
}

// The retry path. This is what plain MarkNonce got wrong.
func TestSameTransactionMayReclaimItsOwnNonce(t *testing.T) {
	s := newClaimStore(t)
	ctx := context.Background()
	if _, err := s.ClaimNonce(ctx, "n1", "tx-aaa", 1900000000); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		res, err := s.ClaimNonce(ctx, "n1", "tx-aaa", 1900000000)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK {
			t.Fatalf("retry %d refused; the on-demand retry path would break", i)
		}
		if !res.Reclaimed {
			t.Fatalf("retry %d should report Reclaimed", i)
		}
	}
}

// The attack. A replayed intent is a NEW Accumulate transaction reusing a nonce.
func TestDifferentTransactionCannotReuseANonce(t *testing.T) {
	s := newClaimStore(t)
	ctx := context.Background()
	if _, err := s.ClaimNonce(ctx, "n1", "tx-aaa", 1900000000); err != nil {
		t.Fatal(err)
	}
	res, err := s.ClaimNonce(ctx, "n1", "tx-bbb", 1900000000)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a different transaction reusing the nonce must be refused")
	}
	// The refusal must name the holder, or the operator cannot tell a replay
	// from a bug.
	if res.Owner != "tx-aaa" {
		t.Fatalf("refusal lost the original owner, got %q", res.Owner)
	}
}

func TestDistinctNoncesAreIndependent(t *testing.T) {
	s := newClaimStore(t)
	ctx := context.Background()
	for _, n := range []string{"n1", "n2", "n3"} {
		res, err := s.ClaimNonce(ctx, n, "tx-"+n, 1900000000)
		if err != nil || !res.OK {
			t.Fatalf("claiming %s failed: %+v %v", n, res, err)
		}
	}
}

// A nonce written by the OLD MarkNonce format has no owner recorded. It must
// stay refused rather than becoming adoptable by whoever asks first — otherwise
// deploying this change would hand every historical nonce to the next caller.
func TestLegacyRecordWithoutOwnerIsNotAdoptable(t *testing.T) {
	s := newClaimStore(t)
	ctx := context.Background()
	if err := s.MarkNonce(ctx, "legacy", 1900000000); err != nil {
		t.Fatal(err)
	}
	res, err := s.ClaimNonce(ctx, "legacy", "tx-whoever", 1900000000)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a legacy ownerless nonce must not be claimable")
	}
}

// The two APIs must agree, or a mixed-version fleet would disagree about what a
// replay is.
func TestClaimedNonceIsVisibleToHasNonce(t *testing.T) {
	s := newClaimStore(t)
	ctx := context.Background()
	if _, err := s.ClaimNonce(ctx, "n1", "tx-aaa", 1900000000); err != nil {
		t.Fatal(err)
	}
	seen, err := s.HasNonce(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("a claimed nonce must be visible to HasNonce")
	}
}

func TestMarkNonceStillRejectsDuplicates(t *testing.T) {
	// The legacy path must keep working for a store that predates the extension.
	s := newClaimStore(t)
	ctx := context.Background()
	if err := s.MarkNonce(ctx, "n1", 1900000000); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNonce(ctx, "n1", 1900000000); err == nil {
		t.Fatal("MarkNonce must still refuse a duplicate")
	}
}

// ── The validator-facing wrapper ────────────────────────────────────────────

func TestValidateNonceForOwnerRefusesAnEmptyNonce(t *testing.T) {
	ci := &CertenIntent{TransactionHash: "tx-aaa"}
	if err := ci.ValidateNonceForOwner(&ReplayData{Nonce: ""}, "tx-aaa"); err == nil {
		t.Fatal("an empty nonce must be refused")
	}
}

// Without a transaction hash we cannot tell a retry from a replay, and an intent
// with no transaction hash has not been established on chain anyway.
func TestValidateNonceForOwnerRefusesWithoutATransactionHash(t *testing.T) {
	ci := &CertenIntent{}
	if err := ci.ValidateNonceForOwner(&ReplayData{Nonce: "n1"}, ""); err == nil {
		t.Fatal("no owner means we cannot distinguish retry from replay; must refuse")
	}
}

func TestValidateNonceForOwnerRetryThenReplay(t *testing.T) {
	s := newClaimStore(t)
	SetReplayStore(s)
	t.Cleanup(func() { SetReplayStore(nil) })

	rd := &ReplayData{Nonce: "n-shared", ExpiresAt: 1900000000}

	victim := &CertenIntent{TransactionHash: "tx-victim"}
	if err := victim.ValidateNonceForOwner(rd, victim.TransactionHash); err != nil {
		t.Fatalf("first submission refused: %v", err)
	}
	// Same transaction, re-processed. Must pass.
	if err := victim.ValidateNonceForOwner(rd, victim.TransactionHash); err != nil {
		t.Fatalf("retry of the same transaction refused: %v", err)
	}
	// A different transaction reusing the nonce. Must fail.
	attacker := &CertenIntent{TransactionHash: "tx-attacker"}
	if err := attacker.ValidateNonceForOwner(rd, attacker.TransactionHash); err == nil {
		t.Fatal("a replay from a different transaction must be refused")
	}
}
