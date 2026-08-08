package entitlement

import (
	"testing"
	"time"
)

// Health must report the epoch's OWN expiry, not just local fetch staleness.
//
// Two different clocks, and conflating them hides the failure that matters:
//
//	Age/Stale     how long since this node last FETCHED
//	NotAfterUnix  when the document stops being valid at all
//
// A node can have fetched seconds ago — perfectly fresh by Age — while holding an epoch that is
// about to expire, because the publisher died right after issuing it and every subsequent
// refresh returned the same document. Under the gate's `enforce` mode expiry means every
// validator refuses every ValidatorBlock, so this is the number that predicts a fleet halt and
// Age cannot see it.

func TestHealthReportsEpochExpiry(t *testing.T) {
	notAfter := time.Now().UTC().Add(90 * time.Minute).Unix()
	s := &Store{
		header:    &Header{Epoch: 4242, NotAfterUnix: notAfter},
		set:       &Set{Leaves: []Leaf{{ADIURL: "acc://a.acme/data"}}},
		fetchedAt: time.Now(),
	}
	s.cfg.URL = "https://example.invalid/entitlement"

	h := s.Health()
	if h.Epoch != 4242 {
		t.Fatalf("Epoch = %d, want 4242", h.Epoch)
	}
	if h.NotAfterUnix != notAfter {
		t.Fatalf("NotAfterUnix = %d, want %d", h.NotAfterUnix, notAfter)
	}
	if h.Accounts != 1 {
		t.Fatalf("Accounts = %d, want 1", h.Accounts)
	}
}

// The case Age cannot see: freshly fetched, but the epoch itself is nearly expired.
//
// If this ever reports "healthy" on the strength of Age alone, an enforcing fleet halts with no
// prior warning.
func TestFreshFetchOfAnExpiringEpochStillReportsExpiry(t *testing.T) {
	almostGone := time.Now().UTC().Add(20 * time.Second).Unix()
	s := &Store{
		header:    &Header{Epoch: 7, NotAfterUnix: almostGone},
		set:       &Set{Leaves: []Leaf{}},
		fetchedAt: time.Now(), // fetched just now — Age is ~0
	}
	s.cfg.URL = "https://example.invalid/entitlement"
	s.cfg.MaxAge = time.Hour

	h := s.Health()
	if h.Stale {
		t.Fatal("Stale should be false: the fetch is recent — that is exactly why Age is not enough")
	}
	remaining := h.NotAfterUnix - time.Now().UTC().Unix()
	if remaining > 60 {
		t.Fatalf("remaining = %ds, want <= 60: the epoch is nearly expired and must be visible as such", remaining)
	}
}

// An already-expired epoch must report a NEGATIVE remaining, never zero.
//
// Zero and "slightly negative" are operationally different states — one is a warning, the other
// means this node is refusing right now — and clamping would collapse them.
func TestExpiredEpochReportsNegativeRemaining(t *testing.T) {
	past := time.Now().UTC().Add(-5 * time.Minute).Unix()
	s := &Store{
		header:    &Header{Epoch: 9, NotAfterUnix: past},
		set:       &Set{Leaves: []Leaf{}},
		fetchedAt: time.Now(),
	}
	s.cfg.URL = "https://example.invalid/entitlement"

	remaining := s.Health().NotAfterUnix - time.Now().UTC().Unix()
	if remaining >= 0 {
		t.Fatalf("remaining = %d, want negative for an expired epoch", remaining)
	}
}

// A store that has never fetched reports no expiry rather than a misleading zero.
//
// Zero would read as "expired at the epoch" (1970) and could trip an expiry alert on a node
// that is simply still starting up.
func TestNeverFetchedReportsNoExpiry(t *testing.T) {
	s := &Store{}
	s.cfg.URL = "https://example.invalid/entitlement"

	h := s.Health()
	if h.NotAfterUnix != 0 {
		t.Fatalf("NotAfterUnix = %d, want 0 before the first successful fetch", h.NotAfterUnix)
	}
	if !h.Stale {
		t.Fatal("a store that has never fetched must report Stale")
	}
}
