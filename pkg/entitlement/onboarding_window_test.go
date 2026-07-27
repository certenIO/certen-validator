package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// THE ONBOARDING WINDOW.
//
// A newly created identity is absent from every epoch a validator holds until
// the gateway republishes AND the validator refetches — up to
// publish_interval + refresh_interval, about a minute in production. Under
// enforce that refuses a legitimate customer's FIRST intent, which looks
// exactly like a billing fault and is the worst possible first impression.
//
// A cache miss therefore triggers one immediate refetch. This is proposer-side
// work: it decides whether to ATTACH evidence, never whether to accept a block,
// so a non-deterministic outcome here cannot diverge the fleet.

// epochServer serves a signed epoch whose membership can change between polls,
// which is what makes it possible to test "the account appeared just now".
func epochServer(t *testing.T, priv ed25519.PrivateKey, keyID string, members *atomic.Value, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		leaves, _ := members.Load().([]Leaf)

		set := &Set{Leaves: leaves}
		setHash, err := set.SetHash()
		if err != nil {
			t.Error(err)
			return
		}
		now := time.Now().Unix()
		hdr := Header{
			Epoch: 1, Root: set.Root(), SetHash: setHash,
			NativeUSDMicro: 3000 * 1_000_000,
			IssuedAtUnix:   now, NotAfterUnix: now + 900,
			KeyID: keyID,
		}
		hdr.Signature = hex.EncodeToString(ed25519.Sign(priv, hdr.SigningBytes()))

		_ = json.NewEncoder(w).Encode(Document{Header: hdr, Set: *set})
	}))
}

func activeLeafFor(adi string) Leaf {
	return Leaf{
		ADIURL: adi, Status: StatusActive,
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 100_000_000,
	}
}

// A principal that appears in the epoch AFTER the last scheduled refresh must
// still resolve, without waiting for the next poll.
func TestNewlyOnboardedAccountResolvesWithoutWaitingForTheNextPoll(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "entitlement-v1"
	const newcomer = "acc://just-created.acme/data"

	var members atomic.Value
	members.Store([]Leaf{activeLeafFor("acc://existing.acme/data")})
	var hits atomic.Int64

	srv := epochServer(t, priv, keyID, &members, &hits)
	defer srv.Close()

	store := NewStore(StoreConfig{
		URL: srv.URL, RefreshInterval: time.Hour, // deliberately never polls again
		MaxAge: 900 * time.Second, Timeout: 5 * time.Second,
	}, KeySet{keyID: pub}, log.New(io.Discard, "", 0))

	if err := store.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.BuildEvidence(newcomer) != nil {
		t.Fatal("the newcomer should not be in the first epoch")
	}

	// The gateway now knows about them. The scheduled refresh is an hour away,
	// so without a miss-triggered refetch this stays broken for an hour.
	members.Store([]Leaf{
		activeLeafFor("acc://existing.acme/data"),
		activeLeafFor(newcomer),
	})

	// Rate limiter: the failed lookup above already consumed this window.
	time.Sleep(MinRefetchInterval + 100*time.Millisecond)

	if ev := store.BuildEvidence(newcomer); ev == nil {
		t.Fatal("a cache miss did not trigger a refetch; the onboarding window is still open")
	}
}

// The refetch must be rate-limited, or a flood of genuinely unknown principals
// — the direct-submission bypass, say — turns every intent into an HTTP request
// against the gateway.
func TestMissTriggeredRefetchIsRateLimited(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "entitlement-v1"

	var members atomic.Value
	members.Store([]Leaf{activeLeafFor("acc://existing.acme/data")})
	var hits atomic.Int64

	srv := epochServer(t, priv, keyID, &members, &hits)
	defer srv.Close()

	store := NewStore(StoreConfig{
		URL: srv.URL, RefreshInterval: time.Hour,
		MaxAge: 900 * time.Second, Timeout: 5 * time.Second,
	}, KeySet{keyID: pub}, log.New(io.Discard, "", 0))

	if err := store.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()

	// Fifty misses in a burst, as an attacker would produce.
	for i := 0; i < 50; i++ {
		store.BuildEvidence("acc://unknown.acme/data")
	}

	extra := hits.Load() - before
	if extra > 1 {
		t.Fatalf("50 misses caused %d fetches; the rate limit is not holding", extra)
	}
}

// A store with no URL must never attempt a fetch, however many misses occur.
func TestDisabledStoreNeverRefetches(t *testing.T) {
	store := NewStore(StoreConfig{}, KeySet{}, log.New(io.Discard, "", 0))
	if store.refetchOnMiss() {
		t.Fatal("a disabled store attempted a refetch")
	}
	if store.BuildEvidence("acc://anything.acme/data") != nil {
		t.Fatal("a disabled store produced evidence")
	}
}
