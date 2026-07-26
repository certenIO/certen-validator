package entitlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The store is the one place this design lets a validator talk to the network.
// These tests pin the four properties that keep that from being a liability:
// never inline, untrusted transport, fails closed, and not in the consensus
// path.

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

type publisher struct {
	priv  ed25519.PrivateKey
	keyID string
	keys  KeySet
	epoch uint64
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &publisher{priv: priv, keyID: "pk1", keys: KeySet{"pk1": pub}, epoch: 1}
}

func (p *publisher) doc(t *testing.T, leaves ...Leaf) Document {
	t.Helper()
	set := Set{Leaves: leaves}
	sh, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	h := Header{
		Epoch: p.epoch, Root: set.Root(), SetHash: sh,
		NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix:   time.Now().Add(-time.Minute).Unix(),
		NotAfterUnix:   time.Now().Add(time.Hour).Unix(),
		KeyID:          p.keyID,
	}
	h.Signature = hex.EncodeToString(ed25519.Sign(p.priv, h.SigningBytes()))
	return Document{Header: h, Set: set}
}

func serve(t *testing.T, body func() ([]byte, int)) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b, code := body()
		w.WriteHeader(code)
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func storeFor(url string, keys KeySet) *Store {
	return NewStore(StoreConfig{
		URL: url, RefreshInterval: time.Hour, MaxAge: time.Hour, Timeout: 5 * time.Second,
	}, keys, quietLogger())
}

// ── Happy path ──────────────────────────────────────────────────────────────

func TestStoreFetchesAndBuildsUsableEvidence(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal), activeLeaf("acc://b.acme/data"))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	ev := s.BuildEvidence(principal)
	if ev == nil {
		t.Fatal("expected evidence for a set member")
	}
	// The evidence must actually verify — building something that fails the
	// consensus gate would be worse than building nothing.
	if err := Verify(ev, principal, time.Now().Unix(), p.keys); err != nil {
		t.Fatalf("store produced evidence the verifier rejects: %v", err)
	}
}

// ── Untrusted transport ─────────────────────────────────────────────────────

func TestRejectsDocumentSignedByUnpinnedKey(t *testing.T) {
	p := newPublisher(t)
	evil := newPublisher(t) // different keypair entirely
	doc := evil.doc(t, activeLeaf(principal))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys) // pinned to p, not evil
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a document signed by an unpinned key must be rejected")
	}
	if s.BuildEvidence(principal) != nil {
		t.Fatal("rejected document must not populate the cache")
	}
}

// A hostile mirror serves a valid, correctly-signed header but swaps the set to
// insert itself. The set hash must catch it.
func TestRejectsSetThatDoesNotMatchSignedHash(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))
	doc.Set.Leaves = append(doc.Set.Leaves, activeLeaf("acc://attacker.acme/data"))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys)
	err := s.Refresh(context.Background())
	if err == nil {
		t.Fatal("a set that does not match the signed hash must be rejected")
	}
	if !strings.Contains(err.Error(), "hash mismatch") && !strings.Contains(err.Error(), "root mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRejectsTamperedHeaderFields(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))
	doc.Header.NativeUSDMicro = 1 // cheap ETH would inflate every ceiling
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	if err := storeFor(srv.URL, p.keys).Refresh(context.Background()); err == nil {
		t.Fatal("a tampered header must be rejected")
	}
}

// Rolling the blob endpoint back to an older epoch would reinstate revoked
// entitlements. This is the shape a replay attack would take.
func TestRefusesToMoveBackwardsToAnOlderEpoch(t *testing.T) {
	p := newPublisher(t)
	p.epoch = 5
	newer := p.doc(t, activeLeaf(principal))
	p.epoch = 2
	older := p.doc(t, activeLeaf(principal), activeLeaf("acc://revoked.acme/data"))

	var serveOlder atomic.Bool
	srv := serve(t, func() ([]byte, int) {
		if serveOlder.Load() {
			return mustJSON(t, older), 200
		}
		return mustJSON(t, newer), 200
	})

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	serveOlder.Store(true)
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("an epoch rollback must be refused")
	}
	if h := s.Health(); h.Epoch != 5 {
		t.Fatalf("cache must retain the newer epoch, got %d", h.Epoch)
	}
}

// ── Fails closed ────────────────────────────────────────────────────────────

func TestNoSnapshotYieldsNoEvidence(t *testing.T) {
	s := storeFor("http://127.0.0.1:1/never", KeySet{})
	if s.BuildEvidence(principal) != nil {
		t.Fatal("a store that has never fetched must not produce evidence")
	}
}

func TestUnreachableEndpointFailsClosed(t *testing.T) {
	s := storeFor("http://127.0.0.1:1/nope", KeySet{})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("expected a fetch error")
	}
	if s.BuildEvidence(principal) != nil {
		t.Fatal("an unreachable gateway must yield no evidence, never a default-allow")
	}
}

func TestHTTPErrorFailsClosed(t *testing.T) {
	srv := serve(t, func() ([]byte, int) { return []byte("nope"), 503 })
	s := storeFor(srv.URL, KeySet{})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a 503 must be an error")
	}
	if s.BuildEvidence(principal) != nil {
		t.Fatal("must not produce evidence after an HTTP failure")
	}
}

func TestGarbageBodyFailsClosed(t *testing.T) {
	srv := serve(t, func() ([]byte, int) { return []byte("{not json"), 200 })
	s := storeFor(srv.URL, KeySet{})
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

func TestStaleSnapshotStopsProducingEvidence(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := NewStore(StoreConfig{
		URL: srv.URL, RefreshInterval: time.Hour,
		MaxAge:  time.Nanosecond, // everything is instantly stale
		Timeout: 5 * time.Second,
	}, p.keys, quietLogger())
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	if s.BuildEvidence(principal) != nil {
		t.Fatal("a stale snapshot must stop producing evidence; serving on a dead publisher is the cheapest bypass")
	}
	if h := s.Health(); !h.Stale {
		t.Fatal("Health must report staleness")
	}
}

func TestAbsentAccountYieldsNoEvidence(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf("acc://someone-else.acme/data"))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.BuildEvidence(principal) != nil {
		t.Fatal("an account absent from the set must yield no evidence")
	}
}

// A failed poll must not wipe a good snapshot — one network blip should not look
// like a fee-layer outage.
func TestFailedRefreshKeepsPreviousSnapshot(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))
	var broken atomic.Bool
	srv := serve(t, func() ([]byte, int) {
		if broken.Load() {
			return []byte("garbage"), 500
		}
		return mustJSON(t, doc), 200
	})

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("expected the second refresh to fail")
	}
	if s.BuildEvidence(principal) == nil {
		t.Fatal("a transient failure must not discard a good snapshot")
	}
}

// ── Never inline ────────────────────────────────────────────────────────────

// BuildEvidence sits on the intent-processing path. If it could block on the
// network, a hanging gateway would stall the validator.
func TestBuildEvidenceNeverPerformsIO(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(mustJSON(t, doc))
	}))
	defer srv.Close()

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	for range 100 {
		_ = s.BuildEvidence(principal)
		_, _ = s.Lookup(principal)
	}
	if hits.Load() != before {
		t.Fatalf("BuildEvidence/Lookup hit the network %d times; they must be pure cache reads",
			hits.Load()-before)
	}
}

func TestBuildEvidenceIsFastEnoughForTheHotPath(t *testing.T) {
	p := newPublisher(t)
	leaves := make([]Leaf, 0, 2000)
	for i := range 2000 {
		leaves = append(leaves, activeLeaf("acc://payer"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))+".acme/data"))
	}
	leaves = append(leaves, activeLeaf(principal))
	doc := p.doc(t, leaves...)
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 100 {
		if s.BuildEvidence(principal) == nil {
			t.Fatal("expected evidence")
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("100 evidence builds took %s; too slow for the intent path", elapsed)
	}
}

// ── Disabled and health ─────────────────────────────────────────────────────

func TestDisabledStoreIsInertNotFatal(t *testing.T) {
	s := NewStore(StoreConfig{URL: ""}, KeySet{}, quietLogger())
	if s.Enabled() {
		t.Fatal("empty URL must disable the store")
	}
	s.Start(context.Background()) // must not panic or block
	if s.BuildEvidence(principal) != nil {
		t.Fatal("a disabled store must produce no evidence")
	}
}

func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	if s.Enabled() {
		t.Fatal("nil store must not report enabled")
	}
	if s.BuildEvidence(principal) != nil {
		t.Fatal("nil store must produce no evidence")
	}
	if _, ok := s.Lookup(principal); ok {
		t.Fatal("nil store must not report a lookup hit")
	}
	_ = s.Health()
}

// An empty store looks identical to a working one until intents start being
// refused. Health is how that becomes visible before it becomes a mystery.
func TestHealthReportsFailures(t *testing.T) {
	srv := serve(t, func() ([]byte, int) { return []byte("x"), 500 })
	s := storeFor(srv.URL, KeySet{})
	_ = s.Refresh(context.Background())
	_ = s.Refresh(context.Background())

	h := s.Health()
	if h.RefreshFail != 2 {
		t.Fatalf("expected 2 failures, got %d", h.RefreshFail)
	}
	if h.LastError == "" {
		t.Fatal("Health must surface the last error")
	}
	if !h.Stale {
		t.Fatal("a store that never fetched must report stale")
	}
}

func TestHealthReportsSuccess(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal), activeLeaf("acc://b.acme/data"))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })

	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := s.Health()
	if h.Accounts != 2 || h.Epoch != 1 || h.RefreshOK != 1 || h.Stale {
		t.Fatalf("unexpected health: %+v", h)
	}
}

func TestConcurrentReadsDuringRefreshAreSafe(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf(principal))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })
	s := storeFor(srv.URL, p.keys)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_ = s.BuildEvidence(principal)
			_ = s.Health()
		}
	}()
	for range 20 {
		_ = s.Refresh(context.Background())
	}
	<-done
}
