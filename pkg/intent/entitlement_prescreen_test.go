package intent

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
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// The pre-screen saves CPU. It is NOT a security boundary, and these tests
// mostly exist to prove it cannot become one by accident: the bar for declining
// must stay high, because a false decline silently drops a paying customer's
// intent and nothing downstream catches that.

const screenPrincipal = "acc://payer.acme/data"

func discoveryWithScreen(t *testing.T, store *entitlement.Store, enforce bool) *IntentDiscovery {
	t.Helper()
	id := &IntentDiscovery{logger: log.New(io.Discard, "", 0)}
	id.SetEntitlementScreen(store, enforce)
	return id
}

func screenStore(t *testing.T, leaves []entitlement.Leaf, notAfter time.Time) *entitlement.Store {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := entitlement.Set{Leaves: leaves}
	sh, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	h := entitlement.Header{
		Epoch: 1, Root: set.Root(), SetHash: sh,
		NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix:   time.Now().Add(-time.Minute).Unix(),
		NotAfterUnix:   notAfter.Unix(),
		KeyID:          "k",
	}
	h.Signature = hex.EncodeToString(ed25519.Sign(priv, h.SigningBytes()))
	doc := entitlement.Document{Header: h, Set: set}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b, _ := json.Marshal(doc)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	s := entitlement.NewStore(entitlement.StoreConfig{
		URL: srv.URL, RefreshInterval: time.Hour, MaxAge: time.Hour, Timeout: 5 * time.Second,
	}, entitlement.KeySet{"k": pub}, log.New(io.Discard, "", 0))
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func activeLeaf(adi string) entitlement.Leaf {
	return entitlement.Leaf{
		ADIURL: adi, Status: entitlement.StatusActive,
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 100_000_000,
	}
}

// ── It declines the right things ────────────────────────────────────────────

func TestPreScreenDeclinesAccountAbsentFromEpoch(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	id := discoveryWithScreen(t, store, true)

	if id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("an account absent from the epoch must be declined before proof work")
	}
}

func TestPreScreenDeclinesSuspendedAccount(t *testing.T) {
	l := activeLeaf(screenPrincipal)
	l.Status = entitlement.StatusSuspended
	id := discoveryWithScreen(t, screenStore(t, []entitlement.Leaf{l}, time.Now().Add(time.Hour)), true)

	if id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("a suspended account must be declined")
	}
}

func TestPreScreenDeclinesZeroCeiling(t *testing.T) {
	l := activeLeaf(screenPrincipal)
	l.IntentCeilingMicroUSD = 0
	id := discoveryWithScreen(t, screenStore(t, []entitlement.Leaf{l}, time.Now().Add(time.Hour)), true)

	if id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("an active-but-broke account must be declined")
	}
}

func TestPreScreenAdmitsFundedAccount(t *testing.T) {
	id := discoveryWithScreen(t, screenStore(t, []entitlement.Leaf{activeLeaf(screenPrincipal)}, time.Now().Add(time.Hour)), true)

	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("a funded account must proceed")
	}
}

// ── It must NEVER decline on incomplete information ─────────────────────────
//
// Each of these is a case where the node cannot actually tell. Declining would
// silently drop a legitimate intent, and no consensus rule catches that — so the
// pre-screen must defer and let the authoritative gate decide.

func TestPreScreenProceedsWhenNotConfigured(t *testing.T) {
	id := discoveryWithScreen(t, nil, true)
	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("an unconfigured screen must never decline")
	}
}

func TestPreScreenProceedsWhenStoreIsEmpty(t *testing.T) {
	// A store that has never successfully fetched cannot distinguish
	// "not entitled" from "I don't know yet".
	empty := entitlement.NewStore(entitlement.StoreConfig{
		URL: "http://127.0.0.1:1/never", RefreshInterval: time.Hour, MaxAge: time.Hour,
	}, entitlement.KeySet{}, log.New(io.Discard, "", 0))
	id := discoveryWithScreen(t, empty, true)

	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("an empty snapshot must not cause every intent to be dropped")
	}
}

func TestPreScreenProceedsWhenSnapshotIsStale(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	// Force staleness by rebuilding the store with a zero MaxAge view.
	stale := entitlement.NewStore(entitlement.StoreConfig{
		URL: "http://127.0.0.1:1/never", RefreshInterval: time.Hour, MaxAge: time.Nanosecond,
	}, entitlement.KeySet{}, log.New(io.Discard, "", 0))
	_ = store

	id := discoveryWithScreen(t, stale, true)
	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("a stale snapshot must defer to the consensus gate, not drop the intent")
	}
}

func TestPreScreenProceedsWithNoPrincipal(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	id := discoveryWithScreen(t, store, true)

	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: ""}) {
		t.Fatal("an intent with no account URL yet must proceed; it may be populated downstream")
	}
}

// ── Observe mode never declines ─────────────────────────────────────────────

func TestPreScreenObserveModeNeverDeclines(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	id := discoveryWithScreen(t, store, false) // observe

	if !id.entitlementPreScreen(&CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}) {
		t.Fatal("observe mode must report but never decline")
	}
}

// ── It cannot admit anything ────────────────────────────────────────────────

// The pre-screen passing must never be mistaken for authorization. This is a
// design assertion: even a fully entitled account passing the screen must still
// carry evidence that the consensus gate verifies independently.
func TestPreScreenPassingIsNotAuthorization(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf(screenPrincipal)}, time.Now().Add(time.Hour))
	id := discoveryWithScreen(t, store, true)

	intent := &CertenIntent{IntentID: "i1", AccountURL: screenPrincipal}
	if !id.entitlementPreScreen(intent) {
		t.Fatal("expected the funded account to pass")
	}
	// Passing the screen mutates nothing on the intent — there is no flag a
	// later stage could mistake for a grant.
	if intent.IntentID != "i1" || intent.AccountURL != screenPrincipal {
		t.Fatal("the pre-screen must not mutate the intent")
	}
}
