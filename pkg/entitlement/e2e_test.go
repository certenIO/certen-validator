package entitlement

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// EXHAUSTIVE END-TO-END.
//
// The unit tests prove each piece in isolation. These drive the whole path the
// way production does, against a document the REAL TypeScript publisher emitted:
//
//	gateway document -> HTTP -> Store.Refresh -> verify -> BuildEvidence -> Verify
//
// with a 254-account population covering every case that exists in practice:
// funded at several tiers, suspended, closed, active-but-broke, mixed case, and
// a ceiling beyond 2^53.
//
// Regenerate the fixture from api-gateway with e2egen.ts (see git history).

type e2eFixture struct {
	PubKey string `json:"pubkey"`
	Doc    string `json:"doc"`
}

func loadE2E(t *testing.T) (string, KeySet) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gateway_e2e.json"))
	if err != nil {
		t.Skipf("no e2e fixture: %v", err)
	}
	var fx e2eFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(fx.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal("bad fixture pubkey")
	}
	return fx.Doc, KeySet{"e2e-key": ed25519.PublicKey(pub)}
}

// serveDoc stands up a real HTTP server, so the Store exercises its actual
// fetch/verify path rather than a hand-injected snapshot.
func serveDoc(t *testing.T, body string, code int) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func e2eStore(t *testing.T, url string, keys KeySet) *Store {
	t.Helper()
	return NewStore(StoreConfig{
		URL: url, RefreshInterval: time.Hour, MaxAge: time.Hour, Timeout: 10 * time.Second,
	}, keys, log.New(io.Discard, "", 0))
}

// docTime returns a block time inside the fixture's validity window.
func docTime(t *testing.T, doc string) int64 {
	t.Helper()
	var d Document
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	return d.Header.IssuedAtUnix + 60
}

// ── The full path, every account ────────────────────────────────────────────

func TestE2EEveryFundedAccountIsAdmittedAndEveryOtherRefused(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	now := docTime(t, docJSON)

	var parsed Document
	if err := json.Unmarshal([]byte(docJSON), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Set.Leaves) < 250 {
		t.Fatalf("fixture too small to be meaningful: %d accounts", len(parsed.Set.Leaves))
	}

	var admitted, refused int
	for _, leaf := range parsed.Set.Leaves {
		ev := store.BuildEvidence(leaf.ADIURL)
		if ev == nil {
			t.Fatalf("no evidence for a set member %q", leaf.ADIURL)
		}
		err := Verify(ev, leaf.ADIURL, now, keys)

		// Ground truth comes from the leaf itself, so this checks the WHOLE
		// pipeline agrees with the gateway's own statement about each account.
		if leaf.Entitled() {
			if err != nil {
				t.Fatalf("funded account %q was refused: %v", leaf.ADIURL, err)
			}
			admitted++
		} else {
			if err == nil {
				t.Fatalf("account %q is %s with ceiling %d but was ADMITTED",
					leaf.ADIURL, leaf.Status, leaf.IntentCeilingMicroUSD)
			}
			refused++
		}
	}
	t.Logf("admitted %d, refused %d across %d accounts", admitted, refused, len(parsed.Set.Leaves))
	if admitted == 0 || refused == 0 {
		t.Fatal("fixture must contain both admitted and refused accounts to be a real test")
	}
}

// The direct-submit bypass, end to end: a stranger has no evidence to attach.
func TestE2EStrangerCannotBeAdmitted(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := docTime(t, docJSON)

	for _, stranger := range []string{
		"acc://freeloader.acme/data",
		"acc://payer0000.acme",       // real payer, but the IDENTITY not the data account
		"acc://payer0000.acme/other", // real payer, wrong account
		"acc://payer9999.acme/data",  // plausible but absent
		"",
	} {
		if ev := store.BuildEvidence(stranger); ev != nil {
			t.Fatalf("built evidence for a non-member %q", stranger)
		}
		if err := Verify(nil, stranger, now, keys); err == nil {
			t.Fatalf("stranger %q was admitted with no evidence", stranger)
		}
	}
}

// ── Cross-account substitution, at scale ────────────────────────────────────

func TestE2ENoAccountsEvidenceWorksForAnyOther(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := docTime(t, docJSON)

	// Take a well-funded account's perfectly valid evidence and try it against
	// 100 other principals. Every one must fail.
	donor := "acc://whale.acme/data"
	ev := store.BuildEvidence(donor)
	if ev == nil {
		t.Fatal("expected evidence for the whale account")
	}
	if err := Verify(ev, donor, now, keys); err != nil {
		t.Fatalf("donor evidence should be valid for itself: %v", err)
	}

	for i := range 100 {
		victim := fmt.Sprintf("acc://payer%04d.acme/data", i)
		if err := Verify(ev, victim, now, keys); err == nil {
			t.Fatalf("whale evidence was accepted for %q", victim)
		}
	}
}

// ── Tampering, exhaustively ─────────────────────────────────────────────────

func TestE2EAnyTamperedByteIsRejected(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := docTime(t, docJSON)
	adi := "acc://payer0001.acme/data"

	base := store.BuildEvidence(adi)
	if base == nil {
		t.Fatal("expected evidence")
	}
	if err := Verify(base, adi, now, keys); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}

	// Flip one bit in every proof step, one step at a time.
	for i := range base.Proof {
		ev := *base
		steps := make([]ProofStep, len(base.Proof))
		copy(steps, base.Proof)
		b, _ := hex.DecodeString(steps[i].Hash)
		b[0] ^= 0x01
		steps[i].Hash = hex.EncodeToString(b)
		ev.Proof = steps
		if err := Verify(&ev, adi, now, keys); err == nil {
			t.Fatalf("a single flipped bit in proof step %d was accepted", i)
		}
	}

	// Truncate the proof at every length.
	for n := range len(base.Proof) {
		ev := *base
		ev.Proof = base.Proof[:n]
		if err := Verify(&ev, adi, now, keys); err == nil {
			t.Fatalf("a proof truncated to %d steps was accepted", n)
		}
	}

	// Mutate each leaf field.
	for name, mutate := range map[string]func(*Leaf){
		"ceiling": func(l *Leaf) { l.IntentCeilingMicroUSD *= 1000 },
		"epoch":   func(l *Leaf) { l.EpochCeilingMicroUSD *= 1000 },
		"status":  func(l *Leaf) { l.Status = StatusSuspended },
		"tier":    func(l *Leaf) { l.Tier = l.Tier + "-tampered" },
		"adi":     func(l *Leaf) { l.ADIURL = "acc://payer0002.acme/data" },
	} {
		ev := *base
		leaf := base.Leaf
		mutate(&leaf)

		// Guard against a no-op "mutation". Setting a field to the value it
		// already held proves nothing, and the test would pass for the wrong
		// reason — which is exactly what happened when this mutated status to
		// StatusActive on an already-active account.
		if string(leaf.Canonical()) == string(base.Leaf.Canonical()) {
			t.Fatalf("mutation %q did not change the leaf; the case is vacuous", name)
		}

		ev.Leaf = leaf
		if err := Verify(&ev, adi, now, keys); err == nil {
			t.Fatalf("tampering with leaf.%s was accepted", name)
		}
	}
}

// ── Staleness across the whole population ───────────────────────────────────

func TestE2EExpiryRefusesEveryAccountAtOnce(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var parsed Document
	_ = json.Unmarshal([]byte(docJSON), &parsed)
	expired := parsed.Header.NotAfterUnix + 1

	// Killing the publisher must not yield free service — for anybody.
	for i := range 50 {
		adi := fmt.Sprintf("acc://payer%04d.acme/data", i)
		ev := store.BuildEvidence(adi)
		if ev == nil {
			t.Fatalf("expected evidence for %q", adi)
		}
		if err := Verify(ev, adi, expired, keys); err == nil {
			t.Fatalf("expired epoch admitted %q", adi)
		}
	}
}

// ── Transport hostility ─────────────────────────────────────────────────────

func TestE2EHostileTransportCannotForgeEntitlement(t *testing.T) {
	docJSON, keys := loadE2E(t)
	var parsed Document
	if err := json.Unmarshal([]byte(docJSON), &parsed); err != nil {
		t.Fatal(err)
	}

	// A mirror that inserts itself into an otherwise genuine document.
	tampered := parsed
	tampered.Set.Leaves = append(append([]Leaf{}, parsed.Set.Leaves...),
		Leaf{ADIURL: "acc://attacker.acme/data", Status: StatusActive,
			IntentCeilingMicroUSD: 999_000_000, EpochCeilingMicroUSD: 999_000_000})
	body, _ := json.Marshal(tampered)

	srv := serveDoc(t, string(body), 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err == nil {
		t.Fatal("a set that does not match the signed hash must be rejected")
	}
	if store.BuildEvidence("acc://attacker.acme/data") != nil {
		t.Fatal("a rejected document must not populate the cache")
	}
	// And nothing legitimate leaked into the cache either.
	if store.BuildEvidence("acc://payer0001.acme/data") != nil {
		t.Fatal("a rejected document must leave the cache empty, not partially populated")
	}
}

func TestE2EEveryTransportFailureFailsClosed(t *testing.T) {
	docJSON, keys := loadE2E(t)

	for name, body := range map[string]struct {
		payload string
		code    int
	}{
		"500":            {"boom", 500},
		"404":            {"nope", 404},
		"empty":          {"", 200},
		"truncated":      {docJSON[:len(docJSON)/2], 200},
		"html":           {"<!doctype html><h1>gateway</h1>", 200},
		"null":           {"null", 200},
		"array":          {"[]", 200},
		"missing header": {`{"set":{"leaves":[]}}`, 200},
	} {
		srv := serveDoc(t, body.payload, body.code)
		store := e2eStore(t, srv.URL, keys)
		_ = store.Refresh(context.Background())
		if ev := store.BuildEvidence("acc://payer0001.acme/data"); ev != nil {
			t.Fatalf("%s produced usable evidence; every transport failure must fail closed", name)
		}
	}
}

// ── Property tests over random populations ──────────────────────────────────

// Randomly generated sets, verified exhaustively. Catches ordering and
// odd/even Merkle bugs that a fixed fixture cannot.
func TestPropertyEveryMemberVerifiesAndNoNonMemberDoes(t *testing.T) {
	rng := rand.New(rand.NewSource(20260726))
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatal(err)
	}
	keys := KeySet{"p": pub}

	for round := range 60 {
		n := 1 + rng.Intn(120)
		leaves := make([]Leaf, 0, n)
		for i := range n {
			st := StatusActive
			ceiling := int64(1 + rng.Intn(50_000_000))
			switch rng.Intn(6) {
			case 0:
				st = StatusSuspended
				ceiling = 0
			case 1:
				st = StatusClosed
				ceiling = 0
			case 2:
				ceiling = 0 // active but broke
			}
			leaves = append(leaves, Leaf{
				ADIURL:                fmt.Sprintf("acc://r%dn%04d.acme/data", round, i),
				Status:                st,
				Tier:                  []string{"", "starter", "growth"}[rng.Intn(3)],
				IntentCeilingMicroUSD: ceiling,
				EpochCeilingMicroUSD:  ceiling * 20,
			})
		}
		set := &Set{Leaves: leaves}
		sh, err := set.SetHash()
		if err != nil {
			t.Fatal(err)
		}
		hdr := Header{
			Epoch: uint64(round), Root: set.Root(), SetHash: sh,
			NativeUSDMicro: 3_000_000_000,
			IssuedAtUnix:   now - 60, NotAfterUnix: now + 600, KeyID: "p",
		}
		hdr.Signature = hex.EncodeToString(ed25519.Sign(priv, hdr.SigningBytes()))

		for _, leaf := range set.Leaves {
			proof, l, ok := set.BuildProof(leaf.ADIURL)
			if !ok {
				t.Fatalf("round %d: no proof for member %q", round, leaf.ADIURL)
			}
			err := Verify(&Evidence{Header: hdr, Leaf: l, Proof: proof}, leaf.ADIURL, now, keys)
			if leaf.Entitled() && err != nil {
				t.Fatalf("round %d: entitled member %q refused: %v", round, leaf.ADIURL, err)
			}
			if !leaf.Entitled() && err == nil {
				t.Fatalf("round %d: unentitled member %q admitted", round, leaf.ADIURL)
			}
		}
		// Non-members can never obtain a proof.
		for i := range 5 {
			if _, _, ok := set.BuildProof(fmt.Sprintf("acc://ghost%d-%d.acme/data", round, i)); ok {
				t.Fatalf("round %d: built a proof for a non-member", round)
			}
		}
	}
}

// The root must be a pure function of set CONTENT, never of insertion order.
// Two gateway replicas reading the same rows in different orders must publish
// the same root, or validators would reject one of them.
func TestPropertyRootIsOrderIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for round := range 40 {
		n := 1 + rng.Intn(60)
		leaves := make([]Leaf, 0, n)
		for i := range n {
			leaves = append(leaves, Leaf{
				ADIURL: fmt.Sprintf("acc://o%dn%04d.acme/data", round, i),
				Status: StatusActive, IntentCeilingMicroUSD: int64(i + 1), EpochCeilingMicroUSD: int64(i+1) * 10,
			})
		}
		want := (&Set{Leaves: leaves}).Root()
		for range 5 {
			shuffled := make([]Leaf, len(leaves))
			copy(shuffled, leaves)
			rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			if got := (&Set{Leaves: shuffled}).Root(); got != want {
				t.Fatalf("round %d: root depends on input order", round)
			}
		}
	}
}

// ── Concurrency under refresh ───────────────────────────────────────────────

func TestE2EConcurrentAdmissionDuringRefresh(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := docTime(t, docJSON)

	var wg sync.WaitGroup
	errCh := make(chan error, 64)

	// Readers on the admission path while the refresher runs — the real
	// production shape, where intents arrive during a poll.
	for w := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 200 {
				adi := fmt.Sprintf("acc://payer%04d.acme/data", (w*37+i)%250)
				ev := store.BuildEvidence(adi)
				if ev == nil {
					errCh <- fmt.Errorf("lost evidence for %s mid-refresh", adi)
					return
				}
				if err := Verify(ev, adi, now, keys); err != nil {
					errCh <- fmt.Errorf("%s refused mid-refresh: %w", adi, err)
					return
				}
			}
		}(w)
	}
	for range 15 {
		_ = store.Refresh(context.Background())
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// ── Scale ───────────────────────────────────────────────────────────────────

func TestE2EEvidenceStaysSmallEnoughToRideInEveryBlock(t *testing.T) {
	docJSON, keys := loadE2E(t)
	srv := serveDoc(t, docJSON, 200)
	store := e2eStore(t, srv.URL, keys)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	ev := store.BuildEvidence("acc://payer0100.acme/data")
	if ev == nil {
		t.Fatal("expected evidence")
	}
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	// Evidence is carried inside EVERY ValidatorBlock, so its size is consensus
	// bandwidth. An inclusion proof is logarithmic — 254 accounts needs 8 steps —
	// so this should stay small even as the customer base grows.
	if len(encoded) > 4096 {
		t.Fatalf("evidence is %d bytes; too large to ride in every block", len(encoded))
	}
	t.Logf("evidence for a 254-account set: %d bytes, %d proof steps", len(encoded), len(ev.Proof))

	if len(ev.Proof) > 12 {
		t.Fatalf("proof has %d steps for 254 accounts; expected ~8 (log2)", len(ev.Proof))
	}
}

func TestE2ESetHashCoversTheWholePopulation(t *testing.T) {
	docJSON, _ := loadE2E(t)
	var parsed Document
	if err := json.Unmarshal([]byte(docJSON), &parsed); err != nil {
		t.Fatal(err)
	}
	got, err := parsed.Set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got, parsed.Header.SetHash) {
		t.Fatalf("Go and the gateway disagree on the hash of a 254-account set:\n Go %s\n TS %s",
			got, parsed.Header.SetHash)
	}
	if got := parsed.Set.Root(); !strings.EqualFold(got, parsed.Header.Root) {
		t.Fatalf("Go and the gateway disagree on the root:\n Go %s\n TS %s", got, parsed.Header.Root)
	}
}
