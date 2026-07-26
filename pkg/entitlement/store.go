package entitlement

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store holds the current entitlement epoch so a proposer can attach evidence
// without doing I/O on the hot path.
//
// # THE ONE OUTBOUND DEPENDENCY THIS DESIGN ADDS, and how it is contained
//
// A proposer needs the full set in order to build an inclusion proof, so a
// validator must obtain it from somewhere. Four properties keep that from
// becoming a liability:
//
//  1. It is NEVER fetched inline. A background loop refreshes; the proposer only
//     reads an in-memory snapshot. A slow or hanging gateway cannot stall intent
//     processing, consensus, or execution.
//
//  2. The transport is UNTRUSTED. Whatever is fetched is verified against an
//     ed25519 signature over the header and a SHA-256 over the set. A hostile
//     mirror, a corrupted CDN or a MITM can withhold the set but cannot forge
//     one. This is why the blob may be served from anywhere.
//
//  3. Failure fails CLOSED. No set, a stale set, or a set that does not match
//     its signed hash all mean "no evidence to attach", which the consensus gate
//     refuses. An attacker who takes the gateway offline stops CERTEN spending
//     money; they do not get free service.
//
//  4. It is not in the consensus path. Verification of a ValidatorBlock reads
//     only what the block carries. The Store is used by the PROPOSER to build
//     evidence, never by a verifier to check it — so two validators with
//     different cache states can still agree on whether a given block is valid.
//
// The honest cost of this design: while the gateway is down, no NEW intents can
// be admitted. That is the correct direction to fail for a fee layer, but it is
// a real availability coupling and should be understood rather than discovered.
type Store struct {
	mu     sync.RWMutex
	set    *Set
	header *Header
	// fetchedAt is local wall time, used ONLY for refresh scheduling and
	// staleness reporting. It never influences a consensus decision — expiry for
	// that purpose is judged against block time inside Verify.
	fetchedAt time.Time

	cfg    StoreConfig
	keys   KeySet
	client *http.Client
	logger *log.Logger

	// Observability. A silently empty store looks identical to a working one
	// until intents start being refused, so the counters are part of the design.
	refreshOK   uint64
	refreshFail uint64
	lastErr     string
}

// StoreConfig configures the background refresher.
type StoreConfig struct {
	// URL serves the epoch document (header + set). Empty disables the store
	// entirely, which is the correct behaviour for a deployment not using the
	// entitlement gate.
	URL string

	// RefreshInterval is how often to poll. Should be well under the epoch
	// lifetime so a missed poll is not immediately fatal.
	RefreshInterval time.Duration

	// MaxAge bounds how long a cached epoch may be used after it was fetched.
	// A second line of defence behind the epoch's own NotAfter, protecting
	// against a publisher that keeps signing long-lived epochs.
	MaxAge time.Duration

	// Timeout for a single fetch.
	Timeout time.Duration
}

// Document is what the publisher serves and the store consumes.
type Document struct {
	Header Header `json:"header"`
	Set    Set    `json:"set"`
}

// StoreConfigFromEnv reads the refresher configuration.
//
//	CERTEN_ENTITLEMENT_URL              (no default; empty disables)
//	CERTEN_ENTITLEMENT_REFRESH_SEC      default 30
//	CERTEN_ENTITLEMENT_MAX_AGE_SEC      default 900 (15 min)
//	CERTEN_ENTITLEMENT_TIMEOUT_SEC      default 10
//
// MaxAge defaults generously relative to the refresh interval — 30 missed polls
// — because refusing every intent the moment one poll fails would make a
// transient network blip look like a fee-layer outage. The epoch's own NotAfter
// remains the authoritative bound.
func StoreConfigFromEnv() StoreConfig {
	return StoreConfig{
		URL:             strings.TrimSpace(os.Getenv("CERTEN_ENTITLEMENT_URL")),
		RefreshInterval: envDuration("CERTEN_ENTITLEMENT_REFRESH_SEC", 30*time.Second),
		MaxAge:          envDuration("CERTEN_ENTITLEMENT_MAX_AGE_SEC", 900*time.Second),
		Timeout:         envDuration("CERTEN_ENTITLEMENT_TIMEOUT_SEC", 10*time.Second),
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// NewStore builds a store. It does not fetch; call Start.
func NewStore(cfg StoreConfig, keys KeySet, logger *log.Logger) *Store {
	if logger == nil {
		logger = log.New(log.Writer(), "[Entitlement] ", log.LstdFlags)
	}
	return &Store{
		cfg:    cfg,
		keys:   keys,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger,
	}
}

// Enabled reports whether this store can ever produce evidence.
func (s *Store) Enabled() bool { return s != nil && s.cfg.URL != "" }

// Start begins background refreshing. Returns immediately.
//
// The first refresh is attempted synchronously so a misconfiguration is visible
// at startup rather than as mysterious refusals later — but a FAILED first
// refresh is not fatal. A validator must be able to boot while the gateway is
// down; it simply cannot admit new intents until the set arrives.
func (s *Store) Start(ctx context.Context) {
	if !s.Enabled() {
		s.logger.Printf("entitlement store disabled (CERTEN_ENTITLEMENT_URL unset)")
		return
	}
	if err := s.Refresh(ctx); err != nil {
		s.logger.Printf("⚠️ initial entitlement refresh failed: %v (will retry every %s; intents cannot be admitted until it succeeds)",
			err, s.cfg.RefreshInterval)
	}
	go func() {
		t := time.NewTicker(s.cfg.RefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.Refresh(ctx); err != nil {
					s.logger.Printf("⚠️ entitlement refresh failed: %v", err)
				}
			}
		}
	}()
}

// Refresh fetches and verifies one epoch document.
//
// A failed refresh leaves the previous good snapshot in place. That is
// deliberate: a single failed poll should not immediately halt admission, and
// the snapshot's own expiry still bounds how long it can be used.
func (s *Store) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return s.fail(fmt.Errorf("build request: %w", err))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return s.fail(fmt.Errorf("fetch: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s.fail(fmt.Errorf("fetch: HTTP %d", resp.StatusCode))
	}
	// Bounded read: an unbounded body from an untrusted endpoint is a memory
	// exhaustion vector, and a legitimate set of a few thousand accounts is far
	// below this.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return s.fail(fmt.Errorf("read: %w", err))
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return s.fail(fmt.Errorf("decode: %w", err))
	}
	if err := s.verifyDocument(&doc); err != nil {
		return s.fail(err)
	}

	s.mu.Lock()
	prevEpoch := uint64(0)
	if s.header != nil {
		prevEpoch = s.header.Epoch
	}
	// Never move backwards. A rollback to an older epoch would reinstate
	// entitlements that have since been revoked, and is the shape a replay
	// attack against the blob endpoint would take.
	if doc.Header.Epoch < prevEpoch {
		s.mu.Unlock()
		return s.fail(fmt.Errorf("refusing epoch %d, older than cached epoch %d", doc.Header.Epoch, prevEpoch))
	}
	set := doc.Set
	s.set = &set
	h := doc.Header
	s.header = &h
	s.fetchedAt = time.Now()
	s.refreshOK++
	s.lastErr = ""
	s.mu.Unlock()

	if doc.Header.Epoch != prevEpoch {
		s.logger.Printf("✅ entitlement epoch %d loaded: %d accounts, expires %s",
			doc.Header.Epoch, len(doc.Set.Leaves), time.Unix(doc.Header.NotAfterUnix, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// verifyDocument checks the document against the pinned keys and its own hash.
// The transport is untrusted; this is what makes that acceptable.
func (s *Store) verifyDocument(doc *Document) error {
	if err := verifyHeaderSignature(doc.Header, s.keys); err != nil {
		return err
	}
	// The set must be exactly the set the header committed to.
	gotHash, err := doc.Set.SetHash()
	if err != nil {
		return fmt.Errorf("hash set: %w", err)
	}
	if !strings.EqualFold(gotHash, doc.Header.SetHash) {
		return fmt.Errorf("set hash mismatch: computed %s, header says %s", gotHash, doc.Header.SetHash)
	}
	// And the root must be reproducible from the set, or an inclusion proof
	// built against it would never verify downstream.
	if gotRoot := doc.Set.Root(); !strings.EqualFold(gotRoot, doc.Header.Root) {
		return fmt.Errorf("root mismatch: computed %s, header says %s", gotRoot, doc.Header.Root)
	}
	return nil
}

func verifyHeaderSignature(h Header, keys KeySet) error {
	pub, ok := keys[h.KeyID]
	if !ok {
		return fmt.Errorf("header signed by unpinned key %q", h.KeyID)
	}
	sig, err := hex.DecodeString(h.Signature)
	if err != nil {
		return fmt.Errorf("header signature is not hex")
	}
	if !ed25519.Verify(pub, h.SigningBytes(), sig) {
		return fmt.Errorf("header signature invalid for key %q", h.KeyID)
	}
	return nil
}

func (s *Store) fail(err error) error {
	s.mu.Lock()
	s.refreshFail++
	s.lastErr = err.Error()
	s.mu.Unlock()
	return err
}

// BuildEvidence produces entitlement evidence for an ADI, or nil.
//
// Returns nil (not an error) when evidence cannot be built — absent account,
// no snapshot, stale snapshot. Absence IS the refusal downstream, and
// distinguishing "not entitled" from "cannot currently tell" at this layer would
// invite a caller to treat the latter as permission.
//
// Never performs I/O. Safe to call on the intent-processing path.
func (s *Store) BuildEvidence(adiURL string) *Evidence {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	set, header, fetchedAt := s.set, s.header, s.fetchedAt
	s.mu.RUnlock()

	if set == nil || header == nil {
		return nil
	}
	// Local staleness bound, on top of the epoch's own NotAfter. Uses wall time,
	// which is fine here: this decides whether to ATTACH evidence, and attaching
	// stale evidence merely gets it rejected by the deterministic verifier.
	if s.cfg.MaxAge > 0 && time.Since(fetchedAt) > s.cfg.MaxAge {
		return nil
	}

	proof, leaf, ok := set.BuildProof(adiURL)
	if !ok {
		return nil
	}
	return &Evidence{Header: *header, Leaf: leaf, Proof: proof}
}

// Lookup reports an account's entitlement from the cached snapshot, for the
// cheap pre-screen. The second return is false when the answer is unknown —
// which callers must NOT treat as entitled.
func (s *Store) Lookup(adiURL string) (Leaf, bool) {
	if s == nil {
		return Leaf{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.set == nil {
		return Leaf{}, false
	}
	return s.set.Lookup(adiURL)
}

// Snapshot reports store health for logging and metrics.
type Snapshot struct {
	Enabled     bool
	Epoch       uint64
	Accounts    int
	FetchedAt   time.Time
	Age         time.Duration
	Stale       bool
	RefreshOK   uint64
	RefreshFail uint64
	LastError   string
}

// Health returns the current store state. A silently empty store is
// indistinguishable from a healthy one until intents start being refused, so
// this is deliberately exposed rather than kept internal.
func (s *Store) Health() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		Enabled:     s.cfg.URL != "",
		RefreshOK:   s.refreshOK,
		RefreshFail: s.refreshFail,
		LastError:   s.lastErr,
		FetchedAt:   s.fetchedAt,
	}
	if s.header != nil {
		snap.Epoch = s.header.Epoch
	}
	if s.set != nil {
		snap.Accounts = len(s.set.Leaves)
	}
	if !s.fetchedAt.IsZero() {
		snap.Age = time.Since(s.fetchedAt)
		snap.Stale = s.cfg.MaxAge > 0 && snap.Age > s.cfg.MaxAge
	} else {
		snap.Stale = true
	}
	return snap
}
