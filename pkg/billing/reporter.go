// Copyright 2026 Certen Protocol
//
// The cost reporter: a durable, non-blocking pipe from "leg confirmed on
// chain" to "gateway knows what it cost".
package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CostEvent is the wire payload POSTed to the gateway.
//
// Field names and JSON shape must match the gateway's
// POST /internal/v1/billing/cost-events schema. Note what is NOT here: any USD
// amount. The validator reports chain facts and the gateway prices them with
// its own signed FX observation, so "what CERTEN spent" is never an assertion
// by whichever process happened to report it.
type CostEvent struct {
	IntentID string `json:"intent_id"`
	// AccumTxHash correlates this cost back to the gateway's intent.
	//
	// IntentID is the VALIDATOR's own identifier and means nothing to the
	// gateway, whose intents are keyed by their own UUID. Without a shared key
	// the gateway could store cost events but never join them to an intent, so
	// measured gas never reached settlement and no intent could be shown to
	// have executed. The Accumulate transaction hash is the one identifier both
	// sides already hold.
	AccumTxHash string `json:"accum_tx_hash,omitempty"`

	// ADIURL is the Accumulate identity that authorised the intent, e.g.
	// "acc://certen-kermit-12.acme".
	//
	// Carried because the validator CANNOT supply OrgID and never could: org_id is a UUID from
	// the gateway's own organizations table, and the validator only ever sees Accumulate ADIs.
	// Sending anything else fails the uuid cast at insert with a 500 — which is exactly what
	// happened on 2026-08-05 when the batch path began reporting and passed the intent's
	// created_by ("v8_1-cadence-...") through as org_id.
	//
	// The ADI is the identity the validator DOES hold authoritatively, and it gives the gateway
	// a second, human-meaningful key to resolve an org from when accum_tx_hash alone does not
	// (an intent submitted directly to Accumulate never appears in gateway_intents).
	ADIURL string `json:"adi_url,omitempty"`

	// OrgID is populated by the GATEWAY, not here. Kept on the wire only so an operator tool
	// can round-trip an event; the validator always sends it empty.
	OrgID string `json:"org_id,omitempty"`

	// ProofClass is "on_cadence" or "on_demand", and is a PRICE dimension at the
	// gateway rather than a label.
	//
	// on_cadence batches up to 20 intents behind one anchor, so a member pays
	// roughly 1/N of it; on_demand is a batch of one and pays that anchor
	// outright. Until this was carried, the gateway took a single median across
	// both populations, so batched intents were charged for anchor capacity they
	// never used and expedited intents were charged less than their own anchor
	// cost — CERTEN covering the difference on every one.
	//
	// Omitted when the reporting path cannot know the class. The gateway treats
	// absent as unclassified and prices from those rows only when a class has no
	// history of its own, so omitting costs precision but never corrupts a
	// classified median.
	ProofClass string `json:"proof_class,omitempty"`

	Chain                string `json:"chain"`
	ChainID              int64  `json:"chain_id,omitempty"`
	Leg                  string `json:"leg"`
	TxHash               string `json:"tx_hash"`
	BlockNumber          string `json:"block_number,omitempty"`
	GasUsed              string `json:"gas_used"`
	EffectiveGasPriceWei string `json:"effective_gas_price_wei"`
	// L1FeeWei is the OP-stack L1 data fee, ADDITIVE to gas_used * gas_price.
	//
	// Omitted on chains that do not have one. The gateway must compute
	// native = gas_used * gas_price + l1_fee_wei; using the product alone
	// under-charges Base and Optimism by the whole data fee.
	L1FeeWei       string            `json:"l1_fee_wei,omitempty"`
	NativeSymbol   string            `json:"native_symbol"`
	WeiPerNative   string            `json:"wei_per_native"`
	InclusionProof interface{}       `json:"inclusion_proof,omitempty"`
	Breakdown      map[string]string `json:"breakdown,omitempty"`
	FreeAtMargin   bool              `json:"free_at_margin,omitempty"`
	ObservedAt     string            `json:"observed_at"`
	IdempotencyKey string            `json:"idempotency_key"`
}

// NewCostEvent converts a measured ChainCost into the wire payload.
//
// adiURL identifies the authorising Accumulate identity. There is deliberately NO orgID
// parameter: see CostEvent.OrgID — the validator cannot know the gateway's org UUID, and the
// one time it tried to supply something org-shaped it produced a 500 on every event.
func NewCostEvent(intentID, adiURL, accumTxHash string, c *ChainCost, inclusionProof interface{}) (*CostEvent, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if intentID == "" {
		return nil, fmt.Errorf("billing: intent_id is required to attribute a cost")
	}
	return &CostEvent{
		IntentID:             intentID,
		AccumTxHash:          accumTxHash,
		ADIURL:               adiURL,
		Chain:                c.Chain,
		ChainID:              c.ChainID,
		Leg:                  c.Leg,
		TxHash:               c.TxHash,
		BlockNumber:          c.BlockNumber,
		GasUsed:              fmt.Sprintf("%d", c.GasUsed),
		EffectiveGasPriceWei: c.GasPriceWei.String(),
		L1FeeWei:             l1FeeString(c.L1FeeWei),
		NativeSymbol:         c.NativeSymbol,
		WeiPerNative:         c.WeiPerNative.String(),
		InclusionProof:       inclusionProof,
		Breakdown:            c.Breakdown,
		FreeAtMargin:         c.FreeAtMargin,
		ObservedAt:           c.ObservedAt.UTC().Format(time.RFC3339Nano),
		// Deterministic per (chain, tx, leg): a WAL replay, a retry, and a
		// duplicated call all collapse to one row at the gateway.
		IdempotencyKey: fmt.Sprintf("cost:%s:%s:%s", c.Chain, c.TxHash, c.Leg),
	}, nil
}

// ReporterConfig configures the reporter.
type ReporterConfig struct {
	// GatewayURL is the gateway base URL, e.g. https://gateway.kompendium.co
	GatewayURL string
	// ServiceTokenSecret is shared with the gateway's
	// VALIDATOR_SERVICE_TOKEN_SECRET. Empty disables reporting entirely.
	ServiceTokenSecret string
	// ServiceTokenVersion selects the key version ("v1"/"v2") for rotation.
	ServiceTokenVersion string
	// WALDir persists undelivered events across restarts.
	WALDir string
	// QueueSize bounds in-memory buffering; overflow spills to the WAL only.
	QueueSize int
	// MaxAttempts before an event is parked for manual inspection.
	MaxAttempts int
	// RetryBase is the initial backoff, doubled per attempt.
	RetryBase time.Duration
	HTTP      *http.Client
	Logger    *log.Logger
}

// Reporter delivers cost events to the gateway.
//
// Durability model: an event is written to the WAL BEFORE it is queued, and
// removed only after the gateway acknowledges it. A crash at any point leaves
// the event on disk and it is replayed on the next start. The alternative — an
// in-memory queue — loses the number permanently while the chain has already
// charged us for the gas.
type Reporter struct {
	cfg    ReporterConfig
	queue  chan string // WAL filenames pending delivery
	wg     sync.WaitGroup
	stop   chan struct{}
	once   sync.Once
	logger *log.Logger

	mu       sync.Mutex
	inflight map[string]bool

	// Counters for observability.
	delivered uint64
	failed    uint64
	parked    uint64
}

// NewReporter creates a reporter. Returns nil (and logs) when reporting is not
// configured, so callers can hold a nil *Reporter and call Report on it safely.
func NewReporter(cfg ReporterConfig) *Reporter {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[CostReporter] ", log.LstdFlags)
	}
	if cfg.GatewayURL == "" || cfg.ServiceTokenSecret == "" {
		logger.Printf("⚠️ Cost reporting disabled (CERTEN_GATEWAY_URL / VALIDATOR_SERVICE_TOKEN_SECRET unset). " +
			"Chains will stay unpriceable at the gateway until measured cost data exists.")
		return nil
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 12
	}
	if cfg.RetryBase <= 0 {
		cfg.RetryBase = 2 * time.Second
	}
	if cfg.ServiceTokenVersion == "" {
		cfg.ServiceTokenVersion = "v1"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.WALDir == "" {
		cfg.WALDir = filepath.Join(os.TempDir(), "certen-cost-wal")
	}
	if err := os.MkdirAll(cfg.WALDir, 0o700); err != nil {
		logger.Printf("❌ Cannot create WAL dir %s: %v — cost reporting disabled", cfg.WALDir, err)
		return nil
	}

	r := &Reporter{
		cfg:      cfg,
		queue:    make(chan string, cfg.QueueSize),
		stop:     make(chan struct{}),
		logger:   logger,
		inflight: map[string]bool{},
	}
	return r
}

// Start launches the delivery worker and replays anything left by a previous
// process.
func (r *Reporter) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.wg.Add(1)
	go r.worker(ctx)
	go r.replayWAL()
	r.logger.Printf("🚀 Cost reporter started (wal=%s, gateway=%s)", r.cfg.WALDir, r.cfg.GatewayURL)
}

// Stop drains briefly and shuts the worker down. Undelivered events stay in the
// WAL for the next process.
func (r *Reporter) Stop(timeout time.Duration) {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.stop) })
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		r.logger.Printf("⚠️ Cost reporter stop timed out; %d event(s) remain in the WAL", r.pendingCount())
	}
	r.logger.Printf("🛑 Cost reporter stopped (delivered=%d failed=%d parked=%d)", r.delivered, r.failed, r.parked)
}

// Report durably records an event and queues it for delivery.
//
// NEVER blocks and NEVER returns an error that a caller should act on: cost
// reporting must not be able to fail a proof cycle. A full queue still writes
// the WAL, so the event is delivered on the next replay rather than dropped.
func (r *Reporter) Report(event *CostEvent) {
	if r == nil || event == nil {
		return
	}
	name, err := r.writeWAL(event)
	if err != nil {
		// Last resort: log the whole event so the number is at least
		// recoverable from logs.
		blob, _ := json.Marshal(event)
		r.logger.Printf("❌ WAL write failed (%v). Event: %s", err, string(blob))
		return
	}
	select {
	case r.queue <- name:
	default:
		// Queue full — the WAL replay will pick it up. Not an error.
		r.logger.Printf("⚠️ Cost queue full; %s deferred to WAL replay", event.IdempotencyKey)
	}
}

// ObserveAndReport probes the chain for a transaction's real cost and reports
// it. Intended to be called from the executor right after a leg confirms.
//
// Runs in its own goroutine and swallows every error: a chain that will not
// answer must not stall an intent. Errors are logged and the event simply does
// not exist — which the gateway's chain-priceability gate then treats as
// "unmeasured", i.e. it refuses to price that chain rather than guessing. That
// is the correct failure direction.
func (r *Reporter) ObserveAndReport(
	ctx context.Context,
	probeCfg ProbeConfig,
	intentID, adiURL, accumTxHash, txHash string,
	inclusionProof interface{},
) {
	if r == nil {
		return
	}
	go func() {
		// Detach from the request context: the proof cycle may finish (and
		// cancel) long before a chain indexes the transaction.
		bg, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		probe, err := NewProbe(probeCfg)
		if err != nil {
			r.logger.Printf("⚠️ No fee model for %s: %v", probeCfg.Chain, err)
			return
		}

		// Chains index at very different speeds; retry rather than accept a
		// missing number, because a missing number is money we cannot recover.
		var cost *ChainCost
		delay := 2 * time.Second
		for attempt := 1; attempt <= 8; attempt++ {
			cost, err = probe.ObservedCost(bg, txHash)
			if err == nil {
				break
			}
			select {
			case <-bg.Done():
				r.logger.Printf("⚠️ Cost probe for %s/%s timed out: %v", probeCfg.Chain, txHash, err)
				return
			case <-time.After(delay):
			}
			if delay < 30*time.Second {
				delay *= 2
			}
		}
		if cost == nil {
			r.logger.Printf("❌ Could not measure cost for %s/%s after retries: %v", probeCfg.Chain, txHash, err)
			return
		}

		event, err := NewCostEvent(intentID, adiURL, accumTxHash, cost, inclusionProof)
		if err != nil {
			r.logger.Printf("❌ Rejecting malformed cost event for %s/%s: %v", probeCfg.Chain, txHash, err)
			return
		}
		event.ProofClass = probeCfg.ProofClass
		r.logger.Printf("💰 %s %s leg=%s cost=%s %s (tx %s)",
			probeCfg.Chain, humanAmount(cost), cost.Leg, cost.NativeAmount.String(), cost.NativeSymbol, txHash)
		r.Report(event)
	}()
}

func humanAmount(c *ChainCost) string {
	if c.FreeAtMargin {
		return "(free at margin)"
	}
	return ""
}

// ── WAL ─────────────────────────────────────────────────────────────────────
//
// One file per pending event, named after its idempotency key. Written to a
// temp file and renamed, so a crash mid-write never leaves a half-parsed event.
// Delivery deletes the file. No compaction, no index, nothing to corrupt.

func walFileName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16]) + ".json"
}

func (r *Reporter) writeWAL(event *CostEvent) (string, error) {
	name := walFileName(event.IdempotencyKey)
	full := filepath.Join(r.cfg.WALDir, name)
	if _, err := os.Stat(full); err == nil {
		return name, nil // already pending; idempotent
	}
	blob, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return name, nil
}

func (r *Reporter) readWAL(name string) (*CostEvent, error) {
	blob, err := os.ReadFile(filepath.Join(r.cfg.WALDir, name))
	if err != nil {
		return nil, err
	}
	var e CostEvent
	if err := json.Unmarshal(blob, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *Reporter) deleteWAL(name string) {
	if err := os.Remove(filepath.Join(r.cfg.WALDir, name)); err != nil && !os.IsNotExist(err) {
		r.logger.Printf("⚠️ Could not remove WAL entry %s: %v", name, err)
	}
}

// park moves a permanently failing event aside so it stops consuming retries
// but is still available for inspection. Deleting it would destroy the only
// record of money we spent.
func (r *Reporter) park(name string, reason string) {
	parkDir := filepath.Join(r.cfg.WALDir, "parked")
	if err := os.MkdirAll(parkDir, 0o700); err != nil {
		r.logger.Printf("⚠️ Cannot create parked dir: %v", err)
		return
	}
	src := filepath.Join(r.cfg.WALDir, name)
	dst := filepath.Join(parkDir, name)
	if err := os.Rename(src, dst); err != nil {
		r.logger.Printf("⚠️ Could not park %s: %v", name, err)
		return
	}
	r.parked++
	r.logger.Printf("🅿️ Parked undeliverable cost event %s (%s). Inspect %s", name, reason, dst)
}

func (r *Reporter) pendingCount() int {
	entries, err := os.ReadDir(r.cfg.WALDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// replayWAL re-queues everything left on disk by a previous process.
func (r *Reporter) replayWAL() {
	entries, err := os.ReadDir(r.cfg.WALDir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	r.logger.Printf("♻️ Replaying %d undelivered cost event(s) from the WAL", len(names))
	for _, n := range names {
		select {
		case r.queue <- n:
		case <-r.stop:
			return
		}
	}
}

// ── delivery ────────────────────────────────────────────────────────────────

func (r *Reporter) worker(ctx context.Context) {
	defer r.wg.Done()
	// Periodic sweep catches anything that overflowed the queue or was written
	// while the worker was busy.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-ticker.C:
			r.replayWAL()
		case name := <-r.queue:
			r.deliver(ctx, name)
		}
	}
}

func (r *Reporter) deliver(ctx context.Context, name string) {
	r.mu.Lock()
	if r.inflight[name] {
		r.mu.Unlock()
		return
	}
	r.inflight[name] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inflight, name)
		r.mu.Unlock()
	}()

	event, err := r.readWAL(name)
	if err != nil {
		if os.IsNotExist(err) {
			return // already delivered
		}
		r.park(name, fmt.Sprintf("unreadable: %v", err))
		return
	}

	delay := r.cfg.RetryBase
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		status, body, err := r.post(ctx, event)
		switch {
		case err == nil && (status == http.StatusCreated || status == http.StatusOK):
			// 200 means the gateway already had it (idempotent replay) — just
			// as final as 201.
			r.delivered++
			r.deleteWAL(name)
			return

		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			// A bad secret will not fix itself by retrying, and burning
			// attempts hides the real problem.
			r.park(name, fmt.Sprintf("auth rejected (%d): %s", status, truncate(body, 200)))
			return

		case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
			r.park(name, fmt.Sprintf("rejected as malformed (%d): %s", status, truncate(body, 200)))
			return

		case status == http.StatusServiceUnavailable:
			// Billing disabled, or no fresh FX observation. Both are transient
			// operator states worth waiting out.
			r.logger.Printf("⏳ Gateway not ready for cost events (503); retrying %s", event.IdempotencyKey)

		default:
			if err != nil {
				r.logger.Printf("⚠️ Cost delivery attempt %d/%d failed: %v", attempt, r.cfg.MaxAttempts, err)
			} else {
				r.logger.Printf("⚠️ Cost delivery attempt %d/%d got HTTP %d: %s",
					attempt, r.cfg.MaxAttempts, status, truncate(body, 200))
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-time.After(delay):
		}
		if delay < 5*time.Minute {
			delay *= 2
		}
	}

	r.failed++
	r.logger.Printf("⚠️ Cost event %s undelivered after %d attempts; it stays in the WAL for the next process",
		event.IdempotencyKey, r.cfg.MaxAttempts)
}

func (r *Reporter) post(ctx context.Context, event *CostEvent) (int, string, error) {
	// Marshal ONCE and sign exactly these bytes. The gateway verifies the HMAC
	// against the raw body it received, so any re-serialization here (or there)
	// would break every request with an opaque signature mismatch.
	body, err := json.Marshal(event)
	if err != nil {
		return 0, "", err
	}

	const path = "/internal/v1/billing/cost-events"
	url := strings.TrimSuffix(r.cfg.GatewayURL, "/") + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Certen-Service-Caller", "certen-validator")
	req.Header.Set("X-Certen-Service-Token", ServiceToken(
		http.MethodPost, path, body, r.cfg.ServiceTokenSecret, r.cfg.ServiceTokenVersion,
	))

	resp, err := r.cfg.HTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), nil
}

// ServiceToken builds the X-Certen-Service-Token header.
//
// Wire format and signed string must match the gateway's verifier exactly
// (api-gateway/src/clients/downstream-auth.ts):
//
//	header: t=<unix>,m=<METHOD>,kv=<version>,n=<nonce>,v1=<hex>
//	signed: "${t}.${METHOD}.${path}.${bodyLen}.${bodyHash}.${nonce}"
//
// The bindings each defeat a specific attack: `t` bounds replay to a window,
// METHOD stops a GET/POST swap, `path` is canonicalized (query keys sorted),
// bodyLen defeats truncation, bodyHash defeats payload swap, and the nonce
// defeats replay inside the window.
func ServiceToken(method, path string, body []byte, secret, version string) string {
	t := time.Now().Unix()
	nonce := newNonce()
	sum := sha256.Sum256(body)
	signed := fmt.Sprintf("%d.%s.%s.%d.%s.%s",
		t, strings.ToUpper(method), canonicalPath(path), len(body), hex.EncodeToString(sum[:]), nonce)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	return fmt.Sprintf("t=%d,m=%s,kv=%s,n=%s,v1=%s",
		t, strings.ToUpper(method), version, nonce, hex.EncodeToString(mac.Sum(nil)))
}

// canonicalPath sorts query parameters by key, byte-for-byte identical to the
// gateway's implementation in clients/downstream-auth.ts.
//
// Note the valueless-key case: the gateway parses `?flag` into the pair
// ("flag", "") and re-emits it as `flag=`. Preserving the bare `flag` here
// would produce a different signing string and a signature mismatch that no
// error message would explain. The verifier defines the format; this follows
// it. (Caught by the cross-language vector test, not by review.)
func canonicalPath(rawURL string) string {
	parts := strings.SplitN(rawURL, "?", 2)
	if len(parts) == 1 || parts[1] == "" {
		return parts[0]
	}

	type pair struct{ k, v string }
	pairs := make([]pair, 0, 8)
	for _, p := range strings.Split(parts[1], "&") {
		if p == "" {
			continue // the gateway filters empty segments before splitting
		}
		if i := strings.Index(p, "="); i >= 0 {
			pairs = append(pairs, pair{p[:i], p[i+1:]})
		} else {
			pairs = append(pairs, pair{p, ""})
		}
	}
	// Stable sort on the key only — matches the gateway's comparator, which
	// leaves equal keys in their original order.
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return parts[0] + "?" + strings.Join(out, "&")
}

// newNonce returns a UUID-shaped random value (the gateway only requires
// uniqueness, not a specific format).
func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Stats exposes delivery counters for health endpoints.
func (r *Reporter) Stats() map[string]interface{} {
	if r == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":   true,
		"delivered": r.delivered,
		"failed":    r.failed,
		"parked":    r.parked,
		"pending":   r.pendingCount(),
		"wal_dir":   r.cfg.WALDir,
	}
}

// l1FeeString renders an optional L1 fee. Empty when there is none, so the field is omitted on
// chains that do not have one rather than asserting a zero fee.
func l1FeeString(v *big.Int) string {
	if v == nil || v.Sign() == 0 {
		return ""
	}
	return v.String()
}
