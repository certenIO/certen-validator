// Package ethrpc provides a cost-aware failover pool over several EVM JSON-RPC providers.
//
// The problem it solves is economic, not just availability. A free public endpoint
// (ethereum-sepolia-rpc.publicnode.com) serves ordinary reads perfectly well and costs nothing, but
// refuses archive queries:
//
//	403 Forbidden: {"code":-32602,"message":"Archive requests require a personal token."}
//
// A paid provider (Infura, Alchemy) serves those, but has a monthly quota that, once exhausted,
// starts returning 429 — and burning it on ordinary reads is what exhausts it early. Pinning every
// call to either one alone therefore fails: pinned free, archive-dependent work (the Phase 7 event
// watcher) never runs; pinned paid, the quota is gone before month end and everything 429s.
//
// So endpoints are ordered cheapest-first and tried in order. An endpoint that answers with a
// "this provider will not serve this" signal — archive required, rate limited, quota exhausted — is
// put in cooldown and the next one is tried. Cooldown EXPIRES, so the free endpoint is re-preferred
// as soon as it is plausibly useful again, rather than the pool drifting permanently onto the paid
// provider after one bad response.
package ethrpc

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

// DefaultCooldown is how long a failing endpoint is skipped before being tried again.
//
// Deliberately short. The cost of retrying the free endpoint too eagerly is one wasted request that
// fails fast; the cost of backing off too long is paid quota spent on calls the free endpoint would
// have served. The asymmetry favours short.
const DefaultCooldown = 2 * time.Minute

type endpoint struct {
	url        string
	client     *ethclient.Client
	coolUntil  time.Time
	failures   int
	lastReason string
}

// Pool is an ordered set of EVM RPC endpoints with cost-aware failover.
type Pool struct {
	mu        sync.Mutex
	endpoints []*endpoint
	cooldown  time.Duration
	logger    *log.Logger
}

// ParseEndpoints splits a provider list. Accepts comma, semicolon or whitespace separation so it is
// forgiving about how the env var was written, and drops blanks and duplicates while preserving
// order — order is the cost ranking, so it must not be disturbed.
func ParseEndpoints(values ...string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range values {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
		}) {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

// NewPool dials every endpoint. Endpoints that fail to dial are kept but start in cooldown, so a
// provider that is merely down at startup is not lost for the process lifetime.
func NewPool(urls []string, cooldown time.Duration, logger *log.Logger) (*Pool, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("ethrpc: no endpoints configured")
	}
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	if logger == nil {
		logger = log.New(log.Writer(), "[ethrpc] ", log.LstdFlags)
	}

	p := &Pool{cooldown: cooldown, logger: logger}
	var dialed int
	for _, u := range urls {
		e := &endpoint{url: u}
		c, err := ethclient.Dial(u)
		if err != nil {
			e.coolUntil = time.Now().Add(cooldown)
			e.lastReason = err.Error()
			logger.Printf("⚠️ endpoint %s failed to dial, starting in cooldown: %v", redact(u), err)
		} else {
			e.client = c
			dialed++
		}
		p.endpoints = append(p.endpoints, e)
	}
	if dialed == 0 {
		return nil, fmt.Errorf("ethrpc: no endpoint could be dialed (%d configured)", len(urls))
	}
	logger.Printf("✅ pool ready: %d/%d endpoints dialed, primary=%s", dialed, len(urls), redact(urls[0]))
	return p, nil
}

// Primary returns the client for the highest-priority usable endpoint, for callers that need a
// plain *ethclient.Client. Prefer Do, which can fail over mid-call; this cannot.
func (p *Pool) Primary() *ethclient.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, e := range p.endpoints {
		if e.client != nil && now.After(e.coolUntil) {
			return e.client
		}
	}
	// Everything is cooling down: return the first dialed client rather than nil, so the caller
	// gets a real error from the provider instead of a nil dereference.
	for _, e := range p.endpoints {
		if e.client != nil {
			return e.client
		}
	}
	return nil
}

// Do runs fn against endpoints in cost order, advancing on a failover-worthy error.
//
// A non-failover error (bad address, reverted call, context cancelled) is returned immediately: it
// would fail identically on every provider, and retrying it across paid endpoints spends quota to
// learn nothing.
func (p *Pool) Do(ctx context.Context, fn func(*ethclient.Client) error) error {
	candidates := p.candidates()
	if len(candidates) == 0 {
		return fmt.Errorf("ethrpc: no usable endpoint")
	}

	var lastErr error
	for _, e := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(e.client)
		if err == nil {
			p.markSuccess(e)
			return nil
		}
		lastErr = err
		if !ShouldFailover(err) {
			return err
		}
		p.markFailure(e, err)
		p.logger.Printf("↪️ %s unusable (%s), trying next provider", redact(e.url), summarize(err))
	}
	return fmt.Errorf("ethrpc: all %d endpoints failed, last error: %w", len(candidates), lastErr)
}

// candidates returns dialed endpoints in cost order: those out of cooldown first, then those still
// cooling. The cooling ones are kept as a last resort — a stale cooldown must never turn into a
// hard outage when that provider is the only one left.
func (p *Pool) candidates() []*endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	var ready, cooling []*endpoint
	for _, e := range p.endpoints {
		if e.client == nil {
			continue
		}
		if now.After(e.coolUntil) {
			ready = append(ready, e)
		} else {
			cooling = append(cooling, e)
		}
	}
	return append(ready, cooling...)
}

func (p *Pool) markSuccess(e *endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.failures = 0
	e.coolUntil = time.Time{}
}

func (p *Pool) markFailure(e *endpoint, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.failures++
	e.lastReason = err.Error()
	// Back off further the more consecutively an endpoint fails, capped so a recovered provider is
	// still retried within a few minutes.
	mult := time.Duration(e.failures)
	if mult > 4 {
		mult = 4
	}
	e.coolUntil = time.Now().Add(p.cooldown * mult)
}

// Close releases every dialed client.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.endpoints {
		if e.client != nil {
			e.client.Close()
		}
	}
}

// Status reports each endpoint's health, for logging and diagnostics.
func (p *Pool) Status() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(p.endpoints))
	for i, e := range p.endpoints {
		state := "ready"
		switch {
		case e.client == nil:
			state = "undialed"
		case now.Before(e.coolUntil):
			state = fmt.Sprintf("cooling %ds", int(time.Until(e.coolUntil).Seconds()))
		}
		out = append(out, fmt.Sprintf("%d:%s=%s", i, redact(e.url), state))
	}
	return out
}

// ShouldFailover reports whether an error means "this provider will not serve this request", as
// opposed to "this request is wrong".
//
// Matching is on message text because providers signal these differently and mostly outside the
// JSON-RPC error code space: publicnode returns HTTP 403 carrying code -32602, Alchemy and Infura
// return 429, and quota messages are prose. Deliberately conservative — anything unrecognised is
// treated as a real error and NOT retried elsewhere, so a genuine bug is not silently multiplied
// across every provider.
func ShouldFailover(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "archive"): // "Archive requests require a personal token"
		return true
	case strings.Contains(m, "429"), strings.Contains(m, "too many requests"), strings.Contains(m, "rate limit"):
		return true
	case strings.Contains(m, "quota"), strings.Contains(m, "credits"), strings.Contains(m, "capacity"):
		return true
	case strings.Contains(m, "403"), strings.Contains(m, "forbidden"), strings.Contains(m, "unauthorized"), strings.Contains(m, "401"):
		return true
	case strings.Contains(m, "payment required"), strings.Contains(m, "402"):
		return true
	// Transport-level trouble: the next provider may simply be reachable.
	case strings.Contains(m, "connection refused"), strings.Contains(m, "no such host"),
		strings.Contains(m, "timeout"), strings.Contains(m, "eof"),
		strings.Contains(m, "connection reset"), strings.Contains(m, "bad gateway"),
		strings.Contains(m, "service unavailable"), strings.Contains(m, "502"), strings.Contains(m, "503"), strings.Contains(m, "504"):
		return true
	}
	return false
}

// redact removes the API key from a provider URL before logging. Alchemy and Infura carry the key
// in the path, so a bare URL in a log line is a leaked credential.
func redact(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return u
	}
	host := rest[:slash]
	path := rest[slash:]
	if len(strings.Trim(path, "/")) == 0 {
		return u
	}
	return u[:i+3] + host + "/<redacted>"
}

func summarize(err error) string {
	s := err.Error()
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}
