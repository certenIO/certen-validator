package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// A provider that stays unable to answer rests, instead of costing every read its whole budget
// =============================================================================
//
// askAll waits for every provider it asks, because a provider that answers late may answer differently: RB5-F53 takes a
// fact only when EVERY provider that answered agrees, and a lagging or forked provider must be heard, not outvoted. With
// transient retries, a provider that is hard down (refusing, 503 for hours, blackholed) is asked until the read's own
// deadline (DefaultReadTimeout, 20 s) on EVERY read, and the outcome path chains dozens of reads in sequence: an outcome
// peer's 8+D reads would take minutes against its 4-minute deadline, a Phase 8 peer's first observation 80 s of its 90.
//
// So once a provider has failed transiently for a read's whole budget, it RESTS: for ProviderRestBase it is not asked,
// and counts as not answering - exactly what it was during that read. When the rest ends, the next read asks it ONCE (a
// probe, no retries): an answer ends the rest, another transient failure doubles it, up to ProviderRestMax. Resting never
// substitutes a provider and never lowers the rule: a read still needs MinAgreeingProviders answers that agree, and a
// resting provider's view is not taken from anyone else. Rest is kept per chain and provider endpoint for the process, so
// every reader of that provider - including the observers built per request - shares it.

// ProviderRestBase and ProviderRestMax bound a provider's rest: 30 s after its first exhausted read, doubling with each
// failed probe to 5 minutes, so a provider that recovers is asked again within at most five minutes and a provider that
// stays down costs at most one probe per rest.
const (
	ProviderRestBase = 30 * time.Second
	ProviderRestMax  = 5 * time.Minute
)

// The rest bounds in force; tests shorten them.
var (
	providerRestBase = ProviderRestBase
	providerRestMax  = ProviderRestMax
)

// ErrProviderResting: the provider failed transiently for a whole read's budget and is resting; it was not asked.
var ErrProviderResting = errors.New("provider resting after failing transiently")

type providerHealth struct {
	mu        sync.Mutex
	restUntil time.Time
	restFor   time.Duration
	reason    string
}

var healthByProvider sync.Map // "chainID|host:port" -> *providerHealth

// healthOf is the shared health of chainID's provider at rawurl. The key keeps the port, so two endpoints of one host on
// different ports (as in tests) rest separately.
func healthOf(chainID int64, rawurl string) *providerHealth {
	key := fmt.Sprintf("%d|%s", chainID, providerEndpoint(rawurl))
	h, _ := healthByProvider.LoadOrStore(key, &providerHealth{})
	return h.(*providerHealth)
}

func providerEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// admit reports whether the provider is asked now, and whether as a probe (one attempt).
func (h *providerHealth) admit(now time.Time) (ask, probe bool, resting error) {
	if h == nil {
		return true, false, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.restFor == 0 {
		return true, false, nil
	}
	if now.Before(h.restUntil) {
		return false, false, fmt.Errorf("%w until %s (%s)", ErrProviderResting, h.restUntil.UTC().Format(time.RFC3339), h.reason)
	}
	return true, true, nil
}

// record updates the provider's health from one read. caller is the read's caller's context, read the read's own.
func (h *providerHealth) record(caller, read context.Context, err error) {
	if h == nil || err != nil && caller.Err() != nil {
		return // the caller gave up; that says nothing about the provider
	}
	var te *TransientError
	failed := err != nil && (errors.As(err, &te) || read.Err() != nil || IsTransient(err))
	h.mu.Lock()
	defer h.mu.Unlock()
	if !failed {
		h.restFor, h.restUntil, h.reason = 0, time.Time{}, ""
		return
	}
	switch {
	case h.restFor == 0:
		h.restFor = providerRestBase
	case h.restFor*2 > providerRestMax:
		h.restFor = providerRestMax
	default:
		h.restFor *= 2
	}
	h.restUntil = time.Now().Add(h.restFor)
	h.reason = err.Error()
	if len(h.reason) > 200 {
		h.reason = h.reason[:200] + "…"
	}
}

// askProvider runs one read against one provider under its health: a resting provider is not asked; a probe is asked
// once; otherwise transient failures are asked again for up to budget. deadline, when positive, is the read's own
// deadline (an agreed read's); zero leaves the read bounded by ctx alone (a locator's, as before). The outcome is recorded.
func askProvider[T any](ctx context.Context, h *providerHealth, host string, hint *retryAfterHint, budget, deadline time.Duration,
	fn func(context.Context) (T, error)) (T, error) {
	var zero T
	ask, probe, resting := h.admit(time.Now())
	if !ask {
		return zero, resting
	}
	if probe {
		budget = 0 // one attempt
	}
	rctx, cancel := ctx, context.CancelFunc(func() {})
	if deadline > 0 {
		rctx, cancel = context.WithTimeout(ctx, deadline)
	}
	defer cancel()
	v, err := retryTransient(rctx, host, hint, budget, 0, fn)
	h.record(ctx, rctx, err)
	return v, err
}
