package ethrpc

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"time"
)

// =============================================================================
// Which providers a reader asks: only those whose chain id is verified
// =============================================================================
//
// A reader used to require EVERY configured provider to dial and answer its chain id before it would exist, so one
// provider down at boot stopped the validator's start (and `validator repair`), and each provider added made a start
// LESS likely. RB5-F53 needs at least MinAgreeingProviders answers that agree among VERIFIED providers, not every
// configured provider up at one moment.
//
// So a reader starts once MinAgreeingProviders distinct hosts are verified. A provider not verified yet is asked for
// nothing - its answers can never count - and is re-verified in the background with bounded backoff; it joins the set
// only when its chain id is verified. A provider that answers ANOTHER chain id is a misconfiguration and refuses the
// reader outright at construction; found later in the background, it is logged and never joins. The agreement rule is
// unchanged.

// UnverifiedProviderGrace is how long a construction that already has MinAgreeingProviders verified hosts still waits for
// the others before it starts without them: long enough for a provider that is merely slow to answer its chain id, short
// enough that a provider that is down costs a start (and each observer built per request) at most five seconds.
const UnverifiedProviderGrace = 5 * time.Second

// ReverifyBase and ReverifyMax bound how often an unverified provider is asked its chain id again: 15 s after the
// construction, doubling to 5 minutes.
const (
	ReverifyBase = 15 * time.Second
	ReverifyMax  = 5 * time.Minute
)

// The bounds in force; tests shorten them.
var (
	unverifiedProviderGrace = UnverifiedProviderGrace
	reverifyBase            = ReverifyBase
	reverifyMax             = ReverifyMax
)

// unverifiedProvider is a configured provider whose chain id is not verified. It is never asked for a fact.
type unverifiedProvider struct {
	host, url string
	err       error // why it is not verified
	nextTry   time.Time
	backoff   time.Duration
	trying    bool
	refused   bool // it answered another chain id: it never joins
}

type verification struct {
	i     int
	p     agreeingProvider
	wrong string // the chain id it answered, when not ours
	err   error
}

// verifyOne dials one provider and reads its chain id, asking again while it answers transiently, for up to budget.
func verifyOne(ctx context.Context, chainID int64, host, rawurl string, timeout, budget time.Duration) verification {
	c, hint, err := dialProvider(ctx, host, rawurl, timeout, budget)
	if err != nil {
		return verification{err: fmt.Errorf("dial: %w", err)}
	}
	id, err := retryTransient(ctx, host, hint, budget, timeout, c.ChainID)
	if err != nil {
		c.Close()
		return verification{err: fmt.Errorf("read its chain id: %w", err)}
	}
	if id.Int64() != chainID {
		c.Close()
		return verification{wrong: id.String()}
	}
	return verification{p: agreeingProvider{host: host, client: c, hint: hint, health: healthOf(chainID, rawurl)}}
}

// verifyAll is the construction: see NewAgreeingReader.
func (r *AgreeingReader) verifyAll(ctx context.Context, urls []string) error {
	type candidate struct{ host, url string }
	var cands []candidate
	seen := map[string]bool{}
	for _, u := range urls {
		h := providerHost(u)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		cands = append(cands, candidate{h, u})
	}

	caller := ctx
	ctx, cancelAll := context.WithTimeout(ctx, constructionRetryBudget)
	defer cancelAll()
	results := make(chan verification, len(cands))
	for i, c := range cands {
		go func(i int, c candidate) {
			v := verifyOne(ctx, r.chainID, c.host, c.url, r.timeout, constructionRetryBudget)
			v.i = i
			results <- v
		}(i, c)
	}

	verified := map[int]agreeingProvider{}
	failed := map[int]error{}
	var grace <-chan time.Time
wait:
	for len(verified)+len(failed) < len(cands) {
		select {
		case v := <-results:
			switch {
			case v.wrong != "":
				for _, p := range verified {
					p.client.Close()
				}
				return fmt.Errorf("chain %d provider %s serves chain %s", r.chainID, cands[v.i].host, v.wrong)
			case v.err != nil:
				failed[v.i] = v.err
			default:
				verified[v.i] = v.p
				if len(verified) >= MinAgreeingProviders && grace == nil {
					grace = time.After(unverifiedProviderGrace)
				}
			}
		case <-grace:
			break wait
		case <-ctx.Done():
			break wait
		}
	}
	// A verification still running is stopped; it returns at once with the provider's own last error, which is what it
	// is logged and refused by. It is re-verified in the background.
	cancelAll()
	drain := time.After(time.Second)
collect:
	for len(verified)+len(failed) < len(cands) {
		select {
		case v := <-results:
			switch {
			case v.wrong != "":
				for _, p := range verified {
					p.client.Close()
				}
				return fmt.Errorf("chain %d provider %s serves chain %s", r.chainID, cands[v.i].host, v.wrong)
			case v.err != nil:
				failed[v.i] = v.err
			default:
				v.p.client.Close() // verified only after the wait ended: it joins through the background
				failed[v.i] = fmt.Errorf("its chain id was verified only after the construction's wait")
			}
		case <-drain:
			break collect
		}
	}
	for i := range cands {
		if _, ok := verified[i]; ok {
			continue
		}
		if _, ok := failed[i]; !ok {
			failed[i] = fmt.Errorf("its chain id was not verified within the construction's wait")
		}
	}

	if len(verified) < MinAgreeingProviders {
		for _, p := range verified {
			p.client.Close()
		}
		// Each unverified provider's own error is kept (errors.Is/As see it), by name, in configuration order.
		format := "chain %d has %d verified independent provider(s) of %d configured %v; at least %d are required, so " +
			"that no single provider's view is taken as the chain's (RB5-F53); unverified:"
		args := []interface{}{r.chainID, len(verified), len(cands), ProviderHosts(urls), MinAgreeingProviders}
		for i, c := range cands {
			if err, ok := failed[i]; ok {
				format += " %s: %w;"
				args = append(args, c.host, err)
			}
		}
		if caller.Err() != nil {
			format += " stopped by %w"
			args = append(args, caller.Err())
		}
		return fmt.Errorf(strings.TrimSuffix(format, ";"), args...)
	}

	now := time.Now()
	for i, c := range cands {
		if p, ok := verified[i]; ok {
			r.providers = append(r.providers, p)
			continue
		}
		log.Printf("⚠️ [ethrpc] chain %d provider %s is not verified (%v): it is asked for nothing until its chain id is "+
			"verified; re-verifying in the background", r.chainID, c.host, failed[i])
		r.pending = append(r.pending, &unverifiedProvider{host: c.host, url: c.url, err: failed[i], backoff: reverifyBase,
			nextTry: now.Add(reverifyBase)})
	}
	return nil
}

// verified is the set of providers asked for facts. Using the reader is also what re-verifies its unverified providers:
// each one whose backoff has passed is asked its chain id again, in the background, one attempt at a time.
func (r *AgreeingReader) verified() []agreeingProvider {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, p := range r.pending {
		if !p.refused && !p.trying && !now.Before(p.nextTry) {
			p.trying = true
			go r.reverify(p)
		}
	}
	return append([]agreeingProvider(nil), r.providers...)
}

func (r *AgreeingReader) reverify(p *unverifiedProvider) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	v := verifyOne(ctx, r.chainID, p.host, p.url, r.timeout, 0)
	r.mu.Lock()
	defer r.mu.Unlock()
	p.trying = false
	switch {
	case v.wrong != "":
		p.refused = true
		log.Printf("❌ [ethrpc] chain %d provider %s serves chain %s: misconfigured, it never joins", r.chainID, p.host, v.wrong)
	case v.err != nil:
		p.err = v.err
		if p.backoff *= 2; p.backoff > reverifyMax {
			p.backoff = reverifyMax
		}
		p.nextTry = time.Now().Add(p.backoff/2 + rand.N(p.backoff/2+1))
	default:
		r.providers = append(r.providers, v.p)
		for i, q := range r.pending {
			if q == p {
				r.pending = append(r.pending[:i], r.pending[i+1:]...)
				break
			}
		}
		log.Printf("✅ [ethrpc] chain %d provider %s verified; it is now asked", r.chainID, p.host)
	}
}
