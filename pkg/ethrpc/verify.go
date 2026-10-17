package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"log"
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

type verification struct {
	i     int
	p     agreeingProvider
	wrong string // the chain id it answered, when not ours
	// wrongGenesis: it serves our chain id on another genesis than the chain is pinned to (ErrGenesisMismatch).
	wrongGenesis error
	err          error
}

// refusal is why a verification refuses the provider for good: another genesis than the chain is pinned to. It refuses
// the reader outright, and the provider never joins.
func (v verification) refusal(chainID int64, host string) error {
	return v.wrongGenesis
}

// wrongChainErr is why a provider that answered ANOTHER chain id is left out. Its answer never counts toward agreement,
// but it is not exiled for good: a load-balanced or misrouted backend answers the right chain later, so the provider is
// asked again after a bounded backoff, like one that did not answer, and joins when it names the right chain.
func (v verification) wrongChainErr(chainID int64, host string) error {
	if v.wrong == "" {
		return nil
	}
	return fmt.Errorf("chain %d provider %s serves chain %s", chainID, host, v.wrong)
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
	// A pinned chain (RB7 D8): the provider's block 0 must be the pinned genesis. Read like the chain id - asked again
	// while it answers transiently - and refused for good when it is another.
	guard, err := newGenesisGuard(chainID, host)
	if err != nil {
		c.Close()
		return verification{err: err}
	}
	if guard != nil {
		if _, err := retryTransient(ctx, host, hint, budget, timeout, func(rc context.Context) (struct{}, error) {
			return struct{}{}, guard.ensure(rc, c)
		}); err != nil {
			c.Close()
			if errors.Is(err, ErrGenesisMismatch) {
				return verification{wrongGenesis: err}
			}
			return verification{err: err}
		}
	}
	return verification{p: agreeingProvider{host: host, client: c, hint: hint, health: healthOf(chainID, rawurl), genesis: guard}}
}

// verifyAll is the construction: see NewAgreeingReader. Each provider is verified once per process (registry.go): one
// already verified is taken as it is, one being verified is waited for, and one that failed recently is not asked again
// before its own backoff - unless fewer than MinAgreeingProviders are verified, when it is asked again now.
func (r *AgreeingReader) verifyAll(ctx context.Context, urls []string) error {
	type candidate struct {
		host, url string
		sp        *sharedProvider
	}
	var cands []candidate
	seen := map[string]bool{}
	for _, u := range urls {
		h := providerHost(u)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		cands = append(cands, candidate{h, u, sharedFor(r.chainID, h, u)})
	}

	verified := map[int]agreeingProvider{}
	failed := map[int]error{}
	known := 0
	for _, c := range cands {
		if v, _, _, _ := c.sp.state(); v != nil {
			known++
		}
	}
	var ask []int
	for i, c := range cands {
		v, refusal, perr, retryAt := c.sp.state()
		switch {
		case v != nil:
			verified[i] = *v
		case refusal != nil:
			return c.sp.refused().refusal(r.chainID, c.host)
		case perr != nil && known >= MinAgreeingProviders && time.Now().Before(retryAt):
			failed[i] = perr // asked again by its backoff, in the background, not by this construction
		default:
			ask = append(ask, i)
		}
	}

	caller := ctx
	ctx, cancelAll := context.WithTimeout(ctx, constructionRetryBudget)
	defer cancelAll()
	results := make(chan verification, len(cands))
	for _, i := range ask {
		go func(i int) {
			v := cands[i].sp.verify(ctx, r.timeout, constructionRetryBudget)
			v.i = i
			results <- v
		}(i)
	}

	var grace <-chan time.Time
	if len(verified) >= MinAgreeingProviders {
		grace = time.After(unverifiedProviderGrace)
	}
wait:
	for len(verified)+len(failed) < len(cands) {
		select {
		case v := <-results:
			switch {
			case v.refusal(r.chainID, cands[v.i].host) != nil:
				return v.refusal(r.chainID, cands[v.i].host)
			case v.wrong != "":
				failed[v.i] = v.wrongChainErr(r.chainID, cands[v.i].host)
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
			case v.refusal(r.chainID, cands[v.i].host) != nil:
				return v.refusal(r.chainID, cands[v.i].host)
			case v.wrong != "":
				failed[v.i] = v.wrongChainErr(r.chainID, cands[v.i].host)
			case v.err != nil:
				failed[v.i] = v.err
			default:
				// Verified only after the wait ended: it is recorded in the registry, so it joins this reader through
				// its next use, like any provider that was verified in the background.
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

	for i, c := range cands {
		if p, ok := verified[i]; ok {
			r.providers = append(r.providers, p)
			continue
		}
		if c.sp.logUnverified() {
			log.Printf("⚠️ [ethrpc] chain %d provider %s is not verified (%v): it is asked for nothing until its chain id is "+
				"verified; re-verifying in the background", r.chainID, c.host, failed[i])
		}
		r.pending = append(r.pending, c.sp)
	}
	return nil
}

// verified is the set of providers asked for facts. Using the reader is also what re-verifies its unverified providers:
// each one whose backoff has passed is asked its chain id again, in the background, one attempt at a time for the whole
// process (registry.go). A provider verified meanwhile - by this reader's attempt or another reader's - joins it here.
func (r *AgreeingReader) verified() []agreeingProvider {
	r.mu.Lock()
	defer r.mu.Unlock()
	still := r.pending[:0]
	for _, sp := range r.pending {
		if v, _, _, _ := sp.state(); v != nil {
			r.providers = append(r.providers, *v)
			log.Printf("✅ [ethrpc] chain %d provider %s verified; it is now asked", r.chainID, sp.host)
			continue
		}
		sp.startReverify(r.timeout)
		still = append(still, sp)
	}
	r.pending = still
	return append([]agreeingProvider(nil), r.providers...)
}
