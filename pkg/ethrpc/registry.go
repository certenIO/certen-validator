package ethrpc

import (
	"context"
	"log"
	"math/rand/v2"
	"sync"
	"time"
)

// =============================================================================
// One verification per provider per process
// =============================================================================
//
// Every reader used to dial each of its providers and ask each one its chain id (and, on a pinned chain, its genesis)
// for itself. A validator builds a reader per component and per chain at boot, and one per peer-attestation request
// afterwards, so all seven validators together asked the same few providers, under one shared key, for the same fact
// dozens of times a minute: Infura answered 429 to the chain id read, and each 429 cost a construction up to
// UnverifiedProviderGrace (RB7 Task 5, T5-7).
//
// A provider's chain id is a fact about the provider, not about the reader that happens to ask. The registry holds one
// entry per (chain id, provider URL) for the life of the process:
//   - a provider verified once is handed, already verified, to every later reader: no further chain id read;
//   - a verification already in flight is waited for, not repeated;
//   - a provider that failed is not asked again before its own backoff has passed, whichever reader asks, and one
//     background re-verification serves every reader that lists it;
//   - a provider that answered ANOTHER genesis than a pinned chain's is refused for good, for every reader;
//   - a provider that answered ANOTHER chain id is EXCLUDED, for every reader, and named loudly: its answer never counts
//     toward agreement and it is asked nothing, but it is asked its chain id again after a bounded backoff (a
//     load-balanced or misrouted backend answers the right chain later) and joins when it names the right one. One
//     misrouted answer does not take down every reader of the chain while MinAgreeingProviders others are verified.
// The agreement rules are untouched: a reader still asks only verified providers, still needs MinAgreeingProviders of
// them, and never counts a provider on the wrong chain. The URL is a map key only and is never logged.

type registryKey struct {
	chainID int64
	url     string
}

var registry = struct {
	mu sync.Mutex
	m  map[registryKey]*sharedProvider
}{m: map[registryKey]*sharedProvider{}}

// sharedProvider is one provider's verification state, shared by every reader of its chain that lists it.
type sharedProvider struct {
	chainID   int64
	host, url string

	mu       sync.Mutex
	verified *agreeingProvider // set once its chain id (and genesis) is verified; never cleared
	refusal  error             // another genesis than the chain is pinned to: it never joins
	err      error             // why it is not verified, while it is not
	attempts int               // verifications finished (a test and a log fact)
	nextTry  time.Time         // not asked again before this, after a failure
	backoff  time.Duration
	trying   bool          // a background re-verification is in flight
	flight   chan struct{} // closed when the verification in flight finishes
	last     verification  // the in-flight verification's result, for the readers that waited for it
	logged   bool          // its failure was logged once
	lastStop bool          // the verification ended because its leader's context did, not because of the provider
}

func sharedFor(chainID int64, host, url string) *sharedProvider {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	k := registryKey{chainID, url}
	sp := registry.m[k]
	if sp == nil {
		sp = &sharedProvider{chainID: chainID, host: host, url: url, backoff: reverifyBase}
		registry.m[k] = sp
	}
	return sp
}

// resetRegistryForTests forgets every verification, so a test starts from a cold process.
func resetRegistryForTests() {
	registry.mu.Lock()
	registry.m = map[registryKey]*sharedProvider{}
	registry.mu.Unlock()
}

// state is the provider as a reader finds it.
func (sp *sharedProvider) state() (verified *agreeingProvider, refusal, err error, retryAfter time.Time) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.verified, sp.refusal, sp.err, sp.nextTry
}

// verify is the one verification of this provider: the first caller dials and asks, every caller that arrives while it
// runs waits for its answer, and every later caller finds it recorded. A caller whose context ends before the answer
// stops waiting; a verification stopped only because its own caller's context ended is not taken as the provider's answer,
// so the next caller asks again.
func (sp *sharedProvider) verify(ctx context.Context, timeout, budget time.Duration) verification {
	for {
		sp.mu.Lock()
		if sp.verified != nil {
			p := *sp.verified
			sp.mu.Unlock()
			return verification{p: p}
		}
		if sp.refusal != nil {
			sp.mu.Unlock()
			return sp.refused()
		}
		if sp.flight != nil {
			wait := sp.flight
			sp.mu.Unlock()
			select {
			case <-wait:
			case <-ctx.Done():
				return verification{err: ctx.Err()}
			}
			sp.mu.Lock()
			if !sp.lastStop {
				v := sp.last
				sp.mu.Unlock()
				return v
			}
			sp.mu.Unlock()
			continue
		}
		sp.flight = make(chan struct{})
		sp.mu.Unlock()

		v := verifyOne(ctx, sp.chainID, sp.host, sp.url, timeout, budget)
		sp.record(v, ctx.Err() != nil)
		return v
	}
}

// refused is the verification a refused provider answers every reader with.
func (sp *sharedProvider) refused() verification {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.last.wrongGenesis != nil || sp.last.wrong != "" {
		return sp.last
	}
	return verification{wrongGenesis: sp.refusal}
}

// record stores a finished verification and releases the readers waiting for it.
func (sp *sharedProvider) record(v verification, stopped bool) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.attempts++
	sp.last, sp.lastStop = v, stopped && v.err != nil
	switch {
	case v.wrongGenesis != nil:
		sp.refusal = v.wrongGenesis
	case v.wrong != "":
		// Excluded, not exiled: never counted, asked again by the backoff, and named every time it answers wrong.
		sp.err = v.wrongChainErr(sp.chainID, sp.host)
		sp.nextTry = time.Now().Add(sp.backoff)
		log.Printf("❌ [ethrpc] %v: EXCLUDED from agreement, never counted; asked its chain id again in %s", sp.err, sp.backoff)
	case v.err != nil:
		// Not verified in the time its caller gave it (or refused outright): not asked again before its backoff,
		// whichever reader comes next; the background re-verification is what asks.
		sp.err = v.err
		sp.nextTry = time.Now().Add(sp.backoff)
	default:
		p := v.p
		sp.verified, sp.err = &p, nil
	}
	if sp.flight != nil {
		close(sp.flight)
		sp.flight = nil
	}
}

// logUnverified is true once per provider per process, so a provider that stays down is named once, not once per reader
// built.
func (sp *sharedProvider) logUnverified() bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.logged {
		return false
	}
	sp.logged = true
	return true
}

// startReverify asks the provider its chain id again in the background, when its backoff has passed and no other reader
// already is.
func (sp *sharedProvider) startReverify(timeout time.Duration) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.verified != nil || sp.refusal != nil || sp.trying || sp.flight != nil || time.Now().Before(sp.nextTry) {
		return
	}
	sp.trying = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		v := verifyOne(ctx, sp.chainID, sp.host, sp.url, timeout, 0)
		sp.mu.Lock()
		defer sp.mu.Unlock()
		sp.trying = false
		sp.attempts++
		switch {
		case v.refusal(sp.chainID, sp.host) != nil:
			sp.refusal, sp.last = v.refusal(sp.chainID, sp.host), v
			log.Printf("❌ [ethrpc] %v: it never joins", sp.refusal)
		case v.wrong != "":
			sp.err = v.wrongChainErr(sp.chainID, sp.host)
			if sp.backoff *= 2; sp.backoff > reverifyMax {
				sp.backoff = reverifyMax
			}
			sp.nextTry = time.Now().Add(sp.backoff/2 + rand.N(sp.backoff/2+1))
			log.Printf("❌ [ethrpc] %v: still EXCLUDED from agreement; asked again by %s", sp.err, sp.nextTry.Format("15:04:05"))
		case v.err != nil:
			sp.err = v.err
			if sp.backoff *= 2; sp.backoff > reverifyMax {
				sp.backoff = reverifyMax
			}
			sp.nextTry = time.Now().Add(sp.backoff/2 + rand.N(sp.backoff/2+1))
		default:
			p := v.p
			sp.verified, sp.err = &p, nil
		}
	}()
}
