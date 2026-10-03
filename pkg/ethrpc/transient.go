package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// =============================================================================
// "This provider cannot answer right now" (transient provider errors)
// =============================================================================
//
// All seven validators read Base Sepolia through one Infura key, whose per-second limit answers a burst with HTTP 429
// (JSON-RPC -32005). On 2026-10-03 that 429, on the chain-id check at construction, aborted `validator repair
// outcome-trees` at its first call, and a transient transport error from tenderly's gateway stopped a validator's start
// ("batch path: outcome reads of chain 84532: ... read its chain id: Post ...") until Docker restarted it.
//
// A 429, a 502/503/504, a reset or refused connection, a temporary DNS failure or an attempt that timed out says only that
// THIS provider cannot answer now; it says nothing about the chain. Such a query is asked again, of the SAME provider,
// within a bounded time. It is never answered by another provider instead, never counted as an answer, and never taken
// as success when the time runs out: the reader still needs MinAgreeingProviders providers that answer and agree
// (RB5-F53). A well-formed answer - a wrong chain id, a different block hash, a JSON-RPC execution error, "not found" - is
// an answer and is never retried.

// TransientRetryBudget caps how long constructing an AgreeingReader keeps asking its providers for their chain id while
// they answer transiently: about thirty seconds, a few dozen of Infura's one-second rate-limit windows, short enough that
// a provider which is really down still stops a start promptly and by name. A read's own cap is its reader's per-read
// timeout (DefaultReadTimeout in production); a caller's context deadline always ends retrying sooner.
const TransientRetryBudget = 30 * time.Second

// DefaultReadTimeout is an agreed read's own deadline, its transient retries included.
const DefaultReadTimeout = 20 * time.Second

// transientBackoffBase and transientBackoffMax bound the wait between two attempts: 250 ms doubling to 4 s, each wait
// jittered to between half and all of its nominal value so that seven validators throttled together do not retry in
// step. A provider's Retry-After, when longer, is waited instead.
const (
	transientBackoffBase = 250 * time.Millisecond
	transientBackoffMax  = 4 * time.Second
)

// The budgets in force; tests shorten them.
var (
	constructionRetryBudget = TransientRetryBudget
	backoffBase             = transientBackoffBase
	backoffMax              = transientBackoffMax
)

// IsTransient reports whether err means the provider could not answer now, as opposed to an answer. Transient: HTTP 429,
// 502, 503, 504; JSON-RPC -32005 (limit exceeded) and -32029 (another provider's rate-limit code); a refused, reset or
// prematurely closed (EOF) connection; a temporary DNS failure; a network timeout. Anything else - including every
// well-formed JSON-RPC error and a cancelled or expired context - is not.
func IsTransient(err error) bool {
	// The caller's own cancellation or deadline ends the query; an attempt's own timeout is told apart by retryTransient,
	// which knows whether the caller's context is still live.
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var he rpc.HTTPError
	if errors.As(err, &he) {
		switch he.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	var ec rpc.Error
	if errors.As(err, &ec) {
		return ec.ErrorCode() == -32005 || ec.ErrorCode() == -32029
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.IsTemporary || de.IsTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// Errors that reach here only as text (wrapped with %v somewhere, or Windows' socket messages).
	s := strings.ToLower(err.Error())
	for _, m := range []string{"429 too many requests", "rate limit exceeded", "connection refused", "connection reset",
		"actively refused", "forcibly closed", "502 bad gateway", "503 service unavailable", "504 gateway timeout"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// TransientError is a query a provider kept answering transiently until the retries ran out. It wraps the provider's own
// last error (errors.Is/As see it) and, when the caller's context ended the retries, that context's error.
type TransientError struct {
	Host     string
	Attempts int
	Elapsed  time.Duration
	Err      error // the provider's own error, from the last attempt
	Stopped  error // the caller's context error, when that is what ended the retries
}

func (e *TransientError) Error() string {
	stop := ""
	if e.Stopped != nil {
		stop = fmt.Sprintf("; stopped by %v", e.Stopped)
	}
	return fmt.Sprintf("%v (provider %s, %d attempts over %s%s)", e.Err, e.Host, e.Attempts, e.Elapsed.Round(time.Millisecond), stop)
}

func (e *TransientError) Unwrap() []error {
	if e.Stopped != nil {
		return []error{e.Err, e.Stopped}
	}
	return []error{e.Err}
}

// retryAfterHint is the most recent Retry-After a provider sent with a 429 or 503. go-ethereum's rpc.HTTPError carries no
// headers, so the provider's HTTP transport records it here for the retry loop to honour.
type retryAfterHint struct {
	mu sync.Mutex
	d  time.Duration
}

func (h *retryAfterHint) set(d time.Duration) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.d = d
	h.mu.Unlock()
}

// take returns the recorded wait and clears it.
func (h *retryAfterHint) take() time.Duration {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.d
	h.d = 0
	return d
}

type retryAfterTransport struct {
	base http.RoundTripper
	hint *retryAfterHint
}

func (t *retryAfterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			t.hint.set(d)
		}
	}
	return resp, err
}

// parseRetryAfter reads a Retry-After value: delay-seconds or an HTTP date.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(v); err == nil {
		if s < 0 {
			return 0, false
		}
		return time.Duration(s) * time.Second, true
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := at.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// dialProvider dials one provider with a transport that records its Retry-After; a transient failure to connect (a
// websocket endpoint dials eagerly) is retried like a query.
func dialProvider(ctx context.Context, host, rawurl string, timeout, budget time.Duration) (*ethclient.Client, *retryAfterHint, error) {
	hint := &retryAfterHint{}
	httpClient := &http.Client{Transport: &retryAfterTransport{base: http.DefaultTransport, hint: hint}}
	c, err := retryTransient(ctx, host, hint, budget, timeout, func(c context.Context) (*rpc.Client, error) {
		return rpc.DialOptions(c, rawurl, rpc.WithHTTPClient(httpClient))
	})
	if err != nil {
		return nil, nil, err
	}
	return ethclient.NewClient(c), hint, nil
}

// retryTransient runs one query against one provider, asking again while the provider answers transiently: with
// jittered exponential backoff (backoffBase to backoffMax), or the provider's Retry-After when that is longer, until
// budget has passed since the first attempt or ctx ends, whichever is sooner. attemptTimeout, when positive, bounds each
// attempt, and an attempt that times out while ctx is still live is transient too. An answer, or a non-transient error,
// is returned at once; running out of retries returns the provider's own error in a *TransientError.
func retryTransient[T any](ctx context.Context, host string, hint *retryAfterHint, budget, attemptTimeout time.Duration,
	fn func(context.Context) (T, error)) (T, error) {
	var zero T
	start := time.Now()
	stopAt := start.Add(budget)
	if dl, ok := ctx.Deadline(); ok && dl.Before(stopAt) {
		stopAt = dl
	}
	backoff := backoffBase
	for attempt := 1; ; attempt++ {
		actx, cancel := ctx, context.CancelFunc(func() {})
		if attemptTimeout > 0 {
			actx, cancel = context.WithTimeout(ctx, attemptTimeout)
		}
		v, err := fn(actx)
		attemptTimedOut := err != nil && actx.Err() != nil && ctx.Err() == nil
		cancel()
		if err == nil {
			return v, nil
		}
		if !attemptTimedOut && !IsTransient(err) {
			return v, err
		}
		exhausted := func(stopped error) (T, error) {
			return zero, &TransientError{Host: host, Attempts: attempt, Elapsed: time.Since(start), Err: err, Stopped: stopped}
		}
		if ctx.Err() != nil {
			return exhausted(ctx.Err())
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		if ra := hint.take(); ra > wait {
			wait = ra
		}
		if time.Now().Add(wait).After(stopAt) {
			return exhausted(nil)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return exhausted(ctx.Err())
		case <-t.C:
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
}
