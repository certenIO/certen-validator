// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RB12-SEPOLIA-SPINE: the execution endpoint of the Sepolia spine is a public provider that answers 429 under load. Everything here is
// the pure, testable part of how the header source behaves towards it: what a Retry-After header means, how long a 429 is waited out,
// and how the gap between two requests follows the provider's mood. None of it is evidence: a header is self-authenticating.

// Bounds of the 429 handling.
const (
	// DefaultMaxRetryAfter is the longest Retry-After one call waits out itself; a longer one ends the call at once and is handed to
	// the caller as the time to come back (SourceError.Throttle).
	DefaultMaxRetryAfter = 30 * time.Second
	// MaxRetryAfterKept bounds a Retry-After taken from a provider: whatever it states, the caller is never told to wait longer.
	MaxRetryAfterKept = 30 * time.Minute
	// backoff429Step is the wait of the n-th retry of a 429 that states no Retry-After: n * step (1.5 s, 3 s, ...).
	backoff429Step = 1500 * time.Millisecond
	// maxTries429 is the number of attempts of one request to one endpoint while it answers 429.
	maxTries429 = 8
	// gapAfterThrottle is the first gap kept between requests once a provider has answered 429; it doubles on every further 429.
	gapAfterThrottle = 500 * time.Millisecond
	// maxGap is the largest gap the pacing ever imposes.
	maxGap = 8 * time.Second
)

// ParseRetryAfter reads a Retry-After header value (RFC 9110 10.2.3): a non-negative whole number of seconds, or an HTTP date (a date in
// the past is a zero wait). ok is false for an absent or malformed value, a negative number, or a number that does not fit; the
// result is never above MaxRetryAfterKept.
func ParseRetryAfter(v string, now time.Time) (d time.Duration, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if allDigits(v) {
		secs, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return MaxRetryAfterKept, true // more seconds than any wait we keep: the cap, not a parse failure
		}
		d = time.Duration(secs) * time.Second
	} else {
		t, err := http.ParseTime(v)
		if err != nil {
			return 0, false
		}
		d = t.Sub(now)
		if d < 0 {
			d = 0
		}
	}
	if d > MaxRetryAfterKept {
		d = MaxRetryAfterKept
	}
	return d, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// Backoff429 is the wait before retry number try (0-based) of a request that was answered 429 without a Retry-After.
func Backoff429(try int) time.Duration { return time.Duration(try+1) * backoff429Step }

// ThrottleWait decides what a 429 costs: the time to sleep before the next try and whether to give up on the endpoint at once. A
// stated Retry-After is honoured (never shortened); an unstated one takes the backoff of the try. The call gives up, without sleeping,
// when the wait is longer than maxWait (the provider asked for more than this call waits out) or does not fit in the time the
// caller's context has left (remaining < 0 means no deadline). When it gives up, hint is the time the CALLER should come back after.
func ThrottleWait(retryAfter time.Duration, stated bool, try int, maxWait, remaining time.Duration) (wait time.Duration, giveUp bool, hint time.Duration) {
	wait = Backoff429(try)
	if stated && retryAfter > wait {
		wait = retryAfter
	}
	hint = wait
	if stated {
		hint = retryAfter
	}
	if try+1 >= maxTries429 {
		return 0, true, hint // the last try was answered 429 as well
	}
	if wait > maxWait || (remaining >= 0 && wait >= remaining) {
		return 0, true, hint
	}
	return wait, false, hint
}

// NextGap is the gap kept between two requests after the latest answer: a 429 raises it (from gapAfterThrottle, doubling, never above
// maxGap), a success halves it, never below floor. A gap below 50 ms that is not the floor is dropped to the floor.
func NextGap(cur, floor time.Duration, throttled bool) time.Duration {
	if throttled {
		g := cur * 2
		if g < gapAfterThrottle {
			g = gapAfterThrottle
		}
		if g > maxGap {
			g = maxGap
		}
		if g < floor {
			g = floor
		}
		return g
	}
	g := cur / 2
	if g < 50*time.Millisecond {
		g = 0
	}
	if g < floor {
		g = floor
	}
	return g
}

// NextSlot is the start time of a request given the end of the previous request's slot and the gap: a request never starts before
// the previous one's slot ends, and its own slot ends gap later. It returns the start and the end of the new slot.
func NextSlot(prevEnd, now time.Time, gap time.Duration) (start, end time.Time) {
	start = now
	if prevEnd.After(start) {
		start = prevEnd
	}
	return start, start.Add(gap)
}

// pacer keeps one source's requests apart. The zero value is ready; it is safe for concurrent use (the upgrader builds several legs at
// once and they share the one source, so the gap holds for all of them together).
type pacer struct {
	mu   sync.Mutex
	gap  time.Duration
	free time.Time // the end of the latest reserved slot
}

// wait blocks until this request's slot and returns the context's error if it ends first. floor is the source's MinGap.
func (p *pacer) wait(ctx context.Context, floor time.Duration, now func() time.Time) error {
	p.mu.Lock()
	gap := p.gap
	if gap < floor {
		gap = floor
	}
	t := now()
	start, end := NextSlot(p.free, t, gap)
	p.free = end
	p.mu.Unlock()
	d := start.Sub(t)
	if d <= 0 {
		return ctx.Err()
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

// answered records the provider's mood after a request.
func (p *pacer) answered(floor time.Duration, throttled bool) {
	p.mu.Lock()
	p.gap = NextGap(p.gap, floor, throttled)
	p.mu.Unlock()
}

// httpStatusError is a non-200 answer. Its text is "HTTP <code>" (callers and tests match that); RetryAfter is the provider's Retry-After
// when it stated one.
type httpStatusError struct {
	Code       int
	RetryAfter time.Duration
	Stated     bool
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }
