// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/metrics"
)

// maxRequestBody bounds a request body read into memory for replay (a batch of header or proof requests is a few KB).
const maxRequestBody = 8 << 20

// maxResponseBody bounds a batch answer assembled from chunk answers.
const maxResponseBody = 256 << 20

// Hosts returns the host labels of provider URLs: scheme and host only, never userinfo, path or query, where credentials live.
func Hosts(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		out = append(out, HostLabel(raw))
	}
	return out
}

// HostLabel is "scheme://host[:port]" of a provider URL, or "provider" when it does not parse.
func HostLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "provider"
	}
	return u.Scheme + "://" + u.Host
}

// Transport is the http.RoundTripper every finality provider client uses. It adds, per provider host:
//   - a token-bucket rate limit (RPS requests per second, Burst at once);
//   - a bound on JSON-RPC batches: a batch of more than MaxBatch requests is sent as several batches of at most MaxBatch and
//     the answers are joined (Arbitrum's public RPC answers 429 to 100-request batches);
//   - bounded backoff on 429 and 503 answers: Retry-After when the provider states it, else exponential from 500 ms, never more
//     than BackoffMax, at most Retries retries; every backoff is counted in certen_finality_provider_throttled_total.
//
// It never retries anything else and never changes a request's meaning: the answers are verified by the kinds downstream.
type Transport struct {
	Base       http.RoundTripper
	RPS        float64
	Burst      int
	MaxBatch   int
	Retries    int
	BackoffMax time.Duration
	// Now and Sleep are the clock and the wait (tests script them); Sleep returns early with ctx.Err() when ctx ends.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// Throttled is told of every backoff (default: the metric).
	Throttled func(host string)

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewTransport returns the transport for a Config.
func NewTransport(c Config) *Transport {
	return &Transport{RPS: c.RateRPS, Burst: c.RateBurst, MaxBatch: c.MaxBatch, Retries: c.BackoffRetries, BackoffMax: c.BackoffMax}
}

// Client returns an http.Client over the transport.
func (t *Transport) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: t, Timeout: timeout}
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Transport) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if t.Sleep != nil {
		return t.Sleep(ctx, d)
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

func (t *Transport) throttled(host string) {
	if t.Throttled != nil {
		t.Throttled(host)
		return
	}
	metrics.IncFinalityProviderThrottled(host)
}

// take waits for one token of host's bucket.
func (t *Transport) take(ctx context.Context, host string) error {
	if t.RPS <= 0 {
		return nil
	}
	burst := float64(t.Burst)
	if burst < 1 {
		burst = 1
	}
	for {
		t.mu.Lock()
		if t.buckets == nil {
			t.buckets = map[string]*bucket{}
		}
		b := t.buckets[host]
		now := t.now()
		if b == nil {
			b = &bucket{tokens: burst, last: now}
			t.buckets[host] = b
		}
		b.tokens += now.Sub(b.last).Seconds() * t.RPS
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			t.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - b.tokens) / t.RPS * float64(time.Second))
		t.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if err := t.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// retryAfter reads a Retry-After header in seconds; 0 when absent or not a small whole number (a date form is ignored: the
// exponential bound applies).
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 3600 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// backoff is the wait before retry number attempt (0-based): the provider's Retry-After when it states one, else 500 ms doubling,
// at most BackoffMax.
func (t *Transport) backoff(attempt int, h http.Header) time.Duration {
	max := t.BackoffMax
	if max <= 0 {
		max = time.Minute
	}
	d := retryAfter(h)
	if d == 0 {
		d = 500 * time.Millisecond << uint(attempt)
		if attempt > 10 {
			d = max
		}
	}
	if d > max {
		d = max
	}
	return d
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody+1))
		req.Body.Close()
		if err != nil {
			return nil, ethrpc.RedactError(err)
		}
		if len(b) > maxRequestBody {
			return nil, errors.New("finality transport: request body exceeds the bound")
		}
		body = b
	}
	if t.MaxBatch > 0 && req.Method == http.MethodPost && len(body) > 2 && bytes.TrimLeft(body, " \t\r\n")[0] == '[' {
		var items []json.RawMessage
		if json.Unmarshal(body, &items) == nil && len(items) > t.MaxBatch {
			return t.chunked(req, items)
		}
	}
	return t.once(req, body)
}

// once sends one request body under the rate limit and the 429 backoff.
func (t *Transport) once(req *http.Request, body []byte) (*http.Response, error) {
	ctx := req.Context()
	host := HostLabel(req.URL.String())
	for attempt := 0; ; attempt++ {
		if err := t.take(ctx, host); err != nil {
			return nil, err
		}
		r2 := req.Clone(ctx)
		if body != nil {
			r2.Body = io.NopCloser(bytes.NewReader(body))
			r2.ContentLength = int64(len(body))
			r2.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		}
		resp, err := t.base().RoundTrip(r2)
		if err != nil {
			return nil, err
		}
		if (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) || attempt >= t.Retries {
			return resp, nil
		}
		wait := t.backoff(attempt, resp.Header)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		t.throttled(host)
		if err := t.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// chunked sends a JSON-RPC batch as several batches of at most MaxBatch requests and joins the answers in request order.
func (t *Transport) chunked(req *http.Request, items []json.RawMessage) (*http.Response, error) {
	var joined []json.RawMessage
	var last *http.Response
	for lo := 0; lo < len(items); lo += t.MaxBatch {
		hi := lo + t.MaxBatch
		if hi > len(items) {
			hi = len(items)
		}
		sub, err := json.Marshal(items[lo:hi])
		if err != nil {
			return nil, err
		}
		resp, err := t.once(req, sub)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return resp, nil // the caller reports the status; the chunks answered so far are discarded, never half-delivered
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
		resp.Body.Close()
		if err != nil {
			return nil, ethrpc.RedactError(err)
		}
		if len(raw) > maxResponseBody {
			return nil, errors.New("finality transport: batch answer exceeds the bound")
		}
		var part []json.RawMessage
		if err := json.Unmarshal(raw, &part); err != nil {
			// a provider that answers a batch with an object (an error) is passed through as it is
			return &http.Response{Status: resp.Status, StatusCode: resp.StatusCode, Header: resp.Header, Body: io.NopCloser(bytes.NewReader(raw)),
				ContentLength: int64(len(raw)), Request: req, Proto: resp.Proto, ProtoMajor: resp.ProtoMajor, ProtoMinor: resp.ProtoMinor}, nil
		}
		joined = append(joined, part...)
		last = resp
	}
	out, err := json.Marshal(joined)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	resp := &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(bytes.NewReader(out)), ContentLength: int64(len(out)),
		Request: req, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	if last != nil {
		resp.Proto, resp.ProtoMajor, resp.ProtoMinor = last.Proto, last.ProtoMajor, last.ProtoMinor
	}
	return resp, nil
}
