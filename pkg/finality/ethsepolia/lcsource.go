// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

// LCSource serves beacon light-client objects. It is an AVAILABILITY dependency, never evidence: every byte it returns is
// verified (ethl1) before it reaches a container, and the order of Sources in a Multi is only the order in which availability
// is tried. Implementations return SSZ bytes exactly as the endpoint serves them.
type LCSource interface {
	// Name labels the endpoint in states (scheme and host only; no path, no credentials).
	Name() string
	// FinalityUpdate is /eth/v1/beacon/light_client/finality_update as SSZ.
	FinalityUpdate(ctx context.Context) ([]byte, error)
	// Updates is /eth/v1/beacon/light_client/updates?start_period&count as SSZ objects, one per period, in period order.
	Updates(ctx context.Context, startPeriod uint64, count int) ([][]byte, error)
	// Bootstrap is /eth/v1/beacon/light_client/bootstrap/{block_root} as SSZ.
	Bootstrap(ctx context.Context, blockRoot [32]byte) ([]byte, error)
	// HeadSlot is the observed head slot (/eth/v1/beacon/headers/head), reported in pending states only.
	HeadSlot(ctx context.Context) (uint64, error)
}

// EndpointFailure is one entry of finality_lc_unavailable{per endpoint}: what the endpoint answered, with provider text redacted.
type EndpointFailure struct {
	Endpoint string
	Op       string
	HTTP     int
	Reason   string
	// Throttled marks a provider that answered 429 and was not waited out inside the call; RetryAfter is the time to come back after
	// (the provider's own Retry-After; ZERO when it stated none, so that a caller escalates its own wait instead of taking a backoff for a request).
	// Both are zero for every other failure.
	Throttled  bool
	RetryAfter time.Duration
}

func (f EndpointFailure) String() string {
	s := fmt.Sprintf("%s %s http=%d: %s", f.Endpoint, f.Op, f.HTTP, f.Reason)
	if f.Throttled && f.RetryAfter > 0 {
		s += fmt.Sprintf(" (retry after %s)", f.RetryAfter.Round(time.Second))
	}
	return s
}

// SourceError is the error of an LCSource call: the failure per endpoint tried. It is not a verdict about any block.
type SourceError struct{ Failures []EndpointFailure }

func (e *SourceError) Error() string {
	parts := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		parts[i] = f.String()
	}
	return "light-client source unavailable: " + strings.Join(parts, "; ")
}

// Throttle reports whether at least one endpoint of the call answered 429 and was not waited out, and the time to come back after: the
// longest RetryAfter any throttled endpoint gave (0 when none gave one). The text of every other failure stays in the error.
func (e *SourceError) Throttle() (retryAfter time.Duration, throttled bool) {
	for _, f := range e.Failures {
		if f.Throttled {
			throttled = true
			if f.RetryAfter > retryAfter {
				retryAfter = f.RetryAfter
			}
		}
	}
	return retryAfter, throttled
}

// HTTPSource is a Lodestar-compatible Beacon API endpoint (also serves Lighthouse where that serves the object).
type HTTPSource struct {
	// Base is the endpoint URL without a trailing slash, e.g. https://lodestar-sepolia.chainsafe.io.
	Base   string
	Client *http.Client
}

// NewHTTPSource returns a source for base with a 60 s client.
func NewHTTPSource(base string) *HTTPSource {
	return &HTTPSource{Base: strings.TrimRight(base, "/"), Client: &http.Client{Timeout: 60 * time.Second}}
}

var _ LCSource = (*HTTPSource)(nil)

// Name is scheme://host of the endpoint.
func (s *HTTPSource) Name() string {
	b := s.Base
	if i := strings.Index(b, "://"); i >= 0 {
		rest := b[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if k := strings.LastIndex(rest, "@"); k >= 0 {
			rest = rest[k+1:]
		}
		return b[:i+3] + rest
	}
	return b
}

func (s *HTTPSource) fail(op string, code int, err error) *SourceError {
	reason := ""
	if err != nil {
		reason = ethrpc.RedactText(err.Error())
	}
	return &SourceError{Failures: []EndpointFailure{{Endpoint: s.Name(), Op: op, HTTP: code, Reason: reason}}}
}

func (s *HTTPSource) get(ctx context.Context, op, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Base+path, nil)
	if err != nil {
		return nil, s.fail(op, 0, err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, s.fail(op, 0, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, s.fail(op, resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		// the provider's body is not echoed into a state: its status and a redacted first line are enough
		line := strings.SplitN(string(b), "\n", 2)[0]
		if len(line) > 160 {
			line = line[:160]
		}
		return nil, s.fail(op, resp.StatusCode, fmt.Errorf("%s", line))
	}
	return b, nil
}

// FinalityUpdate implements LCSource.
func (s *HTTPSource) FinalityUpdate(ctx context.Context) ([]byte, error) {
	return s.get(ctx, "finality_update", "/eth/v1/beacon/light_client/finality_update")
}

// Updates implements LCSource.
func (s *HTTPSource) Updates(ctx context.Context, startPeriod uint64, count int) ([][]byte, error) {
	b, err := s.get(ctx, "updates", "/eth/v1/beacon/light_client/updates?start_period="+strconv.FormatUint(startPeriod, 10)+"&count="+strconv.Itoa(count))
	if err != nil {
		return nil, err
	}
	objs, _, err := lcssz.SplitFramedUpdates(b)
	if err != nil {
		return nil, s.fail("updates", http.StatusOK, err)
	}
	if len(objs) != count {
		return nil, s.fail("updates", http.StatusOK, fmt.Errorf("asked for %d updates from period %d, got %d", count, startPeriod, len(objs)))
	}
	return objs, nil
}

// Bootstrap implements LCSource.
func (s *HTTPSource) Bootstrap(ctx context.Context, blockRoot [32]byte) ([]byte, error) {
	return s.get(ctx, "bootstrap", "/eth/v1/beacon/light_client/bootstrap/0x"+hex.EncodeToString(blockRoot[:]))
}

// HeadSlot implements LCSource.
func (s *HTTPSource) HeadSlot(ctx context.Context) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Base+"/eth/v1/beacon/headers/head", nil)
	if err != nil {
		return 0, s.fail("head", 0, err)
	}
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, s.fail("head", 0, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0, s.fail("head", resp.StatusCode, err)
	}
	i := strings.Index(string(b), `"slot":"`)
	if i < 0 {
		return 0, s.fail("head", resp.StatusCode, fmt.Errorf("no slot in the head header"))
	}
	rest := string(b[i+len(`"slot":"`):])
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return 0, s.fail("head", resp.StatusCode, fmt.Errorf("slot is not terminated"))
	}
	v, perr := strconv.ParseUint(rest[:j], 10, 64)
	if perr != nil {
		return 0, s.fail("head", resp.StatusCode, perr)
	}
	return v, nil
}

// Multi tries its sources in order and returns the first answer: the order is availability only, it is never a vote and the
// answers of two sources are never compared or merged. Every failure is kept, per endpoint.
type Multi []LCSource

var _ LCSource = Multi(nil)

// Name lists the endpoints.
func (m Multi) Name() string {
	names := make([]string, len(m))
	for i, s := range m {
		names[i] = s.Name()
	}
	return strings.Join(names, ",")
}

func (m Multi) each(do func(LCSource) error) error {
	var all []EndpointFailure
	for _, s := range m {
		err := do(s)
		if err == nil {
			return nil
		}
		if se, ok := err.(*SourceError); ok {
			all = append(all, se.Failures...)
		} else {
			all = append(all, EndpointFailure{Endpoint: s.Name(), Reason: ethrpc.RedactText(err.Error())})
		}
	}
	if len(all) == 0 {
		all = []EndpointFailure{{Endpoint: "(none configured)", Reason: "no light-client endpoint is configured"}}
	}
	return &SourceError{Failures: all}
}

// FinalityUpdate implements LCSource.
func (m Multi) FinalityUpdate(ctx context.Context) (out []byte, err error) {
	err = m.each(func(s LCSource) (e error) { out, e = s.FinalityUpdate(ctx); return })
	return
}

// Updates implements LCSource.
func (m Multi) Updates(ctx context.Context, start uint64, count int) (out [][]byte, err error) {
	err = m.each(func(s LCSource) (e error) { out, e = s.Updates(ctx, start, count); return })
	return
}

// Bootstrap implements LCSource.
func (m Multi) Bootstrap(ctx context.Context, root [32]byte) (out []byte, err error) {
	err = m.each(func(s LCSource) (e error) { out, e = s.Bootstrap(ctx, root); return })
	return
}

// HeadSlot implements LCSource.
func (m Multi) HeadSlot(ctx context.Context) (out uint64, err error) {
	err = m.each(func(s LCSource) (e error) { out, e = s.HeadSlot(ctx); return })
	return
}
