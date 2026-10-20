// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rtStubRT func(*http.Request) (*http.Response, error)

func (f rtStubRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func rtStubResp(code int, hdr map[string]string, body string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

func rtPost(t *testing.T, tr http.RoundTripper, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	return resp
}

func TestRTTransportRetriesOnce429AndHonoursRetryAfterUpToTheCap(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		retryAfter string
		max        time.Duration
		want       time.Duration
	}{
		{"429 with Retry-After 3", 429, "3", time.Minute, 3 * time.Second},
		{"429 with Retry-After above the cap", 429, "120", 10 * time.Second, 10 * time.Second},
		{"503 without Retry-After starts at 500ms", 503, "", time.Minute, 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == 1 {
					if tc.retryAfter != "" {
						w.Header().Set("Retry-After", tc.retryAfter)
					}
					w.WriteHeader(tc.status)
					return
				}
				w.Write([]byte(`{"ok":true}`))
			}))
			defer srv.Close()
			var sleeps []time.Duration
			var hosts []string
			tr := &Transport{Retries: 3, BackoffMax: tc.max,
				Sleep:     func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
				Throttled: func(h string) { hosts = append(hosts, h) }}
			resp := rtPost(t, tr, srv.URL+"/v1/tok-abc?apikey=1", `{"a":1}`)
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status %d, want 200 after one retry", resp.StatusCode)
			}
			if hits.Load() != 2 {
				t.Fatalf("the server saw %d requests, want exactly 2 (one retry)", hits.Load())
			}
			if len(sleeps) != 1 || sleeps[0] != tc.want {
				t.Fatalf("slept %v, want exactly [%v]", sleeps, tc.want)
			}
			if len(hosts) != 1 || hosts[0] != HostLabel(srv.URL) {
				t.Fatalf("throttled labels %v, want the host label only [%s]", hosts, HostLabel(srv.URL))
			}
			if strings.Contains(hosts[0], "tok-abc") || strings.Contains(hosts[0], "apikey") {
				t.Fatalf("the throttle label %q carries path or query", hosts[0])
			}
		})
	}
}

func TestRTTransport429ForeverReturnsTheLastStatusAfterBoundedExponentialBackoff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	var sleeps []time.Duration
	var throttled int
	tr := &Transport{Retries: 4, BackoffMax: 3 * time.Second,
		Sleep:     func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
		Throttled: func(string) { throttled++ }}
	resp := rtPost(t, tr, srv.URL, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d: the last 429 must be visible to the caller", resp.StatusCode)
	}
	if hits.Load() != 5 {
		t.Fatalf("%d requests, want 1 + 4 retries", hits.Load())
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 3 * time.Second}
	if fmt.Sprint(sleeps) != fmt.Sprint(want) {
		t.Fatalf("sleeps %v, want %v (exponential from 500ms, capped at BackoffMax)", sleeps, want)
	}
	for i := 1; i < len(sleeps); i++ {
		if sleeps[i] < sleeps[i-1] {
			t.Fatalf("sleeps are not non-decreasing: %v", sleeps)
		}
	}
	if throttled != 4 {
		t.Fatalf("throttled hook called %d times, want once per backoff (4)", throttled)
	}
}

// rtBatchServer answers a JSON-RPC batch with one result per request and records the size of every batch it received.
type rtBatchServer struct {
	mu     sync.Mutex
	sizes  []int
	raw    [][]byte
	failOn int // the request number (1-based) answered with 500; 0 = never
	n      int
}

func (b *rtBatchServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.n++
	n := b.n
	b.raw = append(b.raw, body)
	b.mu.Unlock()
	if b.failOn == n {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var items []json.RawMessage
	if json.Unmarshal(body, &items) != nil {
		w.Write([]byte(`{"single":true}`))
		return
	}
	b.mu.Lock()
	b.sizes = append(b.sizes, len(items))
	b.mu.Unlock()
	out := make([]json.RawMessage, len(items))
	for i, it := range items {
		var m struct {
			ID int `json:"id"`
		}
		json.Unmarshal(it, &m)
		out[i] = json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":"r%d"}`, m.ID, m.ID))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func rtBatchBody(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"eth_getBlockByNumber","params":["0x%x",false]}`, i, i)
	}
	return "[" + strings.Join(items, ",") + "]"
}

func TestRTTransportSplitsABatchOf100IntoChunksOfAtMost40AndJoinsTheAnswersInOrder(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want []int
	}{
		{100, []int{40, 40, 20}},
		{41, []int{40, 1}},
		{40, []int{40}},
		{1, []int{1}},
	} {
		t.Run(fmt.Sprintf("%d requests", tc.n), func(t *testing.T) {
			bs := &rtBatchServer{}
			srv := httptest.NewServer(bs)
			defer srv.Close()
			tr := &Transport{MaxBatch: 40, Retries: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
			resp, err := tr.Client(5*time.Second).Post(srv.URL, "application/json", bytes.NewReader([]byte(rtBatchBody(tc.n))))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			var got []struct {
				ID     int    `json:"id"`
				Result string `json:"result"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(bs.sizes) != fmt.Sprint(tc.want) {
				t.Fatalf("the provider received batches of %v, want %v", bs.sizes, tc.want)
			}
			if len(got) != tc.n {
				t.Fatalf("joined answer has %d items, want %d", len(got), tc.n)
			}
			for i, g := range got {
				if g.ID != i || g.Result != fmt.Sprintf("r%d", i) {
					t.Fatalf("answer %d is %+v: the joined answers are not in request order", i, g)
				}
			}
		})
	}
}

func TestRTTransportPassesANonBatchBodyUntouchedAndStopsOnAFailingChunk(t *testing.T) {
	bs := &rtBatchServer{}
	srv := httptest.NewServer(bs)
	defer srv.Close()
	tr := &Transport{MaxBatch: 40, Sleep: func(context.Context, time.Duration) error { return nil }}
	single := `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`
	resp := rtPost(t, tr, srv.URL, single)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != `{"single":true}` {
		t.Fatalf("a non-batch answer was changed: %s", b)
	}
	if len(bs.raw) != 1 || string(bs.raw[0]) != single {
		t.Fatalf("a non-batch request body was changed or split: %q", bs.raw)
	}

	// a failing second chunk: the caller sees the 500, the third chunk is never sent, nothing is half delivered
	bs2 := &rtBatchServer{failOn: 2}
	srv2 := httptest.NewServer(bs2)
	defer srv2.Close()
	resp2 := rtPost(t, tr, srv2.URL, rtBatchBody(100))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want the failing chunk's 500", resp2.StatusCode)
	}
	if bs2.n != 2 {
		t.Fatalf("the provider saw %d requests, want 2 (the third chunk is not sent after a failure)", bs2.n)
	}
}

func TestRTTransportTokenBucketSpacesRequestsAtOneOverRPSPerHost(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var sleeps []time.Duration
	var calls []time.Time
	tr := &Transport{RPS: 2, Burst: 3,
		Base: rtStubRT(func(r *http.Request) (*http.Response, error) {
			calls = append(calls, now)
			return rtStubResp(200, nil, "{}"), nil
		}),
		Now: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			now = now.Add(d)
			return nil
		}}
	t0 := now
	near := func(got, want time.Duration) bool {
		return got >= want-2*time.Millisecond && got <= want+2*time.Millisecond
	}
	for i := 0; i < 6; i++ {
		rtPost(t, tr, "http://a.example/x", `{}`).Body.Close()
	}
	want := []time.Duration{0, 0, 0, 500 * time.Millisecond, time.Second, 1500 * time.Millisecond}
	for i, c := range calls {
		if !near(c.Sub(t0), want[i]) {
			t.Fatalf("request %d was sent at +%v, want +%v (burst 3, then 1/RPS = 500ms apart)", i, c.Sub(t0), want[i])
		}
	}
	// another host has its own bucket: the same instant, no wait
	before, nsleeps := now, len(sleeps)
	rtPost(t, tr, "http://b.example/x", `{}`).Body.Close()
	if !now.Equal(before) || len(sleeps) != nsleeps {
		t.Fatalf("host b waited for host a's bucket (slept %v)", sleeps[nsleeps:])
	}
	// the bucket refills to the burst and no further: after 10s three requests are immediate and the fourth waits 500ms
	now = now.Add(10 * time.Second)
	base := now
	calls = nil
	for i := 0; i < 4; i++ {
		rtPost(t, tr, "http://a.example/x", `{}`).Body.Close()
	}
	for i, w := range []time.Duration{0, 0, 0, 500 * time.Millisecond} {
		if !near(calls[i].Sub(base), w) {
			t.Fatalf("after the refill, request %d was sent at +%v, want +%v", i, calls[i].Sub(base), w)
		}
	}
}

func TestRTTransportACancelledContextDuringABackoffOrABucketWaitDoesNotRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	tr := &Transport{Retries: 5, Sleep: func(c context.Context, d time.Duration) error { cancel(); return c.Err() }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("the server saw %d requests: a cancelled backoff must not retry", hits.Load())
	}

	// cancelled while waiting for a token: the base transport is not called again
	ctx2, cancel2 := context.WithCancel(context.Background())
	var based int
	tr2 := &Transport{RPS: 1, Burst: 1,
		Base:  rtStubRT(func(r *http.Request) (*http.Response, error) { based++; return rtStubResp(200, nil, "{}"), nil }),
		Now:   func() time.Time { return time.Unix(5, 0) },
		Sleep: func(c context.Context, d time.Duration) error { cancel2(); return c.Err() }}
	r1, _ := http.NewRequestWithContext(ctx2, http.MethodPost, "http://a.example/", strings.NewReader(`{}`))
	if resp, err := tr2.RoundTrip(r1); err != nil {
		t.Fatalf("first request: %v", err)
	} else {
		resp.Body.Close()
	}
	r2, _ := http.NewRequestWithContext(ctx2, http.MethodPost, "http://a.example/", strings.NewReader(`{}`))
	if _, err := tr2.RoundTrip(r2); !errors.Is(err, context.Canceled) {
		t.Fatalf("second request error %v, want context.Canceled", err)
	}
	if based != 1 {
		t.Fatalf("the base transport was called %d times, want 1", based)
	}
}

func TestRTHostLabelNeverCarriesUserinfoPathOrQuery(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:pw@host/v1/tok-abc?apikey=1": "https://host",
		"https://host.example:8545/rpc/secret":  "https://host.example:8545",
		"http://127.0.0.1:9596":                 "http://127.0.0.1:9596",
		"://bad":                                "provider",
		"not a url":                             "provider",
	} {
		if got := HostLabel(in); got != want {
			t.Errorf("HostLabel(%q) = %q, want %q", in, got, want)
		}
	}
	var hosts []string
	var n int
	tr := &Transport{Retries: 2, Sleep: func(context.Context, time.Duration) error { return nil }, Throttled: func(h string) { hosts = append(hosts, h) },
		Base: rtStubRT(func(r *http.Request) (*http.Response, error) {
			if n++; n == 1 {
				return rtStubResp(429, nil, ""), nil
			}
			return rtStubResp(200, nil, "{}"), nil
		})}
	rtPost(t, tr, "https://u:pw@provider.example/v1/tok-abc?apikey=1", `{}`).Body.Close()
	if len(hosts) != 1 || hosts[0] != "https://provider.example" {
		t.Fatalf("throttle labels %v, want [https://provider.example]", hosts)
	}
}

// A failing round trip: whatever text the base transport put in its error, the error that leaves the transport carries no
// credential (userinfo, path token or query key). Provider text reaches logs and states only through pkg/ethrpc.
func TestRTTransportErrorFromAFailingRoundTripCarriesNoCredential(t *testing.T) {
	tr := &Transport{Retries: 1, Sleep: func(context.Context, time.Duration) error { return nil },
		Base: rtStubRT(func(r *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("Post %q: dial tcp: connection refused", r.URL.String())
		})}
	req, _ := http.NewRequest(http.MethodPost, "https://u:pw@provider.example/v1/tok-abcdef0123456789?apikey=K3Y-0123456789", strings.NewReader(`{}`))
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected the base transport's failure")
	}
	for _, leak := range []string{"tok-abcdef0123456789", "K3Y-0123456789", "u:pw"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the transport's error leaks %q: %v", leak, err)
		}
	}
}
