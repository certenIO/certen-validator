// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfterReadsSecondsAndHTTPDatesAndRefusesTheRest(t *testing.T) {
	now := time.Date(2026, 10, 23, 18, 59, 0, 0, time.UTC)
	for _, c := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"120", 120 * time.Second, true},
		{"0", 0, true},
		{"  7 ", 7 * time.Second, true},
		{"", 0, false},
		{"-5", 0, false},
		{"1.5", 0, false},
		{"soon", 0, false},
		{"Fri, 23 Oct 2026 19:00:30 GMT", 90 * time.Second, true},
		{"Fri, 23 Oct 2026 18:00:00 GMT", 0, true}, // a date in the past: retry now
		{"99999999999999999999", MaxRetryAfterKept, true},
		{"4294967295", MaxRetryAfterKept, true},
		{"1800", MaxRetryAfterKept, true},
		{"1801", MaxRetryAfterKept, true},
	} {
		got, ok := ParseRetryAfter(c.in, now)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseRetryAfter(%q) = %s, %v; want %s, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestBackoff429StepsByOneAndAHalfSeconds(t *testing.T) {
	for try, want := range []time.Duration{1500 * time.Millisecond, 3 * time.Second, 4500 * time.Millisecond, 6 * time.Second} {
		if got := Backoff429(try); got != want {
			t.Errorf("Backoff429(%d) = %s, want %s", try, got, want)
		}
	}
}

func TestThrottleWaitHonoursAStatedRetryAfterAndGivesUpExactlyWhereTheWaitCannotBeAfforded(t *testing.T) {
	s := time.Second
	const none = time.Duration(-1)
	for _, c := range []struct {
		name         string
		ra           time.Duration
		stated       bool
		try          int
		maxWait, rem time.Duration
		wait         time.Duration
		giveUp       bool
		hint         time.Duration
	}{
		{"unstated: the backoff of the try", 0, false, 0, 30 * s, none, 1500 * time.Millisecond, false, 1500 * time.Millisecond},
		{"unstated, third try", 0, false, 2, 30 * s, none, 4500 * time.Millisecond, false, 4500 * time.Millisecond},
		{"stated longer than the backoff: honoured", 5 * s, true, 0, 30 * s, none, 5 * s, false, 5 * s},
		{"stated shorter than the backoff: never shortened below it", s, true, 0, 30 * s, none, 1500 * time.Millisecond, false, s},
		{"stated exactly the patience: waited", 30 * s, true, 0, 30 * s, none, 30 * s, false, 30 * s},
		{"stated one nanosecond over the patience: handed back", 30*s + 1, true, 0, 30 * s, none, 0, true, 30*s + 1},
		{"the wait fits the deadline by a nanosecond", 5 * s, true, 0, 30 * s, 5*s + 1, 5 * s, false, 5 * s},
		{"the wait equals what the deadline has left: handed back", 5 * s, true, 0, 30 * s, 5 * s, 0, true, 5 * s},
		{"no time left at all", 0, false, 0, 30 * s, 0, 0, true, 1500 * time.Millisecond},
		{"the eighth 429 in a row is final", 0, false, 7, 300 * s, none, 0, true, 12 * s},
		{"the seventh is still retried", 0, false, 6, 300 * s, none, 10500 * time.Millisecond, false, 10500 * time.Millisecond},
	} {
		wait, giveUp, hint := ThrottleWait(c.ra, c.stated, c.try, c.maxWait, c.rem)
		if wait != c.wait || giveUp != c.giveUp || hint != c.hint {
			t.Errorf("%s: wait %s giveUp %v hint %s; want %s %v %s", c.name, wait, giveUp, hint, c.wait, c.giveUp, c.hint)
		}
	}
}

func TestNextGapGrowsOnThrottleAndShrinksOnSuccessWithinItsBounds(t *testing.T) {
	ms := time.Millisecond
	for _, c := range []struct {
		cur, floor time.Duration
		throttled  bool
		want       time.Duration
	}{
		{0, 0, true, 500 * ms}, {500 * ms, 0, true, time.Second}, {time.Second, 0, true, 2 * time.Second}, {4 * time.Second, 0, true, 8 * time.Second},
		{8 * time.Second, 0, true, 8 * time.Second}, {6 * time.Second, 0, true, 8 * time.Second}, {0, 2 * time.Second, true, 2 * time.Second},
		{time.Second, 0, false, 500 * ms}, {100 * ms, 0, false, 50 * ms}, {99 * ms, 0, false, 0}, {200 * ms, 0, false, 100 * ms},
		{100 * ms, 100 * ms, false, 100 * ms}, {0, 100 * ms, false, 100 * ms}, {120 * ms, 0, false, 60 * ms}, {time.Second, 400 * ms, false, 500 * ms}, {600 * ms, 400 * ms, false, 400 * ms},
	} {
		if got := NextGap(c.cur, c.floor, c.throttled); got != c.want {
			t.Errorf("NextGap(%s, floor %s, throttled=%v) = %s, want %s", c.cur, c.floor, c.throttled, got, c.want)
		}
	}
}

func TestNextSlotNeverStartsBeforeThePreviousSlotEnds(t *testing.T) {
	t0 := time.Date(2026, 10, 23, 19, 0, 0, 0, time.UTC)
	if s, e := NextSlot(t0.Add(-time.Second), t0, 50*time.Millisecond); !s.Equal(t0) || !e.Equal(t0.Add(50*time.Millisecond)) {
		t.Errorf("an idle pacer: %s %s", s, e)
	}
	if s, e := NextSlot(t0.Add(time.Second), t0, 50*time.Millisecond); !s.Equal(t0.Add(time.Second)) || !e.Equal(t0.Add(time.Second+50*time.Millisecond)) {
		t.Errorf("a busy pacer: %s %s", s, e)
	}
	if s, _ := NextSlot(t0, t0, 0); !s.Equal(t0) {
		t.Errorf("no gap: %s", s)
	}
}

func TestSourceErrorThrottleReportsTheLongestRetryAfter(t *testing.T) {
	e := &SourceError{Failures: []EndpointFailure{{Reason: "boom"}, {Throttled: true, RetryAfter: 5 * time.Second}, {Throttled: true, RetryAfter: 40 * time.Second}}}
	if ra, ok := e.Throttle(); !ok || ra != 40*time.Second {
		t.Errorf("Throttle() = %s, %v", ra, ok)
	}
	if _, ok := (&SourceError{Failures: []EndpointFailure{{Reason: "HTTP 500"}}}).Throttle(); ok {
		t.Error("a 500 is not a throttle")
	}
	if s := (EndpointFailure{Endpoint: "e", Op: "headers", Reason: "HTTP 429", Throttled: true, RetryAfter: 90 * time.Second}).String(); !strings.Contains(s, "retry after 1m30s") {
		t.Errorf("failure text %q", s)
	}
}

// ---- the source against a server that throttles ----

// slowDownServer answers 429 (with retryAfter in its header when not empty) to the first n requests and then serves headers from the
// recorded spine, recording when each request arrived.
func slowDownServer(t *testing.T, n int32, retryAfter string) (*httptest.Server, *int32, func() []time.Time, [32]byte, uint64) {
	t.Helper()
	l := loadRecorded(t, "gloas_latest")
	byHash, byNum := map[string][]byte{}, map[uint64][]byte{}
	for _, raw := range l.body.Spine[:12] {
		f := rlpFields(t, raw)
		byHash["0x"+hex.EncodeToString(f.hash[:])] = raw
		byNum[f.number] = raw
	}
	var calls int32
	inner := rpcServer(t, byHash, byNum, 429, 0, new(int32))
	t.Cleanup(inner.Close)
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		if atomic.AddInt32(&calls, 1) <= n {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	top := rlpFields(t, l.body.Spine[0])
	return srv, &calls, func() []time.Time { mu.Lock(); defer mu.Unlock(); return append([]time.Time(nil), at...) }, top.hash, top.number
}

func TestRPCHeadersWaitsOutAStatedRetryAfterThatFitsAndNeverLess(t *testing.T) {
	srv, calls, _, _, topN := slowDownServer(t, 1, "2")
	r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 4}
	t0 := time.Now()
	hs, err := r.HeadersByNumber(context.Background(), topN-3, topN)
	if err != nil || len(hs) != 4 {
		t.Fatalf("%v %d headers", err, len(hs))
	}
	if d := time.Since(t0); d < 2*time.Second || d > 6*time.Second {
		t.Fatalf("waited %s for a stated Retry-After of 2 s", d)
	}
	if atomic.LoadInt32(calls) != 2 {
		t.Fatalf("%d requests", *calls)
	}
}

func TestRPCHeadersHandsBackARetryAfterItCannotWaitOut(t *testing.T) {
	for _, c := range []struct {
		name  string
		hdr   string
		maxRA time.Duration
		ctxT  time.Duration
		want  time.Duration
	}{
		{"longer than the default patience", "120", 0, 20 * time.Second, 120 * time.Second},
		{"longer than the configured patience", "3", 2 * time.Second, 20 * time.Second, 3 * time.Second},
		{"longer than the deadline has left", "10", 0, time.Second, 10 * time.Second},
		{"unstated, backoff beyond the deadline: no Retry-After is reported", "", 0, time.Second, 0},
	} {
		srv, calls, _, _, topN := slowDownServer(t, 100, c.hdr)
		r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 4, MaxRetryAfter: c.maxRA}
		ctx, cancel := context.WithTimeout(context.Background(), c.ctxT)
		t0 := time.Now()
		_, err := r.HeadersByNumber(ctx, topN-3, topN)
		cancel()
		se, ok := err.(*SourceError)
		if !ok {
			t.Fatalf("%s: %T %v", c.name, err, err)
		}
		ra, throttled := se.Throttle()
		if !throttled || ra != c.want {
			t.Fatalf("%s: Throttle() = %s, %v; want %s", c.name, ra, throttled, c.want)
		}
		if d := time.Since(t0); d > 800*time.Millisecond {
			t.Fatalf("%s: took %s", c.name, d)
		}
		if n := atomic.LoadInt32(calls); n != 1 {
			t.Fatalf("%s: %d requests, want 1", c.name, n)
		}
	}
}

func TestRPCHeadersKeepsItsRequestsAGapApartForAllCallersTogether(t *testing.T) {
	srv, _, arrivals, _, topN := slowDownServer(t, 0, "")
	gap := 60 * time.Millisecond
	r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 1, MinGap: gap}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if _, err := r.HeadersByNumber(context.Background(), topN-uint64(i+j), topN-uint64(i+j)); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	at := arrivals()
	if len(at) != 12 {
		t.Fatalf("%d requests", len(at))
	}
	sort.Slice(at, func(i, j int) bool { return at[i].Before(at[j]) })
	for i := 1; i < len(at); i++ {
		// the slots are reserved a gap apart; arrival at the server jitters by the timer resolution of the machine (15 ms on Windows)
		if d := at[i].Sub(at[i-1]); d < gap/3 {
			t.Fatalf("requests %d and %d arrived %s apart, the gap is %s", i-1, i, d, gap)
		}
	}
}

func TestRPCHeadersGapGrowsAfterA429AndShrinksAgainOnSuccess(t *testing.T) {
	srv, _, _, _, topN := slowDownServer(t, 1, "1")
	r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 4}
	if _, err := r.HeadersByNumber(context.Background(), topN-3, topN); err != nil {
		t.Fatal(err)
	}
	r.pace.mu.Lock()
	g := r.pace.gap
	r.pace.mu.Unlock()
	// one 429 raised the gap to 500 ms and the answer after it halved it
	if g != 250*time.Millisecond {
		t.Fatalf("gap %s after a 429 and a success, want 250ms", g)
	}
	for i := 0; i < 4; i++ {
		if _, err := r.HeadersByNumber(context.Background(), topN-3, topN); err != nil {
			t.Fatal(err)
		}
	}
	r.pace.mu.Lock()
	g = r.pace.gap
	r.pace.mu.Unlock()
	if g != 0 {
		t.Fatalf("gap %s after more successes, want none", g)
	}
}
