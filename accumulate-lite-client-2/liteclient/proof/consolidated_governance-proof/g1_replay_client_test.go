// Copyright 2026 Certen Protocol

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// A capture of every v3 exchange one G1 proof made against Kermit, byte exact, and the client that serves it back.
//
// The live G1 tests in this package read Kermit and cannot run offline. The delegation fixtures are recorded from the
// live transactions once (g1_record_fixtures_test.go, build tag g1record) and replayed here: the recorded bytes are
// exactly what the network answered, so the parsers and both signature routes run against what Accumulate actually
// sends, deterministically and without a network. A query the recording does not hold is an error that names it - the
// replay never invents an answer.

// recordedCapture is the file format: testdata/g1_delegation/<case>.json.gz.
type recordedCapture struct {
	Description string             `json:"description"`
	Endpoint    string             `json:"endpoint"`
	CapturedAt  string             `json:"capturedAt"`
	Account     string             `json:"account"`
	TxHash      string             `json:"txHash"`
	KeyPage     string             `json:"keyPage"`
	Exchanges   []recordedExchange `json:"exchanges"`
}

// recordedExchange is one request and the exact response bytes it got. Response is the JSON text as received.
type recordedExchange struct {
	Scope    string          `json:"scope"`
	Query    json.RawMessage `json:"query"`
	Response string          `json:"response"`
}

// exchangeKey is the identity of a request: the scope as the proof layer spells it and the canonical JSON of the query
// (encoding/json writes map keys sorted, so the same query is the same key whichever goroutine built it).
func exchangeKey(scope string, query map[string]interface{}) string {
	q, _ := json.Marshal(query)
	return (URLUtils{}).NormalizeScope(scope) + "\n" + string(q)
}

func loadCapture(t *testing.T, name string) *recordedCapture {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "g1_delegation", name))
	if err != nil {
		t.Fatalf("recorded capture %s: %v", name, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("recorded capture %s: %v", name, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("recorded capture %s: %v", name, err)
	}
	var c recordedCapture
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("recorded capture %s is not JSON: %v", name, err)
	}
	if len(c.Exchanges) == 0 {
		t.Fatalf("recorded capture %s holds no exchanges", name)
	}
	return &c
}

// replayClient serves a capture. rewrite, when set, may alter a response before it is served (to inject a fault into
// real bytes); unrecorded lists every request the capture did not hold.
type replayClient struct {
	mu         sync.Mutex
	responses  map[string][]byte
	rewrite    func(scope string, query map[string]interface{}, raw []byte) []byte
	unrecorded []string
	served     int
}

func newReplayClient(t *testing.T, c *recordedCapture) *replayClient {
	t.Helper()
	r := &replayClient{responses: map[string][]byte{}}
	for _, e := range c.Exchanges {
		var q map[string]interface{}
		if err := json.Unmarshal(e.Query, &q); err != nil {
			t.Fatalf("recorded query for %s: %v", e.Scope, err)
		}
		key := exchangeKey(e.Scope, q)
		if _, dup := r.responses[key]; !dup {
			r.responses[key] = []byte(e.Response)
		}
	}
	return r
}

func (r *replayClient) QueryRaw(_ context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, ok := r.responses[exchangeKey(scope, query)]
	if !ok {
		q, _ := json.Marshal(query)
		r.unrecorded = append(r.unrecorded, scope+" "+string(q))
		return nil, fmt.Errorf("replay: no recorded response for %s %s", scope, q)
	}
	r.served++
	if r.rewrite != nil {
		return r.rewrite(scope, query, append([]byte(nil), raw...)), nil
	}
	return raw, nil
}

func (r *replayClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	raw, err := r.QueryRaw(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Non-JSON response: %v", err)}
	}
	return out, nil
}

func (r *replayClient) GetEndpoint() string { return "replay" }

func (r *replayClient) missing() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.unrecorded...)
	sort.Strings(out)
	return out
}

// requireNoUnrecorded fails with every request the proof made that the capture did not hold.
func (r *replayClient) requireNoUnrecorded(t *testing.T) {
	t.Helper()
	if m := r.missing(); len(m) > 0 {
		t.Fatalf("the proof made %d request(s) the capture does not hold:\n  %s", len(m), strings.Join(m, "\n  "))
	}
}
