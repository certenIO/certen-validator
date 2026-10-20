// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// ---- LC sources ----

func TestHTTPSourceNameIsSchemeAndHostOnly(t *testing.T) {
	for in, want := range map[string]string{
		"https://lodestar.example":                   "https://lodestar.example",
		"https://user:secret@lodestar.example/a/b?k": "https://lodestar.example",
		"http://127.0.0.1:9000/x":                    "http://127.0.0.1:9000",
		"https://tok@h.example":                      "https://h.example",
		"no-scheme":                                  "no-scheme",
	} {
		if got := (&HTTPSource{Base: in}).Name(); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := NewHTTPSource("https://h.example///").Base; got != "https://h.example" {
		t.Errorf("base %q", got)
	}
}

func frame(objs ...[]byte) []byte {
	var out []byte
	for _, o := range objs {
		out = binary.LittleEndian.AppendUint64(out, uint64(len(o)+4))
		out = append(out, 1, 2, 3, 4)
		out = append(out, o...)
	}
	return out
}

func TestHTTPSourceServesTheBeaconObjectsAndNamesFailuresPerEndpoint(t *testing.T) {
	var accept atomic.Value
	var last atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept.Store(r.Header.Get("Accept"))
		last.Store(r.URL.RequestURI())
		switch {
		case strings.HasSuffix(r.URL.Path, "/finality_update"):
			w.Write([]byte("FU"))
		case strings.HasSuffix(r.URL.Path, "/updates"):
			if r.URL.Query().Get("start_period") == "7" && r.URL.Query().Get("count") == "2" {
				w.Write(frame([]byte("U7"), []byte("U8")))
				return
			}
			w.Write(frame([]byte("only-one")))
		case strings.Contains(r.URL.Path, "/bootstrap/"):
			w.Write([]byte("BOOT"))
		case strings.HasSuffix(r.URL.Path, "/headers/head"):
			w.Write([]byte(`{"data":{"header":{"message":{"slot":"11396503","proposer_index":"1"}}}}`))
		default:
			http.Error(w, "first line\nsecond line that must not appear", http.StatusTeapot)
		}
	}))
	defer srv.Close()
	s := NewHTTPSource(srv.URL)
	ctx := context.Background()
	if b, err := s.FinalityUpdate(ctx); err != nil || string(b) != "FU" {
		t.Fatalf("%q %v", b, err)
	}
	if accept.Load() != "application/octet-stream" {
		t.Errorf("Accept %v", accept.Load())
	}
	ups, err := s.Updates(ctx, 7, 2)
	if err != nil || len(ups) != 2 || string(ups[0]) != "U7" || string(ups[1]) != "U8" {
		t.Fatalf("%q %v", ups, err)
	}
	if _, err := s.Updates(ctx, 9, 2); err == nil || !strings.Contains(err.Error(), "asked for 2 updates") {
		t.Fatalf("a short answer: %v", err)
	}
	var root [32]byte
	root[0], root[31] = 0xab, 0xcd
	if b, err := s.Bootstrap(ctx, root); err != nil || string(b) != "BOOT" || !strings.Contains(last.Load().(string), "/bootstrap/0xab") || !strings.HasSuffix(last.Load().(string), "cd") {
		t.Fatalf("%q %v %v", b, err, last.Load())
	}
	if h, err := s.HeadSlot(ctx); err != nil || h != 11396503 {
		t.Fatalf("%d %v", h, err)
	}
	// a non-200 answer: the status and the first line only
	teapot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "first line\nsecond line that must not appear", http.StatusTeapot)
	}))
	defer teapot.Close()
	_, err = NewHTTPSource(teapot.URL).FinalityUpdate(ctx)
	se, ok := err.(*SourceError)
	if !ok || len(se.Failures) != 1 || se.Failures[0].HTTP != http.StatusTeapot {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "second line") || se.Failures[0].Op != "finality_update" || se.Failures[0].Endpoint != teapot.URL {
		t.Fatalf("%v", err)
	}
	// an unreachable endpoint is a failure with status 0
	dead := NewHTTPSource("http://127.0.0.1:1")
	if _, err := dead.HeadSlot(ctx); err == nil || err.(*SourceError).Failures[0].Op != "head" {
		t.Fatalf("%v", err)
	}
}

func TestHTTPSourceHeadSlotRefusesMalformedAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"no slot":          `{"data":{}}`,
		"unterminated":     `{"slot":"12`,
		"not a number":     `{"slot":"abc"}`,
		"a negative value": `{"slot":"-5"}`,
	} {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		if _, err := NewHTTPSource(srv.URL).HeadSlot(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		srv.Close()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) }))
	defer srv.Close()
	if _, err := NewHTTPSource(srv.URL).HeadSlot(context.Background()); err == nil {
		t.Error("a 500 answer was accepted")
	}
}

type stubSource struct {
	name string
	fail bool
	slot uint64
}

func (s stubSource) Name() string { return s.name }
func (s stubSource) err(op string) error {
	return &SourceError{Failures: []EndpointFailure{{Endpoint: s.name, Op: op, Reason: "down"}}}
}
func (s stubSource) FinalityUpdate(context.Context) ([]byte, error) {
	if s.fail {
		return nil, s.err("finality_update")
	}
	return []byte(s.name), nil
}
func (s stubSource) Updates(context.Context, uint64, int) ([][]byte, error) {
	if s.fail {
		return nil, s.err("updates")
	}
	return [][]byte{[]byte(s.name)}, nil
}
func (s stubSource) Bootstrap(context.Context, [32]byte) ([]byte, error) {
	if s.fail {
		return nil, s.err("bootstrap")
	}
	return []byte(s.name), nil
}
func (s stubSource) HeadSlot(context.Context) (uint64, error) {
	if s.fail {
		return 0, s.err("head")
	}
	return s.slot, nil
}

// The order is availability only: the first source that answers wins, and nothing is compared or merged; every failure is kept.
func TestMultiTriesSourcesInOrderForAvailabilityOnly(t *testing.T) {
	ctx := context.Background()
	m := Multi{stubSource{name: "a", fail: true}, stubSource{name: "b", slot: 5}, stubSource{name: "c", slot: 9}}
	if m.Name() != "a,b,c" {
		t.Errorf("name %q", m.Name())
	}
	if b, err := m.FinalityUpdate(ctx); err != nil || string(b) != "b" {
		t.Fatalf("%q %v", b, err)
	}
	if u, err := m.Updates(ctx, 1, 1); err != nil || string(u[0]) != "b" {
		t.Fatalf("%q %v", u, err)
	}
	if b, err := m.Bootstrap(ctx, [32]byte{}); err != nil || string(b) != "b" {
		t.Fatalf("%q %v", b, err)
	}
	if h, err := m.HeadSlot(ctx); err != nil || h != 5 {
		t.Fatalf("%d %v", h, err)
	}
	all := Multi{stubSource{name: "a", fail: true}, stubSource{name: "b", fail: true}}
	for name, call := range map[string]func() error{
		"finality_update": func() error { _, e := all.FinalityUpdate(ctx); return e },
		"updates":         func() error { _, e := all.Updates(ctx, 1, 1); return e },
		"bootstrap":       func() error { _, e := all.Bootstrap(ctx, [32]byte{}); return e },
		"head":            func() error { _, e := all.HeadSlot(ctx); return e },
	} {
		se, ok := call().(*SourceError)
		if !ok || len(se.Failures) != 2 || se.Failures[0].Endpoint != "a" || se.Failures[1].Endpoint != "b" || se.Failures[0].Op != name {
			t.Errorf("%s: %v", name, se)
		}
	}
	se, ok := Multi(nil).HeadSlot(ctx)
	_ = se
	if _, err := (Multi{}).FinalityUpdate(ctx); err == nil || !strings.Contains(err.Error(), "no light-client endpoint is configured") || ok != nil && false {
		t.Errorf("an empty list: %v", err)
	}
	// an error that is not a SourceError is kept as text under its endpoint
	odd := Multi{oddSource{}}
	if _, err := odd.FinalityUpdate(ctx); err == nil || !strings.Contains(err.Error(), "odd  http=0: plain") {
		t.Errorf("%v", err)
	}
	if got := (&SourceError{Failures: []EndpointFailure{{Endpoint: "e", Op: "o", HTTP: 7, Reason: "r"}}}).Error(); got != "light-client source unavailable: e o http=7: r" {
		t.Errorf("%q", got)
	}
}

type oddSource struct{ stubSource }

func (oddSource) Name() string { return "odd" }
func (oddSource) FinalityUpdate(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("plain")
}

// ---- execution headers ----

// jsonOf renders the JSON-RPC block object of a raw header RLP, the inverse of HeaderRLPFromJSON.
func jsonOf(t testing.TB, raw []byte) map[string]any {
	t.Helper()
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) > len(headerFields) {
		t.Fatalf("%d items", len(items))
	}
	m := map[string]any{"hash": "0x" + hex.EncodeToString(crypto.Keccak256(raw))}
	for i, it := range items {
		f := headerFields[i]
		var b []byte
		if err := rlp.DecodeBytes(it, &b); err != nil {
			t.Fatal(err)
		}
		if f.kind == 'q' {
			m[f.name] = "0x" + new(big.Int).SetBytes(b).Text(16)
		} else {
			m[f.name] = "0x" + hex.EncodeToString(b)
		}
	}
	return m
}

func TestHeaderRLPFromJSONRebuildsTheConsensusBytesAndRefusesAnythingElse(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	for _, idx := range []int{0, 1, len(l.body.Spine) - 1} {
		raw := l.body.Spine[idx]
		js, _ := json.Marshal(jsonOf(t, raw))
		got, hash, err := HeaderRLPFromJSON(js)
		if err != nil || string(got) != string(raw) || hash != crypto.Keccak256Hash(raw) {
			t.Fatalf("header %d: %v", idx, err)
		}
	}
	raw := l.body.Spine[0]
	good := jsonOf(t, raw)
	mutate := func(f func(m map[string]any)) json.RawMessage {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	for name, js := range map[string]json.RawMessage{
		"not an object":                  json.RawMessage(`[1]`),
		"null":                           json.RawMessage(`null`),
		"a required field is missing":    mutate(func(m map[string]any) { delete(m, "stateRoot") }),
		"a field is not a string":        mutate(func(m map[string]any) { m["number"] = 5 }),
		"a quantity is not hex":          mutate(func(m map[string]any) { m["gasUsed"] = "0xzz" }),
		"a bytes field is not hex":       mutate(func(m map[string]any) { m["parentHash"] = "0xzz" }),
		"the hash is not the node hash":  mutate(func(m map[string]any) { m["hash"] = "0x" + strings.Repeat("00", 32) }),
		"the hash is absent":             mutate(func(m map[string]any) { delete(m, "hash") }),
		"a field changed":                mutate(func(m map[string]any) { m["gasLimit"] = "0x1" }),
		"a trailing optional field gone": mutate(func(m map[string]any) { delete(m, "slotNumber") }),
		"an unknown field is ignored but the hash then fails": mutate(func(m map[string]any) { m["gasUsed"] = "0x5" }),
	} {
		if _, _, err := HeaderRLPFromJSON(js); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// an extra unknown field the consensus encoding does not contain does not change the bytes: the hash still holds
	extra := mutate(func(m map[string]any) { m["totalDifficulty"] = "0x0" })
	if b, _, err := HeaderRLPFromJSON(extra); err != nil || string(b) != string(raw) {
		t.Errorf("an unknown field the node serves beside the header: %v", err)
	}
}

type rpcCall struct {
	method string
	params []any
}

// rpcServer answers a JSON-RPC batch from the headers it holds; failEvery makes the first n requests fail with the given status.
func rpcServer(t testing.TB, byHash map[string][]byte, byNum map[uint64][]byte, status int, failFirst int32, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(calls, 1)
		if n <= failFirst {
			http.Error(w, "busy", status)
			return
		}
		var reqs []struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		var out []any
		for _, q := range reqs {
			var raw []byte
			switch q.Method {
			case "eth_getBlockByHash":
				raw = byHash[q.Params[0].(string)]
			case "eth_getBlockByNumber":
				var n uint64
				fmt.Sscanf(q.Params[0].(string), "0x%x", &n)
				raw = byNum[n]
			}
			if raw == nil {
				out = append(out, map[string]any{"id": q.ID, "result": nil})
				continue
			}
			out = append(out, map[string]any{"id": q.ID, "result": jsonOf(t, raw)})
		}
		json.NewEncoder(w).Encode(out)
	}))
}

func TestRPCHeadersServesRawHeadersInBatchesAndRetriesOnlyRateLimits(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	byHash, byNum := map[string][]byte{}, map[uint64][]byte{}
	for _, raw := range l.body.Spine[:7] {
		f := rlpFields(t, raw)
		byHash["0x"+hex.EncodeToString(f.hash[:])] = raw
		byNum[f.number] = raw
	}
	top := rlpFields(t, l.body.Spine[0])
	ctx := context.Background()

	var calls int32
	srv := rpcServer(t, byHash, byNum, 429, 2, &calls)
	defer srv.Close()
	r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 3}
	got, err := r.HeaderByHash(ctx, top.hash)
	if err != nil || string(got) != string(l.body.Spine[0]) || calls != 3 {
		t.Fatalf("two 429s then success: %v calls %d", err, calls)
	}
	atomic.StoreInt32(&calls, 0)
	calm := rpcServer(t, byHash, byNum, 429, 0, &calls)
	defer calm.Close()
	r = &RPCHeaders{Endpoints: []string{calm.URL}, BatchSize: 3}
	hs, err := r.HeadersByNumber(ctx, top.number-6, top.number)
	if err != nil || len(hs) != 7 || calls != 3 { // 7 headers in batches of 3: 3+3+1
		t.Fatalf("%v %d headers in %d requests", err, len(hs), calls)
	}
	for i, h := range hs { // ascending
		if string(h) != string(l.body.Spine[6-i]) {
			t.Fatalf("header %d is out of order", i)
		}
	}
	// a block the node does not have, then the endpoint list is exhausted: a source error naming the endpoint
	if _, err := r.HeadersByNumber(ctx, top.number-7, top.number-7); err == nil {
		t.Fatal("a missing block was served")
	} else if se, ok := err.(*SourceError); !ok || len(se.Failures) != 1 || se.Failures[0].Op != "headers" || !strings.Contains(se.Failures[0].Reason, "no such block") {
		t.Fatalf("%v", err)
	}
	// the node answers another block for the hash asked: refused
	other := rlpFields(t, l.body.Spine[1])
	if _, err := r.HeaderByHash(ctx, [32]byte{9}); err == nil {
		t.Fatal("an unknown hash was served")
	}
	byHash["0x"+hex.EncodeToString(top.hash[:])] = l.body.Spine[1]
	if _, err := r.HeaderByHash(ctx, top.hash); err == nil || !strings.Contains(err.Error(), "different block") {
		t.Fatalf("%v (other %x)", err, other.hash[:2])
	}
	// a first endpoint that fails with a non-429 status is skipped (no retry), the second answers
	var c1, c2 int32
	bad := rpcServer(t, nil, nil, 500, 1000, &c1)
	defer bad.Close()
	byHash["0x"+hex.EncodeToString(top.hash[:])] = l.body.Spine[0]
	good := rpcServer(t, byHash, byNum, 500, 0, &c2)
	defer good.Close()
	two := &RPCHeaders{Endpoints: []string{bad.URL, good.URL}}
	if b, err := two.HeaderByHash(ctx, top.hash); err != nil || string(b) != string(l.body.Spine[0]) || c1 != 1 {
		t.Fatalf("%v first endpoint called %d times", err, c1)
	}
	// no endpoint configured
	if _, err := (&RPCHeaders{}).HeaderByHash(ctx, top.hash); err == nil || !strings.Contains(err.Error(), "no execution endpoint is configured") {
		t.Fatalf("%v", err)
	}
}

type fields struct {
	hash   [32]byte
	number uint64
}

func rlpFields(t testing.TB, raw []byte) fields {
	t.Helper()
	m := jsonOf(t, raw)
	var f fields
	copy(f.hash[:], crypto.Keccak256(raw))
	fmt.Sscanf(m["number"].(string), "0x%x", &f.number)
	return f
}
