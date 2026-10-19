// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// A World is every raw JSON-RPC exchange the capture had with the chain's public providers, exactly as the providers
// answered: the request (method and params as sent), the result or the error text. It is format-independent: it holds
// no CERTEN evidence encoding, so a later generator can rebuild any evidence form from it, and the replay transport
// serves it back to the same go-ethereum clients the capture used.
type World struct {
	Format     string     `json:"format"`
	ChainID    int64      `json:"chainId"`
	Chain      string     `json:"chain"`
	Providers  []Provider `json:"providers"`
	TxHash     string     `json:"txHash"`
	Note       string     `json:"note,omitempty"`
	StartedUTC string     `json:"startedUtc"`
	Exchanges  []Exchange `json:"exchanges"`
}

// WorldFormat names this raw form.
const WorldFormat = "certen:s6-live-world:v1"

// Provider is one public provider: its host (the key of its exchanges) and its public URL (no key, no secret).
type Provider struct {
	Host string `json:"host"`
	URL  string `json:"url"`
}

// Exchange is one JSON-RPC call to one provider and that provider's answer.
type Exchange struct {
	Seq        int             `json:"seq"`
	AtUTC      string          `json:"atUtc"`
	Host       string          `json:"host"`
	Method     string          `json:"method"`
	Params     json.RawMessage `json:"params"`
	Result     json.RawMessage `json:"result,omitempty"`
	RPCError   json.RawMessage `json:"rpcError,omitempty"`
	HTTPStatus int             `json:"httpStatus,omitempty"`
	Body       string          `json:"body,omitempty"`      // the response body when it was not a JSON-RPC answer
	Transport  string          `json:"transport,omitempty"` // the transport error when no response came
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func compact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("[]")
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return raw
	}
	return json.RawMessage(b.String())
}

func exchangeKey(host, method string, params json.RawMessage) string {
	return host + "|" + method + "|" + strings.ToLower(string(compact(params)))
}

// parseRequests reads a JSON-RPC body: one call or a batch.
func parseRequests(body []byte) ([]rpcReq, bool, error) {
	t := bytes.TrimSpace(body)
	if len(t) > 0 && t[0] == '[' {
		var rs []rpcReq
		err := json.Unmarshal(t, &rs)
		return rs, true, err
	}
	var r rpcReq
	err := json.Unmarshal(t, &r)
	return []rpcReq{r}, false, err
}

// Recorder records every exchange made through its transports.
type Recorder struct {
	mu    sync.Mutex
	world *World
}

// NewRecorder starts a world.
func NewRecorder(chainID int64, chain string, providers []Provider) *Recorder {
	return &Recorder{world: &World{Format: WorldFormat, ChainID: chainID, Chain: chain, Providers: providers,
		StartedUTC: time.Now().UTC().Format(time.RFC3339Nano)}}
}

func (r *Recorder) add(x Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x.Seq = len(r.world.Exchanges)
	x.AtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	r.world.Exchanges = append(r.world.Exchanges, x)
}

// World is a copy of what has been recorded.
func (r *Recorder) World() *World {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := *r.world
	w.Exchanges = append([]Exchange(nil), r.world.Exchanges...)
	return &w
}

// Transport is a live transport to host that records each exchange.
func (r *Recorder) Transport(host string) http.RoundTripper {
	return &recordTransport{rec: r, host: host, base: http.DefaultTransport}
}

type recordTransport struct {
	rec  *Recorder
	host string
	base http.RoundTripper
}

func (t *recordTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	reqs, _, perr := parseRequests(body)
	req2 := req.Clone(req.Context())
	req2.Body = io.NopCloser(bytes.NewReader(body))
	req2.ContentLength = int64(len(body))
	resp, err := t.base.RoundTrip(req2)
	if err != nil {
		if perr == nil {
			for _, q := range reqs {
				t.rec.add(Exchange{Host: t.host, Method: q.Method, Params: compact(q.Params), Transport: err.Error()})
			}
		}
		return nil, err
	}
	rb, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(rb))
	if perr != nil {
		return resp, nil
	}
	if rerr != nil {
		for _, q := range reqs {
			t.rec.add(Exchange{Host: t.host, Method: q.Method, Params: compact(q.Params), HTTPStatus: resp.StatusCode, Transport: rerr.Error()})
		}
		return resp, nil
	}
	// Match answers to calls by id.
	answers := map[string]rpcResp{}
	trim := bytes.TrimSpace(rb)
	okJSON := false
	if len(trim) > 0 && trim[0] == '[' {
		var as []rpcResp
		if json.Unmarshal(trim, &as) == nil {
			okJSON = true
			for _, a := range as {
				answers[string(compact(a.ID))] = a
			}
		}
	} else {
		var a rpcResp
		if json.Unmarshal(trim, &a) == nil && (len(a.Result) > 0 || len(a.Error) > 0) {
			okJSON = true
			answers[string(compact(a.ID))] = a
		}
	}
	for _, q := range reqs {
		x := Exchange{Host: t.host, Method: q.Method, Params: compact(q.Params)}
		if resp.StatusCode != http.StatusOK {
			x.HTTPStatus = resp.StatusCode
		}
		a, found := answers[string(compact(q.ID))]
		switch {
		case okJSON && found:
			x.Result, x.RPCError = a.Result, a.Error
			if len(x.Result) == 0 && len(x.RPCError) == 0 {
				x.Result = json.RawMessage("null")
			}
		default:
			x.HTTPStatus = resp.StatusCode
			x.Body = string(rb)
		}
		t.rec.add(x)
	}
	return resp, nil
}

// replayTransport serves a recorded world to host's client: for each call the LAST answer recorded for that exact call
// (provider, method, params), so a call repeated while the head moved is answered as the provider last answered it.
type replayTransport struct {
	host string
	last map[string]Exchange
}

// ReplayTransports are the transports of every provider of the world.
func ReplayTransports(w *World) map[string]http.RoundTripper {
	byHost := map[string]map[string]Exchange{}
	for _, p := range w.Providers {
		byHost[p.Host] = map[string]Exchange{}
	}
	for _, x := range w.Exchanges {
		m := byHost[x.Host]
		if m == nil {
			m = map[string]Exchange{}
			byHost[x.Host] = m
		}
		m[exchangeKey(x.Host, x.Method, x.Params)] = x
	}
	out := map[string]http.RoundTripper{}
	for h, m := range byHost {
		out[h] = &replayTransport{host: h, last: m}
	}
	return out
}

func (t *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	reqs, batch, err := parseRequests(body)
	if err != nil {
		return nil, fmt.Errorf("replay %s: unreadable request: %w", t.host, err)
	}
	mk := func(status int, b []byte) *http.Response {
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(b)),
			ContentLength: int64(len(b)), Request: req}
	}
	var out []rpcResp
	for _, q := range reqs {
		x, ok := t.last[exchangeKey(t.host, q.Method, q.Params)]
		if !ok {
			out = append(out, rpcResp{JSONRPC: "2.0", ID: q.ID,
				Error: json.RawMessage(`{"code":-32001,"message":"not in the recorded world: this provider was not asked this at capture time"}`)})
			continue
		}
		if !batch {
			if x.Transport != "" {
				return nil, fmt.Errorf("%s", x.Transport)
			}
			if x.Body != "" || (x.HTTPStatus != 0 && len(x.Result) == 0 && len(x.RPCError) == 0) {
				st := x.HTTPStatus
				if st == 0 {
					st = http.StatusOK
				}
				return mk(st, []byte(x.Body)), nil
			}
		}
		a := rpcResp{JSONRPC: "2.0", ID: q.ID, Result: x.Result, Error: x.RPCError}
		if len(a.Result) == 0 && len(a.Error) == 0 {
			msg, _ := json.Marshal(fmt.Sprintf("recorded failure: http %d %s %s", x.HTTPStatus, x.Transport, x.Body))
			a.Error = json.RawMessage(`{"code":-32002,"message":` + string(msg) + `}`)
		}
		out = append(out, a)
	}
	var b []byte
	if batch {
		b, err = json.Marshal(out)
	} else {
		b, err = json.Marshal(out[0])
	}
	if err != nil {
		return nil, err
	}
	return mk(http.StatusOK, b), nil
}

// WriteWorldGz writes the world as gzipped, indented JSON.
func WriteWorldGz(path string, w *World) error {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	enc := json.NewEncoder(zw)
	enc.SetIndent("", " ")
	if err := enc.Encode(w); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// ReadWorldGz reads a world written by WriteWorldGz.
func ReadWorldGz(path string) (*World, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var w World
	if err := json.NewDecoder(zr).Decode(&w); err != nil {
		return nil, err
	}
	if w.Format != WorldFormat {
		return nil, fmt.Errorf("%s: format %q is not %s", path, w.Format, WorldFormat)
	}
	return &w, nil
}
