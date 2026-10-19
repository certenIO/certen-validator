// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

const leakKey = "SECRETKEY123"

// roundTripFunc is a transport that answers as a provider does.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func keyedProviders() []Provider {
	return []Provider{
		{Host: "eth-sepolia.g.alchemy.com", URL: "https://eth-sepolia.g.alchemy.com/v2/" + leakKey},
		{Host: "mainnet.infura.io", URL: "https://user:" + leakKey + "@mainnet.infura.io/v3/" + leakKey + "?apikey=" + leakKey},
	}
}

func rpcCall(t *testing.T, c *http.Client, u, method string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":["0x01"]}`
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// RB10-B11: the world the recorder stores holds the host of each provider and its answers, and no credential: the
// providers' URLs, the transport errors that quote them, the bodies and JSON-RPC errors that echo them.
func TestTheRecordedWorldHoldsNoProviderCredential(t *testing.T) {
	provs := keyedProviders()
	rec := NewRecorder(1, "test", provs)
	answers := map[string]roundTripFunc{
		"eth_a": func(r *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("dial tcp 10.0.0.1:443: i/o timeout")}
		},
		"eth_b": func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 401, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader("invalid key for " + r.URL.String())), Header: http.Header{}}, nil
		},
		"eth_c": func(r *http.Request) (*http.Response, error) {
			msg, _ := json.Marshal("bad request " + r.URL.String())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":` + string(msg) + `}}`)), Header: http.Header{}}, nil
		},
	}
	for _, p := range provs {
		base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var q rpcReq
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &q)
			return answers[q.Method](r)
		})
		c := &http.Client{Transport: &recordTransport{rec: rec, host: p.Host, base: base}}
		for m := range answers {
			rpcCall(t, c, p.URL, m)
		}
	}
	w := rec.World()
	if len(w.Exchanges) != 3*len(provs) {
		t.Fatalf("%d exchanges recorded", len(w.Exchanges))
	}
	path := filepath.Join(t.TempDir(), "x.world.json.gz")
	if err := WriteWorldGz(path, w); err != nil {
		t.Fatal(err)
	}
	f, _ := os.ReadFile(path)
	zr, err := gzip.NewReader(bytes.NewReader(f))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	if strings.Contains(string(raw), leakKey) {
		t.Fatalf("a credential is in the stored world:\n%s", raw)
	}
	for _, h := range []string{"eth-sepolia.g.alchemy.com", "mainnet.infura.io"} {
		if !strings.Contains(string(raw), h) {
			t.Fatalf("the host %s is no longer named in the stored world", h)
		}
	}
	back, err := ReadWorldGz(path)
	if err != nil || len(back.Exchanges) != len(w.Exchanges) {
		t.Fatalf("the stored world does not read back: %v", err)
	}
}

// A world written by something that did not go through the recorder is scrubbed as it is written.
func TestAWorldIsScrubbedAsItIsWritten(t *testing.T) {
	w := &World{Format: WorldFormat, ChainID: 1, Chain: "x", Providers: keyedProviders(), TxHash: "0x01", Note: "from https://mainnet.infura.io/v3/" + leakKey,
		Exchanges: []Exchange{
			{Host: "mainnet.infura.io", Method: "m", Params: json.RawMessage(`["0x01"]`), Transport: `Post "https://mainnet.infura.io/v3/` + leakKey + `": EOF`},
			{Host: "mainnet.infura.io", Method: "n", Params: json.RawMessage(`["0x02"]`), Body: "see https://mainnet.infura.io/v3/" + leakKey},
			{Host: "mainnet.infura.io", Method: "o", Params: json.RawMessage(`["0x03"]`), RPCError: json.RawMessage(`{"code":-1,"message":"x https://mainnet.infura.io/v3/` + leakKey + `"}`)},
		}}
	path := filepath.Join(t.TempDir(), "x.world.json.gz")
	if err := WriteWorldGz(path, w); err != nil {
		t.Fatal(err)
	}
	f, _ := os.ReadFile(path)
	zr, _ := gzip.NewReader(bytes.NewReader(f))
	raw, _ := io.ReadAll(zr)
	if strings.Contains(string(raw), leakKey) {
		t.Fatalf("a credential is in the stored world:\n%s", raw)
	}
	if w.Providers[0].URL == "" || !strings.Contains(w.Providers[0].URL, leakKey) {
		t.Fatalf("writing a world changed the caller's world")
	}
}

// The source's errors name each provider by host and carry no URL of it, whatever the transport said.
func TestTheSourceErrorsHoldNoProviderCredential(t *testing.T) {
	ctx := context.Background()
	fail := func(string) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("i/o timeout")}
		})
	}
	s, err := newSource(ctx, 1, keyedProviders(), fail)
	if err != nil {
		t.Fatal(err)
	}
	_, e1 := s.TransactionReceipt(ctx, common.Hash{1})
	_, e2 := s.HeaderByNumber(ctx, nil)
	_, e3 := s.HeaderByHash(ctx, common.Hash{2})
	for _, e := range []error{e1, e2, e3} {
		if e == nil || strings.Contains(e.Error(), leakKey) || !strings.Contains(e.Error(), "alchemy.com") {
			t.Fatalf("not a credential-free error that names the host: %v", e)
		}
	}
	if _, err := newSource(ctx, 1, []Provider{{Host: "h.example.org", URL: "https://h.example.org:notaport/v2/" + leakKey}}, fail); err == nil ||
		strings.Contains(err.Error(), leakKey) {
		t.Fatalf("the dial error holds the credential: %v", err)
	}
	if h := hostOf("https://user:" + leakKey + "@h.example.org:notaport/v2/" + leakKey); strings.Contains(h, leakKey) {
		t.Fatalf("hostOf returns the URL it could not parse: %s", h)
	}
}

// A world recorded before the recorder scrubbed, judged now: the verdict and the evidence it writes hold no credential.
func TestTheVerdictOfALeakyWorldHoldsNoProviderCredential(t *testing.T) {
	w := &World{Format: WorldFormat, ChainID: 1, Chain: "x", Providers: keyedProviders(), TxHash: common.Hash{0x01}.Hex(), StartedUTC: "2026-10-19T00:00:00Z"}
	for _, p := range w.Providers {
		w.Exchanges = append(w.Exchanges, Exchange{Host: p.Host, Method: "eth_getTransactionReceipt", Params: json.RawMessage(`["` + common.Hash{0x01}.Hex() + `"]`),
			Transport: `Post "` + p.URL + `": EOF`})
	}
	v, ev, err := Judge(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	vb, _ := json.Marshal(v)
	eb, _ := json.Marshal(ev)
	if strings.Contains(string(vb), leakKey) || strings.Contains(string(eb), leakKey) {
		t.Fatalf("a credential is in the verdict or the evidence:\n%s\n%s", vb, eb)
	}
	if !strings.Contains(string(vb)+string(eb), "alchemy.com") {
		t.Fatalf("the provider is not named:\n%s\n%s", vb, eb)
	}
}
