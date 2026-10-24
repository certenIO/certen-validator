// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/finality"
)

func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// prune answers every eth_getBlockByHash the way a pruning provider does (sepolia.base.org: error 4444).
func prune(calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":4444,"message":"pruned history unavailable: requested 46468457, earliest available 46474861"}}`))
	})
}

func wantUnserved(t *testing.T, err error, asked, notServed, unreachable, wrong, oversized int) *Unserved {
	t.Helper()
	var u *Unserved
	if !errors.As(err, &u) {
		t.Fatalf("want *Unserved, got %T %v", err, err)
	}
	if u.Asked != asked || u.NotServed != notServed || u.Unreachable != unreachable || u.WrongBlock != wrong || u.Oversized != oversized {
		t.Fatalf("counts = asked %d not_served %d unreachable %d wrong_block %d oversized %d; want %d %d %d %d %d",
			u.Asked, u.NotServed, u.Unreachable, u.WrongBlock, u.Oversized, asked, notServed, unreachable, wrong, oversized)
	}
	return u
}

// The real captured block of each chain, served over JSON-RPC as a provider serves it, rebuilds the header byte for byte (the hash
// is the one the bundle stores) and the leg verifies with it.
func TestRPCSourceServesTheRealHeaderOfEachChain(t *testing.T) {
	for _, c := range chainFixtures {
		t.Run(c.name, func(t *testing.T) {
			f := ethprooftest.Load(t, c.fixture)
			lg := legacyOf(t, c.fixture)
			src := &RPCSource{URLs: map[uint64][]string{c.chain: {serve(t, &ethprooftest.Provider{F: f})}}}
			hdr, err := src.HeaderByHash(context.Background(), c.chain, lg.leg.BlockHash)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(hdr, lg.header) {
				t.Fatal("the rebuilt header is not the header the bundle's block hash commits to")
			}
			if err := lg.leg.Verify(hdr); err != nil {
				t.Fatalf("the served header does not verify the leg: %v", err)
			}
		})
	}
}

// A pruning primary is an availability miss: the next configured provider is asked, and a provider that serves ends the search.
func TestRPCSourceTriesTheNextProviderWhenThePrimaryPrunes(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	f := ethprooftest.Load(t, "base_sepolia_47368146")
	var first, third atomic.Int32
	good := &ethprooftest.Provider{F: f}
	src := &RPCSource{URLs: map[uint64][]string{84532: {serve(t, prune(&first)), serve(t, good), serve(t, prune(&third))}}}
	hdr, err := src.HeaderByHash(context.Background(), 84532, lg.leg.BlockHash)
	if err != nil || !bytes.Equal(hdr, lg.header) {
		t.Fatalf("err %v", err)
	}
	if first.Load() != 1 || good.Calls("eth_getBlockByHash") != 1 || third.Load() != 0 {
		t.Fatalf("calls: primary %d, serving %d, after %d; the search must end at the first provider that serves", first.Load(), good.Calls("eth_getBlockByHash"), third.Load())
	}
}

func TestRPCSourceNamesWhyNoProviderServed(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	f := ethprooftest.Load(t, "base_sepolia_47368146")
	other := ethprooftest.Load(t, "arbitrum_sepolia_315455204")
	hash := lg.leg.BlockHash
	null := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	})
	html := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>Bad gateway</html>", http.StatusBadGateway)
	})
	// another block, with its own correct hash: a provider that answers a different block than asked
	wrongBlock := &ethprooftest.Provider{F: f, Mutate: func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method == "eth_getBlockByHash" {
			return other.Block
		}
		return res
	}}
	// the right block with a field changed but the claimed hash kept: the rebuilt header does not hash to it
	tampered := &ethprooftest.Provider{F: f, Mutate: func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getBlockByHash" {
			return res
		}
		var m map[string]any
		_ = json.Unmarshal(res, &m)
		m["gasUsed"] = "0x1"
		out, _ := json.Marshal(m)
		return out
	}}
	cases := []struct {
		name string
		urls []string
		want [5]int // asked, not served, unreachable, wrong block, oversized
	}{
		{"every provider prunes", []string{serve(t, prune(nil)), serve(t, prune(nil))}, [5]int{2, 2, 0, 0, 0}},
		{"a null result is not served", []string{serve(t, null)}, [5]int{1, 1, 0, 0, 0}},
		{"an HTTP error page is unreachable", []string{serve(t, html)}, [5]int{1, 0, 1, 0, 0}},
		{"a connection that cannot be made is unreachable", []string{"http://127.0.0.1:1"}, [5]int{1, 0, 1, 0, 0}},
		{"another block is a wrong block", []string{serve(t, wrongBlock)}, [5]int{1, 0, 0, 1, 0}},
		{"a tampered block is a wrong block", []string{serve(t, tampered)}, [5]int{1, 0, 0, 1, 0}},
		{"one of each", []string{serve(t, prune(nil)), serve(t, html), serve(t, wrongBlock)}, [5]int{3, 1, 1, 1, 0}},
		{"no provider configured", nil, [5]int{0, 0, 0, 0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := &RPCSource{URLs: map[uint64][]string{84532: c.urls}}
			_, err := src.HeaderByHash(context.Background(), 84532, hash)
			u := wantUnserved(t, err, c.want[0], c.want[1], c.want[2], c.want[3], c.want[4])
			st := u.State(lg.leg)
			if st.Code != finality.CodeIncludedUnavailable || st.Fields["reason"] != finality.IncludedLegacyHeaderUnserved ||
				st.Fields["chain"] != uint64(84532) || st.Fields["block"] != lg.leg.BlockNumber || st.Fields["proof_id"] != testProof {
				t.Fatalf("state = %v", st)
			}
		})
	}
	// a chain the source has no providers for is judged the same way, not as another chain's
	src := &RPCSource{URLs: map[uint64][]string{11155111: {serve(t, &ethprooftest.Provider{F: f})}}}
	_, err := src.HeaderByHash(context.Background(), 84532, hash)
	wantUnserved(t, err, 0, 0, 0, 0, 0)
}

// The response bound is exact: a body of N bytes passes at limit N and is oversized at limit N-1.
func TestRPCSourceResponseBoundIsExact(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	f := ethprooftest.Load(t, "base_sepolia_47368146")
	rec := httptest.NewRecorder()
	(&ethprooftest.Provider{F: f}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByHash","params":["`+lg.leg.BlockHash.Hex()+`",false]}`))))
	body := rec.Body.Bytes()
	url := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	n := int64(len(body))
	pass := &RPCSource{URLs: map[uint64][]string{84532: {url}}, MaxResponse: n}
	if hdr, err := pass.HeaderByHash(context.Background(), 84532, lg.leg.BlockHash); err != nil || !bytes.Equal(hdr, lg.header) {
		t.Fatalf("a response of exactly the bound (%d) was refused: %v", n, err)
	}
	fail := &RPCSource{URLs: map[uint64][]string{84532: {url}}, MaxResponse: n - 1}
	_, err := fail.HeaderByHash(context.Background(), 84532, lg.leg.BlockHash)
	wantUnserved(t, err, 1, 0, 0, 0, 1)
	// an unbounded stream is cut at the bound, not read to its end
	endless := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 1024; i++ { // 64 MiB offered
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	huge := &RPCSource{URLs: map[uint64][]string{84532: {endless}}, MaxResponse: 1 << 20}
	_, err = huge.HeaderByHash(context.Background(), 84532, lg.leg.BlockHash)
	wantUnserved(t, err, 1, 0, 0, 0, 1)
}

func TestRPCSourceStopsOnACancelledContextWithoutNamingAnUnservedBlock(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	var calls atomic.Int32
	src := &RPCSource{URLs: map[uint64][]string{84532: {serve(t, prune(&calls)), serve(t, prune(&calls))}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := src.HeaderByHash(ctx, 84532, lg.leg.BlockHash)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	var u *Unserved
	if errors.As(err, &u) || calls.Load() != 0 {
		t.Fatalf("a cancelled context judged the block (%v) or asked a provider (%d)", u, calls.Load())
	}
}

// A provider cannot make the source return a header for a block it was not asked for: even a response that is internally consistent
// (a real header whose JSON hash is its own) is refused when that is not the requested hash.
func TestRPCSourceNeverReturnsAHeaderForAnotherHash(t *testing.T) {
	f := ethprooftest.Load(t, "base_sepolia_47368146")
	asked := common.HexToHash("0x" + "ab")
	// serves the fixture's block for every hash it is asked (the stock provider answers null for other hashes)
	liar := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + string(f.Block) + `}`))
	})
	src := &RPCSource{URLs: map[uint64][]string{84532: {serve(t, liar)}}}
	hdr, err := src.HeaderByHash(context.Background(), 84532, asked)
	if hdr != nil {
		t.Fatalf("a header was returned for a hash that was not the block's: %x", hdr[:8])
	}
	wantUnserved(t, err, 1, 0, 0, 1, 0)
}
