// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// leakKey stands for an API key that a provider URL carries in its path or its query.
const leakKey = "SECRETKEY123"

// leakError is an error built the way net/http and go-ethereum build them, and the host it must still name.
type leakError struct {
	name string
	err  error
	host string
}

func leakErrors() []leakError {
	urlErr := &url.Error{Op: "Post", URL: "https://eth-sepolia.g.alchemy.com/v2/" + leakKey, Err: errors.New("dial tcp 10.0.0.1:443: i/o timeout")}
	return []leakError{
		{"a url.Error with the key in the path", urlErr, "eth-sepolia.g.alchemy.com"},
		{"an rpc.HTTPError whose body echoes the URL", rpc.HTTPError{StatusCode: 401, Status: "401 Unauthorized",
			Body: []byte(`{"error":"invalid key for https://mainnet.infura.io/v3/` + leakKey + `"}`)}, "mainnet.infura.io"},
		{"a url.Error wrapped with %w", fmt.Errorf("provider failed: %w", fmt.Errorf("attempt 3: %w", urlErr)), "eth-sepolia.g.alchemy.com"},
		{"a URL with userinfo and a query", &url.Error{Op: "Get", URL: "https://user:" + leakKey + "@rpc.example.org/some/path?apikey=" + leakKey + "#frag" + leakKey,
			Err: io.ErrUnexpectedEOF}, "rpc.example.org"},
		{"a quoted URL inside a longer message", fmt.Errorf("%q: %w", `Post "https://eth-sepolia.g.alchemy.com/v2/`+leakKey+`"`, io.EOF), "eth-sepolia.g.alchemy.com"},
		{"a bare host and path", errors.New("dial eth-sepolia.g.alchemy.com/v2/" + leakKey + ": connection refused"), "eth-sepolia.g.alchemy.com"},
		{"a bare host:port and path", errors.New("proxyconnect eth-sepolia.g.alchemy.com:443/v2/" + leakKey + " refused"), "eth-sepolia.g.alchemy.com"},
		{"a ws URL", errors.New("websocket: bad handshake wss://eth-sepolia.g.alchemy.com/v2/" + leakKey + "."), "eth-sepolia.g.alchemy.com"},
	}
}

// leakSource is a chain whose reads fail with a provider's transport error at the point a test picks.
type leakSource struct {
	*fakeChain
	receiptErr error // every receipt read
	latestErr  error // every read of the latest header
	hashErr    error // the reads of the header with hash failHash
	failHash   common.Hash
	txErr      error // every provider's transaction read
	proofErr   error // every provider's proof read
	beforeErr  error // every provider's proof read at a block before the settlement block's
}

func (l *leakSource) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	if l.receiptErr != nil {
		return nil, l.receiptErr
	}
	return l.fakeChain.TransactionReceipt(ctx, h)
}

func (l *leakSource) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	if l.latestErr != nil && n.Sign() < 0 {
		return nil, l.latestErr
	}
	return l.fakeChain.HeaderByNumber(ctx, n)
}

func (l *leakSource) HeaderByHash(ctx context.Context, h common.Hash) (*types.Header, error) {
	if l.hashErr != nil && h == l.failHash {
		return nil, l.hashErr
	}
	return l.fakeChain.HeaderByHash(ctx, h)
}

func (l *leakSource) StateProviders() []ethproof.ReplayStateProvider {
	var out []ethproof.ReplayStateProvider
	for _, p := range l.fakeChain.providers {
		out = append(out, leakProvider{p, l})
	}
	return out
}

type leakProvider struct {
	*fakeProvider
	l *leakSource
}

func (p leakProvider) TransactionByHash(ctx context.Context, h common.Hash) (*types.Transaction, bool, error) {
	if p.l.txErr != nil {
		return nil, false, p.l.txErr
	}
	return p.fakeProvider.TransactionByHash(ctx, h)
}

func (p leakProvider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	if p.l.proofErr != nil {
		return nil, p.l.proofErr
	}
	if p.l.beforeErr != nil {
		if n, ok := new(big.Int).SetString(strings.TrimPrefix(block, "0x"), 16); ok && n.Uint64() < testN {
			return nil, p.l.beforeErr
		}
	}
	return p.fakeProvider.GetProof(ctx, account, keys, block)
}

// leakPhases are the places a capture keeps a provider's error text: each builds the source whose failure lands there.
var leakPhases = []struct {
	name string
	make func(t *testing.T, err error) *leakSource
}{
	{"the receipt read", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, receiptErr: err}
	}},
	{"the settlement transaction read", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, txErr: err}
	}},
	{"the settlement block's header", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, hashErr: err, failHash: f.w.headerN.Hash()}
	}},
	{"the latest header", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, latestErr: err}
	}},
	{"the After proof", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, proofErr: err}
	}},
	{"the parent header", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("head-only.example", testN, testN)
		return &leakSource{fakeChain: f, hashErr: err, failHash: f.w.parent.Hash()}
	}},
	{"the Before proof", func(t *testing.T, err error) *leakSource {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("windowed.example", testN-1, testN)
		return &leakSource{fakeChain: f, beforeErr: err}
	}},
}

// V-R10B4 credential leak: a capture stores the text of a provider's error in its evidence (the named state's detail, the
// providers' errors, the Before-unavailable reason) and in its log, and a provider URL carries its API key in the path.
// Whatever the error is, the key appears nowhere and the provider's host is still named.
func TestCapture_NoProviderCredentialReachesTheEvidenceOrTheLog(t *testing.T) {
	for _, ph := range leakPhases {
		for _, le := range leakErrors() {
			t.Run(ph.name+"/"+le.name, func(t *testing.T) {
				src := ph.make(t, le.err)
				sink := &logSink{}
				cfg := cfgFor(src.fakeChain)
				cfg.Source, cfg.Budget, cfg.Poll, cfg.Logf = src, 60*time.Millisecond, 5*time.Millisecond, sink.logf
				ev := ethproof.CaptureReplayGuard(context.Background(), cfg, src.w.tx.Hash())
				if ev == nil {
					t.Fatal("no evidence")
				}
				raw, err := json.Marshal(ev)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), leakKey) || strings.Contains(sink.all(), leakKey) {
					t.Fatalf("the key of the provider URL is in the stored evidence or the log:\nevidence: %s\nlog: %s", raw, sink.all())
				}
				if !strings.Contains(string(raw), le.host) {
					t.Fatalf("the provider's host %s is no longer named:\nevidence: %s", le.host, raw)
				}
			})
		}
	}
}

// The same through Begin (a panic carrying the provider's error), Resolve and Bind (a settlement whose verification fails
// with it): the named states and the log lines.
func TestCapturer_NoProviderCredentialReachesANamedStateOrTheLog(t *testing.T) {
	for _, le := range leakErrors() {
		t.Run("a panic in the source/"+le.name, func(t *testing.T) {
			f := newChain(t, worldOpts{after: 0}, testN)
			f.add("head-only.example", testN, testN)
			sink := &logSink{}
			cfg := cfgFor(f)
			cfg.Source, cfg.Logf = leakPanicSource{f, le.err}, sink.logf
			store := ethproof.NewReplayGuardStore(16)
			ethproof.NewReplayGuardCapturer(cfg, store).Begin(f.w.tx.Hash())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
				t.Fatal(err)
			}
			ev, _, _ := store.Get(testChainID, f.w.tx.Hash())
			assertClean(t, le, ev, sink)
		})
		t.Run("Resolve and Bind of a settlement that does not verify/"+le.name, func(t *testing.T) {
			f := newChain(t, worldOpts{after: 0}, testN)
			f.add("head-only.example", testN, testN)
			sink := &logSink{}
			cfg := cfgFor(f)
			cfg.Logf = sink.logf
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(cfg, store)
			cp.Begin(f.w.tx.Hash())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
				t.Fatal(err)
			}
			cp.SetSettlementVerifierForTest(func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error) { return nil, nil, le.err })
			assertClean(t, le, cp.Resolve(f.w.settlement), sink)
			cp.Bind(f.w.settlement)
			ev := waitStored(t, store, testChainID, f.w.tx.Hash(), true)
			assertClean(t, le, ev, sink)
		})
		t.Run("Bind of a settlement first seen at finality/"+le.name, func(t *testing.T) {
			f := newChain(t, worldOpts{after: 0}, testN)
			sink := &logSink{}
			cfg := cfgFor(f)
			cfg.Logf = sink.logf
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(cfg, store)
			cp.SetSettlementVerifierForTest(func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error) { panic(le.err) })
			cp.Bind(f.w.settlement)
			assertClean(t, le, waitStored(t, store, testChainID, f.w.tx.Hash(), true), sink)
		})
	}
}

type leakPanicSource struct {
	*fakeChain
	err error
}

func (s leakPanicSource) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	panic(s.err)
}

func assertClean(t *testing.T, le leakError, ev *ethproof.ReplayGuardEvidence, sink *logSink) {
	t.Helper()
	if ev == nil {
		t.Fatal("no evidence")
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), leakKey) || strings.Contains(sink.all(), leakKey) {
		t.Fatalf("the key of the provider URL is in the named state or the log:\nevidence: %s\nlog: %s", raw, sink.all())
	}
	if !strings.Contains(string(raw), le.host) && !strings.Contains(sink.all(), le.host) {
		t.Fatalf("the provider's host %s is named nowhere:\nevidence: %s\nlog: %s", le.host, raw, sink.all())
	}
}
