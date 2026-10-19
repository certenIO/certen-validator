// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// minAgreeing is how many providers must answer, all alike, before a fact (receipt, header, block body) is taken: the
// production reader's floor (ethrpc.MinAgreeingProviders).
const minAgreeing = 2

// provider is one provider's clients, over a recording or a replaying transport.
type provider struct {
	host string
	rpc  *rpc.Client
	eth  *ethclient.Client
}

func (p *provider) Name() string { return p.host }

func (p *provider) TransactionByHash(ctx context.Context, h common.Hash) (*types.Transaction, bool, error) {
	return p.eth.TransactionByHash(ctx, h)
}

func (p *provider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := p.rpc.CallContext(ctx, &raw, "eth_getProof", account, keys, block)
	return raw, err
}

// source is the chain as its providers agree on it: ethproof.ReplayCaptureSource and ethproof.Source.
type source struct {
	chainID   int64
	providers []*provider
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ethproof.RedactEndpoints(raw) // a URL that does not parse may still carry a key
	}
	return strings.ToLower(u.Hostname())
}

// newSource dials each provider through the transport given for its host.
func newSource(ctx context.Context, chainID int64, provs []Provider, transports func(host string) http.RoundTripper) (*source, error) {
	s := &source{chainID: chainID}
	for _, p := range provs {
		ethrpc.RegisterProviderURL(p.URL) // the key a URL carries is a secret literal from here on (RB10-B14a)
		c, err := rpc.DialOptions(ctx, p.URL, rpc.WithHTTPClient(&http.Client{Transport: transports(p.Host), Timeout: 40 * time.Second}))
		if err != nil {
			return nil, fmt.Errorf("dial %s: %s", p.Host, ethproof.BoundProviderText(err.Error()))
		}
		s.providers = append(s.providers, &provider{host: p.Host, rpc: c, eth: ethclient.NewClient(c)})
	}
	return s, nil
}

func (s *source) StateProviders() []ethproof.ReplayStateProvider {
	out := make([]ethproof.ReplayStateProvider, len(s.providers))
	for i, p := range s.providers {
		out[i] = p
	}
	return out
}

type answer[T any] struct {
	host string
	v    T
	key  string
	err  error
}

// agree asks every provider at once and returns the value all answering providers agree on (by key), when at least
// minAgreeing answered. Otherwise it names every provider's answer.
func agree[T any](ctx context.Context, s *source, what string, read func(context.Context, *provider) (T, string, error)) (T, error) {
	as := make([]answer[T], len(s.providers))
	var wg sync.WaitGroup
	for i, p := range s.providers {
		wg.Add(1)
		go func(i int, p *provider) {
			defer wg.Done()
			v, k, err := read(ctx, p)
			as[i] = answer[T]{host: p.host, v: v, key: k, err: err}
		}(i, p)
	}
	wg.Wait()
	var zero T
	var ok []answer[T]
	var notes []string
	for _, a := range as {
		if a.err != nil {
			notes = append(notes, ethproof.BoundProviderText(fmt.Sprintf("%s: %v", a.host, a.err)))
			continue
		}
		ok = append(ok, a)
	}
	if len(ok) < minAgreeing {
		return zero, fmt.Errorf("%s: %d of %d providers answered, %d needed (%s)", what, len(ok), len(s.providers), minAgreeing, strings.Join(notes, "; "))
	}
	for _, a := range ok[1:] {
		if a.key != ok[0].key {
			return zero, fmt.Errorf("%s: %s and %s disagree", what, ok[0].host, a.host)
		}
	}
	return ok[0].v, nil
}

func receiptKey(r *types.Receipt) (string, error) {
	enc, err := r.MarshalBinary()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x|%s|%d|%d", enc, r.BlockHash.Hex(), r.BlockNumber, r.TransactionIndex), nil
}

func (s *source) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	return agree(ctx, s, "receipt "+h.Hex(), func(ctx context.Context, p *provider) (*types.Receipt, string, error) {
		r, err := p.eth.TransactionReceipt(ctx, h)
		if err != nil {
			return nil, "", err
		}
		if r == nil || r.BlockNumber == nil {
			return nil, "", fmt.Errorf("no receipt")
		}
		k, err := receiptKey(r)
		return r, k, err
	})
}

func headerKey(h *types.Header) (*types.Header, string, error) {
	if h == nil || h.Number == nil {
		return nil, "", fmt.Errorf("no header")
	}
	return h, h.Hash().Hex(), nil
}

// HeaderByNumber is the agreed header at number; for the latest block, the agreed header at the lowest head any
// answering provider reports (providers' heads differ by a block or two).
func (s *source) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if number != nil && number.Sign() < 0 {
		heads, err := s.heads(ctx)
		if err != nil {
			return nil, err
		}
		number = new(big.Int).SetUint64(heads[0])
	}
	return agree(ctx, s, fmt.Sprintf("header %v", number), func(ctx context.Context, p *provider) (*types.Header, string, error) {
		h, err := p.eth.HeaderByNumber(ctx, number)
		if err != nil {
			return nil, "", err
		}
		return headerKey(h)
	})
}

// heads are the providers' latest block numbers, lowest first.
func (s *source) heads(ctx context.Context) ([]uint64, error) {
	var mu sync.Mutex
	var out []uint64
	var notes []string
	var wg sync.WaitGroup
	for _, p := range s.providers {
		wg.Add(1)
		go func(p *provider) {
			defer wg.Done()
			h, err := p.eth.HeaderByNumber(ctx, nil)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || h == nil || h.Number == nil {
				notes = append(notes, ethproof.BoundProviderText(fmt.Sprintf("%s: %v", p.host, err)))
				return
			}
			out = append(out, h.Number.Uint64())
		}(p)
	}
	wg.Wait()
	if len(out) == 0 {
		return nil, fmt.Errorf("no provider served its latest header (%s)", strings.Join(notes, "; "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *source) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return agree(ctx, s, "header "+hash.Hex(), func(ctx context.Context, p *provider) (*types.Header, string, error) {
		h, err := p.eth.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, "", err
		}
		return headerKey(h)
	})
}

// AgreedLists is ethproof.Source's: the lists every answering provider serves alike.
func (s *source) AgreedLists(ctx context.Context, what string, read func(context.Context, *rpc.Client) ([][]byte, error)) ([][]byte, error) {
	return agree(ctx, s, what, func(ctx context.Context, p *provider) ([][]byte, string, error) {
		v, err := read(ctx, p.rpc)
		if err != nil {
			return nil, "", err
		}
		enc, err := rlp.EncodeToBytes(v)
		return v, string(enc), err
	})
}

var _ ethproof.ReplayCaptureSource = (*source)(nil)
var _ ethproof.Source = (*source)(nil)
