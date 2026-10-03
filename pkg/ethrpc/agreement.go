package ethrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// MinAgreeingProviders is how many independent providers must answer, and agree, before a settlement's finality facts are
// taken as the chain's (RB5-F53).
//
// Every validator used to read one load-balanced endpoint per chain, and all seven read the SAME one. On 2026-10-02 a
// backend of that endpoint served a header from a short-lived fork for Sepolia block 11832868, so the quorum's
// "independent re-observation" was seven readings of one view. A fact now holds only when at least two providers, run by
// different operators, return it identically, and no provider that answers contradicts it.
const MinAgreeingProviders = 2

// ErrProvidersDisagree: the providers that answered returned different facts. While a block is young this is expected,
// because a backend may still be on a fork. The caller waits, and a disagreement that outlasts its deadline is named.
var ErrProvidersDisagree = errors.New("providers disagree")

// ErrTooFewProviders: fewer than MinAgreeingProviders answered, so no fact is established. The caller waits.
var ErrTooFewProviders = errors.New("too few providers answered")

// AgreeingReader is a FinalityReader over several independent providers of one chain. A fact is returned only when every
// provider that answered agrees and at least MinAgreeingProviders answered.
type AgreeingReader struct {
	chainID   int64
	providers []agreeingProvider
	timeout   time.Duration
}

type agreeingProvider struct {
	host   string
	client *ethclient.Client
}

// ProviderHosts reduces endpoint URLs to their hosts, without any path or query, so that two URLs of one operator are
// counted once and nothing secret is logged.
func ProviderHosts(urls []string) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, u := range urls {
		h := providerHost(u)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	return hosts
}

func providerHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// NewAgreeingReader dials every endpoint, keeps one per host, and checks that each serves chainID. It refuses fewer than
// MinAgreeingProviders distinct hosts, and any endpoint that serves another chain.
func NewAgreeingReader(ctx context.Context, chainID int64, urls []string, timeout time.Duration) (*AgreeingReader, error) {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	r := &AgreeingReader{chainID: chainID, timeout: timeout}
	seen := map[string]bool{}
	for _, u := range urls {
		h := providerHost(u)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		c, err := ethclient.DialContext(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("chain %d provider %s: dial: %w", chainID, h, err)
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		id, err := c.ChainID(cctx)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("chain %d provider %s: read its chain id: %w", chainID, h, err)
		}
		if id.Int64() != chainID {
			return nil, fmt.Errorf("chain %d provider %s serves chain %s", chainID, h, id)
		}
		r.providers = append(r.providers, agreeingProvider{host: h, client: c})
	}
	if len(r.providers) < MinAgreeingProviders {
		return nil, fmt.Errorf("chain %d has %d independent provider(s) %v; at least %d are required, so that no single "+
			"provider's view is taken as the chain's (RB5-F53)", chainID, len(r.providers), ProviderHosts(urls), MinAgreeingProviders)
	}
	return r, nil
}

// FinalityReaderForChain is the agreeing reader over every endpoint configured for chainID (its primary plus
// <PREFIX>_URL_FALLBACKS and the paid fallbacks; see EndpointsForChainID). It refuses fewer than MinAgreeingProviders
// independent hosts: there is no single-provider mode.
func FinalityReaderForChain(ctx context.Context, chainID int64, primary string) (*AgreeingReader, error) {
	return NewAgreeingReader(ctx, chainID, EndpointsForChainID(chainID, primary), 20*time.Second)
}

// Hosts names the providers, for logs.
func (r *AgreeingReader) Hosts() []string {
	hosts := make([]string, len(r.providers))
	for i, p := range r.providers {
		hosts[i] = p.host
	}
	return hosts
}

type answer[T any] struct {
	host  string
	value T
	err   error
}

func askAll[T any](ctx context.Context, r *AgreeingReader, read func(context.Context, *ethclient.Client) (T, error)) []answer[T] {
	out := make([]answer[T], len(r.providers))
	var wg sync.WaitGroup
	for i, p := range r.providers {
		wg.Add(1)
		go func(i int, p agreeingProvider) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			v, err := read(cctx, p.client)
			out[i] = answer[T]{host: p.host, value: v, err: err}
		}(i, p)
	}
	wg.Wait()
	return out
}

func unanswered[T any](as []answer[T]) string {
	var parts []string
	for _, a := range as {
		if a.err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", a.host, a.err))
		}
	}
	return strings.Join(parts, "; ")
}

// receiptFacts is everything a receipt asserts: its consensus encoding and where it says it is.
func receiptFacts(r *types.Receipt) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil receipt")
	}
	enc, err := r.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var n []byte
	if r.BlockNumber != nil {
		n = r.BlockNumber.Bytes()
	}
	return bytes.Join([][]byte{enc, r.TxHash.Bytes(), r.BlockHash.Bytes(), n, big.NewInt(int64(r.TransactionIndex)).Bytes()}, []byte{0}), nil
}

// TransactionReceipt returns the receipt when every provider that answered returns the same one. A provider that has
// not seen the transaction yet makes it not found here too: one that lags is waited for, never outvoted.
func (r *AgreeingReader) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) (*types.Receipt, error) {
		return cl.TransactionReceipt(c, txHash)
	})
	var found *types.Receipt
	var facts []byte
	answered, notFound := 0, 0
	for _, a := range as {
		switch {
		case errors.Is(a.err, ethereum.NotFound):
			answered++
			notFound++
		case a.err != nil:
		default:
			answered++
			f, err := receiptFacts(a.value)
			if err != nil {
				return nil, fmt.Errorf("chain %d provider %s: receipt of %s: %w", r.chainID, a.host, txHash.Hex(), err)
			}
			if found == nil {
				found, facts = a.value, f
			} else if !bytes.Equal(f, facts) {
				return nil, fmt.Errorf("%w: chain %d receipt of %s: one provider names block %s, %s names block %s",
					ErrProvidersDisagree, r.chainID, txHash.Hex(), found.BlockHash.Hex(), a.host, a.value.BlockHash.Hex())
			}
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d receipt of %s: %d of %d (%s)", ErrTooFewProviders, r.chainID, txHash.Hex(),
			answered, len(as), unanswered(as))
	}
	if notFound > 0 {
		return nil, ethereum.NotFound
	}
	return found, nil
}

// HeaderByNumber answers a height only when every provider that answered returns the same header. For the finalized tag
// it returns the LOWEST finalized header any answering provider reports: a block is final here only once it is final in
// every view.
func (r *AgreeingReader) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) (*types.Header, error) {
		return cl.HeaderByNumber(c, number)
	})
	var picked *types.Header
	answered := 0
	tag := number != nil && number.Sign() < 0
	for _, a := range as {
		if a.err != nil || a.value == nil {
			continue
		}
		answered++
		switch {
		case picked == nil:
			picked = a.value
		case tag:
			if a.value.Number.Cmp(picked.Number) < 0 {
				picked = a.value
			}
		case a.value.Hash() != picked.Hash():
			return nil, fmt.Errorf("%w: chain %d block %s: one provider serves %s, %s serves %s", ErrProvidersDisagree,
				r.chainID, number, picked.Hash().Hex(), a.host, a.value.Hash().Hex())
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d header %v: %d of %d (%s)", ErrTooFewProviders, r.chainID, number, answered, len(as), unanswered(as))
	}
	return picked, nil
}

// BlockReceipts returns a block's receipts when every provider that answered returns the same list.
func (r *AgreeingReader) BlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]*types.Receipt, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) ([]*types.Receipt, error) {
		return cl.BlockReceipts(c, blockNrOrHash)
	})
	var picked []*types.Receipt
	var facts [][]byte
	answered := 0
	for _, a := range as {
		if a.err != nil {
			continue
		}
		answered++
		fs := make([][]byte, len(a.value))
		for i, rc := range a.value {
			f, err := receiptFacts(rc)
			if err != nil {
				return nil, fmt.Errorf("chain %d provider %s: block receipts: %w", r.chainID, a.host, err)
			}
			fs[i] = f
		}
		if facts == nil {
			picked, facts = a.value, fs
			continue
		}
		same := len(fs) == len(facts)
		for i := 0; same && i < len(fs); i++ {
			same = bytes.Equal(fs[i], facts[i])
		}
		if !same {
			return nil, fmt.Errorf("%w: chain %d receipts of block %s differ at %s", ErrProvidersDisagree, r.chainID, blockNrOrHash.String(), a.host)
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d receipts of block %s: %d of %d (%s)", ErrTooFewProviders, r.chainID,
			blockNrOrHash.String(), answered, len(as), unanswered(as))
	}
	return picked, nil
}

// HeaderByHash returns the header with this hash when every provider that answered returns it.
func (r *AgreeingReader) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) (*types.Header, error) { return cl.HeaderByHash(c, hash) })
	var picked *types.Header
	answered := 0
	for _, a := range as {
		if a.err != nil || a.value == nil {
			continue
		}
		answered++
		if a.value.Hash() != hash {
			return nil, fmt.Errorf("%w: chain %d header %s: %s served a header hashing to %s", ErrProvidersDisagree,
				r.chainID, hash.Hex(), a.host, a.value.Hash().Hex())
		}
		if picked == nil {
			picked = a.value
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d header %s: %d of %d (%s)", ErrTooFewProviders, r.chainID, hash.Hex(), answered, len(as), unanswered(as))
	}
	return picked, nil
}
