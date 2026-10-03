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
// provider that answered agrees and at least MinAgreeingProviders answered. Only providers whose chain id has been
// verified are ever asked (verify.go).
type AgreeingReader struct {
	chainID int64
	timeout time.Duration

	mu        sync.Mutex
	providers []agreeingProvider    // verified: the only providers asked for facts
	pending   []*unverifiedProvider // configured, chain id not yet verified: never asked for a fact
}

type agreeingProvider struct {
	host   string
	client *ethclient.Client
	hint   *retryAfterHint // its last Retry-After
	health *providerHealth // whether it is resting (see health.go)
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

// NewAgreeingReader dials every endpoint, keeps one per host, and verifies, all hosts at once, that each serves chainID.
// timeout bounds each attempt and is each later read's own deadline.
//
//   - A provider that answers ANOTHER chain id refuses the construction outright: that is a misconfiguration, not an
//     outage.
//   - A provider that answers transiently (IsTransient) is asked again, the same provider for the same chain id, within
//     TransientRetryBudget (sooner if ctx ends).
//   - The construction succeeds once at least MinAgreeingProviders distinct hosts are verified: it then waits at most
//     UnverifiedProviderGrace for the rest. Every provider still unverified is logged by name with its error, is asked
//     for nothing, and is re-verified in the background (verify.go); it joins only once its chain id is verified.
//   - Fewer than MinAgreeingProviders verified hosts within the budget refuses the construction, naming every
//     unverified provider and its error.
func NewAgreeingReader(ctx context.Context, chainID int64, urls []string, timeout time.Duration) (*AgreeingReader, error) {
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	r := &AgreeingReader{chainID: chainID, timeout: timeout}
	if err := r.verifyAll(ctx, urls); err != nil {
		return nil, err
	}
	return r, nil
}

// FinalityReaderForChain is the agreeing reader over every endpoint configured for chainID (its primary plus
// <PREFIX>_URL_FALLBACKS and the paid fallbacks; see EndpointsForChainID). It refuses fewer than MinAgreeingProviders
// independent hosts: there is no single-provider mode.
func FinalityReaderForChain(ctx context.Context, chainID int64, primary string) (*AgreeingReader, error) {
	return NewAgreeingReader(ctx, chainID, EndpointsForChainID(chainID, primary), DefaultReadTimeout)
}

// Hosts names the providers, for logs.
func (r *AgreeingReader) Hosts() []string {
	providers := r.verified()
	hosts := make([]string, len(providers))
	for i, p := range providers {
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
	providers := r.verified()
	out := make([]answer[T], len(providers))
	var wg sync.WaitGroup
	for i, p := range providers {
		wg.Add(1)
		go func(i int, p agreeingProvider) {
			defer wg.Done()
			// A provider that cannot answer now (throttled, a gateway error, a dropped connection) has not answered yet:
			// it is asked again, the same query, within the read's own deadline, rather than counted out - a throttled
			// provider would otherwise leave every fact unestablished in a burst of reads. One that never answers stays
			// unanswered: it is not replaced by another provider, and it is not counted. One that stayed unable to answer
			// for a whole read rests (health.go), so that the reads after it do not each wait out its deadline.
			v, err := askProvider(ctx, p.health, p.host, p.hint, r.timeout, r.timeout, func(c context.Context) (T, error) {
				return read(c, p.client)
			})
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

// AgreedLists returns a list of byte strings - a block's transactions or receipts in their consensus encoding - when
// every provider that answered returns the identical list and at least MinAgreeingProviders answered. read is asked of
// each verified provider's raw client and reduces that provider's answer to the list; what names the list in errors.
//
// It exists for what the decoded reads cannot carry: go-ethereum decodes neither an OP-stack deposit transaction (0x7e)
// nor an Arbitrum internal one (0x6a), and re-encodes a deposit receipt without its deposit fields, so a block's bodies
// are compared here as the caller encodes them (pkg/ethproof).
func (r *AgreeingReader) AgreedLists(ctx context.Context, what string, read func(context.Context, *rpc.Client) ([][]byte, error)) ([][]byte, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) ([][]byte, error) {
		return read(c, cl.Client())
	})
	var picked [][]byte
	answered := 0
	for _, a := range as {
		if a.err != nil {
			continue
		}
		answered++
		if answered == 1 {
			picked = a.value
			continue
		}
		same := len(a.value) == len(picked)
		for i := 0; same && i < len(picked); i++ {
			same = bytes.Equal(a.value[i], picked[i])
		}
		if !same {
			return nil, fmt.Errorf("%w: chain %d %s: %s serves a different list", ErrProvidersDisagree, r.chainID, what, a.host)
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d %s: %d of %d (%s)", ErrTooFewProviders, r.chainID, what, answered, len(as), unanswered(as))
	}
	return picked, nil
}

// RecentStateDepth is how far below the lowest latest head of the answering providers RecentAgreedHeader reads: deep
// enough that every provider has the block, shallow enough that every provider still serves its state (a provider that
// keeps no historical state - Arbitrum Sepolia's publicnode at the finalized block, measured 2026-10-03 - serves the
// head's recent past only).
const RecentStateDepth = 3

// RecentAgreedHeader is a recent block every answering provider holds identically: the header at RecentStateDepth below
// the lowest latest head any of them reports. It is the block agreed eth_calls read state at (CallContractAtHash). It is
// NOT a finalized block; a caller that needs finality establishes it separately.
func (r *AgreeingReader) RecentAgreedHeader(ctx context.Context) (*types.Header, error) {
	latest, err := r.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if err != nil {
		return nil, err
	}
	n := latest.Number.Uint64()
	if n > RecentStateDepth {
		n -= RecentStateDepth
	}
	return r.HeaderByNumber(ctx, new(big.Int).SetUint64(n))
}

// CallContractAtHash returns the result of a call at the block with this hash when every provider that answered returns
// the same bytes and at least MinAgreeingProviders answered. A provider that does not hold the block, or its state, does
// not answer; one that answers differently is a disagreement.
func (r *AgreeingReader) CallContractAtHash(ctx context.Context, msg ethereum.CallMsg, blockHash common.Hash) ([]byte, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) ([]byte, error) {
		return cl.CallContractAtHash(c, msg, blockHash)
	})
	return agreedBytes(r, as, fmt.Sprintf("call to %s at block %s", addrOf(msg.To), blockHash.Hex()))
}

// CodeAtHash returns an account's code at the block with this hash when every provider that answered returns the same.
func (r *AgreeingReader) CodeAtHash(ctx context.Context, account common.Address, blockHash common.Hash) ([]byte, error) {
	as := askAll(ctx, r, func(c context.Context, cl *ethclient.Client) ([]byte, error) {
		return cl.CodeAtHash(c, account, blockHash)
	})
	return agreedBytes(r, as, fmt.Sprintf("code of %s at block %s", account.Hex(), blockHash.Hex()))
}

func addrOf(a *common.Address) string {
	if a == nil {
		return "<creation>"
	}
	return a.Hex()
}

func agreedBytes(r *AgreeingReader, as []answer[[]byte], what string) ([]byte, error) {
	var picked []byte
	answered := 0
	for _, a := range as {
		if a.err != nil {
			continue
		}
		answered++
		if answered == 1 {
			picked = a.value
			continue
		}
		if !bytes.Equal(a.value, picked) {
			return nil, fmt.Errorf("%w: chain %d %s: one provider returns 0x%x, %s returns 0x%x", ErrProvidersDisagree,
				r.chainID, what, picked, a.host, a.value)
		}
	}
	if answered < MinAgreeingProviders {
		return nil, fmt.Errorf("%w: chain %d %s: %d of %d (%s)", ErrTooFewProviders, r.chainID, what, answered, len(as), unanswered(as))
	}
	return picked, nil
}

// LocatorClient is one provider's client, for LOCATING an event only. Nothing a locator returns is a fact: a log it finds
// is established through an agreed read (its transaction's agreed receipt) before anything rests on it, and a provider
// that hides a log only delays that, because every provider is asked.
//
// Its HeaderByNumber, FilterLogs and TransactionByHash ask the provider again while it answers transiently, within the
// reader's per-read timeout, exactly as an agreed read does; Client is the bare client.
type LocatorClient struct {
	Host    string
	Client  *ethclient.Client
	hint    *retryAfterHint
	health  *providerHealth
	timeout time.Duration
}

// Locators are the providers' clients, for locating events (see LocatorClient).
func (r *AgreeingReader) Locators() []LocatorClient {
	providers := r.verified()
	out := make([]LocatorClient, len(providers))
	for i, p := range providers {
		out[i] = LocatorClient{Host: p.host, Client: p.client, hint: p.hint, health: p.health, timeout: r.timeout}
	}
	return out
}

func (l LocatorClient) budget() time.Duration {
	if l.timeout <= 0 {
		return DefaultReadTimeout
	}
	return l.timeout
}

// HeaderByNumber is the provider's header at number, asked again while the provider answers transiently.
func (l LocatorClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return askProvider(ctx, l.health, l.Host, l.hint, l.budget(), 0, func(c context.Context) (*types.Header, error) {
		return l.Client.HeaderByNumber(c, number)
	})
}

// FilterLogs is the provider's answer to q, asked again while the provider answers transiently.
func (l LocatorClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return askProvider(ctx, l.health, l.Host, l.hint, l.budget(), 0, func(c context.Context) ([]types.Log, error) {
		return l.Client.FilterLogs(c, q)
	})
}

// TransactionByHash is the provider's transaction with this hash, asked again while the provider answers transiently.
func (l LocatorClient) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	type found struct {
		tx      *types.Transaction
		pending bool
	}
	f, err := askProvider(ctx, l.health, l.Host, l.hint, l.budget(), 0, func(c context.Context) (found, error) {
		tx, pending, err := l.Client.TransactionByHash(c, hash)
		return found{tx, pending}, err
	})
	return f.tx, f.pending, err
}

