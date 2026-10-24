// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Provider is one RPC provider asked for state. Its answers are never trusted: every proof is verified against the AGREED header's state
// root and every code against the proven code hash before anything is kept.
type Provider interface {
	Name() string
	// GetProof is the provider's eth_getProof answer (all keys of one account in one call) as JSON.
	GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error)
	// GetCode is eth_getCode at the block.
	GetCode(ctx context.Context, account common.Address, block string) ([]byte, error)
}

// Source is what a capture reads: the chain through its agreeing providers (transaction, receipt, headers) and the individual providers it
// asks for state. ethproof.ReplayCaptureSource has the same shape; the production adapter adds GetCode and the agreed transaction read.
type Source interface {
	TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error)
	TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	Providers() []Provider
}

// Defaults of a capture (the S6 numbers: ethproof.ReplayCaptureBudget, a 2 s poll).
const (
	DefaultBudget  = ethproof.ReplayCaptureBudget
	DefaultBackoff = 2 * time.Second
	DefaultPasses  = 3
	// MaxResponseBytes bounds one provider answer before it is parsed (a provider can answer with megabytes).
	MaxResponseBytes = 8 << 20
)

// Config configures the captures of one chain.
type Config struct {
	Chain    uint64
	Manifest *ci.Manifest
	Source   Source
	Clock    ethproof.ReplayClock // default ethproof.WallClock; a replay clock in tests
	Budget   time.Duration        // default DefaultBudget: bounds the whole capture (every request carries its deadline)
	Backoff  time.Duration        // between passes over the providers, on Clock; default DefaultBackoff
	Passes   int                  // passes over the providers per read; default DefaultPasses
	Parallel int                  // provider calls of one pass that run at once (default 1: one after the other)
	Gate     *Gate                // per-chain concurrency (optional)
	// MaxPoolBytes bounds the verified proof nodes a capture holds (default 2 x the container cap); on top of it comes one provider answer of
	// at most MaxResponseBytes while it is parsed. Past the pool bound the capture ends with ErrTooLarge and stores nothing.
	MaxPoolBytes int
	Logf         func(string, ...interface{})
}

func (c *Config) check() error {
	switch {
	case c.Source == nil:
		return errors.New("capture: Config.Source is nil")
	case c.Manifest == nil:
		return errors.New("capture: Config.Manifest is nil")
	case c.Chain == 0:
		return errors.New("capture: Config.Chain is zero")
	}
	return nil
}

func (c *Config) clock() ethproof.ReplayClock {
	if c.Clock == nil {
		return ethproof.WallClock
	}
	return c.Clock
}

func (c *Config) budget() time.Duration {
	if c.Budget <= 0 {
		return DefaultBudget
	}
	return c.Budget
}

func (c *Config) backoff() time.Duration {
	if c.Backoff <= 0 {
		return DefaultBackoff
	}
	return c.Backoff
}

func (c *Config) passes() int {
	if c.Passes <= 0 {
		return DefaultPasses
	}
	return c.Passes
}

func (c *Config) parallel() int {
	if c.Parallel < 1 {
		return 1
	}
	return c.Parallel
}

func (c *Config) poolCap() int {
	if c.MaxPoolBytes <= 0 {
		return 2 * ci.DefaultLimits().MaxContainerBytes
	}
	return c.MaxPoolBytes
}

// logf sanitises the text arguments: whatever a provider said may carry its URL and so its key.
func (c *Config) logf(format string, args ...interface{}) {
	if c.Logf == nil {
		return
	}
	clean := make([]interface{}, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			clean[i] = ethproof.BoundProviderText(v)
		case error:
			clean[i] = ethproof.BoundProviderText(v.Error())
		default:
			clean[i] = a
		}
	}
	c.Logf(format, clean...)
}

// Gate bounds the captures of one chain that run at once (S6: DefaultReplayCaptureConcurrency). A capture holds a slot for its whole run
// and releases it on every path.
type Gate struct{ slots chan struct{} }

// NewGate returns a gate of n slots (n < 1 is 1).
func NewGate(n int) *Gate {
	if n < 1 {
		n = 1
	}
	return &Gate{slots: make(chan struct{}, n)}
}

// Acquire waits for a slot or for ctx. The release function is idempotent and terminal.
func (g *Gate) Acquire(ctx context.Context) (func(), error) {
	select {
	case g.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-g.slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// InUse is the number of slots held.
func (g *Gate) InUse() int { return len(g.slots) }

// hostKey is the identity of a provider for the "distinct hosts" rule: lower-cased host, no trailing dot, default port dropped, so
// https://p.io and https://p.io:443 are one provider.
func hostKey(name string) string {
	s := strings.TrimSpace(name)
	host, port := s, ""
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host, port = u.Hostname(), u.Port()
		if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			port = ""
		}
	} else if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if port == "80" || port == "443" {
		port = ""
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// distinct keeps the first provider of every host.
func distinct(ps []Provider) []Provider {
	seen := map[string]bool{}
	var out []Provider
	for _, p := range ps {
		if p == nil {
			continue
		}
		k := hostKey(p.Name())
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// asciiText is provider text as a Stated STR may carry it: redacted and bounded by ethproof.BoundProviderText, ASCII only, no control byte,
// at most ci.DefaultLimits().MaxText bytes.
func asciiText(s string) string {
	s = ethproof.BoundProviderText(ethrpc.RedactText(s))
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if max := ci.DefaultLimits().MaxText; len(b) > max {
		b = b[:max]
	}
	return string(b)
}

// failures keeps, per host, the last thing that went wrong, bounded to ci.DefaultLimits().MaxFailures.
type failures struct {
	byHost map[string]string
}

func newFailures() *failures { return &failures{byHost: map[string]string{}} }

func (f *failures) note(host string, err error) {
	h := asciiText(host)
	if h == "" {
		h = "unknown"
	}
	if _, ok := f.byHost[h]; !ok && len(f.byHost) >= ci.DefaultLimits().MaxFailures {
		return
	}
	f.byHost[h] = asciiText(err.Error())
}

func (f *failures) list() []ci.ProviderFailure {
	out := make([]ci.ProviderFailure, 0, len(f.byHost))
	for h, e := range f.byHost {
		out = append(out, ci.ProviderFailure{Host: h, Error: e})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// UnavailableError: no provider could serve a verified answer within the budget. It carries the bounded, redacted failures.
type UnavailableError struct {
	What     string
	Failures []ci.ProviderFailure
	Cause    error // the context error when the budget or the caller ended the wait
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("capture: %s unavailable from %d provider(s)", e.What, len(e.Failures))
}
func (e *UnavailableError) Unwrap() error { return e.Cause }

// ErrTooLarge: a capture would hold more than its byte budget or the container caps; nothing is stored, nothing is truncated.
var ErrTooLarge = errors.New("capture: evidence exceeds its byte budget")

// PanicError: a capture panicked (a bug); the process lives on.
type PanicError struct{ Value string }

func (e *PanicError) Error() string { return "capture: panic: " + e.Value }
