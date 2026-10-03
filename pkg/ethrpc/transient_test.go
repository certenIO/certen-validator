package ethrpc

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// A 429, a 502/503/504 or a dropped connection says the provider cannot answer NOW, nothing about the chain: the same
// provider is asked the same query again within a bounded time. Observed 2026-10-03: all seven validators share one
// Infura Base Sepolia key, whose per-second limit answered the chain-id check with 429 and aborted
// `validator repair outcome-trees`; a transient gateway error stopped a validator's start.

func TestConstructionSucceedsAfterRateLimiting(t *testing.T) {
	final := header(testHeight, "final")

	t.Run("without Retry-After", func(t *testing.T) {
		a, b := provider(11155111, final), provider(11155111, final)
		a.failNext = 3
		if _, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, b), 2*time.Second); err != nil {
			t.Fatalf("a provider rate-limited three times stopped the construction: %v", err)
		}
		if n := a.callsOf("eth_chainId"); n != 4 {
			t.Fatalf("the rate-limited provider was asked its chain id %d times; want 3 refused + 1 answered", n)
		}
	})

	t.Run("with Retry-After", func(t *testing.T) {
		a, b := provider(11155111, final), provider(11155111, final)
		a.failNext, a.failRetryAfter = 2, "1"
		start := time.Now()
		if _, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, b), 2*time.Second); err != nil {
			t.Fatalf("a provider rate-limited with Retry-After stopped the construction: %v", err)
		}
		// Two refusals each saying "retry after 1 s": the provider was not asked again sooner.
		if d := time.Since(start); d < 1900*time.Millisecond {
			t.Fatalf("Retry-After: 1 was not honoured: two retries took %s", d)
		}
	})
}

func TestAnAgreedReadGetsTwoAnswersWhileOneProviderIsBrieflyRateLimited(t *testing.T) {
	final := header(testHeight, "final")
	steady, limited := provider(11155111, final), provider(11155111, final)
	limited.failNext = 2 // the burst that hits its chain-id check
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, steady, limited), 2*time.Second)
	if err != nil {
		t.Fatalf("construction: %v", err)
	}
	limited.mu.Lock()
	limited.failNext, limited.failStatus = 2, http.StatusServiceUnavailable // and a gateway error on the read
	limited.mu.Unlock()
	got, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b"))
	if err != nil || got.BlockHash != final.Hash() {
		t.Fatalf("two agreeing answers were not established: (%v, %v)", got, err)
	}
	if n := limited.callsOf("eth_getTransactionReceipt"); n != 3 {
		t.Fatalf("the limited provider was asked %d times; want 2 refused + 1 answered", n)
	}
}

func TestAWrongChainIDIsRefusedWithoutRetry(t *testing.T) {
	final := header(testHeight, "final")
	wrong := provider(84532, final)
	_, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, provider(11155111, final), wrong), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "serves chain 84532") {
		t.Fatalf("a provider of another chain was not refused: %v", err)
	}
	if n := wrong.callsOf("eth_chainId"); n != 1 {
		t.Fatalf("a wrong chain id is an answer; it was asked %d times", n)
	}
	// A provider that is throttled first and then names the wrong chain is refused by that answer, not by the throttle.
	late := provider(84532, final)
	late.failNext = 2
	_, err = NewAgreeingReader(context.Background(), 11155111, urlsOf(t, provider(11155111, final), late), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "serves chain 84532") {
		t.Fatalf("a throttled provider of another chain: %v", err)
	}
	if n := late.callsOf("eth_chainId"); n != 3 {
		t.Fatalf("asked %d times; want 2 refused + 1 answered, and no retry of the answer", n)
	}
}

func TestAPermanentRateLimitFailsWithinTheCap(t *testing.T) {
	saved := constructionRetryBudget
	constructionRetryBudget = 1500 * time.Millisecond
	t.Cleanup(func() { constructionRetryBudget = saved })
	final := header(testHeight, "final")
	stuck := provider(11155111, final)
	stuck.failNext = 1 << 30
	start := time.Now()
	_, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, stuck, provider(11155111, final)), 2*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a provider that never answered was accepted")
	}
	if elapsed > constructionRetryBudget+time.Second {
		t.Fatalf("retrying ran %s, past the %s cap", elapsed, constructionRetryBudget)
	}
	var he rpc.HTTPError
	if !errors.As(err, &he) || he.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the provider's own 429 is not the error: %v", err)
	}
	t.Logf("after %s: %v", elapsed.Round(time.Millisecond), err)
	n := stuck.callsOf("eth_chainId")
	if n < 2 || !strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "attempts") ||
		!strings.Contains(err.Error(), strconv.Itoa(n)+" attempts") {
		t.Fatalf("the error must name the provider and its %d attempts: %v", n, err)
	}
}

func TestCancellationStopsTheRetries(t *testing.T) {
	final := header(testHeight, "final")
	stuck := provider(11155111, final)
	stuck.failNext = 1 << 30
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := NewAgreeingReader(ctx, 11155111, urlsOf(t, stuck, provider(11155111, final)), 2*time.Second)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("retries ran %s after the context was cancelled at 200ms", d)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled construction must say so: %v", err)
	}
}
