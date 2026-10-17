package ethrpc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// A reader starts on the providers whose chain id it has verified, once there are at least MinAgreeingProviders of
// them; a provider down at boot is asked for nothing and joins once its chain id is verified. The owner is adding a
// provider per chain (Base and Arbitrum Sepolia to 5, Sepolia to 3): each provider added must not make a start less
// likely.

func shortenVerification(t *testing.T) {
	g, b, m, c := unverifiedProviderGrace, reverifyBase, reverifyMax, constructionRetryBudget
	unverifiedProviderGrace, reverifyBase, reverifyMax, constructionRetryBudget = 300*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond, 2*time.Second
	t.Cleanup(func() { unverifiedProviderGrace, reverifyBase, reverifyMax, constructionRetryBudget = g, b, m, c })
}

func TestAProviderDownAtBootIsLeftOutAndJoinsOnceVerified(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	a, b, late := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	late.failNext, late.failStatus = 1<<30, http.StatusServiceUnavailable
	start := time.Now()
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, b, late), time.Second)
	if err != nil {
		t.Fatalf("one provider down at boot stopped the reader: %v", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("the construction waited %s for the down provider", d)
	}
	if hosts := r.Hosts(); len(hosts) != 2 || strings.Contains(strings.Join(hosts, ","), "127.0.0.2") {
		t.Fatalf("verified %v; want the two that answered", hosts)
	}
	if got, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); err != nil || got.BlockHash != final.Hash() {
		t.Fatalf("(%v, %v)", got, err)
	}
	if n := late.callsOf("eth_getTransactionReceipt"); n != 0 {
		t.Fatalf("an unverified provider was asked for a fact %d times", n)
	}

	// It comes back - on a fork, so that it is visible that it is heard once it joins.
	late.mu.Lock()
	late.failNext = 0
	late.receiptIn = header(testHeight, "fork").Hash()
	late.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for len(r.Hosts()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the provider never joined: %v", r.Hosts())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a provider that joined is not heard: %v", err)
	}
}

func TestFewerThanTwoVerifiedProvidersIsStillRefused(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	a, d1, d2 := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	d1.failNext, d1.failStatus = 1<<30, http.StatusServiceUnavailable
	d2.failNext = 1 << 30
	start := time.Now()
	_, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, d1, d2), time.Second)
	if err == nil {
		t.Fatal("a reader with one verified provider was built")
	}
	if d := time.Since(start); d > constructionRetryBudget+time.Second {
		t.Fatalf("refused only after %s; the budget is %s", d, constructionRetryBudget)
	}
	var he rpc.HTTPError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "::1") || !strings.Contains(err.Error(), "127.0.0.2") ||
		!strings.Contains(err.Error(), "1 verified") {
		t.Fatalf("the refusal must name each unverified provider with its own error: %v", err)
	}
}

// A provider on another chain is excluded loudly, never counted: with two others verified the reader is built from the
// two; with fewer than MinAgreeingProviders left the reader is refused, by name, with the wrong chain in the reason.
func TestAWrongChainIDIsExcludedAndTheReaderIsRefusedOnlyBelowTheMinimum(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	r, err := NewAgreeingReader(context.Background(), 11155111,
		urlsOf(t, provider(11155111, final), provider(11155111, final), provider(84532, final)), time.Second)
	if err != nil {
		t.Fatalf("a misrouted provider took down a reader that still has two right providers: %v", err)
	}
	if hosts := r.Hosts(); len(hosts) != 2 || strings.Contains(strings.Join(hosts, ","), "127.0.0.2") {
		t.Fatalf("verified %v; the wrong-chain provider must not be among them", hosts)
	}
	resetRegistryForTests()
	_, err = NewAgreeingReader(context.Background(), 11155111,
		urlsOf(t, provider(11155111, final), provider(84532, final)), time.Second)
	if err == nil || !strings.Contains(err.Error(), "serves chain 84532") {
		t.Fatalf("one right provider and one wrong must refuse the reader by name: %v", err)
	}
}
