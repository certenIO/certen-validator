package ethrpc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// RB7 Task 5 T5-7: every provider is verified once per process. A validator builds a reader per component, per chain and
// per peer-attestation request, and each build used to ask every provider its chain id again, so seven validators on one
// Infura key were answered 429 at boot and under every burst.

func chainIDCalls(ps ...*stubProvider) int {
	n := 0
	for _, p := range ps {
		n += p.callsOf("eth_chainId")
	}
	return n
}

func TestFiveReadersOnOneChainAskEachProviderItsChainIDOnce(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	a, b, c := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	urls := urlsOf(t, a, b, c)
	for i := 0; i < 5; i++ {
		if _, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second); err != nil {
			t.Fatalf("reader %d: %v", i, err)
		}
	}
	for name, p := range map[string]*stubProvider{"a": a, "b": b, "c": c} {
		if n := p.callsOf("eth_chainId"); n != 1 {
			t.Fatalf("provider %s was asked its chain id %d times by 5 readers; want exactly 1", name, n)
		}
	}
}

func TestReadersBuiltAtTheSameMomentShareOneVerification(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	a, b := provider(11155111, final), provider(11155111, final)
	urls := urlsOf(t, a, b)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second)
			done <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if n := chainIDCalls(a, b); n != 2 {
		t.Fatalf("8 concurrent readers made %d chain id calls on 2 providers; want 2", n)
	}
}

func TestAWarmRegistryMakesNoChainIDCallPerObserver(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	a, b := provider(11155111, final), provider(11155111, final)
	urls := urlsOf(t, a, b)
	if _, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second); err != nil {
		t.Fatal(err)
	}
	before := chainIDCalls(a, b)
	for i := 0; i < 20; i++ { // a peer-attestation request builds one observer, hence one reader
		if _, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if after := chainIDCalls(a, b); after != before {
		t.Fatalf("20 per-request readers made %d chain id calls on a warm registry; want 0", after-before)
	}
}

// Sharing the verification is not weaker verification: a provider on another chain NEVER counts toward agreement, for
// any reader, however many have been built before. It is left out of the reader (and asked for nothing) while the
// providers that did answer still satisfy MinAgreeingProviders; it does not take every reader of the chain down with it.
func TestAWrongChainIDIsExcludedForEveryReaderAndNeverCounted(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	reverifyBase, reverifyMax = time.Hour, time.Hour // no background retry during the test
	final := header(testHeight, "final")
	wrong := provider(84532, final)
	urls := urlsOf(t, provider(11155111, final), provider(11155111, final), wrong)
	for i := 0; i < 3; i++ {
		r, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second)
		if err != nil {
			t.Fatalf("reader %d: one misrouted provider took the chain's reader down: %v", i, err)
		}
		if hosts := r.Hosts(); len(hosts) != 2 || strings.Contains(strings.Join(hosts, ","), "127.0.0.2") {
			t.Fatalf("reader %d verified %v; want the two on the right chain, never the wrong one", i, hosts)
		}
		if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); err != nil {
			t.Fatalf("reader %d: the two right providers did not establish the receipt: %v", i, err)
		}
	}
	if n := wrong.callsOf("eth_getTransactionReceipt"); n != 0 {
		t.Fatalf("a provider on another chain was asked for a fact %d times", n)
	}
	if n := wrong.callsOf("eth_chainId"); n != 1 {
		t.Fatalf("a wrong chain id is an answer shared by every reader; it was asked %d times", n)
	}
}

// A provider that answered another chain id once (a load-balanced or misrouted backend) is asked again after a bounded
// backoff and rejoins when it answers the right one: a transient misroute is not a permanent exile.
func TestAProviderThatAnsweredAnotherChainOnceRejoinsAfterItsBackoff(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	flaky := provider(84532, final)
	urls := urlsOf(t, provider(11155111, final), provider(11155111, final), flaky)
	r, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hosts()) != 2 {
		t.Fatalf("verified %v; want the two right ones", r.Hosts())
	}
	flaky.mu.Lock()
	flaky.chainID = 11155111 // the backend that answered 84532 now answers correctly
	flaky.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for len(r.Hosts()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the provider that misrouted once never rejoined: %v", r.Hosts())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// And a reader built after it recovered finds it verified, with no new chain id call.
	before := flaky.callsOf("eth_chainId")
	r2, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second)
	if err != nil || len(r2.Hosts()) != 3 {
		t.Fatalf("a reader built after the recovery: hosts=%v err=%v", r2.Hosts(), err)
	}
	if after := flaky.callsOf("eth_chainId"); after != before {
		t.Fatalf("a verified provider was asked its chain id again (%d calls)", after-before)
	}
}

// A provider that failed is asked again by its own backoff in the background, not by each reader built meanwhile.
func TestAFailedProviderIsNotAskedAgainByEveryReader(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	reverifyBase, reverifyMax = time.Hour, time.Hour // no background retry during the test
	final := header(testHeight, "final")
	a, b, down := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	down.failNext, down.failStatus = 1<<30, http.StatusTooManyRequests
	urls := urlsOf(t, a, b, down)
	if _, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second); err != nil {
		t.Fatal(err)
	}
	first := down.callsOf("eth_chainId")
	for i := 0; i < 5; i++ {
		if _, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if n := down.callsOf("eth_chainId"); n != first {
		t.Fatalf("a provider answering 429 was asked its chain id %d more times by 5 later readers; want 0", n-first)
	}
}
