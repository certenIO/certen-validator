package ethrpc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
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

// Sharing the verification is not weaker verification: a provider on another chain refuses every reader, however many
// have been built before and whether or not the provider was already asked.
func TestAWrongChainIDIsRefusedForEveryReaderThroughTheRegistry(t *testing.T) {
	shortenVerification(t)
	resetRegistryForTests()
	final := header(testHeight, "final")
	urls := urlsOf(t, provider(11155111, final), provider(11155111, final), provider(84532, final))
	for i := 0; i < 3; i++ {
		_, err := NewAgreeingReader(context.Background(), 11155111, urls, time.Second)
		if err == nil || !strings.Contains(err.Error(), "serves chain 84532") {
			t.Fatalf("reader %d: a provider on another chain did not refuse the reader: %v", i, err)
		}
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
