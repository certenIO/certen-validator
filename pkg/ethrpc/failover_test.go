package ethrpc

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func TestParseEndpointsPreservesCostOrderAndDedupes(t *testing.T) {
	got := ParseEndpoints("https://free.example", "https://paid-a.example, https://paid-b.example", "https://free.example")
	want := []string{"https://free.example", "https://paid-a.example", "https://paid-b.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order changed at %d: got %v, want %v", i, got, want)
		}
	}
}

func TestShouldFailover(t *testing.T) {
	// Provider refusals — the whole reason this package exists.
	failover := []string{
		`403 Forbidden: {"code":-32602,"message":"Archive requests require a personal token."}`,
		"429 Too Many Requests",
		"monthly quota exhausted",
		"out of credits",
		"502 Bad Gateway",
		"dial tcp: connection refused",
		"context deadline exceeded: timeout",
	}
	for _, m := range failover {
		if !ShouldFailover(errors.New(m)) {
			t.Errorf("expected failover for %q", m)
		}
	}

	// Real errors. Retrying these on a paid provider spends quota to get the same answer, so they
	// must NOT trigger failover.
	stay := []string{
		"execution reverted",
		"invalid address",
		"nonce too low",
		"insufficient funds for gas",
	}
	for _, m := range stay {
		if ShouldFailover(errors.New(m)) {
			t.Errorf("expected NO failover for %q", m)
		}
	}

	if ShouldFailover(nil) {
		t.Error("nil must not fail over")
	}
}

func TestRedactHidesProviderKey(t *testing.T) {
	in := "https://eth-sepolia.g.alchemy.com/v2/SuperSecretKey123"
	got := redact(in)
	if strings.Contains(got, "SuperSecretKey123") {
		t.Fatalf("key leaked in %q", got)
	}
	if !strings.Contains(got, "eth-sepolia.g.alchemy.com") {
		t.Fatalf("host should be kept for diagnosis, got %q", got)
	}
	// A keyless public endpoint should survive unchanged, so logs stay readable.
	pub := "https://ethereum-sepolia-rpc.publicnode.com"
	if redact(pub) != pub {
		t.Fatalf("public URL should not be redacted, got %q", redact(pub))
	}
}

// poolOf builds a Pool without dialing, so failover logic can be tested without a network.
func poolOf(n int, cooldown time.Duration) *Pool {
	p := &Pool{cooldown: cooldown, logger: quietLogger()}
	for i := 0; i < n; i++ {
		// A non-nil sentinel client is enough: fn is a stub and never touches it.
		p.endpoints = append(p.endpoints, &endpoint{url: "https://e" + string(rune('0'+i)) + ".example", client: &ethclient.Client{}})
	}
	return p
}

func TestDoPrefersTheCheapestEndpoint(t *testing.T) {
	p := poolOf(3, time.Minute)
	var calls int
	err := p.Do(context.Background(), func(*ethclient.Client) error { calls++; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected the free endpoint only, got %d calls", calls)
	}
}

func TestDoFailsOverThenCoolsDownTheRefusingEndpoint(t *testing.T) {
	p := poolOf(2, time.Minute)
	archive := errors.New(`403 Forbidden: {"message":"Archive requests require a personal token."}`)

	var seen int
	err := p.Do(context.Background(), func(c *ethclient.Client) error {
		seen++
		if seen == 1 {
			return archive // the free endpoint refuses
		}
		return nil // the paid one serves it
	})
	if err != nil {
		t.Fatalf("expected failover to succeed, got %v", err)
	}
	if seen != 2 {
		t.Fatalf("expected 2 attempts, got %d", seen)
	}

	// The refusing endpoint is now cooling, so the next call should start at the paid one.
	var first *endpoint
	if c := p.candidates(); len(c) > 0 {
		first = c[0]
	}
	if first == nil || first.url != p.endpoints[1].url {
		t.Fatalf("expected the paid endpoint to be preferred while the free one cools, got %v", p.Status())
	}
}

func TestDoDoesNotRetryRealErrorsAcrossProviders(t *testing.T) {
	p := poolOf(3, time.Minute)
	var calls int
	err := p.Do(context.Background(), func(*ethclient.Client) error {
		calls++
		return errors.New("execution reverted")
	})
	if err == nil {
		t.Fatal("expected the error to surface")
	}
	if calls != 1 {
		t.Fatalf("a real error must not be retried on paid providers; got %d calls", calls)
	}
}

func TestCooldownExpiresSoTheFreeEndpointIsPreferredAgain(t *testing.T) {
	// The economic point: one bad response must not park the pool on the paid provider forever.
	p := poolOf(2, 20*time.Millisecond)
	_ = p.Do(context.Background(), func(*ethclient.Client) error {
		return errors.New("429 too many requests")
	})
	time.Sleep(40 * time.Millisecond)
	if c := p.candidates(); len(c) == 0 || c[0].url != p.endpoints[0].url {
		t.Fatalf("free endpoint should be preferred again after cooldown, got %v", p.Status())
	}
}

func TestDoSurfacesTheLastErrorWhenEveryProviderRefuses(t *testing.T) {
	p := poolOf(2, time.Minute)
	err := p.Do(context.Background(), func(*ethclient.Client) error {
		return errors.New("429 too many requests")
	})
	if err == nil || !strings.Contains(err.Error(), "all 2 endpoints failed") {
		t.Fatalf("expected an all-endpoints-failed error, got %v", err)
	}
}

func TestDoRespectsContextCancellation(t *testing.T) {
	p := poolOf(2, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Do(ctx, func(*ethclient.Client) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
