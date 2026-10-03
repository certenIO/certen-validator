package ethrpc

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// A provider that is hard down must not cost every read its whole deadline: the outcome path chains dozens of agreed
// reads in sequence against deadlines of 90 s to 4 minutes.
func TestAProviderThatStaysDownDoesNotCostEveryReadItsDeadline(t *testing.T) {
	final := header(testHeight, "final")
	a, b, down := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, b, down), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	down.mu.Lock()
	down.down = true
	down.mu.Unlock()
	start := time.Now()
	for i := 0; i < 8; i++ {
		got, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b"))
		if err != nil || got.BlockHash != final.Hash() {
			t.Fatalf("read %d with two agreeing providers: (%v, %v)", i, got, err)
		}
	}
	// The first read waits out the down provider's deadline (at most 1 s here); the seven after it do not ask it.
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("eight reads took %s: every read waited out the down provider", d)
	}
}

// Resting is not outvoting: a provider that comes back is heard again, and a provider that comes back on a fork blocks
// the fact exactly as before.
func TestARestingProviderIsHeardAgainWhenItComesBack(t *testing.T) {
	savedBase, savedMax := providerRestBase, providerRestMax
	providerRestBase, providerRestMax = 300*time.Millisecond, time.Second
	t.Cleanup(func() { providerRestBase, providerRestMax = savedBase, savedMax })
	final := header(testHeight, "final")
	a, b, flaky := provider(11155111, final), provider(11155111, final), provider(11155111, final)
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, b, flaky), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	flaky.mu.Lock()
	flaky.down = true
	flaky.mu.Unlock()
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); err != nil {
		t.Fatal(err)
	}
	// It comes back, on a fork.
	flaky.mu.Lock()
	flaky.down = false
	flaky.receiptIn = header(testHeight, "fork").Hash()
	flaky.mu.Unlock()
	time.Sleep(400 * time.Millisecond)
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a provider back from rest on a fork was not heard: %v", err)
	}
}

// Two providers, one resting: nothing is established, exactly as with one down - and quickly after the first read.
func TestARestingProviderLeavesTooFewAnswersNotAFact(t *testing.T) {
	final := header(testHeight, "final")
	a, down := provider(11155111, final), provider(11155111, final)
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, a, down), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	down.mu.Lock()
	down.down = true
	down.mu.Unlock()
	for i := 0; i < 3; i++ {
		_, err := r.HeaderByNumber(context.Background(), big.NewInt(testHeight))
		if !errors.Is(err, ErrTooFewProviders) {
			t.Fatalf("read %d with one provider answering: %v", i, err)
		}
	}
	start := time.Now()
	if _, err := r.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(final.Hash(), false)); !errors.Is(err, ErrTooFewProviders) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("a resting provider was waited for: %s", d)
	}
}
