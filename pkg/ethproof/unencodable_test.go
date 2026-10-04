// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Every provider serves a block holding a transaction type no encoder knows (as a chain upgrade would introduce): no
// amount of asking again will prove it, so the build is refused at once, naming the type - not retried as an unanswered
// read until its deadline.
func TestAnAgreedUnencodableBlockIsRefusedAtOnceByName(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.ArbitrumSepolia)
	src := agreed(t, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")}, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")})
	start := time.Now()
	_, err := ethproof.BuildWithin(context.Background(), src, f.BlockHash(), f.SettlementTx, f.SettlementIndex(),
		time.Now().Add(time.Minute), 10*time.Millisecond)
	if err == nil {
		t.Fatal("a block holding an unknown transaction type was proven")
	}
	if errors.Is(err, ethrpc.ErrTooFewProviders) || errors.Is(err, ethrpc.ErrProvidersDisagree) {
		t.Fatalf("THE regression: an unprovable block reported as an unanswered read: %v", err)
	}
	if !errors.Is(err, ethproof.ErrRefused) || !strings.Contains(err.Error(), "0x7d") || !strings.Contains(err.Error(), "cannot be encoded") {
		t.Fatalf("refused, but not by name: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("refused only after %s: the build waited for agreement that cannot come", elapsed)
	}
}

// One provider alone serving an unencodable block cannot make the block unprovable: the read stays unanswered, and the
// build keeps asking until its deadline.
func TestOneProvidersUnencodableAnswerIsNotARefusal(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.ArbitrumSepolia)
	src := agreed(t, honest(f), &ethprooftest.Provider{F: f, Mutate: retype("0x7d")})
	_, err := ethproof.BuildWithin(context.Background(), src, f.BlockHash(), f.SettlementTx, f.SettlementIndex(),
		time.Now().Add(300*time.Millisecond), 10*time.Millisecond)
	if !errors.Is(err, ethrpc.ErrTooFewProviders) || !strings.Contains(err.Error(), "not agreed before the deadline") {
		t.Fatalf("one provider's unencodable answer: %v", err)
	}
}
