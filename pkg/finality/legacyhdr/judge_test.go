// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

type stubSource struct {
	hdr   []byte
	err   error
	calls int
}

func (s *stubSource) HeaderByHash(_ context.Context, _ uint64, _ common.Hash) ([]byte, error) {
	s.calls++
	return s.hdr, s.err
}

type flakyStore struct {
	finality.CaptureStore
	get, put error
}

func (f flakyStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if f.get != nil {
		return nil, false, f.get
	}
	return f.CaptureStore.Get(ctx, k)
}

func (f flakyStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	if f.put != nil {
		return f.put
	}
	return f.CaptureStore.Put(ctx, k, b)
}

func TestJudgeFetchesVerifiesAndKeepsTheHeaderOnceAndNeverAsksAgain(t *testing.T) {
	for _, c := range chainFixtures {
		t.Run(c.name, func(t *testing.T) {
			lg := legacyOf(t, c.fixture)
			store := finality.NewMemCaptureStore()
			src := &stubSource{hdr: lg.header}
			out := Judge(context.Background(), lg.leg, store, src, nil)
			if out.State != StateReconstructed || !out.Fetched || !out.Stored || out.Named != nil || src.calls != 1 {
				t.Fatalf("first judgement = %+v calls %d", out, src.calls)
			}
			if got, ok, _ := store.Get(context.Background(), lg.leg.Key()); !ok || !bytes.Equal(got, lg.header) {
				t.Fatal("the verified header is not in the store")
			}
			// the same leg again, as another validator or a restart: a Get and a verification, nothing fetched, nothing written
			out = Judge(context.Background(), lg.leg, store, &stubSource{err: errors.New("must not be asked")}, nil)
			if out.State != StateReconstructed || out.Fetched || out.Stored {
				t.Fatalf("second judgement = %+v", out)
			}
		})
	}
}

func TestJudgeNamesAnUnservedBlockAndStoresNothing(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	store := finality.NewMemCaptureStore()
	un := &Unserved{Chain: 84532, Hash: lg.leg.BlockHash, Asked: 3, NotServed: 2, Unreachable: 1}
	out := Judge(context.Background(), lg.leg, store, &stubSource{err: un}, nil)
	if out.State != StateUnserved || !out.Fetched || out.Stored || out.Named == nil || out.Named.Code != finality.CodeIncludedUnavailable ||
		out.Named.Fields["reason"] != finality.IncludedLegacyHeaderUnserved || out.Named.Fields["asked"] != 3 || out.Named.Fields["block"] != lg.leg.BlockNumber {
		t.Fatalf("outcome = %+v", out)
	}
	if _, ok, _ := store.Get(context.Background(), lg.leg.Key()); ok {
		t.Fatal("a row exists for an unserved block")
	}
	if strings.Contains(out.Cause, "http") {
		t.Fatalf("the cause carries provider text: %q", out.Cause)
	}
}

// The block's own header is kept even when the bundle contradicts it, so it is never fetched again, and the leg is named by the
// check that failed.
func TestJudgeKeepsTheBlocksOwnHeaderAndNamesALegTheBundleContradicts(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	leg := lg.leg
	leg.TransactionsRoot[0] ^= 1
	store := finality.NewMemCaptureStore()
	out := Judge(context.Background(), leg, store, &stubSource{hdr: lg.header}, nil)
	if out.State != StateInvalid || !out.Stored || out.Named == nil || out.Named.Fields["check"] != CheckStoredRoots {
		t.Fatalf("outcome = %+v", out)
	}
	src := &stubSource{}
	if out := Judge(context.Background(), leg, store, src, nil); out.State != StateInvalid || src.calls != 0 {
		t.Fatalf("a contradicted leg was fetched again: %+v calls %d", out, src.calls)
	}
}

func TestJudgeStoreAndSourceFailuresJudgeNothingExceptAKeyConflict(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	cases := []struct {
		name  string
		store func(finality.CaptureStore) finality.CaptureStore
		src   *stubSource
		state string
		check string
	}{
		{"store unreadable", func(s finality.CaptureStore) finality.CaptureStore {
			return flakyStore{s, errors.New("conn reset"), nil}
		}, &stubSource{hdr: lg.header}, StatePending, ""},
		{"store unwritable", func(s finality.CaptureStore) finality.CaptureStore {
			return flakyStore{s, nil, errors.New("disk full")}
		}, &stubSource{hdr: lg.header}, StatePending, ""},
		{"key holds other bytes", func(s finality.CaptureStore) finality.CaptureStore {
			return flakyStore{s, nil, fmt.Errorf("%w: raced", finality.ErrCaptureConflict)}
		}, &stubSource{hdr: lg.header}, StateInvalid, CheckStoreConflict},
		{"source fails without naming why", func(s finality.CaptureStore) finality.CaptureStore { return s }, &stubSource{err: errors.New("boom")}, StatePending, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Judge(context.Background(), lg.leg, c.store(finality.NewMemCaptureStore()), c.src, nil)
			if out.State != c.state {
				t.Fatalf("state = %s, want %s (%+v)", out.State, c.state, out)
			}
			if c.check != "" && (out.Named == nil || out.Named.Fields["check"] != c.check) {
				t.Fatalf("named = %v", out.Named)
			}
			if c.check == "" && out.Named != nil {
				t.Fatalf("a failure that is no verdict carries the state %v", out.Named)
			}
		})
	}
}

func TestJudgeOnACancelledContextIsPendingAndSilent(t *testing.T) {
	lg := legacyOf(t, "base_sepolia_47368146")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logged []string
	out := Judge(ctx, lg.leg, finality.NewMemCaptureStore(), &stubSource{err: context.Canceled}, func(f string, a ...any) { logged = append(logged, f) })
	if out.State != StatePending || out.Named != nil || len(logged) != 0 {
		t.Fatalf("outcome %+v logged %v", out, logged)
	}
}

// Provider text never reaches the log: a registered provider URL inside a source error is redacted.
func TestJudgeRedactsProviderTextInItsLog(t *testing.T) {
	const secret = "https://rpc.example.invalid/v2/KEY-12345-SECRET"
	ethrpc.RegisterProviderURLs(secret)
	lg := legacyOf(t, "base_sepolia_47368146")
	var logged []string
	out := Judge(context.Background(), lg.leg, finality.NewMemCaptureStore(), &stubSource{err: fmt.Errorf("Post %q: dial tcp: refused", secret)},
		func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if out.State != StatePending || len(logged) != 1 {
		t.Fatalf("outcome %+v logged %v", out, logged)
	}
	if strings.Contains(logged[0], "KEY-12345-SECRET") {
		t.Fatalf("the log carries the provider credential: %s", logged[0])
	}
}
