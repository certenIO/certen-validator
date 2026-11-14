//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2). Read-only against the public Kermit node.

package proofv2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DAX-1G-R2 (DAX-F79), on the real network: an account with a pending transaction cannot have its chains bound, and the capture says so by name.
//
// acc://harbor-mfg-tcl97.acme/data is the payment account of the transaction-controls lab's three-authority scenes. A writeData it carries
// (acc://7981b28c...@harbor-mfg-tcl97.acme/data, initiated by its erp page, never voted on by an authority) has been pending since block 16,902,892
// of its partition, before the four intents of run dax1-3 that the validators then refused with
// "the vote of acc://harbor-mfg-tcl97.acme/book: acc://harbor-mfg-tcl97.acme/data has no signature chain bound at the block". Accumulate hashes the
// pending set of an account into its state (internal/database/observer_prod.go hashPending: for each pending transaction its payments, authority
// votes, validator signatures and active signatures), which no API serves, so H(chains || pending) cannot be recomputed (capturePageWith) and the
// page's chains stay unbound for as long as anything is pending on the account.
//
//	go test -tags live -run TestLiveAnAccountWithAPendingTransactionHasItsChainsUnbound -count=1 -v ./pkg/proof/v2/
func TestLiveAnAccountWithAPendingTransactionHasItsChainsUnbound(t *testing.T) {
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	b := &Builder{C: c, Q: proof.NewHTTPQuerier(endpoint)}
	router, err := proof.LoadNetworkRouter(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}

	pending := func(account string) uint64 {
		u, err := url.Parse(account)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Query(ctx, u, &api.DefaultQuery{})
		if err != nil {
			t.Fatalf("%s: %v", account, err)
		}
		ar, ok := r.(*api.AccountRecord)
		if !ok {
			t.Fatalf("%s: %T", account, r)
		}
		if ar.Pending == nil {
			return 0
		}
		return ar.Pending.Total
	}
	// A recent block of the partition the account is on, which the node still serves.
	recent := func(account string) uint64 {
		id, err := router.PartitionID(account)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Query(ctx, protocol.PartitionUrl(id).JoinPath(protocol.Ledger), &api.DefaultQuery{})
		if err != nil {
			t.Fatalf("ledger of %s: %v", id, err)
		}
		ar, ok := r.(*api.AccountRecord)
		if !ok {
			t.Fatalf("ledger of %s: %T", id, r)
		}
		l, ok := ar.Account.(*protocol.SystemLedger)
		if !ok {
			t.Fatalf("ledger of %s: %T", id, ar.Account)
		}
		return l.Index - 20
	}

	const principal = "acc://harbor-mfg-tcl97.acme/data"
	if n := pending(principal); n == 0 {
		t.Fatalf("%s has nothing pending any more (the lab's pending writeData expired or was completed): the condition this test shows (read on 2026-11-14) is gone from the network", principal)
	}
	p, err := b.CapturePage(ctx, principal, recent(principal))
	if err != nil {
		t.Fatalf("capture of %s: %v", principal, err)
	}
	if len(p.Chains) != 0 || !strings.HasPrefix(p.ChainError, StateChainUnboundPending+":") || !strings.Contains(p.ChainError, "pending") {
		t.Fatalf("%s has a pending transaction, so its chains cannot be bound: chains %d, reason %q", principal, len(p.Chains), p.ChainError)
	}
	t.Logf("%s: %d pending, chains bound %d, reason %q", principal, pending(principal), len(p.Chains), p.ChainError)

	// The same capture of an account with nothing pending (the lab's self-initiated G-83 control payer) binds.
	const control = "acc://dax1-r6s.acme/data"
	if n := pending(control); n != 0 {
		t.Fatalf("the control %s has %d pending", control, n)
	}
	cp, err := b.CapturePage(ctx, control, recent(control))
	if err != nil {
		t.Fatalf("capture of %s: %v", control, err)
	}
	if cp.ChainError != "" || len(cp.Chains) == 0 {
		t.Fatalf("%s has nothing pending, so its chains bind: chains %d, reason %q", control, len(cp.Chains), cp.ChainError)
	}
	t.Logf("%s: 0 pending, chains bound %d", control, len(cp.Chains))
}
