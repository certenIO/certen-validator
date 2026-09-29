// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"testing"
)

// RB4-F64d / G-18: the pages that may carry a vote are every page of every authority the transaction requires - the
// principal's, and the ones its header names. G1 seeded only the principal's live authorities, so a header
// authority's signatures were never collected, while the vote model requires that authority to accept.

func signerPagesFixture(t *testing.T) *G1Layer {
	t.Helper()
	mock := NewMockRPCClient()
	mock.AddMockResponse("acc://p.acme/data", map[string]interface{}{"result": map[string]interface{}{
		"account": map[string]interface{}{"type": "dataAccount",
			"authorities": []interface{}{map[string]interface{}{"url": "acc://p.acme/book"}}}}})
	mock.AddMockResponse("acc://p.acme/book", map[string]interface{}{"result": map[string]interface{}{
		"account": map[string]interface{}{"type": "keyBook", "pageCount": float64(1)}}})
	mock.AddMockResponse("acc://x.acme/book", map[string]interface{}{"result": map[string]interface{}{
		"account": map[string]interface{}{"type": "keyBook", "pageCount": float64(2)}}})
	g1 := &G1Layer{client: mock, g0Layer: &G0Layer{}}
	g1.g0Layer.lastTransaction = map[string]interface{}{
		"header": map[string]interface{}{"principal": "acc://p.acme/data",
			"authorities": []interface{}{"acc://x.acme/book"}},
		"body": map[string]interface{}{"type": "writeData"},
	}
	return g1
}

func TestSignerPages_AHeaderAuthoritysPagesAreSearched(t *testing.T) {
	g1 := signerPagesFixture(t)
	pages, err := g1.accountSignerPages(context.Background(), "acc://p.acme/data", "acc://p.acme/book/1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"acc://x.acme/book/1": false, "acc://x.acme/book/2": false}
	for _, p := range pages {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("the header authority's page %s is not searched for signatures: %v", p, pages)
		}
	}
}
