// Copyright 2026 Certen Protocol

package accumulate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func queryAnswering(t *testing.T, account map[string]interface{}) *LiteClientAdapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"recordType": "account", "account": account}})
	}))
	t.Cleanup(srv.Close)
	a, err := NewLiteClientAdapter(&LiteClientConfig{NetworkURL: srv.URL, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// RB4-F51: a key page whose version could not be read used to sign as version 1, which the network
// rejects once keys have been added to the page.
func TestAKeyPageVersionIsReadOrAnError(t *testing.T) {
	v, err := queryAnswering(t, map[string]interface{}{"type": "keyPage", "version": 9}).
		GetKeyPageVersion(context.Background(), "acc://x.acme/book/2")
	if err != nil || v != 9 {
		t.Fatalf("got %d, %v; want 9", v, err)
	}
	if v, err := queryAnswering(t, map[string]interface{}{"type": "keyPage"}).
		GetKeyPageVersion(context.Background(), "acc://x.acme/book/2"); err == nil {
		t.Fatalf("a key page without a version was read as version %d", v)
	}
}
