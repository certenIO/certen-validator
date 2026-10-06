// Copyright 2026 Certen Protocol

package ethereum

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// chainIDServer answers eth_chainId with the given result, or with an error when result is empty.
func chainIDServer(t *testing.T, result string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method != "eth_chainId" || result == "" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32601,"message":"no such method"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":"` + result + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// RB7 Task 5 T5-5: the client takes its chain id from its own RPC, so no chain id is compiled in or configured.
func TestTheClientReportsTheChainIDItsRPCAnswers(t *testing.T) {
	c, err := NewClient(chainIDServer(t, "0x14a34"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.GetChainID().Int64(); got != 84532 {
		t.Fatalf("chain id %d, want 84532 (what eth_chainId answered)", got)
	}
}

func TestAnRPCThatCannotAnswerItsChainIDIsRefusedByName(t *testing.T) {
	_, err := NewClient(chainIDServer(t, ""))
	if err == nil || !strings.Contains(err.Error(), "ETHEREUM_URL: reading eth_chainId") {
		t.Fatalf("want a named refusal, got %v", err)
	}
}
