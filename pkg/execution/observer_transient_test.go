package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The observer's own client - transaction, head, block, receipts and eth_getProof reads of one provider - asks a
// provider that answers 429 again, the same request to the same provider, instead of failing the observation
// (2026-10-03: one Infura key shared by all seven validators 429s under bursts).
func TestTheObserversOwnClientRetriesARateLimitedProvider(t *testing.T) {
	var mu sync.Mutex
	refusals := 2
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		defer mu.Unlock()
		switch req.Method {
		case "eth_chainId":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0xaa36a7"}`, req.ID)
		case "eth_blockNumber":
			asked++
			if refusals > 0 {
				refusals--
				w.Header().Set("Retry-After", "0")
				http.Error(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"Too Many Requests"}}`, http.StatusTooManyRequests)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x1234"}`, req.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed"}}`, req.ID)
		}
	}))
	defer srv.Close()

	obs, err := NewExternalChainObserver(&ExternalChainObserverConfig{EthereumRPC: srv.URL, ChainID: 11155111, ValidatorID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := obs.ethClient.BlockNumber(context.Background())
	if err != nil || n != 0x1234 {
		t.Fatalf("a provider rate-limited twice failed the observer's read: (%d, %v)", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 3 {
		t.Fatalf("asked %d times; want 2 refused + 1 answered", asked)
	}
}
