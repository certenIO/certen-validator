package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
)

// limitedServer answers the first `fail` requests with fn(w) and then with result.
type limitedServer struct {
	mu     sync.Mutex
	fail   int
	failFn func(w http.ResponseWriter, id json.RawMessage)
	result string
	asked  map[string]int
}

func (s *limitedServer) start(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.asked == nil {
			s.asked = map[string]int{}
		}
		s.asked[req.Method]++
		if s.fail > 0 {
			s.fail--
			s.failFn(w, req.ID)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, s.result)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (s *limitedServer) count(m string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[m]
}

func http429(w http.ResponseWriter, _ json.RawMessage) {
	http.Error(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"Too Many Requests"}}`, http.StatusTooManyRequests)
}

func TestARetryingClientAsksTheSameProviderAgain(t *testing.T) {
	for name, fail := range map[string]func(http.ResponseWriter, json.RawMessage){
		"429": http429,
		"503": func(w http.ResponseWriter, _ json.RawMessage) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		},
		"-32005 in a 200": func(w http.ResponseWriter, id json.RawMessage) {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32005,"message":"limit exceeded"}}`, id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := &limitedServer{fail: 2, failFn: fail, result: `"0x10"`}
			c, err := DialRetrying(context.Background(), s.start(t))
			if err != nil {
				t.Fatal(err)
			}
			n, err := c.BlockNumber(context.Background())
			if err != nil || n != 16 {
				t.Fatalf("(%d, %v)", n, err)
			}
			if got := s.count("eth_blockNumber"); got != 3 {
				t.Fatalf("asked %d times; want 3", got)
			}
		})
	}
}

func TestARetryingClientNeverResendsATransaction(t *testing.T) {
	s := &limitedServer{fail: 5, failFn: http429, result: `"0x01"`}
	c, err := DialRPCRetrying(context.Background(), s.start(t))
	if err != nil {
		t.Fatal(err)
	}
	var out string
	if err := c.CallContext(context.Background(), &out, "eth_sendRawTransaction", "0x00"); err == nil {
		t.Fatal("a refused send was reported sent")
	}
	if got := s.count("eth_sendRawTransaction"); got != 1 {
		t.Fatalf("a send was sent %d times", got)
	}
}

func TestARetryingClientReturnsTheProvidersOwnErrorWithItsAttempts(t *testing.T) {
	saved := queryRetryBudget
	queryRetryBudget = 1200 * time.Millisecond
	t.Cleanup(func() { queryRetryBudget = saved })
	s := &limitedServer{fail: 1 << 30, failFn: http429, result: `"0x01"`}
	c, err := DialRetrying(context.Background(), s.start(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.BlockNumber(context.Background())
	if d := time.Since(start); d > queryRetryBudget+time.Second {
		t.Fatalf("retried for %s past the %s cap", d, queryRetryBudget)
	}
	var he rpc.HTTPError
	if !errors.As(err, &he) || he.StatusCode != http.StatusTooManyRequests || !strings.Contains(err.Error(), "attempts") ||
		!strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("want the provider's 429 naming the provider and its attempts: %v", err)
	}
	if !IsTransient(err) {
		t.Fatal("the exhausted error must still classify as transient")
	}
}

func TestARetryingClientAnswersAWellFormedErrorAtOnce(t *testing.T) {
	s := &limitedServer{fail: 1, failFn: func(w http.ResponseWriter, id json.RawMessage) {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":3,"message":"execution reverted"}}`, id)
	}, result: `"0x01"`}
	c, err := DialRPCRetrying(context.Background(), s.start(t))
	if err != nil {
		t.Fatal(err)
	}
	var out string
	if err := c.CallContext(context.Background(), &out, "eth_call", map[string]string{}, "latest"); err == nil ||
		!strings.Contains(err.Error(), "execution reverted") {
		t.Fatalf("%v", err)
	}
	if got := s.count("eth_call"); got != 1 {
		t.Fatalf("an execution error was asked %d times", got)
	}
}

func TestARetryingClientStopsWhenTheCallerCancels(t *testing.T) {
	s := &limitedServer{fail: 1 << 30, failFn: http429, result: `"0x01"`}
	c, err := DialRetrying(context.Background(), s.start(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if _, err := c.BlockNumber(ctx); err == nil {
		t.Fatal("no error")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("ran %s after cancellation at 200ms", d)
	}
}
