package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// RB5-F53: a settlement's finality facts hold only when independent providers agree.

// stubProvider is one JSON-RPC provider of a chain. Its view is set per test: the header it serves at a height, the
// finalized number it reports, the block its receipt names, and whether it answers at all.
type stubProvider struct {
	mu        sync.Mutex
	chainID   int64
	down      bool
	finalized uint64
	headers   map[uint64]*types.Header // height -> header served
	receiptIn common.Hash              // block the receipt names; zero = not found
	height    uint64
	tx        common.Hash
}

func (p *stubProvider) serve(t *testing.T) string { return p.serveOn(t, "127.0.0.1:0") }

// serveOn listens on addr, so that providers can be told apart by host the way independent operators are.
func (p *stubProvider) serveOn(t *testing.T, addr string) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(v interface{}) {
			b, _ := json.Marshal(v)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, b)
		}
		receipt := func(block common.Hash) map[string]interface{} {
			return map[string]interface{}{"transactionHash": p.tx, "blockHash": block, "blockNumber": fmt.Sprintf("0x%x", p.height),
				"transactionIndex": "0x0", "status": "0x1", "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208",
				"logs": []interface{}{}, "logsBloom": "0x" + strings.Repeat("00", 256), "type": "0x2", "effectiveGasPrice": "0x1",
				"contractAddress": nil, "from": common.Address{}, "to": common.Address{}}
		}
		switch req.Method {
		case "eth_chainId":
			reply(fmt.Sprintf("0x%x", p.chainID))
		case "eth_getTransactionReceipt":
			if p.receiptIn == (common.Hash{}) {
				reply(nil)
				return
			}
			reply(receipt(p.receiptIn))
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			if tag == "finalized" {
				h := *p.headers[p.height]
				h.Number = new(big.Int).SetUint64(p.finalized)
				reply(&h)
				return
			}
			var n uint64
			_, _ = fmt.Sscanf(tag, "0x%x", &n)
			reply(p.headers[n])
		case "eth_getBlockReceipts":
			reply([]interface{}{receipt(p.headers[p.height].Hash())})
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed"}}`, req.ID)
		}
	}))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func header(n uint64, tag string) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1_790_000_000,
		Extra: []byte(tag), BaseFee: big.NewInt(1)}
}

const testHeight = 11832868

func provider(chain int64, final *types.Header) *stubProvider {
	return &stubProvider{chainID: chain, finalized: testHeight + 32, headers: map[uint64]*types.Header{testHeight: final},
		receiptIn: final.Hash(), height: testHeight, tx: common.HexToHash("0x0b0b")}
}

// Each provider listens on its own loopback address, so each is a distinct host.
func urlsOf(t *testing.T, ps ...*stubProvider) []string {
	var urls []string
	addrs := []string{"127.0.0.1:0", "[::1]:0", "127.0.0.2:0"}
	for i, p := range ps {
		urls = append(urls, p.serveOn(t, addrs[i]))
	}
	return urls
}

func reader(t *testing.T, ps ...*stubProvider) *AgreeingReader {
	t.Helper()
	r, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, ps...), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAgreeingProvidersEstablishTheReceipt(t *testing.T) {
	final := header(testHeight, "final")
	r := reader(t, provider(11155111, final), provider(11155111, final))
	got, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b"))
	if err != nil || got.BlockHash != final.Hash() {
		t.Fatalf("(%v, %v)", got, err)
	}
}

func TestAForkedProviderBlocksTheReceipt(t *testing.T) {
	final := header(testHeight, "final")
	fork := provider(11155111, final)
	fork.receiptIn = header(testHeight, "fork").Hash()
	r := reader(t, provider(11155111, final), fork)
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a forked provider was outvoted or ignored: %v", err)
	}
}

func TestALaggingProviderIsWaitedFor(t *testing.T) {
	final := header(testHeight, "final")
	lag := provider(11155111, final)
	lag.receiptIn = common.Hash{}
	r := reader(t, provider(11155111, final), lag)
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); !errors.Is(err, ethereum.NotFound) {
		t.Fatalf("a provider that has not seen the transaction was outvoted: %v", err)
	}
}

func TestOneAnsweringProviderEstablishesNothing(t *testing.T) {
	final := header(testHeight, "final")
	down := provider(11155111, final)
	r := reader(t, provider(11155111, final), down)
	down.mu.Lock()
	down.down = true
	down.mu.Unlock()
	if _, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); !errors.Is(err, ErrTooFewProviders) {
		t.Fatalf("one provider's view was taken as the chain's: %v", err)
	}
}

func TestTwoOfThreeAgreeingWithOneDownIsEnough(t *testing.T) {
	final := header(testHeight, "final")
	down := provider(11155111, final)
	r := reader(t, provider(11155111, final), provider(11155111, final), down)
	down.mu.Lock()
	down.down = true
	down.mu.Unlock()
	if got, err := r.TransactionReceipt(context.Background(), common.HexToHash("0x0b0b")); err != nil || got.BlockHash != final.Hash() {
		t.Fatalf("(%v, %v)", got, err)
	}
}

func TestTheFinalizedHeadIsTheLowestAnyProviderReports(t *testing.T) {
	final := header(testHeight, "final")
	a, b := provider(11155111, final), provider(11155111, final)
	b.finalized = testHeight - 5
	r := reader(t, a, b)
	h, err := r.HeaderByNumber(context.Background(), big.NewInt(-3))
	if err != nil || h.Number.Uint64() != testHeight-5 {
		t.Fatalf("finalized %v, %v; want the lower %d", h, err, testHeight-5)
	}
}

func TestAProviderServingAnotherHeaderAtAHeightBlocksIt(t *testing.T) {
	final := header(testHeight, "final")
	fork := provider(11155111, final)
	fork.headers = map[uint64]*types.Header{testHeight: header(testHeight, "fork")}
	r := reader(t, provider(11155111, final), fork)
	if _, err := r.HeaderByNumber(context.Background(), big.NewInt(testHeight)); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a forked header was outvoted or ignored: %v", err)
	}
}

func TestAReaderRefusesFewerThanTwoIndependentProviders(t *testing.T) {
	final := header(testHeight, "final")
	p := provider(11155111, final)
	u := p.serve(t)
	if _, err := NewAgreeingReader(context.Background(), 11155111, []string{u}, time.Second); err == nil {
		t.Fatal("a single provider was accepted")
	}
	if _, err := NewAgreeingReader(context.Background(), 11155111, []string{u, u + "/again"}, time.Second); err == nil {
		t.Fatal("two URLs on one host were counted as two providers")
	}
	wrong := provider(84532, final)
	if _, err := NewAgreeingReader(context.Background(), 11155111, urlsOf(t, provider(11155111, final), wrong), time.Second); err == nil ||
		!strings.Contains(err.Error(), "serves chain 84532") {
		t.Fatalf("a provider of another chain was accepted: %v", err)
	}
}

// The live sequence through the finality rule: one provider serves a fork header at the height until the block is
// final; the other already serves the block that becomes final. Nothing is taken until both agree.
func TestTheFinalityRuleWaitsForProvidersToAgree(t *testing.T) {
	final := header(testHeight, "final")
	honest, forked := provider(11155111, final), provider(11155111, final)
	honest.finalized, forked.finalized = testHeight-10, testHeight-10
	forked.headers = map[uint64]*types.Header{testHeight: header(testHeight, "fork")}
	r := reader(t, honest, forked)
	go func() {
		time.Sleep(60 * time.Millisecond)
		for _, p := range []*stubProvider{honest, forked} {
			p.mu.Lock()
			p.finalized = testHeight + 32
			p.headers = map[uint64]*types.Header{testHeight: final}
			p.mu.Unlock()
		}
	}()
	got, err := SettledInFinalizedChain(context.Background(), r, common.HexToHash("0x0b0b"), time.Now().Add(3*time.Second), 10*time.Millisecond, nil)
	if err != nil || got.BlockHash != final.Hash() {
		t.Fatalf("(%v, %v)", got, err)
	}
	// A fork that never converges is named at the deadline, never accepted.
	stuck := provider(11155111, final)
	stuck.headers = map[uint64]*types.Header{testHeight: header(testHeight, "fork")}
	r2 := reader(t, provider(11155111, final), stuck)
	if _, err := SettledInFinalizedChain(context.Background(), r2, common.HexToHash("0x0b0b"), time.Now().Add(80*time.Millisecond), 10*time.Millisecond, nil); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a provider stuck on a fork: %v", err)
	}
}
