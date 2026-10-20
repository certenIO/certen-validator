package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// RB10-B16: a client read error that follows a keyed dial names the provider's host and not its key. The node answers
// what the stage needs and refuses the rest with an HTTP 403 whose body echoes the keyed URL, the way a gateway does.

const b16Key = "SECRETKEY-b16-0123456789"

type b16Node struct {
	mu    sync.Mutex
	calls map[string]int
	URL   string
}

func newB16Node(t *testing.T, answers func(method string, nth int) (result string, answered bool)) *b16Node {
	t.Helper()
	n := &b16Node{calls: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		n.mu.Lock()
		nth := n.calls[req.Method]
		n.calls[req.Method]++
		n.mu.Unlock()
		if result, ok := answers(req.Method, nth); ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result)
			return
		}
		http.Error(w, "forbidden: POST http://"+r.Host+r.URL.RequestURI()+" HTTP/1.1 for "+r.URL.RequestURI(), http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	n.URL = srv.URL + "/v2/" + b16Key
	return n
}

func b16Clean(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error", what)
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(text, b16Key) {
			t.Fatalf("%s: the error holds the key: %s", what, text)
		}
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("%s: the error does not name the host: %v", what, err)
	}
	var he rpc.HTTPError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("%s: errors.As does not reach the original rpc.HTTPError: %v", what, err)
	}
}

func b16Word(v *big.Int) string { return fmt.Sprintf(`"0x%064x"`, v) }

func TestB16_TheLayer5OnlineReadErrorsNameNoKey(t *testing.T) {
	txHash := "0x" + strings.Repeat("ab", 32)
	tx := fmt.Sprintf(`{"blockHash":null,"blockNumber":null,"from":"0x00000000000000000000000000000000000000a1","gas":"0x5208","gasPrice":"0x1","hash":"%s","input":"0x","nonce":"0x0","to":"0x00000000000000000000000000000000000000b1","transactionIndex":null,"value":"0x0","type":"0x0","v":"0x1b","r":"0x1","s":"0x1"}`, txHash)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l5 := &Layer5{AnchorTx: txHash}

	refuseAll := newB16Node(t, func(string, int) (string, bool) { return "", false })
	_, err := VerifyLayer5Online(ctx, refuseAll.URL, l5)
	b16Clean(t, "VerifyLayer5Online transaction", err)
	if !strings.Contains(err.Error(), "read anchor transaction") {
		t.Fatalf("the transaction read is not the stage reached: %v", err)
	}

	noReceipt := newB16Node(t, func(m string, _ int) (string, bool) { return tx, m == "eth_getTransactionByHash" })
	_, err = VerifyLayer5Online(ctx, noReceipt.URL, l5)
	b16Clean(t, "VerifyLayer5Online receipt", err)
	if !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("the receipt read is not the stage reached: %v", err)
	}
}

func TestB16_TheOutcomeOnlineReadErrorsNameNoKey(t *testing.T) {
	header := &types.Header{Number: big.NewInt(5), Difficulty: big.NewInt(0), Time: 1}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	blockHash := header.Hash()
	txHash := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000c1")
	receipt := fmt.Sprintf(`{"transactionHash":"%s","blockHash":"%s","blockNumber":"0x5","transactionIndex":"0x0","status":"0x1","gasUsed":"0x5208","cumulativeGasUsed":"0x5208","logs":[],"logsBloom":"0x%s","type":"0x0"}`,
		txHash.Hex(), blockHash.Hex(), strings.Repeat("00", 256))
	anchor := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	registry := common.HexToAddress("0x00000000000000000000000000000000000000b1")
	bundle := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000d1")
	root := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000e1")

	evidence := func(chainID int64) *OutcomeEvidence {
		e := &OutcomeEvidence{ChainID: chainID, Registry: registry.Hex()}
		e.Anchor.Address, e.Anchor.BundleID = anchor.Hex(), bundle.Hex()
		e.Record.OutcomeRoot, e.Record.Tx, e.Record.BlockNumber, e.Record.BlockHash = root.Hex(), txHash.Hex(), 5, blockHash.Hex()
		return e
	}
	// the three registry calls answer in the order the check makes them; any later eth_call (anchors) is refused
	calls := []string{b16Word(new(big.Int).SetBytes(anchor.Bytes())), b16Word(new(big.Int).SetBytes(root.Bytes())), b16Word(big.NewInt(5))}
	node := func(t *testing.T, chainID int64, refuse string) *b16Node {
		return newB16Node(t, func(m string, nth int) (string, bool) {
			if m == refuse {
				return "", false
			}
			switch m {
			case "eth_chainId":
				return fmt.Sprintf(`"0x%x"`, chainID), true
			case "eth_call":
				if nth < len(calls) {
					return calls[nth], true
				}
			case "eth_getBlockByNumber":
				return string(headerJSON), true
			case "eth_getTransactionReceipt":
				return receipt, true
			}
			return "", false
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name    string
		chainID int64
		refuse  string // the method refused from its first call on; "" lets the run reach anchors()
		want    string // the stage the error names
	}{
		{"chain id", 84532, "eth_chainId", "chain id:"},
		{"registry call", 84532, "eth_call", "anchor on"},
		{"canonical record block", 84532, "eth_getBlockByNumber", "the record's block 5"},
		{"record block's L1 number", 42161, "eth_getBlockByNumber", "the record's block 5"},
		{"record transaction", 84532, "eth_getTransactionReceipt", "the record transaction"},
		{"anchors record", 84532, "", "anchors("},
	} {
		n := node(t, tc.chainID, tc.refuse)
		_, err := VerifyOutcomeEvidenceOnline(ctx, n.URL, evidence(tc.chainID))
		b16Clean(t, tc.name, err)
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: the stage reached is not %q: %v", tc.name, tc.want, err)
		}
	}
}

type b16Endpoints struct{ url string }

func (e b16Endpoints) Chains() []int64 { return []int64{84532} }
func (e b16Endpoints) Endpoint(int64) (string, common.Address, error) {
	return e.url, common.Address{1}, nil
}

func TestB16_TheAnchorEventMonitorNamesNoKeyInItsErrorOrItsLog(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	logf := func(format string, a ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, a...))
	}
	logged := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(lines, "\n")
	}

	// the head cannot be read at the start: the error is returned
	refuse := newB16Node(t, func(string, int) (string, bool) { return "", false })
	err := (&AnchorEventMonitor{Endpoints: b16Endpoints{refuse.URL}, Logf: logf}).Start(context.Background())
	b16Clean(t, "Start head", err)

	// the head is read once and then refused: the poll logs it
	once := newB16Node(t, func(m string, nth int) (string, bool) { return `"0x1"`, m == "eth_blockNumber" && nth == 0 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := (&AnchorEventMonitor{Endpoints: b16Endpoints{once.URL}, Interval: 5 * time.Millisecond, Logf: logf}).Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logged(), "head unreadable") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	text := logged()
	if !strings.Contains(text, "head unreadable") {
		t.Fatalf("the poll never logged the refused head, so the sink was not reached:\n%s", text)
	}
	if strings.Contains(text, b16Key) {
		t.Fatalf("the log holds the key:\n%s", text)
	}
	if !strings.Contains(text, "127.0.0.1") {
		t.Fatalf("the log does not name the host:\n%s", text)
	}
}

func TestB16_TheG2StateReadFailureNamesNoKey(t *testing.T) {
	refuse := newB16Node(t, func(string, int) (string, bool) { return "", false })
	l := &b15Logger{}
	s := NewG2OutcomeBindingService(&G2Config{EthereumRPCURL: refuse.URL, VerificationTimeout: 20 * time.Second}, l)
	defer s.Close()
	to := common.HexToAddress("0x00000000000000000000000000000000000000b1")
	slot := common.HexToHash("0x01")
	ok, details := s.verifyStateChangeEffect(&ExternalChainResult{TxTo: &to}, &ExpectedEffect{EffectType: "state_change", ExpectedSlot: &slot}, map[string]interface{}{})
	msg, _ := details["error"].(string)
	if ok || !strings.Contains(msg, "eth_getStorageAt failed") {
		t.Fatalf("the storage read was not refused as expected: ok=%v details=%v", ok, details)
	}
	if strings.Contains(msg, b16Key) || strings.Contains(l.text(), b16Key) {
		t.Fatalf("the detail or the log holds the key: %q\n%s", msg, l.text())
	}
	if !strings.Contains(msg, "127.0.0.1") {
		t.Fatalf("the detail does not name the host: %q", msg)
	}
}
