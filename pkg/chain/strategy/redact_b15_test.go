package strategy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B15 (V-R10B7 D3): the TRON / non-standard-chain path of the observer and the strategy's dial return and log no key.

const b15Key = "ZkQ9xPLm2Tn7VbR4sWcY8dHgJf1A5eUo"

// A node whose receipt and block-number reads answer and whose header and transaction reads fail with a body that echoes
// the request URL, the way a gateway does.
func b15TronNode(t *testing.T, tx common.Hash) string {
	t.Helper()
	blk := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000b1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "eth_getTransactionReceipt":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"transactionHash":"%s","blockHash":"%s","blockNumber":"0x5","transactionIndex":"0x0","status":"0x1","gasUsed":"0x5208","cumulativeGasUsed":"0x5208","logs":[],"logsBloom":"0x%s","type":"0x0"}}`,
				req.ID, tx.Hex(), blk.Hex(), strings.Repeat("00", 256))
		case "eth_blockNumber":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x20"}`, req.ID)
		default:
			http.Error(w, "unknown route; POST http://"+r.Host+r.URL.RequestURI()+" HTTP/1.1; The requested URL "+r.URL.RequestURI()+" was not found", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestB15_D3_TheTronPathLogsNoProviderKey(t *testing.T) {
	tx := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000a1")
	endpoint := b15TronNode(t, tx) + "/v2/" + b15Key
	client, err := ethrpc.DialRetrying(context.Background(), endpoint) // registers the key, as every production dial does
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var logged bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(saved)

	o := &EVMObserver{client: client, chainID: 728126428, pollingInterval: time.Millisecond, requiredConfirmations: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := o.observeTron(ctx, tx, time.Now().Add(20*time.Second))
	if err != nil || res == nil {
		t.Fatalf("the receipt-only observation should succeed: %v", err)
	}
	text := logged.String()
	for _, want := range []string{"HeaderByHash failed", "TransactionByHash failed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the log has no %q line, so the sink was not reached:\n%s", want, text)
		}
	}
	if strings.Contains(text, b15Key) {
		t.Fatalf("the log holds the key:\n%s", text)
	}
}

func TestB15_D3_TheStrategyDialNamesNoKeyForAMalformedURL(t *testing.T) {
	for _, raw := range []string{
		"https://eth-sepolia.g.alchemy.com/v2/" + b15Key + "%zz",
		"https://eth-sepolia.g.alchemy.com:99999x/v2/" + b15Key,
		"https://eth-sepolia.g.alchemy.com\x7f/v2/" + b15Key,
	} {
		_, _, err := dialFirstReachable([]string{raw}, "")
		if err == nil {
			t.Fatalf("%q was dialed", raw)
		}
		if strings.Contains(err.Error(), b15Key) || strings.Contains(fmt.Sprintf("%+v", err), b15Key) {
			t.Fatalf("the error holds the key: %v", err)
		}
	}
}
