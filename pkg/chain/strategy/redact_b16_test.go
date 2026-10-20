package strategy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B16: a client read error that follows a keyed dial names the provider's host and not its key. The node answers
// the methods in ok and refuses every other request with an HTTP 403 whose body echoes the keyed URL, as a gateway does.

const b16Key = "SECRETKEY-b16-0123456789"

func b16Node(t *testing.T, ok map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if result, answered := ok[req.Method]; answered {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result)
			return
		}
		http.Error(w, "forbidden: POST http://"+r.Host+r.URL.RequestURI()+" HTTP/1.1 for "+r.URL.RequestURI(), http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v2/" + b16Key
}

func b16Check(t *testing.T, what string, err error, logged *bytes.Buffer) {
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
	if strings.Contains(logged.String(), b16Key) {
		t.Fatalf("%s: the log holds the key:\n%s", what, logged.String())
	}
}

func b16Capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logged bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(saved) })
	return &logged
}

func TestB16_TheStrategyConstructorChainIDErrorNamesNoKey(t *testing.T) {
	logged := b16Capture(t)
	_, err := NewEVMStrategy(&EVMStrategyConfig{ChainConfig: &ChainConfig{NetworkName: "b16-net", RPC: b16Node(t, nil)}})
	b16Check(t, "NewEVMStrategy", err, logged)
	if !strings.Contains(err.Error(), "get chain ID") {
		t.Fatalf("the refusal is not named: %v", err)
	}
}

func TestB16_TheStrategyReadErrorsNameNoKey(t *testing.T) {
	logged := b16Capture(t)
	tx := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000a1")
	blk := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000b1")
	receipt := fmt.Sprintf(`{"transactionHash":"%s","blockHash":"%s","blockNumber":"0x5","transactionIndex":"0x0","status":"0x1","gasUsed":"0x5208","cumulativeGasUsed":"0x5208","logs":[],"logsBloom":"0x%s","type":"0x0"}`,
		tx.Hex(), blk.Hex(), strings.Repeat("00", 256))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dial := func(ok map[string]string) *EVMStrategy {
		client, err := ethrpc.DialRetrying(context.Background(), b16Node(t, ok)) // registers the key, as every production dial does
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		return &EVMStrategy{client: client, chainID: big.NewInt(84532), auth: &bind.TransactOpts{}}
	}

	_, err := dial(nil).GetTransactionReceipt(ctx, tx.Hex())
	b16Check(t, "GetTransactionReceipt", err, logged)
	_, err = dial(map[string]string{"eth_getTransactionReceipt": receipt}).GetTransactionReceipt(ctx, tx.Hex())
	b16Check(t, "GetTransactionReceipt header", err, logged)
	if !strings.Contains(err.Error(), "header for the receipt's time") {
		t.Fatalf("the header refusal is not the one reached: %v", err)
	}
	_, err = dial(nil).EstimateGas(ctx, &AnchorRequest{})
	b16Check(t, "EstimateGas", err, logged)
	b16Check(t, "HealthCheck block number", dial(nil).HealthCheck(ctx), logged)
	b16Check(t, "HealthCheck chain id", dial(map[string]string{"eth_blockNumber": `"0x20"`}).HealthCheck(ctx), logged)
}
