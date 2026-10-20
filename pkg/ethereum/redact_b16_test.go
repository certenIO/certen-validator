package ethereum

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

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// RB10-B16: a client read error that follows a keyed dial names the provider's host and not its key. The node answers
// eth_chainId, then refuses every other request with an HTTP 403 whose body echoes the keyed URL, the way a gateway does.

const b16Key = "SECRETKEY-b16-0123456789"

func b16Node(t *testing.T, chainIDOK bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if chainIDOK && req.Method == "eth_chainId" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x14a34"}`, req.ID)
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
	if logged.Len() != 0 && strings.Contains(logged.String(), b16Key) {
		t.Fatalf("%s: the log holds the key:\n%s", what, logged.String())
	}
}

func TestB16_TheChainIDReadErrorNamesNoKey(t *testing.T) {
	var logged bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(saved)
	_, err := NewClient(b16Node(t, false))
	b16Check(t, "NewClient", err, &logged)
	if !strings.Contains(err.Error(), "ETHEREUM_URL: reading eth_chainId") {
		t.Fatalf("the refusal is not named: %v", err)
	}
}

func TestB16_EveryClientReadAndSendErrorNamesNoKey(t *testing.T) {
	var logged bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(saved)
	c, err := NewClient(b16Node(t, true))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := common.HexToAddress("0x00000000000000000000000000000000000000b1")
	const abiJSON = `[{"type":"function","name":"f","inputs":[],"outputs":[],"stateMutability":"view"}]`
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyHex := fmt.Sprintf("%x", crypto.FromECDSA(key))

	_, err = c.GetBalance(ctx, addr)
	b16Check(t, "GetBalance", err, &logged)
	_, err = c.GetNonce(ctx, addr)
	b16Check(t, "GetNonce", err, &logged)
	_, err = c.GetGasPrice(ctx)
	b16Check(t, "GetGasPrice", err, &logged)
	_, err = c.EstimateGas(ctx, ethereum.CallMsg{To: &addr})
	b16Check(t, "EstimateGas", err, &logged)
	b16Check(t, "Health", c.Health(ctx), &logged)
	_, err = c.GetHeader(ctx, big.NewInt(1))
	b16Check(t, "GetHeader", err, &logged)
	_, err = c.GetLatestBlockNumber(ctx)
	b16Check(t, "GetLatestBlockNumber", err, &logged)
	_, _, err = c.GetBlockInfo(ctx, 1)
	b16Check(t, "GetBlockInfo", err, &logged)
	_, err = c.CallContract(ctx, addr, abiJSON, "f")
	b16Check(t, "CallContract", err, &logged)
	_, err = c.SendContractTransaction(ctx, addr, abiJSON, keyHex, "f", 21000)
	b16Check(t, "SendContractTransaction", err, &logged)
	_, err = c.SendContractTransactionWithRetry(ctx, addr, abiJSON, keyHex, "f", 21000, 2)
	b16Check(t, "SendContractTransactionWithRetry", err, &logged)
}
