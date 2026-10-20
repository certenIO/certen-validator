package execution

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
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B14a (V-R10B5 D3): what the observers and the outcome builder return, store or log of a provider's failure carries no
// credential, and the errors keep their types.

func b14aLeaky(key string) error {
	return &url.Error{Op: "Post", URL: "https://eth-sepolia.g.alchemy.com/v2/" + key, Err: syscall.ECONNREFUSED}
}

func b14aNoKey(t *testing.T, what, key, got string) {
	t.Helper()
	if strings.Contains(got, key) {
		t.Fatalf("%s holds the key %q:\n%s", what, key, got)
	}
}

// echoNode answers every JSON-RPC request with an error that echoes the request the way a gateway does: the full URL, and the
// path alone.
func echoNode(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		msg := fmt.Sprintf("Post \\\"http://%s%s\\\": denied; The requested URL %s was not found", r.Host, r.URL.RequestURI(), r.URL.RequestURI())
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s"}}`, req.ID, msg)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestB14a_TheObserverReturnsAndLogsNoProviderKey(t *testing.T) {
	const key = "SECRETKEY-observer-0101a"
	tx := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000b0b")
	canon := canonicalAt(11832868)
	n := &reorgNode{tx: tx, height: 11832868, finalized: 11832900, canonical: canon,
		orphan: common.HexToHash("0x0ff1ce00000000000000000000000000000000000000000000000000000000aa"), inBlock: true}
	good := n.serve(t)
	echoURL := echoNode(t) + "/v2/" + key
	ethrpc.RegisterProviderURL(echoURL) // what NewExternalChainObserver does for its single client
	rc, err := ethclient.Dial(echoURL)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	o := &ExternalChainObserver{ethClient: rc, finality: good, chainID: 11155111, pollingInterval: 5 * time.Millisecond, timeout: 2 * time.Second,
		logger: log.New(&logged, "", 0)}
	_, err = o.ObserveTransaction(context.Background(), tx)
	if err == nil || !strings.Contains(err.Error(), "get transaction") {
		t.Fatalf("the transaction read should fail by name: %v", err)
	}
	b14aNoKey(t, "the observer's returned error", key, err.Error())
	b14aNoKey(t, "the observer's log", key, logged.String())
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("the provider's answer must still be told: %v", err)
	}
	// the provider's own error type is still reachable
	var jerr interface{ ErrorCode() int }
	if !errors.As(err, &jerr) || jerr.ErrorCode() != -32000 {
		t.Fatalf("the JSON-RPC error code is no longer reachable through the redacted error: %v", err)
	}
	// the receipt poll's log line
	logged.Reset()
	o.log("⚠️ [OBSERVER] Error getting receipt: %v", b14aLeaky(key))
	if logged.Len() == 0 {
		t.Fatal("nothing logged")
	}
	b14aNoKey(t, "the receipt poll's log", key, logged.String())
}

func TestB14a_AnObserverWithoutAgreeingProvidersRefusesWithNoKey(t *testing.T) {
	const key = "SECRETKEY-observer-0102a"
	var logged bytes.Buffer
	o := &ExternalChainObserver{finalityErr: fmt.Errorf("chain 1: %w", b14aLeaky(key)), chainID: 1, pollingInterval: time.Millisecond, timeout: time.Second,
		logger: log.New(&logged, "", 0)}
	_, err := o.ObserveTransaction(context.Background(), common.HexToHash("0x01"))
	if err == nil {
		t.Fatal("an observer without providers observed")
	}
	b14aNoKey(t, "the refusal", key, err.Error())
	b14aNoKey(t, "the log", key, logged.String())
}

func TestB14a_TheStoredInclusionErrorNamesNoKey(t *testing.T) {
	const key = "SECRETKEY-observer-0103a"
	r := &ExternalChainResult{inclusionErr: fmt.Errorf("the block cannot be proven: %w", b14aLeaky(key))}
	err := r.VerifyInclusionProofs()
	if err == nil {
		t.Fatal("a result with no proofs verified")
	}
	b14aNoKey(t, "VerifyInclusionProofs", key, err.Error())
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("the inclusion error no longer unwraps to its cause: %v", err)
	}
}

func TestB14a_TheOutcomeBuilderWrapsNoProviderKey(t *testing.T) {
	const key = "SECRETKEY-outcome-0104ab"
	leak := b14aLeaky(key)
	for _, failAt := range []string{"getValidatorCount", "blsThresholdNumerator", "blsThresholdDenominator", "totalVotingPower", "validatorList", "validators"} {
		t.Run(failAt, func(t *testing.T) {
			call := func(method string, args ...interface{}) ([]interface{}, error) {
				if method == failAt {
					return nil, leak
				}
				switch method {
				case "getValidatorCount":
					return []interface{}{big.NewInt(1)}, nil
				case "validatorList":
					return []interface{}{common.HexToAddress("0x01")}, nil
				}
				return []interface{}{big.NewInt(1)}, nil
			}
			_, err := readQuorumRegistry(call)
			if err == nil {
				t.Fatal("a failing provider read produced a registry")
			}
			b14aNoKey(t, "the registry error", key, err.Error())
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("the registry error no longer unwraps to its cause: %v", err)
			}
			var ue *url.Error
			if !errors.As(err, &ue) || ue != leak {
				t.Fatalf("errors.As lost the original url.Error: %v", err)
			}
		})
	}
}
