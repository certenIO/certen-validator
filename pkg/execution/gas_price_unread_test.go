// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB3-F101: when the network gas price cannot be read, nothing is sent. refreshGasPrice used to keep
// the previous price and return nil, so the transaction went out past both ceilings unchecked.
func TestNothingIsSentOnAGasPriceNobodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream unavailable"}}`))
	}))
	defer srv.Close()
	cl, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	stale := big.NewInt(1)
	ecm := &EthereumContractManager{
		client: cl,
		auth:   &bind.TransactOpts{GasPrice: stale, GasLimit: 800000},
		config: &CertenContractConfig{ChainID: 84532, MaxGasPriceGwei: 50},
	}
	if err := ecm.refreshGasPrice(context.Background()); err == nil {
		t.Fatalf("the gas price could not be read and the send went ahead at %v wei", ecm.auth.GasPrice)
	}
	if ecm.auth.GasPrice != stale {
		t.Fatal("the gas price changed although none was read")
	}
}
