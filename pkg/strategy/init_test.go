// Copyright 2026 Certen Protocol

package strategy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// RB3-F44: the registry is exactly the chains CERTEN settles on, each observed at the anchor the batch
// path settles on, attested with BLS; anything missing is a startup error, and nothing else is in it.

func blsKey(t *testing.T) []byte {
	t.Helper()
	sk, _, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Bytes()
}

// chainIDStub answers eth_chainId with the chain id in the request path (/<id>).
var chainIDStub = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/"), 10, 64)
	w.Header().Set("Content-Type", "application/json")
	if req.Method != "eth_chainId" {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed"}}`, req.ID)
		return
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x%x"}`, req.ID, id)
})

// Two providers on distinct hosts (RB5-F53: a settlement chain needs independent providers that agree): the primary on
// 127.0.0.1 and a second operator on [::1].
var rpcStub = httptest.NewServer(chainIDStub)

var rpcStub2 = func() *httptest.Server {
	s := httptest.NewUnstartedServer(chainIDStub)
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		panic(fmt.Sprintf("second provider stub: %v", err))
	}
	s.Listener = l
	s.Start()
	return s
}()

func rpcFor(chainID int64) string { return rpcStub.URL + "/" + strconv.FormatInt(chainID, 10) }

func secondProviderFor(chainID int64) string {
	return rpcStub2.URL + "/" + strconv.FormatInt(chainID, 10)
}

// withSecondProviders configures every supported chain's second provider the way production does, through
// <PREFIX>_URL_FALLBACKS.
func withSecondProviders(t *testing.T) {
	t.Helper()
	t.Setenv("ETHEREUM_SEPOLIA_URL_FALLBACKS", secondProviderFor(11155111))
	t.Setenv("BASE_SEPOLIA_URL_FALLBACKS", secondProviderFor(84532))
	t.Setenv("ARBITRUM_SEPOLIA_URL_FALLBACKS", secondProviderFor(421614))
}

// RB5-F53: a settlement chain with one provider is refused at boot, naming the chain and its single host.
func TestARegistryRefusesASettlementChainWithOneProvider(t *testing.T) {
	_, err := InitializeRegistry(&RegistryConfig{ValidatorID: "validator-1", BLSPrivateKey: blsKey(t), SettlementChains: SupportedChainIDs, Chains: supportedEndpoints()})
	if err == nil || !strings.Contains(err.Error(), "RB5-F53") {
		t.Fatalf("a settlement chain observed through one provider was accepted: %v", err)
	}
	withSecondProviders(t)
	if _, err := InitializeRegistry(&RegistryConfig{ValidatorID: "validator-1", BLSPrivateKey: blsKey(t), SettlementChains: SupportedChainIDs, Chains: supportedEndpoints()}); err != nil {
		t.Fatalf("two independent providers per chain were refused: %v", err)
	}
}

func supportedEndpoints() []ChainEndpoint {
	return []ChainEndpoint{
		{ChainID: 11155111, RPC: rpcFor(11155111), Anchor: common.HexToAddress("0x14885Fe8e7b6a4bE0000000000000000000000a1")},
		{ChainID: 84532, RPC: rpcFor(84532), Anchor: common.HexToAddress("0x14885Fe8e7b6a4bE0000000000000000000000a2")},
		{ChainID: 421614, RPC: rpcFor(421614), Anchor: common.HexToAddress("0x14885Fe8e7b6a4bE0000000000000000000000a3")},
	}
}

func TestRegistryIsExactlyTheSupportedChains(t *testing.T) {
	withSecondProviders(t)
	r, err := InitializeRegistry(&RegistryConfig{ValidatorID: "validator-1", BLSPrivateKey: blsKey(t), SettlementChains: SupportedChainIDs, Chains: supportedEndpoints()})
	if err != nil {
		t.Fatalf("InitializeRegistry: %v", err)
	}
	ids := r.ListChainIDs()
	sort.Strings(ids)
	if strings.Join(ids, ",") != "11155111,421614,84532" {
		t.Fatalf("registered chains %v, want exactly the three supported chains", ids)
	}
	for _, c := range supportedEndpoints() {
		got, err := r.GetChainConfig(strconv.FormatInt(c.ChainID, 10))
		if err != nil {
			t.Fatalf("chain %d: %v", c.ChainID, err)
		}
		if !strings.EqualFold(got.ContractAddress, c.Anchor.Hex()) || got.RPC != c.RPC {
			t.Fatalf("chain %d observed at %s via %s, want the batch path's anchor %s via %s",
				c.ChainID, got.ContractAddress, got.RPC, c.Anchor.Hex(), c.RPC)
		}
		if _, att, err := r.GetStrategiesForChain(got.ChainID); err != nil || att == nil || att.Scheme() != "bls12-381" {
			t.Fatalf("chain %d attests with %v (%v), want BLS12-381", c.ChainID, att, err)
		}
	}
	if schemes := r.ListAttestationSchemes(); len(schemes) != 1 {
		t.Fatalf("attestation schemes %v, want BLS12-381 alone", schemes)
	}
}

func TestRegistryLookupsTakeTheChainIDInEitherRecordedForm(t *testing.T) {
	withSecondProviders(t)
	r, err := InitializeRegistry(&RegistryConfig{ValidatorID: "validator-1", BLSPrivateKey: blsKey(t), SettlementChains: SupportedChainIDs, Chains: supportedEndpoints()})
	if err != nil {
		t.Fatal(err)
	}
	// The batch path records a batch's chain as "evm-<id>" (anchor_batches.target_chain).
	for _, key := range []string{"84532", "evm-84532"} {
		if _, err := r.GetChainStrategy(key); err != nil {
			t.Fatalf("lookup %q: %v", key, err)
		}
	}
	// A network name, or a chain CERTEN does not settle on, is refused - never resolved to another chain.
	for _, key := range []string{"base-sepolia", "sepolia", "1", "evm-10", "11155420", ""} {
		if _, err := r.GetChainStrategy(key); err == nil {
			t.Fatalf("lookup %q must be refused", key)
		}
	}
	if err := r.RegisterChainStrategy("base-sepolia", &chain.ChainConfig{}, nil); err == nil {
		t.Fatal("registering under a name must be refused")
	}
}

func TestRegistryRefusesAnIncompleteConfiguration(t *testing.T) {
	withSecondProviders(t)
	without := func(id int64) []ChainEndpoint {
		var out []ChainEndpoint
		for _, c := range supportedEndpoints() {
			if c.ChainID != id {
				out = append(out, c)
			}
		}
		return out
	}
	noRPC := supportedEndpoints()
	noRPC[1].RPC = ""
	noAnchor := supportedEndpoints()
	noAnchor[2].Anchor = common.Address{}
	extra := append(supportedEndpoints(), ChainEndpoint{ChainID: 11155420, RPC: rpcFor(11155420), Anchor: common.HexToAddress("0x01")})
	wrongChain := supportedEndpoints()
	wrongChain[1].RPC = rpcFor(11155111) // Base configured with an RPC that serves Sepolia
	twice := append(supportedEndpoints(), supportedEndpoints()[0])

	all := SupportedChainIDs
	for name, cfg := range map[string]*RegistryConfig{
		"no BLS key":                           {SettlementChains: all, Chains: supportedEndpoints()},
		"unreadable BLS key":                   {BLSPrivateKey: []byte{1, 2, 3}, SettlementChains: all, Chains: supportedEndpoints()},
		"a settlement chain absent":            {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: without(84532)},
		"a chain with no RPC":                  {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: noRPC},
		"a chain with no anchor":               {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: noAnchor},
		"an unsupported chain":                 {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: extra},
		"a chain twice":                        {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: twice},
		"an RPC serving another chain":         {BLSPrivateKey: blsKey(t), SettlementChains: all, Chains: wrongChain},
		"no settlement chains":                 {BLSPrivateKey: blsKey(t), Chains: supportedEndpoints()},
		"an unsupported settlement chain":      {BLSPrivateKey: blsKey(t), SettlementChains: []int64{84532, 97}, Chains: without(11155111)},
		"a chain beside the settlement chains": {BLSPrivateKey: blsKey(t), SettlementChains: []int64{84532}, Chains: supportedEndpoints()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InitializeRegistry(cfg); err == nil {
				t.Fatal("must be a startup error")
			}
		})
	}
}

// RB5-F33: a rollout settles on the chains it names; the proof cycle observes exactly those - Base alone here - and a
// supported chain not named is neither observed nor required.
func TestTheRegistryObservesExactlyTheSettlementChains(t *testing.T) {
	withSecondProviders(t)
	var base []ChainEndpoint
	for _, c := range supportedEndpoints() {
		if c.ChainID == 84532 {
			base = append(base, c)
		}
	}
	r, err := InitializeRegistry(&RegistryConfig{ValidatorID: "validator-1", BLSPrivateKey: blsKey(t), SettlementChains: []int64{84532}, Chains: base})
	if err != nil {
		t.Fatal(err)
	}
	if ids := r.ListChainIDs(); len(ids) != 1 || ids[0] != "84532" {
		t.Fatalf("observed chains %v, want only 84532", ids)
	}
}
