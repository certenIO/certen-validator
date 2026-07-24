package billing

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Fee-model tests against recorded node responses.
//
// These matter more than they look: every constant here is applied to real
// money on every intent, forever, and a wrong denominator misprices a chain by
// orders of magnitude in a direction nobody notices until reconciliation runs.
// The non-EVM models are each wrong in a *specific* way if implemented
// naively, and there is a test below for each of those specific ways.

func rpcServer(t *testing.T, result string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`))
	}))
}

func restServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func probeOrFail(t *testing.T, cfg ProbeConfig, tx string) *ChainCost {
	t.Helper()
	p, err := NewProbe(cfg)
	if err != nil {
		t.Fatalf("NewProbe: %v", err)
	}
	cost, err := p.ObservedCost(context.Background(), tx)
	if err != nil {
		t.Fatalf("ObservedCost: %v", err)
	}
	if err := cost.Validate(); err != nil {
		t.Fatalf("cost failed validation (the gateway would recompute a different number): %v", err)
	}
	return cost
}

func TestEVMUsesEffectiveGasPrice(t *testing.T) {
	// 369,000 gas at 15 gwei — the measured anchor leg from the cost sheet.
	srv := rpcServer(t, `{"gasUsed":"0x5A168","effectiveGasPrice":"0x37E11D600","blockNumber":"0x112A880","status":"0x1"}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "ethereum", RPCURL: srv.URL, Leg: LegAnchor}, "0xabc")

	if cost.GasUsed != 369000 {
		t.Fatalf("gas used = %d, want 369000", cost.GasUsed)
	}
	if cost.GasPriceWei.String() != "15000000000" {
		t.Fatalf("gas price = %s, want 15000000000", cost.GasPriceWei)
	}
	if cost.NativeAmount.String() != "5535000000000000" { // 0.005535 ETH
		t.Fatalf("native amount = %s", cost.NativeAmount)
	}
	if cost.WeiPerNative.String() != "1000000000000000000" {
		t.Fatalf("EVM must use 1e18, got %s", cost.WeiPerNative)
	}
	if cost.NativeSymbol != "ETH" {
		t.Fatalf("symbol = %s", cost.NativeSymbol)
	}
}

func TestEVMIncludesOPStackL1DataFee(t *testing.T) {
	// On Base/Optimism the L1 data fee is a large share of the total. Reading
	// only L2 execution gas under-charges every intent on those chains.
	srv := rpcServer(t, `{"gasUsed":"0x5A168","effectiveGasPrice":"0x2FAF080","blockNumber":"0x10","l1Fee":"0x2386F26FC10000"}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "base", RPCURL: srv.URL, Leg: LegAnchor}, "0xabc")

	l2 := new(big.Int).Mul(big.NewInt(369000), big.NewInt(50000000))
	l1, _ := new(big.Int).SetString("10000000000000000", 10)
	want := new(big.Int).Add(l2, l1)
	if cost.NativeAmount.Cmp(want) != 0 {
		t.Fatalf("total = %s, want %s (L2 execution + L1 data fee)", cost.NativeAmount, want)
	}
	if cost.Breakdown["l1_data_fee_wei"] == "" {
		t.Fatal("L1 data fee must be recorded in the breakdown")
	}
}

func TestEVMFallsBackToTxGasPriceWhenReceiptOmitsIt(t *testing.T) {
	// A pre-EIP-1559 node omits effectiveGasPrice. Reporting zero there would
	// record the transaction as free.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		calls++
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "eth_getTransactionReceipt" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"gasUsed":"0x5208","blockNumber":"0x1"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"gasPrice":"0x3B9ACA00"}}`))
	}))
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "bsc", RPCURL: srv.URL, Leg: LegVerify}, "0xabc")
	if cost.GasPriceWei.String() != "1000000000" {
		t.Fatalf("expected fallback to tx gasPrice, got %s", cost.GasPriceWei)
	}
	if cost.NativeSymbol != "BNB" {
		t.Fatalf("bsc symbol = %s, want BNB", cost.NativeSymbol)
	}
	if calls < 2 {
		t.Fatal("expected a second call to eth_getTransactionByHash")
	}
}

func TestSolanaUsesMetaFeeAndExcludesRent(t *testing.T) {
	// meta.fee is the final total (base + priority). Rent leaves the payer's
	// balance as a refundable deposit and must NOT be billed as gas.
	srv := rpcServer(t, `{"slot":123456,"meta":{"fee":5000,"preBalances":[1000000000],"postBalances":[997895000]}}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "solana", RPCURL: srv.URL, Leg: LegAnchor}, "sig")

	if cost.NativeAmount.String() != "5000" {
		t.Fatalf("fee = %s lamports, want 5000 (rent must not be billed)", cost.NativeAmount)
	}
	if cost.WeiPerNative.String() != "1000000000" {
		t.Fatalf("solana denominator = %s, want 1e9 lamports/SOL", cost.WeiPerNative)
	}
	if cost.Breakdown["payer_rent_lamports"] != "2100000" {
		t.Fatalf("rent should be recorded but not billed, got %q", cost.Breakdown["payer_rent_lamports"])
	}
	if cost.BlockNumber != "123456" {
		t.Fatalf("slot = %s", cost.BlockNumber)
	}
}

func TestSuiSubtractsStorageRebate(t *testing.T) {
	// The rebate is money genuinely returned. Billing the gross
	// (computation + storage) over-charges every Sui intent.
	srv := rpcServer(t, `{"checkpoint":"9001","effects":{"gasUsed":{
		"computationCost":"1000000","storageCost":"2960000","storageRebate":"2900000",
		"nonRefundableStorageFee":"29000"},"status":{"status":"success"}}}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "sui", RPCURL: srv.URL, Leg: LegVaultExecute}, "digest")

	// 1,000,000 + 2,960,000 - 2,900,000 = 1,060,000 MIST
	if cost.NativeAmount.String() != "1060000" {
		t.Fatalf("net = %s MIST, want 1060000", cost.NativeAmount)
	}
	if cost.Breakdown["storage_rebate_mist"] != "2900000" {
		t.Fatal("rebate must be recorded for audit")
	}
	if cost.NativeSymbol != "SUI" || cost.WeiPerNative.String() != "1000000000" {
		t.Fatalf("sui denomination wrong: %s %s", cost.NativeSymbol, cost.WeiPerNative)
	}
}

func TestSuiClampsNetNegativeToZero(t *testing.T) {
	// A rebate exceeding costs is a real Sui outcome (we were paid to free
	// storage). Billing a negative would credit the customer for gas.
	srv := rpcServer(t, `{"checkpoint":"1","effects":{"gasUsed":{
		"computationCost":"1000","storageCost":"1000","storageRebate":"50000"}}}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "sui", RPCURL: srv.URL, Leg: LegAnchor}, "d")
	if cost.NativeAmount.Sign() != 0 {
		t.Fatalf("net-negative must clamp to 0, got %s", cost.NativeAmount)
	}
}

func TestAptosUsesOctaDenomination(t *testing.T) {
	srv := restServer(t, `{"version":"778899","gas_used":"1500","gas_unit_price":"100","success":true,"storage_fee_octas":"5000"}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "aptos", RPCURL: srv.URL, Leg: LegVerify}, "0xdead")

	if cost.NativeAmount.String() != "150000" {
		t.Fatalf("fee = %s octas, want 150000", cost.NativeAmount)
	}
	if cost.WeiPerNative.String() != "100000000" {
		t.Fatalf("aptos denominator = %s, want 1e8 octas/APT", cost.WeiPerNative)
	}
	if cost.BlockNumber != "778899" {
		t.Fatalf("version = %s", cost.BlockNumber)
	}
}

func TestNearSumsReceiptBurnsNotJustTheTransaction(t *testing.T) {
	// A cross-contract call does most of its work in receipts. Reading only
	// transaction_outcome understates the cost by most of it.
	srv := rpcServer(t, `{"transaction_outcome":{"block_hash":"B","outcome":{"tokens_burnt":"241000000000000000000"}},
		"receipts_outcome":[
			{"outcome":{"tokens_burnt":"2000000000000000000000"}},
			{"outcome":{"tokens_burnt":"3000000000000000000000"}}]}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "near", RPCURL: srv.URL, APIKey: "certen.testnet", Leg: LegAnchor}, "txhash")

	want, _ := new(big.Int).SetString("5241000000000000000000", 10)
	if cost.NativeAmount.Cmp(want) != 0 {
		t.Fatalf("burn = %s, want %s (transaction + all receipts)", cost.NativeAmount, want)
	}
	if cost.WeiPerNative.String() != "1000000000000000000000000" {
		t.Fatalf("near denominator = %s, want 1e24 yocto/NEAR", cost.WeiPerNative)
	}
	if cost.Breakdown["receipt_count"] != "2" {
		t.Fatalf("receipt count = %q", cost.Breakdown["receipt_count"])
	}
}

func TestNearRefusesWhenNothingBurnt(t *testing.T) {
	// Zero burn means the transaction is not final. Reporting it as free would
	// record a real cost as zero, permanently.
	srv := rpcServer(t, `{"transaction_outcome":{"outcome":{"tokens_burnt":"0"}},"receipts_outcome":[]}`)
	defer srv.Close()

	p, _ := NewProbe(ProbeConfig{Chain: "near", RPCURL: srv.URL, Leg: LegAnchor})
	if _, err := p.ObservedCost(context.Background(), "tx"); err == nil {
		t.Fatal("expected an error rather than a zero-cost report")
	}
}

func TestTonAddsForwardFees(t *testing.T) {
	// Forward fees are charged for messages this transaction SENT. Every
	// proof-gated call is multi-message, so omitting them under-reports.
	srv := restServer(t, `{"ok":true,"result":[{"fee":"1200000","storage_fee":"300","other_fee":"500",
		"transaction_id":{"lt":"44556677","hash":"h"},
		"out_msgs":[{"fwd_fee":"400000"},{"fwd_fee":"100000"}]}]}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "ton", RPCURL: srv.URL, APIKey: "k", Leg: LegVaultExecute}, "hash")

	if cost.NativeAmount.String() != "1700000" {
		t.Fatalf("total = %s nanoton, want 1700000 (fee + forward fees)", cost.NativeAmount)
	}
	if cost.WeiPerNative.String() != "1000000000" {
		t.Fatalf("ton denominator = %s, want 1e9 nanoton/TON", cost.WeiPerNative)
	}
	if cost.BlockNumber != "44556677" {
		t.Fatalf("lt = %s", cost.BlockNumber)
	}
}

func TestTronFlagsStakedEnergyAsFreeAtMargin(t *testing.T) {
	// TRON genuinely charges nothing when staked energy covers the call. That
	// is not free: the stake has a carrying cost no receipt can see. The flag
	// forces pricing to make that an explicit decision.
	srv := restServer(t, `{"id":"txid","fee":0,"blockNumber":55,
		"receipt":{"energy_usage":130000,"energy_fee":0,"energy_usage_total":130000,"net_usage":345,"net_fee":0,"result":"SUCCESS"}}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "tron", RPCURL: srv.URL + "/jsonrpc", Leg: LegAnchor}, "txid")

	if cost.NativeAmount.Sign() != 0 {
		t.Fatalf("burned = %s, want 0", cost.NativeAmount)
	}
	if !cost.FreeAtMargin {
		t.Fatal("a staked-resource transaction must be flagged FreeAtMargin, or pricing will conclude TRON is free")
	}
	if cost.Breakdown["energy_usage"] != "130000" {
		t.Fatalf("energy usage must be recorded for stake amortization, got %q", cost.Breakdown["energy_usage"])
	}
}

func TestTronBillsBurnedTrxWhenStakeIsInsufficient(t *testing.T) {
	srv := restServer(t, `{"id":"txid","fee":1100000,"blockNumber":56,
		"receipt":{"energy_usage":0,"energy_fee":1000000,"net_usage":0,"net_fee":100000,"result":"SUCCESS"}}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "tron", RPCURL: srv.URL, Leg: LegAnchor}, "txid")

	if cost.NativeAmount.String() != "1100000" {
		t.Fatalf("burned = %s sun, want 1100000 (energy_fee + net_fee)", cost.NativeAmount)
	}
	if cost.FreeAtMargin {
		t.Fatal("a transaction that burned TRX is not free at the margin")
	}
	if cost.WeiPerNative.String() != "1000000" {
		t.Fatalf("tron denominator = %s, want 1e6 sun/TRX", cost.WeiPerNative)
	}
}

func TestCardanoBillsFeesNotRefundableDeposits(t *testing.T) {
	// A UTxO min-ADA deposit is returned when the output is spent. Billing it
	// would charge the customer for money we still hold.
	srv := restServer(t, `{"hash":"h","fees":"174389","deposit":"2000000","size":512,"block_height":9911}`)
	defer srv.Close()

	cost := probeOrFail(t, ProbeConfig{Chain: "cardano", RPCURL: srv.URL, APIKey: "proj", Leg: LegAnchor}, "h")

	if cost.NativeAmount.String() != "174389" {
		t.Fatalf("fee = %s lovelace, want 174389 (deposit excluded)", cost.NativeAmount)
	}
	if cost.Breakdown["refundable_deposit_lovelace"] != "2000000" {
		t.Fatal("the refundable deposit must be recorded but not billed")
	}
	if cost.WeiPerNative.String() != "1000000" {
		t.Fatalf("cardano denominator = %s, want 1e6 lovelace/ADA", cost.WeiPerNative)
	}
}

func TestUnknownChainIsRefusedNotDefaultedToEVM(t *testing.T) {
	// Silently applying the EVM fee model to an unknown chain is how a chain
	// gets mispriced by orders of magnitude.
	if _, err := NewProbe(ProbeConfig{Chain: "some-new-l2", RPCURL: "http://x"}); err == nil {
		t.Fatal("unknown chains must be refused, not defaulted")
	}
	if _, err := NewProbe(ProbeConfig{Chain: "solana"}); err == nil {
		t.Fatal("a probe without an RPC URL must be refused")
	}
}

func TestValidateCatchesInconsistentFactorization(t *testing.T) {
	// The gateway recomputes gas_used * gas_price. If those disagree with the
	// reported total, a "recomputable" receipt would not recompute.
	c := &ChainCost{
		Chain: "x", TxHash: "t", NativeSymbol: "ETH",
		WeiPerNative: big.NewInt(1000), GasUsed: 3,
		GasPriceWei:  big.NewInt(5),
		NativeAmount: big.NewInt(16), // should be 15
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation to reject an inconsistent factorization")
	}
}

func TestNativeSymbolCoversEveryConfiguredChain(t *testing.T) {
	for _, chain := range []string{
		"ethereum", "ethereum-sepolia", "base", "arbitrum", "optimism", "bsc",
		"polygon", "moonbeam", "hedera", "solana", "sui", "aptos", "near",
		"ton", "tron", "cardano",
	} {
		if NativeSymbolFor(chain) == "" {
			t.Errorf("no native symbol mapped for %q — cost would be priced against the wrong asset", chain)
		}
	}
	if NativeSymbolFor("not-a-chain") != "" {
		t.Error("unknown chains must return an empty symbol so the caller refuses")
	}
}
