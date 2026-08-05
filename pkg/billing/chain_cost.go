// Copyright 2026 Certen Protocol
//
// Per-chain cost probes.
//
// Every fee model CERTEN pays into, in one reviewable file, because the cost of
// getting one of them wrong is paid in real money on every intent forever. The
// eight non-EVM chains are NOT gas x gas-price and cannot be approximated as
// such:
//
//	Solana   flat 5,000 lamports/signature + optional priority fee. The node
//	         reports the final total in meta.fee; rent for account creation is
//	         separate and shows as a balance delta, not a fee.
//	Sui      computationCost + storageCost - storageRebate. The rebate is real
//	         money back and routinely exceeds storage cost, so ignoring it
//	         OVER-charges the customer. Net can legitimately be negative; we
//	         clamp at zero and record the components.
//	Aptos    gas_used x gas_unit_price in octas (1e8/APT), plus storage refunds
//	         surfaced separately in recent nodes.
//	NEAR     tokens_burnt summed across the transaction outcome AND every
//	         receipt outcome. Reading only the transaction outcome understates
//	         a cross-contract call by most of its cost.
//	TON      total_fees = gas + storage + forward (in + out messages). Forward
//	         fees are charged for messages this tx SENT, which a naive
//	         "compute phase gas" reading misses entirely.
//	TRON     energy + bandwidth. FREE AT THE MARGIN when covered by staked TRX
//	         — the receipt genuinely shows fee 0. That is not free: the stake
//	         has a carrying cost invisible to any per-tx receipt.
//	Cardano  deterministic min-fee formula (a + b x size), settled at submit.
//	Hedera   EVM JSON-RPC relay, so gas x price — but denominated in weibar
//	         (1e18) while HBAR's native unit is the tinybar (1e8).
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Probe fetches the measured cost of one confirmed transaction.
type Probe interface {
	// ObservedCost returns the cost, or an error if the transaction is not yet
	// final or the fee cannot be determined. Callers treat an error as
	// "retry later", never as "free".
	ObservedCost(ctx context.Context, txHash string) (*ChainCost, error)
}

// ProbeConfig is everything a probe needs to reach a chain.
type ProbeConfig struct {
	Chain   string
	ChainID int64
	RPCURL  string
	APIKey  string // toncenter and some providers
	HTTP    *http.Client
	Leg     string
}

// NewProbe selects the fee model for a chain. Returns an error for unknown
// chains rather than defaulting to EVM: silently applying the wrong fee model
// is how a chain ends up mispriced by three orders of magnitude.
func NewProbe(cfg ProbeConfig) (Probe, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.RPCURL == "" {
		return nil, fmt.Errorf("billing: no RPC URL configured for chain %q", cfg.Chain)
	}
	switch normalizeChain(cfg.Chain) {
	case "ethereum", "base", "arbitrum", "optimism", "bsc", "polygon", "moonbeam", "hedera":
		return &evmProbe{cfg: cfg}, nil
	case "tron":
		// TRON exposes an EVM-compatible JSON-RPC, but its economics are
		// energy/bandwidth, so it gets its own probe against the native API.
		return &tronProbe{cfg: cfg}, nil
	case "solana":
		return &solanaProbe{cfg: cfg}, nil
	case "sui":
		return &suiProbe{cfg: cfg}, nil
	case "aptos":
		return &aptosProbe{cfg: cfg}, nil
	case "near":
		return &nearProbe{cfg: cfg}, nil
	case "ton":
		return &tonProbe{cfg: cfg}, nil
	case "cardano":
		return &cardanoProbe{cfg: cfg}, nil
	default:
		return nil, fmt.Errorf("billing: no fee model implemented for chain %q", cfg.Chain)
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

func jsonRPC(ctx context.Context, client *http.Client, url string, method string, params interface{}, headers map[string]string) (json.RawMessage, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", method, err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: rpc error %d: %s", method, out.Error.Code, out.Error.Message)
	}
	if len(out.Result) == 0 || string(out.Result) == "null" {
		return nil, fmt.Errorf("%s: empty result (transaction not yet available)", method)
	}
	return out.Result, nil
}

func httpGetJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("transaction not found (not yet indexed)")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// parseBig accepts decimal or 0x-hex, as strings or JSON numbers, because the
// chains in this fleet disagree on all three.
func parseBig(v interface{}) (*big.Int, bool) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil, false
		}
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			n, ok := new(big.Int).SetString(s[2:], 16)
			return n, ok
		}
		n, ok := new(big.Int).SetString(s, 10)
		return n, ok
	case float64:
		// JSON numbers lose precision above 2^53; only safe for small fields
		// (gas units, slots), never for fee amounts on 1e24-denominated NEAR.
		return new(big.Int).SetInt64(int64(t)), true
	case json.Number:
		n, ok := new(big.Int).SetString(t.String(), 10)
		return n, ok
	}
	return nil, false
}

func baseCost(cfg ProbeConfig, txHash string) *ChainCost {
	return &ChainCost{
		Chain:        cfg.Chain,
		ChainID:      cfg.ChainID,
		Leg:          cfg.Leg,
		TxHash:       txHash,
		NativeSymbol: NativeSymbolFor(cfg.Chain),
		ObservedAt:   time.Now().UTC(),
		Breakdown:    map[string]string{},
	}
}

// ── EVM (ethereum, base, arbitrum, optimism, bsc, polygon, moonbeam, hedera) ─

type evmProbe struct{ cfg ProbeConfig }

func (p *evmProbe) ObservedCost(ctx context.Context, txHash string) (*ChainCost, error) {
	raw, err := jsonRPC(ctx, p.cfg.HTTP, p.cfg.RPCURL, "eth_getTransactionReceipt", []interface{}{txHash}, nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		GasUsed           string `json:"gasUsed"`
		EffectiveGasPrice string `json:"effectiveGasPrice"`
		BlockNumber       string `json:"blockNumber"`
		Status            string `json:"status"`
		L1Fee             string `json:"l1Fee"`     // OP-stack chains surface the L1 data fee here
		L1GasUsed         string `json:"l1GasUsed"` // recorded for auditing; not used in pricing
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("evm: decode receipt: %w", err)
	}

	gasUsed, ok := parseBig(r.GasUsed)
	if !ok {
		return nil, fmt.Errorf("evm: receipt has no gasUsed")
	}
	price, ok := parseBig(r.EffectiveGasPrice)
	if !ok {
		// Pre-EIP-1559 nodes omit effectiveGasPrice; fall back to the tx's
		// gasPrice rather than reporting a free transaction.
		txRaw, txErr := jsonRPC(ctx, p.cfg.HTTP, p.cfg.RPCURL, "eth_getTransactionByHash", []interface{}{txHash}, nil)
		if txErr != nil {
			return nil, fmt.Errorf("evm: no effectiveGasPrice and cannot read tx: %w", txErr)
		}
		var tx struct {
			GasPrice string `json:"gasPrice"`
		}
		if err := json.Unmarshal(txRaw, &tx); err != nil {
			return nil, err
		}
		if price, ok = parseBig(tx.GasPrice); !ok {
			return nil, fmt.Errorf("evm: no gas price available for %s", txHash)
		}
	}

	cost := baseCost(p.cfg, txHash)
	cost.WeiPerNative = new(big.Int).Set(wei)
	cost.setGas(gasUsed.Uint64(), price)
	if bn, ok := parseBig(r.BlockNumber); ok {
		cost.BlockNumber = bn.String()
	}

	// OP-stack L1 data fee is charged on top of L2 execution gas and is a
	// large share of the total on Base/Optimism. Omitting it under-charges.
	//
	// Recorded as a SEPARATE additive term rather than folded into the total. Folding it
	// (setTotal) kept the arithmetic right but forced GasUsed to 1, which destroyed the gas
	// figure and broke the shared-anchor split — see ChainCost.setGasWithL1.
	if l1, ok := parseBig(r.L1Fee); ok && l1.Sign() > 0 {
		cost.Breakdown["l2_execution_wei"] = cost.NativeAmount.String()
		cost.Breakdown["l1_data_fee_wei"] = l1.String()
		if l1GasUsed, ok := parseBig(r.L1GasUsed); ok {
			cost.Breakdown["l1_gas_used"] = l1GasUsed.String()
		}
		cost.setGasWithL1(gasUsed.Uint64(), price, l1)
	}
	if normalizeChain(p.cfg.Chain) == "hedera" {
		// The JSON-RPC relay denominates in weibar (1e18) even though HBAR's
		// native unit is the tinybar (1e8). Keep 1e18 here; converting would
		// double-apply the relay's own scaling.
		cost.Breakdown["note"] = "hedera json-rpc relay reports weibar (1e18/HBAR)"
	}
	return cost, nil
}

// ── Solana ──────────────────────────────────────────────────────────────────

type solanaProbe struct{ cfg ProbeConfig }

func (p *solanaProbe) ObservedCost(ctx context.Context, txSig string) (*ChainCost, error) {
	raw, err := jsonRPC(ctx, p.cfg.HTTP, p.cfg.RPCURL, "getTransaction", []interface{}{
		txSig,
		map[string]interface{}{"encoding": "json", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"},
	}, nil)
	if err != nil {
		return nil, err
	}
	var t struct {
		Slot uint64 `json:"slot"`
		Meta *struct {
			Fee          uint64           `json:"fee"`
			PreBalances  []uint64         `json:"preBalances"`
			PostBalances []uint64         `json:"postBalances"`
			Err          *json.RawMessage `json:"err"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("solana: decode transaction: %w", err)
	}
	if t.Meta == nil {
		return nil, fmt.Errorf("solana: transaction has no meta (not yet confirmed)")
	}

	cost := baseCost(p.cfg, txSig)
	cost.WeiPerNative = new(big.Int).Set(lamport)
	cost.BlockNumber = strconv.FormatUint(t.Slot, 10)
	// meta.fee is the FINAL total: base signature fee plus any priority fee.
	cost.setTotal(new(big.Int).SetUint64(t.Meta.Fee))
	cost.Breakdown["fee_lamports"] = strconv.FormatUint(t.Meta.Fee, 10)

	// Rent for newly created accounts is NOT a fee — it leaves the payer's
	// balance as a deposit. Record it so account-creation legs can be costed
	// properly later, but never bill it as gas.
	if len(t.Meta.PreBalances) > 0 && len(t.Meta.PostBalances) == len(t.Meta.PreBalances) {
		delta := int64(t.Meta.PreBalances[0]) - int64(t.Meta.PostBalances[0])
		if rent := delta - int64(t.Meta.Fee); rent > 0 {
			cost.Breakdown["payer_rent_lamports"] = strconv.FormatInt(rent, 10)
		}
	}
	return cost, nil
}

// ── Sui ─────────────────────────────────────────────────────────────────────

type suiProbe struct{ cfg ProbeConfig }

func (p *suiProbe) ObservedCost(ctx context.Context, digest string) (*ChainCost, error) {
	raw, err := jsonRPC(ctx, p.cfg.HTTP, p.cfg.RPCURL, "sui_getTransactionBlock", []interface{}{
		digest,
		map[string]interface{}{"showEffects": true, "showInput": false, "showEvents": false},
	}, nil)
	if err != nil {
		return nil, err
	}
	var t struct {
		Checkpoint string `json:"checkpoint"`
		Effects    struct {
			GasUsed struct {
				ComputationCost         string `json:"computationCost"`
				StorageCost             string `json:"storageCost"`
				StorageRebate           string `json:"storageRebate"`
				NonRefundableStorageFee string `json:"nonRefundableStorageFee"`
			} `json:"gasUsed"`
			Status struct {
				Status string `json:"status"`
			} `json:"status"`
		} `json:"effects"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("sui: decode transaction block: %w", err)
	}

	computation, _ := parseBig(t.Effects.GasUsed.ComputationCost)
	storage, _ := parseBig(t.Effects.GasUsed.StorageCost)
	rebate, _ := parseBig(t.Effects.GasUsed.StorageRebate)
	if computation == nil || storage == nil {
		return nil, fmt.Errorf("sui: effects missing gasUsed components")
	}
	if rebate == nil {
		rebate = big.NewInt(0)
	}

	// Net = computation + storage - rebate. The rebate is money genuinely
	// returned when objects are deleted or overwritten, and it frequently
	// exceeds storage cost; charging the gross would systematically
	// over-charge every Sui intent.
	net := new(big.Int).Add(computation, storage)
	net.Sub(net, rebate)
	if net.Sign() < 0 {
		// A net-negative transaction is a real Sui outcome (we were paid to
		// free storage). Bill zero rather than a negative charge, and record
		// the true figure.
		net = big.NewInt(0)
	}

	cost := baseCost(p.cfg, digest)
	cost.WeiPerNative = new(big.Int).Set(lamport) // MIST, 1e9 per SUI
	cost.BlockNumber = t.Checkpoint
	cost.setTotal(net)
	cost.Breakdown["computation_mist"] = computation.String()
	cost.Breakdown["storage_mist"] = storage.String()
	cost.Breakdown["storage_rebate_mist"] = rebate.String()
	if nrf, ok := parseBig(t.Effects.GasUsed.NonRefundableStorageFee); ok {
		cost.Breakdown["non_refundable_storage_mist"] = nrf.String()
	}
	return cost, nil
}

// ── Aptos ───────────────────────────────────────────────────────────────────

type aptosProbe struct{ cfg ProbeConfig }

func (p *aptosProbe) ObservedCost(ctx context.Context, txHash string) (*ChainCost, error) {
	url := fmt.Sprintf("%s/v1/transactions/by_hash/%s", strings.TrimSuffix(p.cfg.RPCURL, "/"), txHash)
	var t struct {
		Version          string `json:"version"`
		GasUsed          string `json:"gas_used"`
		GasUnitPrice     string `json:"gas_unit_price"`
		Success          bool   `json:"success"`
		StorageFeeOctas  string `json:"storage_fee_octas"`
		StorageFeeRefund string `json:"storage_fee_refund_octas"`
	}
	if err := httpGetJSON(ctx, p.cfg.HTTP, url, nil, &t); err != nil {
		return nil, fmt.Errorf("aptos: %w", err)
	}
	gasUsed, ok := parseBig(t.GasUsed)
	if !ok {
		return nil, fmt.Errorf("aptos: transaction has no gas_used (still pending)")
	}
	price, ok := parseBig(t.GasUnitPrice)
	if !ok {
		return nil, fmt.Errorf("aptos: transaction has no gas_unit_price")
	}

	cost := baseCost(p.cfg, txHash)
	cost.WeiPerNative = new(big.Int).Set(octa) // 1e8 octas per APT
	cost.BlockNumber = t.Version
	cost.setGas(gasUsed.Uint64(), price)
	if sf, ok := parseBig(t.StorageFeeOctas); ok {
		cost.Breakdown["storage_fee_octas"] = sf.String()
	}
	if rf, ok := parseBig(t.StorageFeeRefund); ok && rf.Sign() > 0 {
		cost.Breakdown["storage_refund_octas"] = rf.String()
	}
	return cost, nil
}

// ── NEAR ────────────────────────────────────────────────────────────────────

type nearProbe struct{ cfg ProbeConfig }

func (p *nearProbe) ObservedCost(ctx context.Context, txHash string) (*ChainCost, error) {
	senderID := p.cfg.APIKey // reused as the NEAR account id; see NewProbe callers
	if senderID == "" {
		senderID = "certen"
	}
	raw, err := jsonRPC(ctx, p.cfg.HTTP, p.cfg.RPCURL, "EXPERIMENTAL_tx_status",
		[]interface{}{txHash, senderID}, nil)
	if err != nil {
		return nil, err
	}
	var t struct {
		TransactionOutcome struct {
			BlockHash string `json:"block_hash"`
			Outcome   struct {
				TokensBurnt string `json:"tokens_burnt"`
			} `json:"outcome"`
		} `json:"transaction_outcome"`
		ReceiptsOutcome []struct {
			Outcome struct {
				TokensBurnt string `json:"tokens_burnt"`
			} `json:"outcome"`
		} `json:"receipts_outcome"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("near: decode tx status: %w", err)
	}

	// Total burn = the transaction's own outcome PLUS every receipt it spawned.
	// A cross-contract call does most of its work in receipts, so reading only
	// the transaction outcome would understate the cost by most of it.
	total := big.NewInt(0)
	if v, ok := parseBig(t.TransactionOutcome.Outcome.TokensBurnt); ok {
		total.Add(total, v)
	}
	receiptBurn := big.NewInt(0)
	for _, r := range t.ReceiptsOutcome {
		if v, ok := parseBig(r.Outcome.TokensBurnt); ok {
			receiptBurn.Add(receiptBurn, v)
		}
	}
	total.Add(total, receiptBurn)
	if total.Sign() == 0 {
		return nil, fmt.Errorf("near: no tokens_burnt reported (tx not final)")
	}

	cost := baseCost(p.cfg, txHash)
	cost.WeiPerNative = new(big.Int).Set(yocto) // 1e24 yoctoNEAR per NEAR
	cost.setTotal(total)
	cost.Breakdown["receipts_burnt_yocto"] = receiptBurn.String()
	cost.Breakdown["receipt_count"] = strconv.Itoa(len(t.ReceiptsOutcome))
	return cost, nil
}

// ── TON ─────────────────────────────────────────────────────────────────────

type tonProbe struct{ cfg ProbeConfig }

func (p *tonProbe) ObservedCost(ctx context.Context, txHash string) (*ChainCost, error) {
	// toncenter v2: look the transaction up by hash. TON identifies
	// transactions by (account, lt, hash); the hash-only lookup is what the
	// executor has available at reporting time.
	url := fmt.Sprintf("%s/getTransactions?hash=%s&limit=1",
		strings.TrimSuffix(p.cfg.RPCURL, "/"), txHash)
	headers := map[string]string{}
	if p.cfg.APIKey != "" {
		headers["X-API-Key"] = p.cfg.APIKey
	}

	var out struct {
		OK     bool `json:"ok"`
		Result []struct {
			Fee           string `json:"fee"`
			StorageFee    string `json:"storage_fee"`
			OtherFee      string `json:"other_fee"`
			TransactionID struct {
				LT   string `json:"lt"`
				Hash string `json:"hash"`
			} `json:"transaction_id"`
			OutMsgs []struct {
				FwdFee string `json:"fwd_fee"`
			} `json:"out_msgs"`
		} `json:"result"`
	}
	if err := httpGetJSON(ctx, p.cfg.HTTP, url, headers, &out); err != nil {
		return nil, fmt.Errorf("ton: %w", err)
	}
	if !out.OK || len(out.Result) == 0 {
		return nil, fmt.Errorf("ton: transaction %s not found", txHash)
	}
	tx := out.Result[0]

	// `fee` is the total the account was charged (gas + storage + action).
	total, ok := parseBig(tx.Fee)
	if !ok {
		return nil, fmt.Errorf("ton: transaction has no fee field")
	}
	// Forward fees for messages this transaction SENT are charged to us as
	// well and are not always folded into `fee` by every node version. Adding
	// them can only over-report; leaving them out under-reports on any
	// multi-message intent, which is every proof-gated call.
	fwd := big.NewInt(0)
	for _, m := range tx.OutMsgs {
		if v, ok := parseBig(m.FwdFee); ok {
			fwd.Add(fwd, v)
		}
	}

	cost := baseCost(p.cfg, txHash)
	cost.WeiPerNative = new(big.Int).Set(lamport) // 1e9 nanoton per TON
	cost.BlockNumber = tx.TransactionID.LT
	cost.setTotal(new(big.Int).Add(total, fwd))
	cost.Breakdown["fee_nanoton"] = total.String()
	cost.Breakdown["fwd_fee_nanoton"] = fwd.String()
	if sf, ok := parseBig(tx.StorageFee); ok {
		cost.Breakdown["storage_fee_nanoton"] = sf.String()
	}
	return cost, nil
}

// ── TRON ────────────────────────────────────────────────────────────────────

type tronProbe struct{ cfg ProbeConfig }

func (p *tronProbe) ObservedCost(ctx context.Context, txID string) (*ChainCost, error) {
	base := strings.TrimSuffix(p.cfg.RPCURL, "/")
	base = strings.TrimSuffix(base, "/jsonrpc") // config points at the EVM shim
	url := base + "/wallet/gettransactioninfobyid"

	payload, _ := json.Marshal(map[string]string{"value": txID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		req.Header.Set("TRON-PRO-API-KEY", p.cfg.APIKey)
	}
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tron: %w", err)
	}
	defer resp.Body.Close()

	var info struct {
		ID          string `json:"id"`
		Fee         int64  `json:"fee"`
		BlockNumber int64  `json:"blockNumber"`
		Receipt     struct {
			EnergyUsage      int64  `json:"energy_usage"` // covered by stake (free)
			EnergyFee        int64  `json:"energy_fee"`   // TRX burned for energy
			EnergyUsageTotal int64  `json:"energy_usage_total"`
			NetUsage         int64  `json:"net_usage"` // bandwidth from stake (free)
			NetFee           int64  `json:"net_fee"`   // TRX burned for bandwidth
			Result           string `json:"result"`
		} `json:"receipt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("tron: decode transaction info: %w", err)
	}
	if info.ID == "" {
		return nil, fmt.Errorf("tron: transaction %s not found or not yet confirmed", txID)
	}

	burned := info.Receipt.EnergyFee + info.Receipt.NetFee
	if burned == 0 && info.Fee > 0 {
		burned = info.Fee
	}

	cost := baseCost(p.cfg, txID)
	cost.WeiPerNative = new(big.Int).Set(sun) // 1e6 sun per TRX
	cost.BlockNumber = strconv.FormatInt(info.BlockNumber, 10)
	cost.setTotal(big.NewInt(burned))
	cost.Breakdown["energy_usage"] = strconv.FormatInt(info.Receipt.EnergyUsage, 10)
	cost.Breakdown["energy_usage_total"] = strconv.FormatInt(info.Receipt.EnergyUsageTotal, 10)
	cost.Breakdown["energy_fee_sun"] = strconv.FormatInt(info.Receipt.EnergyFee, 10)
	cost.Breakdown["net_usage"] = strconv.FormatInt(info.Receipt.NetUsage, 10)
	cost.Breakdown["net_fee_sun"] = strconv.FormatInt(info.Receipt.NetFee, 10)

	// The honest part: when staked energy/bandwidth covered the transaction,
	// TRON charged us nothing and a per-tx receipt cannot see the carrying
	// cost of the stake that made it free. Flag it so pricing amortizes the
	// stake rather than concluding TRON intents are free.
	if burned == 0 && (info.Receipt.EnergyUsage > 0 || info.Receipt.NetUsage > 0) {
		cost.FreeAtMargin = true
		cost.Breakdown["note"] = "covered by staked energy/bandwidth; marginal fee is genuinely 0 but the stake has a carrying cost"
	}
	return cost, nil
}

// ── Cardano ─────────────────────────────────────────────────────────────────

type cardanoProbe struct{ cfg ProbeConfig }

func (p *cardanoProbe) ObservedCost(ctx context.Context, txHash string) (*ChainCost, error) {
	// Cardano fees are deterministic (a + b x size) and settled at submission.
	// The submitting service reports them; this reads them back so the number
	// billed is the number the chain took, not a recomputed estimate.
	url := fmt.Sprintf("%s/tx/%s", strings.TrimSuffix(p.cfg.RPCURL, "/"), txHash)
	headers := map[string]string{}
	if p.cfg.APIKey != "" {
		headers["project_id"] = p.cfg.APIKey // Blockfrost-style
	}
	var t struct {
		Hash        string `json:"hash"`
		Fees        string `json:"fees"`
		Deposit     string `json:"deposit"`
		Size        int64  `json:"size"`
		BlockHeight int64  `json:"block_height"`
	}
	if err := httpGetJSON(ctx, p.cfg.HTTP, url, headers, &t); err != nil {
		return nil, fmt.Errorf("cardano: %w", err)
	}
	fees, ok := parseBig(t.Fees)
	if !ok {
		return nil, fmt.Errorf("cardano: transaction has no fees field")
	}

	cost := baseCost(p.cfg, txHash)
	cost.WeiPerNative = new(big.Int).Set(sun) // 1e6 lovelace per ADA
	cost.BlockNumber = strconv.FormatInt(t.BlockHeight, 10)
	cost.setTotal(fees)
	cost.Breakdown["fees_lovelace"] = fees.String()
	cost.Breakdown["tx_size_bytes"] = strconv.FormatInt(t.Size, 10)
	// A UTxO deposit (e.g. min-ADA locked in an output) is refundable and is
	// NOT a fee. Recorded, never billed.
	if dep, ok := parseBig(t.Deposit); ok && dep.Sign() > 0 {
		cost.Breakdown["refundable_deposit_lovelace"] = dep.String()
	}
	return cost, nil
}
