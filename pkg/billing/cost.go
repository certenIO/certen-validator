// Copyright 2026 Certen Protocol
//
// Package billing reports what CERTEN actually spent executing an intent.
//
// Under Model B the validator fronts native gas on every chain and recovers it
// in stablecoin. That makes "what did this leg cost" a commercial fact, not a
// log line: it is the input the gateway prices from, the number a customer
// recomputes when they check an invoice, and the figure reconciliation
// compares the charge against. Until this package existed the data was
// observed (ExternalChainObserver already reads receipts) and then thrown away.
//
// Design rules, in priority order:
//
//  1. NEVER block or fail a proof cycle. Cost reporting is bookkeeping; an
//     unreachable gateway must not stop an intent from executing. Everything
//     here is asynchronous, buffered, and best-effort-with-durability.
//
//  2. Report FACTS, not prices. This package sends gas used, gas price, tx
//     hash, and block — never a USD amount. The gateway converts using its own
//     signed FX observation. If the validator sent dollars, "what CERTEN spent"
//     would be an assertion by whichever process reported it, and the
//     reconciliation loop would be checking the gateway's arithmetic against
//     the validator's claim rather than against the chain.
//
//  3. Survive restarts. A crash between "leg confirmed" and "cost reported"
//     otherwise loses the number permanently — the chain still charged us.
//     Every event is written to a WAL before acknowledgement and replayed on
//     startup.
package billing

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Leg identifies which of the per-intent transactions a cost belongs to.
// These strings must match the gateway's cost_events.leg CHECK constraint.
const (
	LegAnchor       = "anchor"        // createAnchor / createAnchorWithLegs (onlyValidator)
	LegVerify       = "verify"        // executeComprehensiveProof (BLS/Groth16 verification)
	LegExecuteLegs  = "execute_legs"  // executeLegs
	LegVaultExecute = "vault_execute" // executeGovernanceProofDirect on the user's account
	LegOther        = "other"
)

// ChainCost is the measured cost of one on-chain transaction, expressed in the
// chain's own units.
//
// The (NativeAmount, WeiPerNative) pair is deliberately explicit rather than
// assuming 1e18: Solana is 1e9 lamports/SOL, Aptos 1e8 octas/APT, NEAR 1e24
// yocto/NEAR, TON 1e9 nanoton/TON, TRON 1e6 sun/TRX, Cardano 1e6 lovelace/ADA.
// Hard-coding 1e18 would misprice six of the fourteen chains by orders of
// magnitude and, under Model B, in our own money.
type ChainCost struct {
	Chain   string `json:"chain"`
	ChainID int64  `json:"chain_id,omitempty"`
	Leg     string `json:"leg"`
	TxHash  string `json:"tx_hash"`

	// BlockNumber is the block/slot/version/round the tx landed in, as a
	// decimal string (chains disagree on width and signedness).
	BlockNumber string `json:"block_number,omitempty"`

	// GasUsed and GasPriceWei model chains with a gas x price fee. For chains
	// without that model the adapter synthesizes GasUsed=1 and puts the whole
	// fee in GasPriceWei, so the gateway's single formula
	// (gas_used * gas_price / wei_per_native) stays exact everywhere.
	GasUsed     uint64   `json:"gas_used"`
	GasPriceWei *big.Int `json:"-"`

	// NativeSymbol is the fee token: ETH, SOL, APT, SUI, NEAR, TON, TRX, ADA,
	// HBAR, BNB, POL, GLMR.
	NativeSymbol string `json:"native_symbol"`

	// WeiPerNative is the smallest-unit denominator for NativeSymbol.
	WeiPerNative *big.Int `json:"-"`

	// L1FeeWei is the OP-stack L1 data fee, charged ON TOP of L2 execution gas.
	//
	// Nil everywhere except Base/Optimism and their testnets. It exists because an OP-stack fee
	// cannot be expressed as gas x price: measured on Base Sepolia, an anchor cost 278,081 gas
	// at 7.2 gwei (2,002,183,200,000 wei) PLUS an 11,263,703,277 wei L1 fee. Folding the two
	// into one number is what previously forced GasUsed to 1 and destroyed the gas figure.
	L1FeeWei *big.Int `json:"-"`

	// NativeAmount is the total fee in smallest units:
	//
	//	GasUsed * GasPriceWei + L1FeeWei
	//
	// Carried separately because several chains report only a total and the factorization is
	// synthetic (GasUsed=1, whole fee in GasPriceWei).
	NativeAmount *big.Int `json:"-"`

	// Breakdown records fee components a single number hides — Sui's
	// storage rebate, TON's forward fees, TRON's staked energy. Reported for
	// analysis; not used in pricing.
	Breakdown map[string]string `json:"breakdown,omitempty"`

	// FreeAtMargin is true when the chain charged nothing because the cost was
	// covered by staked resources (TRON energy/bandwidth). The measured cost is
	// then honestly ~0, but the STAKE has a carrying cost that per-transaction
	// receipts cannot see. Pricing must treat these chains as amortized rather
	// than free — see docs; the flag exists so that decision is explicit rather
	// than an accident of a zero fee.
	FreeAtMargin bool `json:"free_at_margin,omitempty"`

	ObservedAt time.Time `json:"observed_at"`
}

// Validate rejects a cost that would produce a wrong or nonsensical price.
func (c *ChainCost) Validate() error {
	if c.Chain == "" {
		return fmt.Errorf("chain is required")
	}
	if c.TxHash == "" {
		return fmt.Errorf("tx_hash is required")
	}
	if c.NativeSymbol == "" {
		return fmt.Errorf("native_symbol is required for %s", c.Chain)
	}
	if c.WeiPerNative == nil || c.WeiPerNative.Sign() <= 0 {
		return fmt.Errorf("wei_per_native must be positive for %s", c.Chain)
	}
	if c.GasPriceWei == nil || c.GasPriceWei.Sign() < 0 {
		return fmt.Errorf("gas_price must be non-negative for %s", c.Chain)
	}
	if c.NativeAmount == nil || c.NativeAmount.Sign() < 0 {
		return fmt.Errorf("native_amount must be non-negative for %s", c.Chain)
	}
	if c.L1FeeWei != nil && c.L1FeeWei.Sign() < 0 {
		return fmt.Errorf("l1_fee must be non-negative for %s", c.Chain)
	}
	// The gateway recomputes gas_used * gas_price + l1_fee and must land on the same
	// number, or a "recomputable" receipt would not recompute.
	product := new(big.Int).Mul(new(big.Int).SetUint64(c.GasUsed), c.GasPriceWei)
	if c.L1FeeWei != nil {
		product = new(big.Int).Add(product, c.L1FeeWei)
	}
	if product.Cmp(c.NativeAmount) != 0 {
		return fmt.Errorf(
			"%s: gas_used*gas_price (%s) != native_amount (%s); the gateway would recompute a different cost",
			c.Chain, product.String(), c.NativeAmount.String(),
		)
	}
	return nil
}

// setTotal stores a total fee that has no natural gas/price factorization by
// synthesizing GasUsed=1. Keeps Validate's identity true by construction.
// setTotal stores a fee that has no gas x price factorization.
//
// Chains without a gas model (Solana, TON, Cardano, ...) report only a total, so GasUsed=1 and
// the whole fee sits in GasPriceWei. The gateway's single formula then stays exact everywhere.
//
// DO NOT use this for an EVM chain that reports real gas. It did, for OP-stack L1 fees, and it
// destroyed the gas figure — see setGasWithL1.
func (c *ChainCost) setTotal(total *big.Int) {
	c.GasUsed = 1
	c.GasPriceWei = new(big.Int).Set(total)
	c.NativeAmount = new(big.Int).Set(total)
	c.L1FeeWei = nil
}

// setGasWithL1 stores an OP-stack fee: real L2 gas x price, PLUS a separate L1 data fee.
//
// # WHY NOT setTotal
//
// Base and Optimism charge L2 execution gas plus an L1 data fee, and the receipt reports both.
// Folding them into one number via setTotal made the arithmetic correct but collapsed GasUsed to
// 1, which broke two things that are not obvious:
//
//   - gas_used stopped meaning anything. Measured live on Base Sepolia, an anchor that burned
//     278,081 gas and a settlement that burned 144,884 were BOTH recorded as 1. The gateway's
//     estimateGasLegs takes a MEDIAN of gas_used, so it would have returned 1 — a plausible
//     number that means nothing, the same failure mode as the chain-name mismatch.
//   - the shared-anchor split broke outright. splitGas(1, 3) is [1,0,0], so a three-member batch
//     charged the first member the entire anchor and the other two nothing. It never bit only
//     because every OP-stack batch so far has had one member.
//
// Keeping the factorization intact fixes both, at the cost of one additive term the gateway must
// carry: native = gas_used * gas_price + l1_fee_wei.
func (c *ChainCost) setGasWithL1(gasUsed uint64, price, l1Fee *big.Int) {
	c.GasUsed = gasUsed
	c.GasPriceWei = new(big.Int).Set(price)
	c.L1FeeWei = new(big.Int).Set(l1Fee)
	c.NativeAmount = new(big.Int).Add(
		new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), price),
		l1Fee,
	)
}

// setGas stores a genuine gas x price fee.
func (c *ChainCost) setGas(gasUsed uint64, price *big.Int) {
	c.GasUsed = gasUsed
	c.GasPriceWei = new(big.Int).Set(price)
	c.NativeAmount = new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), price)
}

// Denominations, smallest unit per whole token.
var (
	wei      = big.NewInt(1_000_000_000_000_000_000) // 1e18  EVM
	yocto, _ = new(big.Int).SetString("1000000000000000000000000", 10)
	lamport  = big.NewInt(1_000_000_000) // 1e9   Solana, Sui (MIST), TON (nanoton)
	octa     = big.NewInt(100_000_000)   // 1e8   Aptos, Hedera (tinybar)
	sun      = big.NewInt(1_000_000)     // 1e6   TRON, Cardano (lovelace)
)

// NativeSymbolFor maps a chain name to its fee token. Unknown chains return ""
// so the caller refuses to report rather than guessing a symbol — a wrong
// symbol silently prices against the wrong asset.
func NativeSymbolFor(chain string) string {
	switch normalizeChain(chain) {
	case "ethereum", "sepolia", "base", "arbitrum", "optimism":
		return "ETH"
	case "bsc":
		return "BNB"
	case "polygon":
		return "POL"
	case "moonbeam":
		return "GLMR"
	case "hedera":
		return "HBAR"
	case "solana":
		return "SOL"
	case "sui":
		return "SUI"
	case "aptos":
		return "APT"
	case "near":
		return "NEAR"
	case "ton":
		return "TON"
	case "tron":
		return "TRX"
	case "cardano":
		return "ADA"
	default:
		return ""
	}
}

// normalizeChain strips network suffixes so "ethereum-sepolia", "sepolia" and
// "ethereum" all resolve to one fee model.
func normalizeChain(chain string) string {
	c := strings.ToLower(strings.TrimSpace(chain))
	// Canonicalize the separator BEFORE trimming network suffixes.
	//
	// Chain names reach this function in whatever form the caller happens to
	// hold: the slug "ethereum-sepolia", the env-var style "ETHEREUM_SEPOLIA",
	// or the human display name "Ethereum Sepolia". The suffix list below is
	// hyphenated, so a spaced or underscored name matched nothing, fell through
	// to the default, and produced "no fee model implemented for chain
	// \"Ethereum Sepolia\"" — every cost event for that leg was dropped before
	// it was ever sent, and the chain stayed permanently unpriceable.
	c = strings.NewReplacer(" ", "-", "_", "-").Replace(c)
	// Collapse repeats so "ethereum  sepolia" and "ethereum_-sepolia" agree.
	for strings.Contains(c, "--") {
		c = strings.ReplaceAll(c, "--", "-")
	}
	for _, suffix := range []string{
		"-mainnet", "-testnet", "-devnet", "-sepolia", "-shasta", "-nile",
		"-preview", "-preprod", "-one", "-goerli",
		// -amoy is Polygon's testnet. Its absence meant "polygon-amoy" never reduced to
		// "polygon", fell through NewProbe's switch, and every cost event for that chain was
		// dropped with "no fee model implemented" — live reporting as well as backfill.
		"-amoy",
		// -alpha covers moonbase-alpha, which reduces to "moonbase" and then to "moonbeam".
		"-alpha",
	} {
		c = strings.TrimSuffix(c, suffix)
	}
	switch c {
	case "eth", "sepolia":
		return "ethereum"
	case "arb", "arbitrum":
		return "arbitrum"
	case "op", "optimism":
		return "optimism"
	case "matic", "polygon":
		return "polygon"
	case "sol", "solana":
		return "solana"
	case "moonbase", "moonriver", "glmr":
		// Moonbase Alpha is Moonbeam's testnet and shares its fee model. Without this the name
		// reduces to "moonbase", misses NewProbe's switch, and every event is dropped.
		return "moonbeam"
	default:
		return c
	}
}
