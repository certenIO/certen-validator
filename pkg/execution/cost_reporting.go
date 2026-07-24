// Copyright 2026 Certen Protocol
//
// Cost reporting hook for the BFT target-chain executor.
//
// Bridges "a leg landed on chain X with tx hash H" to the billing package,
// which measures what it actually cost and ships that to the gateway. Kept in
// its own file so the 275k-line executor is not carrying commercial concerns
// inline, and so the mapping from leg -> tx hash is reviewable in one place.
package execution

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/certen/independant-validator/pkg/billing"
	"github.com/certen/independant-validator/pkg/config"
)

var (
	costReporterOnce sync.Once
	costReporter     *billing.Reporter
)

// CostReporter returns the process-wide reporter, constructing it on first use.
// Nil when reporting is unconfigured; every method on *Reporter is nil-safe, so
// callers need no branch.
func CostReporter() *billing.Reporter {
	costReporterOnce.Do(func() {
		costReporter = billing.NewReporter(billing.ReporterConfig{
			GatewayURL:          os.Getenv("CERTEN_GATEWAY_URL"),
			ServiceTokenSecret:  firstNonEmpty(os.Getenv("VALIDATOR_SERVICE_TOKEN_SECRET_V1"), os.Getenv("VALIDATOR_SERVICE_TOKEN_SECRET")),
			ServiceTokenVersion: firstNonEmpty(os.Getenv("VALIDATOR_SERVICE_TOKEN_VERSION"), "v1"),
			WALDir:              firstNonEmpty(os.Getenv("VALIDATOR_COST_WAL_DIR"), "data/cost-wal"),
		})
		if costReporter != nil {
			costReporter.Start(context.Background())
		}
	})
	return costReporter
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// reportExecutionCosts measures and reports the cost of every leg in a result.
//
// Leg attribution matters for reconciliation: the anchor leg is
// validator-exclusive and always ours, while the vault leg is the one Model B
// adds over Model A. Reporting them as an undifferentiated total would make it
// impossible to price the "customer relays their own leg 4" discount later.
func (btce *BFTTargetChainExecutor) reportExecutionCosts(
	intentID string,
	result *TargetChainExecutionResult,
) {
	reporter := CostReporter()
	if reporter == nil || result == nil {
		return
	}

	chain := result.Chain
	if chain == "" {
		chain = result.Metadata["chain"]
	}
	if chain == "" {
		btce.logger.Printf("⚠️ [COST] Result has no chain; cannot attribute cost")
		return
	}

	rpcURL, apiKey := btce.resolveCostEndpoint(chain)
	if rpcURL == "" {
		btce.logger.Printf("⚠️ [COST] No RPC endpoint resolved for %s; cost for this intent will be unmeasured "+
			"(the gateway will keep refusing to price this chain)", chain)
		return
	}

	var chainID int64
	if raw, ok := result.Metadata["chainId"]; ok {
		chainID, _ = strconv.ParseInt(raw, 10, 64)
	}

	// A synthetic placeholder like "create_failed_base" is not a tx hash; a
	// probe would 404 forever and burn retries.
	legs := []struct {
		leg    string
		txHash string
	}{
		{billing.LegAnchor, result.CreateTxHash},
		{billing.LegVerify, result.VerifyTxHash},
		{billing.LegVaultExecute, result.GovernanceTxHash},
	}

	for _, l := range legs {
		if !looksLikeTxHash(l.txHash) {
			continue
		}
		reporter.ObserveAndReport(
			context.Background(),
			billing.ProbeConfig{
				Chain:   chain,
				ChainID: chainID,
				RPCURL:  rpcURL,
				APIKey:  apiKey,
				Leg:     l.leg,
			},
			intentID,
			"", // org attribution happens gateway-side from the intent
			l.txHash,
			nil,
		)
	}
}

// looksLikeTxHash filters out the failure placeholders the executor puts in
// result fields ("create_failed_base", "verify_failed_solana", ...).
func looksLikeTxHash(h string) bool {
	if h == "" {
		return false
	}
	lower := strings.ToLower(h)
	for _, marker := range []string{"failed", "skipped", "pending", "not_", "none"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	// Shortest real identifier in the fleet is a 44-char base58 Solana
	// signature or a 64-hex hash; anything under 32 chars is a sentinel.
	return len(strings.TrimPrefix(h, "0x")) >= 32
}

// resolveCostEndpoint returns the RPC URL (and optional API key) to probe for a
// chain's fee data.
//
// Reads the same environment the chain clients were configured from, so the
// probe always talks to the endpoint that actually executed the transaction —
// a different provider may not have indexed it, or may prune it.
func (btce *BFTTargetChainExecutor) resolveCostEndpoint(chain string) (string, string) {
	c := strings.ToLower(strings.TrimSpace(chain))
	c = strings.ReplaceAll(c, " ", "-")

	switch {
	case strings.HasPrefix(c, "solana"):
		return firstNonEmpty(os.Getenv("SOLANA_RPC_URL"), os.Getenv("SOLANA_DEVNET_RPC_URL")), ""
	case strings.HasPrefix(c, "sui"):
		return firstNonEmpty(os.Getenv("SUI_RPC_URL"), os.Getenv("SUI_TESTNET_RPC_URL")), ""
	case strings.HasPrefix(c, "aptos"):
		return firstNonEmpty(os.Getenv("APTOS_RPC_URL"), os.Getenv("APTOS_TESTNET_RPC_URL")), ""
	case strings.HasPrefix(c, "near"):
		// The NEAR probe needs the signer account id to query tx status.
		return firstNonEmpty(os.Getenv("NEAR_RPC_URL"), os.Getenv("NEAR_TESTNET_RPC_URL")),
			firstNonEmpty(os.Getenv("NEAR_ACCOUNT_ID"), os.Getenv("NEAR_SIGNER_ACCOUNT_ID"))
	case strings.HasPrefix(c, "ton"):
		return firstNonEmpty(os.Getenv("TON_API_URL"), os.Getenv("TON_TESTNET_API_URL")),
			os.Getenv("TON_API_KEY")
	case strings.HasPrefix(c, "tron"):
		return firstNonEmpty(os.Getenv("TRON_FULL_NODE_URL"), os.Getenv("TRON_API_URL")),
			os.Getenv("TRON_PRO_API_KEY")
	case strings.HasPrefix(c, "cardano"):
		return firstNonEmpty(os.Getenv("CARDANO_API_URL"), os.Getenv("CARDANO_SUBMIT_API_URL")),
			os.Getenv("CARDANO_PROJECT_ID")
	}

	// EVM family: use the per-chain URL the executor itself was configured
	// with, so the probe queries the node that actually saw the transaction.
	if anchorCfg, err := config.LoadAnchorConfigFromEnv(); err == nil && anchorCfg != nil {
		if chainID, ok := evmChainIDForName(c); ok {
			if cfg := anchorCfg.GetEVMChainConfig(chainID); cfg != nil && cfg.RPCURL != "" {
				return cfg.RPCURL, ""
			}
		}
	}
	return os.Getenv("ETHEREUM_URL"), ""
}

// evmChainIDForName maps a chain name to its numeric id for config lookup.
// Deliberately explicit rather than a fuzzy match: resolving "base" to
// Ethereum's config would probe the wrong node and silently report no cost.
func evmChainIDForName(name string) (int64, bool) {
	switch name {
	case "ethereum", "eth":
		return 1, true
	case "ethereum-sepolia", "eth-sepolia", "sepolia":
		return 11155111, true
	case "arbitrum", "arb", "arbitrum-one":
		return 42161, true
	case "arbitrum-sepolia":
		return 421614, true
	case "optimism", "op", "op-mainnet":
		return 10, true
	case "optimism-sepolia", "op-sepolia":
		return 11155420, true
	case "base", "base-mainnet":
		return 8453, true
	case "base-sepolia":
		return 84532, true
	case "polygon", "matic":
		return 137, true
	case "polygon-amoy", "amoy":
		return 80002, true
	case "bsc", "binance":
		return 56, true
	case "bsc-testnet":
		return 97, true
	case "moonbeam":
		return 1284, true
	case "moonbase", "moonbase-alpha", "moonbeam-moonbase-alpha":
		return 1287, true
	case "hedera", "hedera-testnet":
		return 296, true
	case "hedera-mainnet":
		return 295, true
	}
	return 0, false
}
