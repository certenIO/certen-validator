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
	"strings"
	"sync"

	"github.com/certen/independant-validator/pkg/billing"
	"github.com/certen/independant-validator/pkg/config"
)

var (
	costReporterOnce sync.Once
	costReporter     *billing.Reporter
)

// StartCostReporter constructs the reporter eagerly at boot so its write-ahead log is replayed.
//
// # WHY THIS CANNOT BE LEFT TO LAZY INITIALISATION
//
// The reporter is built under a sync.Once on FIRST USE, and Start — which calls replayWAL — runs
// inside that Once. So until something reports a cost, the reporter does not exist and the WAL
// is never read.
//
// That defeats the point of the WAL. It exists so a measured cost survives a restart, but
// recovery was conditional on new work arriving: a validator that restarted with undelivered
// events and then settled nothing would hold them on disk indefinitely, retrying never. Observed
// on 2026-08-05 — two events for intent 825dc808 sat through a restart while the gateway was
// fixed, and did not move, because nothing had called CostReporter() since boot.
//
// Calling this during wiring makes restart the RECOVERY path it was designed to be.
func StartCostReporter(logf func(string, ...interface{})) {
	r := CostReporter()
	if logf == nil {
		return
	}
	if r == nil {
		logf("⚠️ [COST] reporting is not configured (CERTEN_GATEWAY_URL / " +
			"VALIDATOR_SERVICE_TOKEN_SECRET unset); measured cost will not reach the gateway")
		return
	}
	logf("💰 [COST] reporter started; any undelivered events in the write-ahead log are being replayed")
}

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

// resolveCostEndpointForChain is the implementation, package-level so the BATCH settle path can
// reach it too.
//
// It deliberately takes no receiver: the batch orchestrator has no BFTTargetChainExecutor, and
// calling the method on a nil one worked only by accident (the body never touched the receiver).
// One field access added later would have turned that into a panic during settlement.
func resolveCostEndpointForChain(chain string) (string, string) {
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

// evmCanonicalSlugForChainID is the single spelling this fleet uses for each EVM chain.
//
// Deliberately the inverse of evmChainIDForName's ACCEPTED names rather than a second list of
// aliases: many names map in, exactly one comes out.
func evmCanonicalSlugForChainID(chainID int64) (string, bool) {
	switch chainID {
	case 1:
		return "ethereum", true
	case 11155111:
		return "ethereum-sepolia", true
	case 42161:
		return "arbitrum", true
	case 421614:
		return "arbitrum-sepolia", true
	case 10:
		return "optimism", true
	case 11155420:
		return "optimism-sepolia", true
	case 8453:
		return "base", true
	case 84532:
		return "base-sepolia", true
	case 137:
		return "polygon", true
	case 80002:
		return "polygon-amoy", true
	case 56:
		return "bsc", true
	case 97:
		return "bsc-testnet", true
	case 1284:
		return "moonbeam", true
	case 1287:
		return "moonbase-alpha", true
	case 296:
		return "hedera-testnet", true
	case 295:
		return "hedera-mainnet", true
	}
	return "", false
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

// canonicalChainSlug turns whatever the executor wrote into the slug the gateway keys by, plus
// the numeric chain id where one exists.
//
// THIS IS THE JOIN KEY between the validator and the gateway. cost_events.chain must equal
// quotes.chain exactly or every chain-keyed lookup on the gateway silently returns zero rows —
// no error, just a median over an empty set. Normalising at the emitter (rather than asking the
// gateway to be lenient) keeps one canonical spelling in the data, so a later reconciliation
// does not have to know every historical alias.
//
// Two normalisations happen, in order:
//
//  1. Shape: trim, lowercase, spaces to dashes. "Ethereum Sepolia" -> "ethereum-sepolia".
//  2. Alias: resolve through evmChainIDForName and re-emit the CANONICAL slug for that id, so
//     the short form "sepolia" also becomes "ethereum-sepolia". Both forms are present in
//     chain_execution_results today (419 rows "ethereum-sepolia", 234 rows "sepolia"), which is
//     exactly the kind of split that makes a GROUP BY chain lie.
//
// Non-EVM chains pass through with shape normalisation only and a zero chain id — they have no
// EVM chain id, and their slugs ("solana-devnet", "near-testnet") are already canonical.
func canonicalChainSlug(raw string) (string, int64) {
	slug := strings.ToLower(strings.TrimSpace(raw))
	slug = strings.ReplaceAll(slug, " ", "-")
	if slug == "" {
		return "", 0
	}
	chainID, ok := evmChainIDForName(slug)
	if !ok {
		return slug, 0
	}
	if canonical, known := evmCanonicalSlugForChainID(chainID); known {
		return canonical, chainID
	}
	return slug, chainID
}
