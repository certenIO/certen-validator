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
// accumTxHash is the Accumulate transaction that carried the intent. It is the
// ONLY identifier the gateway and the validator both hold: intentID here is the
// validator's own, and the gateway keys intents by a different UUID entirely.
// Without it the gateway can store a cost event but never join it to an intent,
// so measured gas never reaches settlement.
func (btce *BFTTargetChainExecutor) reportExecutionCosts(
	intentID string,
	accumTxHash string,
	result *TargetChainExecutionResult,
) {
	reporter := CostReporter()
	if reporter == nil || result == nil {
		return
	}

	rawChain := result.Chain
	if rawChain == "" {
		rawChain = result.Metadata["chain"]
	}
	if rawChain == "" {
		btce.logger.Printf("⚠️ [COST] Result has no chain; cannot attribute cost")
		return
	}

	// CANONICALISE BEFORE REPORTING.
	//
	// The executor writes a DISPLAY name ("Ethereum Sepolia") on some paths and a slug
	// ("ethereum-sepolia", and sometimes the short "sepolia") on others. The gateway keys
	// everything — quotes, the pricing gate, the gas estimator — by slug. Reporting the display
	// name verbatim meant cost_events.chain held exactly one value, "Ethereum Sepolia", which
	// matched NO quote. pricingGate.assess() therefore saw zero events and estimateGasLegs()
	// returned a median over zero rows, i.e. a gas estimate of zero for every leg.
	//
	// It has not caused an outage only because the gate runs solely for `quoted` SKUs and every
	// live SKU is flat. The first SKU moved to quoted pricing would have failed immediately.
	chain, chainID := canonicalChainSlug(rawChain)

	// Prefer an explicit chainId from the executor when it supplied one; fall back to the value
	// derived from the name. Previously this read Metadata only, which is unpopulated on the
	// live path — hence chain_id NULL on every row ever written.
	if raw, ok := result.Metadata["chainId"]; ok {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed != 0 {
			chainID = parsed
		}
	}
	if chainID == 0 {
		// Non-EVM chains have no EVM chain id; that is expected and not an error. An EVM chain
		// reaching here IS a bug — it means canonicalChainSlug does not know the name.
		btce.logger.Printf("ℹ️ [COST] %s reported without a numeric chain id (non-EVM, or an "+
			"unmapped name — check canonicalChainSlug if this chain is EVM)", chain)
	}

	rpcURL, apiKey := btce.resolveCostEndpoint(chain)
	if rpcURL == "" {
		btce.logger.Printf("⚠️ [COST] No RPC endpoint resolved for %s; cost for this intent will be unmeasured "+
			"(the gateway will keep refusing to price this chain)", chain)
		return
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

	// Fall back to the primary TxHash when the per-leg fields are empty.
	//
	// Not every executor path fills the three leg fields. Several populate only
	// `TxHash`, and the multi-chain path packs all of them as comma-joined,
	// chain-prefixed strings. The hook previously read the three fields verbatim,
	// so on those paths every candidate filtered out and NOTHING was reported —
	// silently, because "no legs" looked identical to "nothing to do". The chain
	// then never accumulated measured cost data and stayed permanently
	// unpriceable, with no error anywhere to explain why.
	//
	// Attribute the fallback to the anchor leg: it is the one leg that always
	// exists, and mislabelling is far better than dropping the measurement.
	if !anyMeasurable(legs) && looksLikeTxHash(result.TxHash) {
		legs = append(legs, struct {
			leg    string
			txHash string
		}{billing.LegAnchor, result.TxHash})
	}

	reported := 0
	for _, l := range legs {
		// One field can carry several hashes (multi-chain: "Chain:leg-N:0x…,…").
		for _, h := range extractTxHashes(l.txHash) {
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
				accumTxHash,
				h,
				nil,
			)
			reported++
		}
	}

	// Never fail silently. An executed intent with nothing measurable is a bug
	// in leg plumbing, and the only symptom downstream is a chain that quietly
	// refuses to be priced.
	if reported == 0 {
		btce.logger.Printf("⚠️ [COST] %s intent %s executed but no measurable tx hash was found "+
			"(create=%q verify=%q governance=%q primary=%q); this intent will be unmeasured",
			chain, intentID, result.CreateTxHash, result.VerifyTxHash, result.GovernanceTxHash, result.TxHash)
	}
}

func anyMeasurable(legs []struct {
	leg    string
	txHash string
}) bool {
	for _, l := range legs {
		if len(extractTxHashes(l.txHash)) > 0 {
			return true
		}
	}
	return false
}

// extractTxHashes pulls every real transaction hash out of an executor result
// field.
//
// Executors write these in three shapes depending on the path taken:
//
//	"0xabc…"                              a bare hash
//	"Ethereum Sepolia:0xabc…"             chain-prefixed
//	"Ethereum Sepolia:leg-1:0xabc…,…"     chain+leg prefixed, comma-joined
//
// and non-EVM chains use native encodings (base58 Solana signatures), so the
// hash is taken as the last colon-separated segment rather than by matching
// "0x". Failure sentinels ("create_failed_base") are dropped.
func extractTxHashes(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Strip any "Chain:" / "Chain:leg-N:" prefix.
		if idx := strings.LastIndex(part, ":"); idx >= 0 && idx+1 < len(part) {
			part = part[idx+1:]
		}
		if !looksLikeTxHash(part) || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
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
	return resolveCostEndpointForChain(chain)
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
