// Copyright 2025 Certen Protocol
//
// Strategy Registry Initialization
// Provides helper functions to initialize the strategy registry with all
// attestation and chain execution strategies.
//
// Per Unified Multi-Chain Architecture:
// - BLS12-381 for EVM chains (ZK-verified on-chain)
// - Ed25519 for non-EVM chains (native support, cost-effective)

package strategy

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"strconv"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// RegistryConfig holds configuration for initializing the strategy registry
type RegistryConfig struct {
	// Validator identity
	ValidatorID    string
	ValidatorIndex uint32

	// BLS key for EVM attestations
	BLSPrivateKey []byte

	// Ed25519 key for non-EVM attestations
	Ed25519PrivateKey ed25519.PrivateKey

	// Ethereum configuration
	EthereumRPC      string
	EthPrivateKey    string
	EthChainID       int64
	AnchorContract   string
	CertenContract   string
	NetworkName      string

	// Logger
	Logger *log.Logger
}

// NewRegistryFromConfig creates a strategy registry from config
func NewRegistryFromConfig(cfg *config.Config, blsKey []byte, ed25519Key ed25519.PrivateKey) (*Registry, error) {
	regConfig := &RegistryConfig{
		ValidatorID:       cfg.ValidatorID,
		ValidatorIndex:    0, // Would come from validator set
		BLSPrivateKey:     blsKey,
		Ed25519PrivateKey: ed25519Key,
		EthereumRPC:       cfg.EthereumURL,
		EthPrivateKey:     cfg.EthPrivateKey,
		EthChainID:        cfg.EthChainID,
		AnchorContract:    cfg.AnchorContractAddress,
		CertenContract:    cfg.CertenContractAddress,
		NetworkName:       cfg.NetworkName,
		Logger:            log.New(log.Writer(), "[StrategyRegistry] ", log.LstdFlags),
	}

	return InitializeRegistry(regConfig)
}

// InitializeRegistry creates and populates a strategy registry with all strategies
func InitializeRegistry(cfg *RegistryConfig) (*Registry, error) {
	registry := NewRegistry()

	// Initialize attestation strategies
	if err := initializeAttestationStrategies(registry, cfg); err != nil {
		return nil, fmt.Errorf("initialize attestation strategies: %w", err)
	}

	// Initialize chain execution strategies
	if err := initializeChainStrategies(registry, cfg); err != nil {
		return nil, fmt.Errorf("initialize chain strategies: %w", err)
	}

	if cfg.Logger != nil {
		cfg.Logger.Printf("✅ Strategy registry initialized with %d attestation schemes and %d chains",
			len(registry.attestationStrategies), len(registry.chainStrategies))
	}

	return registry, nil
}

// initializeAttestationStrategies registers all attestation strategies
func initializeAttestationStrategies(registry *Registry, cfg *RegistryConfig) error {
	// BLS12-381 strategy (for EVM chains)
	if cfg.BLSPrivateKey != nil && len(cfg.BLSPrivateKey) > 0 {
		blsPrivKey, err := bls.PrivateKeyFromBytes(cfg.BLSPrivateKey)
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("⚠️ BLS key deserialization failed: %v (BLS attestation disabled)", err)
			}
		} else {
			blsConfig := attestation.DefaultBLSStrategyConfig()
			blsConfig.ValidatorID = cfg.ValidatorID
			blsConfig.ValidatorIndex = cfg.ValidatorIndex
			blsConfig.PrivateKeyBytes = blsPrivKey.Bytes()

			blsStrategy, err := attestation.NewBLSStrategy(blsConfig)
			if err != nil {
				return fmt.Errorf("create BLS strategy: %w", err)
			}
			if err := registry.RegisterAttestationStrategy(blsStrategy); err != nil {
				return fmt.Errorf("register BLS strategy: %w", err)
			}
			if cfg.Logger != nil {
				cfg.Logger.Printf("✅ BLS12-381 attestation strategy registered")
			}
		}
	}

	// Ed25519 strategy (for non-EVM chains)
	if cfg.Ed25519PrivateKey != nil && len(cfg.Ed25519PrivateKey) > 0 {
		ed25519Config := attestation.DefaultEd25519StrategyConfig()
		ed25519Config.ValidatorID = cfg.ValidatorID
		ed25519Config.ValidatorIndex = cfg.ValidatorIndex
		ed25519Config.PrivateKey = cfg.Ed25519PrivateKey

		ed25519Strategy, err := attestation.NewEd25519Strategy(ed25519Config)
		if err != nil {
			return fmt.Errorf("create Ed25519 strategy: %w", err)
		}
		if err := registry.RegisterAttestationStrategy(ed25519Strategy); err != nil {
			return fmt.Errorf("register Ed25519 strategy: %w", err)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("✅ Ed25519 attestation strategy registered")
		}
	}

	return nil
}

// initializeChainStrategies registers all chain execution strategies
func initializeChainStrategies(registry *Registry, cfg *RegistryConfig) error {
	// Determine Ethereum network from chain ID
	var evmStrategy *chain.EVMStrategy
	var err error

	switch cfg.EthChainID {
	case 1:
		// Ethereum Mainnet
		evmStrategy, err = chain.NewMainnetStrategy(
			cfg.EthereumRPC,
			cfg.EthPrivateKey,
			cfg.AnchorContract,
			cfg.ValidatorID,
		)
	case 11155111:
		// Sepolia Testnet
		evmStrategy, err = chain.NewSepoliaStrategy(
			cfg.EthereumRPC,
			cfg.EthPrivateKey,
			cfg.AnchorContract,
			cfg.ValidatorID,
		)
	default:
		// Custom EVM chain
		evmConfig := chain.DefaultEVMStrategyConfig()
		evmConfig.ChainConfig = &chain.ChainConfig{
			Platform:              chain.ChainPlatformEVM,
			ChainID:               fmt.Sprintf("%d", cfg.EthChainID),
			NetworkName:           cfg.NetworkName,
			RPC:                   cfg.EthereumRPC,
			ContractAddress:       cfg.AnchorContract,
			RequiredConfirmations: 12,
			Enabled:               true,
		}
		evmConfig.PrivateKeyHex = cfg.EthPrivateKey
		evmConfig.AnchorContractAddress = cfg.AnchorContract
		evmConfig.ValidatorID = cfg.ValidatorID

		evmStrategy, err = chain.NewEVMStrategy(evmConfig)
	}

	if err != nil {
		return fmt.Errorf("create EVM strategy: %w", err)
	}

	// Register EVM strategy for all configured chain IDs
	chainID := evmStrategy.ChainID()
	if err := registry.RegisterChainStrategy(chainID, evmStrategy.Config(), evmStrategy); err != nil {
		return fmt.Errorf("register EVM strategy for %s: %w", chainID, err)
	}
	if cfg.Logger != nil {
		cfg.Logger.Printf("✅ EVM chain strategy registered: %s", chainID)
	}

	// Register additional chain aliases
	if cfg.NetworkName != "" && cfg.NetworkName != chainID {
		if err := registry.RegisterChainStrategy(cfg.NetworkName, evmStrategy.Config(), evmStrategy); err != nil {
			// Don't fail on alias registration
			if cfg.Logger != nil {
				cfg.Logger.Printf("⚠️ Could not register alias %s: %v", cfg.NetworkName, err)
			}
		}
	}

	// Register well-known network name aliases for common chains
	// Include both hyphenated and space-separated variants for intent compatibility
	knownAliases := map[int64][]string{
		1:        {"ethereum", "mainnet", "eth-mainnet"},
		11155111: {"sepolia", "eth-sepolia", "ethereum-sepolia", "ethereum sepolia"},
		137:      {"polygon", "matic"},
		80002:    {"polygon-amoy", "polygon amoy", "amoy"},
		42161:    {"arbitrum", "arbitrum-one"},
		421614:   {"arbitrum-sepolia", "arbitrum sepolia"},
		10:       {"optimism", "op-mainnet"},
		11155420: {"optimism-sepolia", "optimism sepolia", "op-sepolia"},
		8453:     {"base", "base-mainnet"},
		84532:    {"base-sepolia", "base sepolia"},
		97:       {"bsc-testnet", "bsc testnet", "binance-testnet"},
		56:       {"bsc", "binance", "bsc-mainnet"},
		1287:     {"moonbase-alpha", "moonbase alpha", "moonbeam-testnet", "moonbeam moonbase alpha"},
		1284:     {"moonbeam"},
		2494104990: {"tron-shasta", "tron shasta", "tron-shasta-testnet", "tron shasta testnet", "tron"},
	}
	if aliases, ok := knownAliases[int64(cfg.EthChainID)]; ok {
		for _, alias := range aliases {
			if alias != chainID && alias != cfg.NetworkName {
				if err := registry.RegisterChainStrategy(alias, evmStrategy.Config(), evmStrategy); err == nil {
					if cfg.Logger != nil {
						cfg.Logger.Printf("   ✅ Registered alias: %s -> %s", alias, chainID)
					}
				}
			}
		}
	}

	// Register L2 EVM chain strategies from environment variables
	// Each L2 chain with a configured RPC URL gets its own EVMStrategy instance
	if err := registerL2EVMStrategies(registry, cfg, knownAliases); err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Printf("⚠️ Some L2 EVM chain strategies failed to register: %v", err)
		}
	}

	// Register stub strategies for other chains (future implementation)
	if err := registerStubChainStrategies(registry, cfg); err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Printf("⚠️ Some stub chain strategies failed to register: %v", err)
		}
	}

	return nil
}

// l2ChainDef defines an L2 EVM chain to register
type l2ChainDef struct {
	chainID       int64
	networkName   string
	rpcEnvVar     string
	anchorEnvVar  string
	anchorDefault string
	confirmations int
}

// registerL2EVMStrategies registers EVM strategies for all configured L2 chains.
// Each chain with an RPC URL env var set gets its own EVMStrategy instance so the
// orchestrator can observe transactions and write back proofs on any target chain.
func registerL2EVMStrategies(registry *Registry, cfg *RegistryConfig, knownAliases map[int64][]string) error {
	l2Chains := []l2ChainDef{
		{421614, "arbitrum-sepolia", "ARBITRUM_SEPOLIA_RPC_URL", "ARBITRUM_SEPOLIA_ANCHORV4_ADDRESS", "0xD2f19FfF59d9eADA39cf5a3737914Aa1F6B4ca12", 2},
		{11155420, "optimism-sepolia", "OPTIMISM_SEPOLIA_RPC_URL", "OPTIMISM_SEPOLIA_ANCHORV4_ADDRESS", "0xA8CB329e6867296084f87Bf0bB800E44932feac7", 2},
		{84532, "base-sepolia", "BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_ANCHORV4_ADDRESS", "0x7a8c5DC01C2d2Ba498F76832dBcbf0Fe2f69a6C3", 2},
		{80002, "polygon-amoy", "POLYGON_AMOY_RPC_URL", "POLYGON_AMOY_ANCHORV4_ADDRESS", "0x7a8c5DC01C2d2Ba498F76832dBcbf0Fe2f69a6C3", 2},
		{97, "bsc-testnet", "BSC_TESTNET_RPC_URL", "BSC_TESTNET_ANCHORV4_ADDRESS", "0x3E7b37a517dec735e06126781A5D01d73d3c26D6", 2},
		{1287, "moonbase-alpha", "MOONBASE_ALPHA_RPC_URL", "MOONBASE_ALPHA_ANCHORV4_ADDRESS", "0x7a8c5DC01C2d2Ba498F76832dBcbf0Fe2f69a6C3", 2},
		// TRON Shasta - EVM-compatible via /jsonrpc for observation; writes use native HTTP API in tron_client.go
		{2494104990, "tron-shasta", "TRON_SHASTA_RPC_URL", "TRON_SHASTA_ANCHORV4_ADDRESS", "0xca04231da28aab992fdffd3c9a7f8ddcd1f26027", 1},
	}

	for _, l2 := range l2Chains {
		// Skip if this L2 is actually the primary chain (already registered)
		if l2.chainID == cfg.EthChainID {
			continue
		}

		rpcURL := os.Getenv(l2.rpcEnvVar)
		if rpcURL == "" {
			continue
		}

		// Resolve anchor address with V6.1 → V6 → V5 → V4 fallback so the
		// watcher observes the newest anchor on each chain without forcing
		// operators to rename env vars in lockstep with contract redeploys.
		chainPrefix := l2.anchorEnvVar[:len(l2.anchorEnvVar)-len("_ANCHORV4_ADDRESS")]
		anchorAddr := os.Getenv(chainPrefix + "_ANCHORV6_1_ADDRESS")
		if anchorAddr == "" {
			anchorAddr = os.Getenv(chainPrefix + "_ANCHORV6_ADDRESS")
		}
		if anchorAddr == "" {
			anchorAddr = os.Getenv(chainPrefix + "_ANCHORV5_ADDRESS")
		}
		if anchorAddr == "" {
			anchorAddr = os.Getenv(l2.anchorEnvVar)
		}
		if anchorAddr == "" {
			anchorAddr = l2.anchorDefault
		}

		chainConfig := &chain.ChainConfig{
			Platform:              chain.ChainPlatformEVM,
			ChainID:               strconv.FormatInt(l2.chainID, 10),
			NetworkName:           l2.networkName,
			RPC:                   rpcURL,
			ContractAddress:       anchorAddr,
			RequiredConfirmations: l2.confirmations,
			Enabled:               true,
		}

		l2Strategy, err := chain.NewEVMStrategyFromConfig(chainConfig, cfg.EthPrivateKey, cfg.ValidatorID)
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("⚠️ Failed to create EVM strategy for %s: %v", l2.networkName, err)
			}
			continue
		}

		l2ChainID := l2Strategy.ChainID()
		if err := registry.RegisterChainStrategy(l2ChainID, l2Strategy.Config(), l2Strategy); err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("⚠️ Failed to register %s (chainID %s): %v", l2.networkName, l2ChainID, err)
			}
			continue
		}

		if cfg.Logger != nil {
			cfg.Logger.Printf("✅ L2 EVM chain strategy registered: %s (chainID %s)", l2.networkName, l2ChainID)
		}

		// Register aliases
		if aliases, ok := knownAliases[l2.chainID]; ok {
			for _, alias := range aliases {
				if alias != l2ChainID {
					if err := registry.RegisterChainStrategy(alias, l2Strategy.Config(), l2Strategy); err == nil {
						if cfg.Logger != nil {
							cfg.Logger.Printf("   ✅ Registered alias: %s -> %s", alias, l2ChainID)
						}
					}
				}
			}
		}
	}

	return nil
}

// registerNonEVMChainStrategies registers non-EVM chain strategies.
// TON is fully implemented; others are stubs pending implementation.
func registerStubChainStrategies(registry *Registry, cfg *RegistryConfig) error {
	// =========================================================================
	// TON — Full implementation using TON Center API v2
	// =========================================================================
	tonAPIURL := os.Getenv("TON_TESTNET_API_URL")
	tonAPIKey := os.Getenv("TON_TESTNET_API_KEY")
	tonAnchorContract := os.Getenv("TON_ANCHOR_CONTRACT")
	tonBLSVerifier := os.Getenv("TON_BLS_VERIFIER_CONTRACT")

	if tonAPIURL != "" {
		// Register TON testnet strategy (primary — matches "ton testnet", "ton-testnet")
		tonTestnetStrategy, err := chain.NewTONTestnetStrategy(
			tonAPIURL, tonAnchorContract, tonBLSVerifier, cfg.ValidatorID,
		)
		if err == nil && tonTestnetStrategy != nil {
			// Set API key if available
			if tonAPIKey != "" {
				tonTestnetStrategy.SetAPIKey(tonAPIKey)
			}

			// Register with all common name variants that intents may use
			tonTestnetAliases := []string{
				"ton-testnet", "ton testnet", "ton_testnet", "ton-test",
			}
			for _, alias := range tonTestnetAliases {
				if regErr := registry.RegisterChainStrategy(alias, tonTestnetStrategy.Config(), tonTestnetStrategy); regErr == nil {
					if cfg.Logger != nil {
						cfg.Logger.Printf("   ✅ TON testnet registered: %s", alias)
					}
				}
			}
		} else if err != nil && cfg.Logger != nil {
			cfg.Logger.Printf("⚠️ Failed to create TON testnet strategy: %v", err)
		}

		// Register TON mainnet strategy (same implementation, different config)
		tonMainnetAPIURL := os.Getenv("TON_MAINNET_API_URL")
		if tonMainnetAPIURL == "" {
			tonMainnetAPIURL = "https://toncenter.com/api/v2"
		}
		tonMainnetStrategy, err := chain.NewTONMainnetStrategy(
			tonMainnetAPIURL, tonAnchorContract, cfg.ValidatorID,
		)
		if err == nil && tonMainnetStrategy != nil {
			tonMainnetAliases := []string{
				"ton-mainnet", "ton mainnet", "ton_mainnet", "ton",
			}
			for _, alias := range tonMainnetAliases {
				if regErr := registry.RegisterChainStrategy(alias, tonMainnetStrategy.Config(), tonMainnetStrategy); regErr == nil {
					if cfg.Logger != nil {
						cfg.Logger.Printf("   ✅ TON mainnet registered: %s", alias)
					}
				}
			}
		}
	} else {
		// No TON API URL configured — register stub for interface compliance
		tonStrategy, _ := chain.NewTONMainnetStrategy("", "", cfg.ValidatorID)
		if tonStrategy != nil {
			_ = registry.RegisterChainStrategy("ton-mainnet", tonStrategy.Config(), tonStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("⚠️ TON_TESTNET_API_URL not set — TON strategies registered as stubs")
		}
	}

	// =========================================================================
	// Solana — Full implementation using Solana JSON-RPC
	// =========================================================================
	solanaRPCURL := os.Getenv("SOLANA_DEVNET_RPC_URL")
	solanaAnchorProgram := os.Getenv("SOLANA_ANCHOR_PROGRAM_ID")

	solanaStrategy, _ := chain.NewSolanaDevnetStrategy(solanaRPCURL, solanaAnchorProgram, cfg.ValidatorID)
	if solanaStrategy != nil {
		solanaAliases := []string{"solana-devnet", "solana devnet", "solana_devnet", "solana-testnet", "solana testnet"}
		for _, alias := range solanaAliases {
			_ = registry.RegisterChainStrategy(alias, solanaStrategy.Config(), solanaStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("   ✅ Solana devnet registered: rpc=%s, program=%s", solanaRPCURL, solanaAnchorProgram)
		}
	}

	// =========================================================================
	// Sui — Full implementation using Sui JSON-RPC
	// =========================================================================
	suiRPCURL := os.Getenv("SUI_TESTNET_RPC_URL")
	suiAnchorPackage := os.Getenv("SUI_ANCHOR_PACKAGE")

	suiStrategy, _ := chain.NewSuiTestnetStrategy(suiRPCURL, suiAnchorPackage, cfg.ValidatorID)
	if suiStrategy != nil {
		suiAliases := []string{"sui-testnet", "sui testnet", "sui_testnet"}
		for _, alias := range suiAliases {
			_ = registry.RegisterChainStrategy(alias, suiStrategy.Config(), suiStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("   ✅ Sui testnet registered: rpc=%s, package=%s", suiRPCURL, suiAnchorPackage)
		}
	}

	// =========================================================================
	// Aptos — Full implementation using Aptos REST API
	// =========================================================================
	aptosRPCURL := os.Getenv("APTOS_TESTNET_RPC_URL")
	aptosAnchorPackage := os.Getenv("APTOS_ANCHOR_PACKAGE")

	aptosStrategy, _ := chain.NewAptosTestnetStrategy(aptosRPCURL, aptosAnchorPackage, cfg.ValidatorID)
	if aptosStrategy != nil {
		aptosAliases := []string{"aptos-testnet", "aptos testnet", "aptos_testnet"}
		for _, alias := range aptosAliases {
			_ = registry.RegisterChainStrategy(alias, aptosStrategy.Config(), aptosStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("   ✅ Aptos testnet registered: rpc=%s, module=%s", aptosRPCURL, aptosAnchorPackage)
		}
	}

	// =========================================================================
	// NEAR — Full implementation using NEAR JSON-RPC
	// =========================================================================
	nearRPCURL := os.Getenv("NEAR_TESTNET_RPC_URL")
	nearAnchorContract := os.Getenv("NEAR_ANCHOR_CONTRACT")
	nearSignerAccount := os.Getenv("NEAR_SIGNER_ACCOUNT_ID")

	nearStrategy, _ := chain.NewNEARTestnetStrategy(nearRPCURL, nearAnchorContract, nearSignerAccount, cfg.ValidatorID)
	if nearStrategy != nil {
		nearAliases := []string{"near-testnet", "near testnet", "near_testnet"}
		for _, alias := range nearAliases {
			_ = registry.RegisterChainStrategy(alias, nearStrategy.Config(), nearStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("   ✅ NEAR testnet registered: rpc=%s, contract=%s", nearRPCURL, nearAnchorContract)
		}
	}

	// =========================================================================
	// Cardano — Full implementation using Blockfrost HTTP API.
	// On-chain proof verification is BLS12-381 Groth16+BSB22 (A+++ parity).
	// Phase 7-9 observation watches tx finality via Blockfrost.
	// =========================================================================
	cardanoProjectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	cardanoAnchorAddr := os.Getenv("CARDANO_PREVIEW_ANCHOR_ADDRESS")

	cardanoStrategy, _ := chain.NewCardanoPreviewStrategy(cardanoProjectID, cardanoAnchorAddr, cfg.ValidatorID)
	if cardanoStrategy != nil {
		cardanoAliases := []string{"cardano-preview", "cardano preview", "cardano_preview", "cardano"}
		for _, alias := range cardanoAliases {
			_ = registry.RegisterChainStrategy(alias, cardanoStrategy.Config(), cardanoStrategy)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("   ✅ Cardano Preview registered: blockfrost=%t, anchor=%s", cardanoProjectID != "", cardanoAnchorAddr)
		}
	}

	return nil
}
