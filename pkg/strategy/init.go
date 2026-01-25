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

	// Register stub strategies for other chains (future implementation)
	if err := registerStubChainStrategies(registry, cfg); err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Printf("⚠️ Some stub chain strategies failed to register: %v", err)
		}
	}

	return nil
}

// registerStubChainStrategies registers placeholder strategies for future chains
func registerStubChainStrategies(registry *Registry, cfg *RegistryConfig) error {
	// Solana Devnet (stub)
	solanaStrategy, _ := chain.NewSolanaDevnetStrategy("", "", cfg.ValidatorID)
	if solanaStrategy != nil {
		_ = registry.RegisterChainStrategy("solana-devnet", solanaStrategy.Config(), solanaStrategy)
	}

	// NEAR Testnet (stub)
	nearStrategy, _ := chain.NewNEARTestnetStrategy("", "", "", cfg.ValidatorID)
	if nearStrategy != nil {
		_ = registry.RegisterChainStrategy("near-testnet", nearStrategy.Config(), nearStrategy)
	}

	// TON (stub)
	tonStrategy, _ := chain.NewTONMainnetStrategy("", "", cfg.ValidatorID)
	if tonStrategy != nil {
		_ = registry.RegisterChainStrategy("ton-mainnet", tonStrategy.Config(), tonStrategy)
	}

	return nil
}
