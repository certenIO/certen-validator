// Copyright 2025 Certen Protocol
//
// Strategy Registry Initialization
//
// The registry serves the proof cycle: Phase 7 observes a settlement on its chain, a peer re-observes
// it, and Phase 8 signs with the attestation scheme the chain's platform uses. CERTEN settles on
// the enabled chains of the chain catalogue (pkg/supportedchains), all EVM, all attested with BLS12-381 - so the
// registry holds exactly those, each observed at the anchor the batch path settles on, and nothing else (RB3-F44).

package strategy

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// SupportedChainIDs are the catalogued chains (supportedchains.All): the chains this build can settle on. Which of them it
// settles on now is the enabled set, CERTEN_SETTLEMENT_CHAINS (RegistryConfig.SettlementChains).
var SupportedChainIDs = supportedchains.IDs()

// supportedNetworks is each catalogued chain's network label (supportedchains.Chain.Network).
var supportedNetworks = func() map[int64]string {
	out := map[int64]string{}
	for _, c := range supportedchains.All {
		out[c.ID] = c.Network
	}
	return out
}()

// requiredConfirmations is the depth Phase 7 waits for on each supported chain.
const requiredConfirmations = 2

// ChainEndpoint is one supported chain as the batch path is configured for it: its RPC and the
// CertenAnchorV8 it settles on.
type ChainEndpoint struct {
	ChainID int64
	RPC     string
	Anchor  common.Address
}

// RegistryConfig holds what the registry is built from.
type RegistryConfig struct {
	ValidatorID string

	// BLSPrivateKey signs Phase 8 attestations. Required.
	BLSPrivateKey []byte

	// EthPrivateKey is the key the chain strategies are constructed with.
	EthPrivateKey string

	// SettlementChains are the chains CERTEN settles on now (CERTEN_SETTLEMENT_CHAINS, RB5-F33): at least one, each
	// supported. Chains must cover exactly these, each once - none silently missing (RB3-F44), none beside them.
	SettlementChains []int64

	// Chains is every settlement chain's endpoint, exactly once.
	Chains []ChainEndpoint

	Logger *log.Logger
}

// ChainKey is the registry key of a chain: its decimal chain id. It accepts the decimal id and the
// "evm-<id>" form the batch path records on anchor rows; anything else - a network name, an
// unsupported chain - is refused rather than guessed at.
func ChainKey(chain string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(chain), "evm-")
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "", fmt.Errorf("chain %q is not a chain id", chain)
	}
	if !isSupported(id) {
		return "", fmt.Errorf("chain %d is not a chain CERTEN settles on (supported: %v)", id, SupportedChainIDs)
	}
	return strconv.FormatInt(id, 10), nil
}

func isSupported(id int64) bool {
	for _, s := range SupportedChainIDs {
		if s == id {
			return true
		}
	}
	return false
}

// InitializeRegistry builds the registry: the BLS12-381 attestation strategy and one EVM observer per
// supported chain. Anything missing is an error - a validator that cannot observe a supported chain,
// or cannot sign, cannot take part in a proof cycle.
func InitializeRegistry(cfg *RegistryConfig) (*Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("no registry config")
	}
	registry := NewRegistry()

	if len(cfg.BLSPrivateKey) == 0 {
		return nil, fmt.Errorf("no BLS key: Phase 8 attestations could not be signed")
	}
	blsPrivKey, err := bls.PrivateKeyFromBytes(cfg.BLSPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("BLS key cannot be read: %w", err)
	}
	blsConfig := attestation.DefaultBLSStrategyConfig()
	blsConfig.ValidatorID = cfg.ValidatorID
	blsConfig.PrivateKeyBytes = blsPrivKey.Bytes()
	blsStrategy, err := attestation.NewBLSStrategy(blsConfig)
	if err != nil {
		return nil, fmt.Errorf("create BLS strategy: %w", err)
	}
	if err := registry.RegisterAttestationStrategy(blsStrategy); err != nil {
		return nil, fmt.Errorf("register BLS strategy: %w", err)
	}

	if len(cfg.SettlementChains) == 0 {
		return nil, fmt.Errorf("no settlement chains: the proof cycle would observe nothing")
	}
	settled := map[int64]bool{}
	for _, id := range cfg.SettlementChains {
		if !isSupported(id) {
			return nil, fmt.Errorf("settlement chain %d is not a chain CERTEN settles on (supported: %v)", id, SupportedChainIDs)
		}
		if settled[id] {
			return nil, fmt.Errorf("settlement chain %d is named twice", id)
		}
		settled[id] = true
	}
	byID := map[int64]ChainEndpoint{}
	for _, c := range cfg.Chains {
		if !isSupported(c.ChainID) {
			return nil, fmt.Errorf("chain %d is not a chain CERTEN settles on (supported: %v)", c.ChainID, SupportedChainIDs)
		}
		if _, dup := byID[c.ChainID]; dup {
			return nil, fmt.Errorf("chain %d is configured twice", c.ChainID)
		}
		if !settled[c.ChainID] {
			return nil, fmt.Errorf("chain %d is configured but is not one CERTEN settles on now", c.ChainID)
		}
		byID[c.ChainID] = c
	}
	for _, id := range SupportedChainIDs {
		if !settled[id] {
			continue
		}
		c, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("settlement chain %d is not configured", id)
		}
		if strings.TrimSpace(c.RPC) == "" {
			return nil, fmt.Errorf("chain %d has no RPC endpoint", id)
		}
		if c.Anchor == (common.Address{}) {
			return nil, fmt.Errorf("chain %d has no CertenAnchorV8", id)
		}
		key := strconv.FormatInt(id, 10)
		evm, err := chain.NewEVMStrategyFromConfig(&chain.ChainConfig{
			Platform:              chain.ChainPlatformEVM,
			ChainID:               key,
			NetworkName:           supportedNetworks[id],
			RPC:                   c.RPC,
			Endpoints:             ethrpc.EndpointsForChainID(id, c.RPC),
			ContractAddress:       c.Anchor.Hex(),
			RequiredConfirmations: requiredConfirmations,
			Enabled:               true,
		}, cfg.EthPrivateKey, cfg.ValidatorID)
		if err != nil {
			return nil, fmt.Errorf("create observer for chain %d: %w", id, err)
		}
		// The observer's chain is what its RPC reports: an RPC for another chain would observe that chain.
		if evm.ChainID() != key {
			return nil, fmt.Errorf("the RPC configured for chain %d serves chain %s", id, evm.ChainID())
		}
		// A settlement is observed only through independent providers that agree (RB5-F53). A chain CERTEN settles on
		// without them is refused here, at boot, instead of refusing every settlement on it later.
		if err := evm.FinalityError(); err != nil {
			return nil, fmt.Errorf("settlement chain %d: %w", id, err)
		}
		if err := registry.RegisterChainStrategy(key, evm.Config(), evm); err != nil {
			return nil, fmt.Errorf("register chain %d: %w", id, err)
		}
		if cfg.Logger != nil {
			cfg.Logger.Printf("✅ chain %d (%s) observed at anchor %s", id, supportedNetworks[id], c.Anchor.Hex())
		}
	}

	if cfg.Logger != nil {
		ids := registry.ListChainIDs()
		sort.Strings(ids)
		cfg.Logger.Printf("✅ Strategy registry: BLS12-381 attestation, chains %v", ids)
	}
	return registry, nil
}
