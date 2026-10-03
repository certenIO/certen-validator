package execution

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// The outcome registries (RB5 D4)
// =============================================================================

// OutcomeRegistryEnvPrefix names each settlement chain's CertenOutcomeRegistryV1: CERTEN_OUTCOME_REGISTRY_<chainId>.
// Required for every chain in CERTEN_SETTLEMENT_CHAINS: a V8.2 batch anchor's outcome is recorded there, and a
// validator without it could neither record nor certify one.
const OutcomeRegistryEnvPrefix = "CERTEN_OUTCOME_REGISTRY_"

// OutcomeRegistriesFromEnv reads CERTEN_OUTCOME_REGISTRY_<chainId> for every settlement chain, refusing a chain without
// one, or with one that is not an address, by name.
func OutcomeRegistriesFromEnv(chains []int64) (map[int64]common.Address, error) {
	if len(chains) == 0 {
		return nil, fmt.Errorf("no settlement chains to read outcome registries for")
	}
	out := make(map[int64]common.Address, len(chains))
	var problems []string
	for _, id := range chains {
		key := fmt.Sprintf("%s%d", OutcomeRegistryEnvPrefix, id)
		v := strings.TrimSpace(os.Getenv(key))
		switch {
		case v == "":
			problems = append(problems, fmt.Sprintf("%s is not set: chain %d is a chain CERTEN settles on, and its batch "+
				"anchors' outcomes are recorded in its CertenOutcomeRegistryV1", key, id))
		case !common.IsHexAddress(v) || common.HexToAddress(v) == (common.Address{}):
			problems = append(problems, fmt.Sprintf("%s=%q is not a contract address", key, v))
		default:
			out[id] = common.HexToAddress(v)
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("outcome registries: %s", strings.Join(problems, "; "))
	}
	return out, nil
}

// RegistryIdentity is what a registry says it is bound to: its anchor and the chain it was deployed on.
type RegistryIdentity interface {
	RegistryIdentity(ctx context.Context) (anchor common.Address, deployedOn *big.Int, err error)
}

// VerifyOutcomeRegistry refuses a registry that is not the one recording chainID's anchor: its anchor() must be the
// chain's CERTEN_ANCHOR_V8_<chainId>, and its DEPLOYMENT_CHAIN_ID the chain itself. A misconfigured registry would
// sign messages the anchor's quorum never checks, or record outcomes of another chain's anchors.
func VerifyOutcomeRegistry(ctx context.Context, chainID int64, registry, anchor common.Address, r RegistryIdentity) error {
	got, deployedOn, err := r.RegistryIdentity(ctx)
	if err != nil {
		return fmt.Errorf("chain %d: reading outcome registry %s: %w", chainID, registry.Hex(), err)
	}
	if got != anchor {
		return fmt.Errorf("chain %d: outcome registry %s records anchor %s, but CERTEN_ANCHOR_V8_%d is %s", chainID,
			registry.Hex(), got.Hex(), chainID, anchor.Hex())
	}
	if deployedOn == nil || !deployedOn.IsInt64() || deployedOn.Int64() != chainID {
		return fmt.Errorf("chain %d: outcome registry %s was deployed for chain %v", chainID, registry.Hex(), deployedOn)
	}
	return nil
}

// RegistryIdentity reads the registry's anchor() and DEPLOYMENT_CHAIN_ID, agreed at a recent block.
func (c *AgreedOutcomeChain) RegistryIdentity(ctx context.Context) (common.Address, *big.Int, error) {
	at, err := c.reader.RecentAgreedHeader(ctx)
	if err != nil {
		return common.Address{}, nil, err
	}
	out, err := c.call(ctx, outcomeRegistryABI, c.registry, at.Hash(), "anchor")
	if err != nil {
		return common.Address{}, nil, err
	}
	anchor, ok := out[0].(common.Address)
	if !ok {
		return common.Address{}, nil, fmt.Errorf("anchor() returned %T", out[0])
	}
	out, err = c.call(ctx, outcomeRegistryABI, c.registry, at.Hash(), "DEPLOYMENT_CHAIN_ID")
	if err != nil {
		return common.Address{}, nil, err
	}
	id, ok := out[0].(*big.Int)
	if !ok {
		return common.Address{}, nil, fmt.Errorf("DEPLOYMENT_CHAIN_ID returned %T", out[0])
	}
	return anchor, id, nil
}

// Registry is the outcome registry this chain records in.
func (c *AgreedOutcomeChain) Registry() common.Address { return c.registry }

// Anchor is the chain's CertenAnchorV8_2.
func (c *AgreedOutcomeChain) Anchor() common.Address { return c.anchor }

// OutcomeChainsFromEnv builds, for every settlement chain, the agreed reads of its anchor and its outcome registry
// (CERTEN_OUTCOME_REGISTRY_<chainId>), and verifies each registry is bound to the chain's anchor on that chain. Any
// chain that cannot be built or verified stops the start, by name.
func OutcomeChainsFromEnv(ctx context.Context, r *EVMChainResolverImpl, chains []int64) (map[int64]*AgreedOutcomeChain, error) {
	if r == nil {
		return nil, fmt.Errorf("outcome chains: no chain resolver")
	}
	registries, err := OutcomeRegistriesFromEnv(chains)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]*AgreedOutcomeChain, len(chains))
	for _, id := range chains {
		rpcURL, anchor, err := r.Endpoint(id)
		if err != nil {
			return nil, fmt.Errorf("chain %d: %w", id, err)
		}
		c, err := NewAgreedOutcomeChain(ctx, id, rpcURL, anchor, registries[id])
		if err != nil {
			return nil, err
		}
		if err := VerifyOutcomeRegistry(ctx, id, registries[id], anchor, c); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, nil
}
