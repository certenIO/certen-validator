// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// SettlementChainsEnv names the chains CERTEN settles on NOW, by chain id ("84532" or "11155111,84532,421614"): the
// enabled set of the chain catalogue (supportedchains.EnabledEnv). It is required - there is no default - and every
// validator must carry the same value (it is read from the shared environment): a leg on a chain not named is refused by
// name at consensus, so validators that disagreed would decide the same intent differently. Each named chain must be one
// this build catalogues, with its configuration complete: RPC providers, a CertenAnchorV8_2 (VerifySettlementAnchors),
// an outcome registry, a leaf version and a gas ceiling, each refused at boot by name. A rollout brings the chains up one
// at a time by naming them (RB5-F33).
const SettlementChainsEnv = supportedchains.EnabledEnv

// SettlementChainsFromEnv reads SettlementChainsEnv against the chains this build supports, ascending.
func SettlementChainsFromEnv(supported []int64) ([]int64, error) {
	return supportedchains.ParseEnabled(os.Getenv(SettlementChainsEnv), supported)
}

// anchorGenerationChain is what reading an anchor's generation needs of a chain.
type anchorGenerationChain interface {
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// VerifySettlementAnchors reads, on every settlement chain, the generation of the anchor configured for it, and refuses
// any that is not a CertenAnchorV8_2: this build sends the V8.2 createBatchAnchor and its quorum message, which an
// earlier anchor cannot take, so configuring one would fail every batch on that chain after the anchor fee was paid.
// An anchor's generation is fixed by its code, so the read is the same on every validator; a chain that cannot be read
// stops the start, never passes it.
func VerifySettlementAnchors(ctx context.Context, r *EVMChainResolverImpl, chains []int64) error {
	for _, id := range chains {
		m, anchor, err := r.ManagerForChain(id)
		if err != nil {
			return fmt.Errorf("chain %d: %w", id, err)
		}
		if m == nil || m.client == nil {
			return fmt.Errorf("chain %d: no client to read its anchor %s", id, anchor.Hex())
		}
		// A pinned chain is settled on only on its pinned genesis (RB7 D8): the client this validator sends through is
		// checked here, at boot; every agreed read checks its providers on every read (ethrpc genesis.go).
		host := ""
		if m.config != nil {
			if hs := ethrpc.ProviderHosts([]string{m.config.EthereumRPC}); len(hs) == 1 {
				host = hs[0]
			}
		}
		if err := ethrpc.CheckGenesis(ctx, id, host, m.client); err != nil {
			return err
		}
		if err := verifyAnchorGeneration(ctx, m.client, id, anchor); err != nil {
			return err
		}
	}
	return nil
}

func verifyAnchorGeneration(ctx context.Context, c anchorGenerationChain, chainID int64, anchor common.Address) error {
	code, err := c.CodeAt(ctx, anchor, nil)
	if err != nil {
		return fmt.Errorf("chain %d: reading the code of anchor %s: %w", chainID, anchor.Hex(), err)
	}
	if len(code) == 0 {
		return fmt.Errorf("chain %d: anchor %s has no code", chainID, anchor.Hex())
	}
	ret, err := c.CallContract(ctx, ethereum.CallMsg{To: &anchor, Data: contracts.AnchorsCallData([32]byte{})}, nil)
	if err != nil {
		return fmt.Errorf("chain %d: reading anchors() on %s: %w", chainID, anchor.Hex(), err)
	}
	st, err := contracts.DecodeAnchorsReturn(ret)
	if err != nil {
		return fmt.Errorf("chain %d: anchor %s: %w", chainID, anchor.Hex(), err)
	}
	if st.Version != contracts.BatchAnchorV8_2 {
		return fmt.Errorf("chain %d: anchor %s is a CertenAnchor%s; this build settles on CertenAnchorV8_2 only "+
			"(configure the chain's V8.2 anchor, or leave the chain out of %s until it has one)",
			chainID, anchor.Hex(), strings.ToUpper(strings.ReplaceAll(string(st.Version), "_", ".")), SettlementChainsEnv)
	}
	return nil
}

// notSettled is the error for a chain this validator does not settle on now: a refusal by name at consensus
// (consensus.ErrChainNotSettled), never an outage to wait out.
func notSettled(chainID int64) error {
	return fmt.Errorf("%w: chain %d is not one CERTEN settles on now (%s)", consensus.ErrChainNotSettled, chainID,
		SettlementChainsEnv)
}
