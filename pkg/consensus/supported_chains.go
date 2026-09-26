// Copyright 2026 Certen Protocol

package consensus

import (
	"errors"
	"fmt"
)

// =============================================================================
// Supported target chains — CERTEN executes on exactly these, and refuses the rest by name
// =============================================================================
//
// Ethereum Sepolia, Base Sepolia and Arbitrum Sepolia are the chains running CERTEN's current
// contracts (CertenAnchorV8_1, CertenAccountFactoryV9, BLSZKVerifierV2). Every other chain the
// validator was ever configured for runs retired contracts, some owned by a key that has been
// published. Before this check an intent naming such a chain was executed anyway — an unknown
// chain ID even fell back to Sepolia against a retired anchor — so the only honest answer for them
// is a refusal that says why.
//
// The check reads the legs the user signed, on every validator, before anything is queued or
// sent, exactly like the account anchor pin. The numeric chain ID is authoritative: it is what the
// batch path settles on. A leg's free-text chain name is not consulted.

// ErrUnsupportedTargetChain is an intent with a leg CERTEN cannot place on a supported chain.
var ErrUnsupportedTargetChain = errors.New("unsupported target chain")

// supportedTargetChains maps each supported chain ID to its name for refusal messages.
var supportedTargetChains = map[int64]string{
	11155111: "ethereum-sepolia",
	84532:    "base-sepolia",
	421614:   "arbitrum-sepolia",
}

// IsSupportedTargetChain reports whether CERTEN executes on the chain.
func IsSupportedTargetChain(chainID int64) bool {
	_, ok := supportedTargetChains[chainID]
	return ok
}

// CheckIntentTargetChains refuses an intent unless every leg names a supported chain, and names the
// same chain in its execution payload when the payload names one at all. An intent whose legs
// cannot be read, or that has none, names no supported chain and is refused too.
func CheckIntentTargetChains(ci *CertenIntent) error {
	if ci == nil {
		return fmt.Errorf("%w: no intent", ErrUnsupportedTargetChain)
	}
	env, err := ci.ParseCrossChain()
	if err != nil {
		return fmt.Errorf("%w: legs cannot be read: %v", ErrUnsupportedTargetChain, err)
	}
	if len(env.Legs) == 0 {
		return fmt.Errorf("%w: intent has no legs", ErrUnsupportedTargetChain)
	}
	for i, leg := range env.Legs {
		if leg.ChainID == 0 {
			return fmt.Errorf("%w: leg %d names no chain ID", ErrUnsupportedTargetChain, i)
		}
		if !IsSupportedTargetChain(leg.ChainID) {
			return fmt.Errorf("%w: leg %d targets chain %d; CERTEN executes only on %s",
				ErrUnsupportedTargetChain, i, leg.ChainID, supportedChainList())
		}
		if ep := leg.ExecutionPayload; ep != nil && ep.ChainID != 0 && ep.ChainID != leg.ChainID {
			return fmt.Errorf("%w: leg %d names chain %d but its execution payload names chain %d",
				ErrUnsupportedTargetChain, i, leg.ChainID, ep.ChainID)
		}
	}
	return nil
}

// supportedChainList renders the supported chains in a fixed order for messages.
func supportedChainList() string {
	return "ethereum-sepolia (11155111), base-sepolia (84532), arbitrum-sepolia (421614)"
}
