// Copyright 2026 Certen Protocol

package consensus

import (
	"errors"
	"fmt"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// Target chains — CERTEN executes on exactly the ENABLED chains, and refuses the rest by name
// =============================================================================
//
// A chain is executed on only when it is in the chain catalogue (supportedchains.All: the chains this build can settle
// on) AND enabled on this network (CERTEN_SETTLEMENT_CHAINS, required, identical on every validator; RB7 §4.1, RB8 §0).
// Every other chain the validator was ever configured for runs retired contracts, some owned by a key that has been
// published; a catalogued chain that is not enabled has no configured anchor, providers or registry here. Before this
// check an intent naming such a chain was executed anyway — an unknown chain ID even fell back to Sepolia against a
// retired anchor — so the only honest answer for them is a refusal that says why.
//
// The check reads the legs the user signed, on every validator, before anything is queued or sent, exactly like the
// account anchor pin. The numeric chain ID is authoritative: it is what the batch path settles on. A leg's free-text
// chain name is not consulted.

// ErrUnsupportedTargetChain is an intent with a leg CERTEN cannot place on an enabled chain.
var ErrUnsupportedTargetChain = errors.New("unsupported target chain")

// IsSupportedTargetChain reports whether CERTEN executes on the chain: catalogued and enabled (supportedchains.IsEnabled).
func IsSupportedTargetChain(chainID int64) bool {
	return supportedchains.IsEnabled(chainID)
}

// CheckIntentTargetChains refuses an intent unless every leg names an enabled chain, and names the same chain in its
// execution payload when the payload names one at all. An intent whose legs cannot be read, or that has none, names no
// enabled chain and is refused too.
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
	enabled, err := supportedchains.EnabledFromEnv()
	if err != nil {
		// The validator does not start with an unreadable enabled set (the batch path refuses it at boot).
		return fmt.Errorf("%w: the enabled chains cannot be read: %v", ErrUnsupportedTargetChain, err)
	}
	on := map[int64]bool{}
	for _, id := range enabled {
		on[id] = true
	}
	for i, leg := range env.Legs {
		if leg.ChainID == 0 {
			return fmt.Errorf("%w: leg %d names no chain ID", ErrUnsupportedTargetChain, i)
		}
		if !on[leg.ChainID] {
			if c, catalogued := supportedchains.Lookup(leg.ChainID); catalogued {
				return fmt.Errorf("%w: leg %d targets chain %d (%s), which is not enabled on this network (%s); CERTEN executes only on %s",
					ErrUnsupportedTargetChain, i, leg.ChainID, c.Name, supportedchains.EnabledEnv, supportedchains.DescribeIDs(enabled))
			}
			return fmt.Errorf("%w: leg %d targets chain %d; CERTEN executes only on %s",
				ErrUnsupportedTargetChain, i, leg.ChainID, supportedchains.DescribeIDs(enabled))
		}
		if ep := leg.ExecutionPayload; ep != nil && ep.ChainID != 0 && ep.ChainID != leg.ChainID {
			return fmt.Errorf("%w: leg %d names chain %d but its execution payload names chain %d",
				ErrUnsupportedTargetChain, i, leg.ChainID, ep.ChainID)
		}
	}
	return nil
}
