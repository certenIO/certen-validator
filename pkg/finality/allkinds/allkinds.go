// Copyright 2026 Certen Protocol

// Package allkinds registers every finality verifier kind implemented so far into a registry, so that one call gives the offline
// verifier (cmd/proofverify --offline) the means to judge every level of every chain from files and the embedded pins.
//
// The call is explicit: there is no init(), and a kind registered twice is refused by the registry. Only verifiers are registered
// here; the provers (the builders that need live provider access) stay unregistered until the runtime configuration that gives
// them their sources is wired (RB11-B2B2b).
package allkinds

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// Kinds are the verifier kinds Register adds, in registration order: adiri/finalized/v1, base-sepolia/l1_posted/v1,
// base-sepolia/finalized/v1 and arb-sepolia/l1_posted/v1. The ethl1-based Ethereum Sepolia finalized kind (RB11-C2) and the
// Arbitrum finalized kind (RB11-E1) are added here when their branches are integrated.
func Kinds() []func(*finality.Registry) error {
	return []func(*finality.Registry) error{adiri.Register, baseposted.Register, basefinal.Register, arbposted.Register}
}

// Register adds every implemented verifier kind to reg. The first refusal (a kind already registered, or one that is not a row of
// the V2_SPEC_S7 section 1 table) is returned and nothing after it is registered.
func Register(reg *finality.Registry) error {
	for i, r := range Kinds() {
		if err := r(reg); err != nil {
			return fmt.Errorf("allkinds: kind %d: %w", i, err)
		}
	}
	return nil
}
