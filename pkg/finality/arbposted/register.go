// Copyright 2026 Certen Protocol

package arbposted

import "github.com/certen/independant-validator/pkg/finality"

// Register adds the verifier of arb-sepolia/l1_posted/v1 to a registry. There is no init(): the process (or a test) calls it
// explicitly, and a second registration of the kind is refused by the registry.
func Register(reg *finality.Registry) error {
	return reg.RegisterKind(New())
}
