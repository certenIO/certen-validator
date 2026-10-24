// Copyright 2026 Certen Protocol

package capture_test

import (
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The acceptance of WP-S8-3b with the REAL composed verifier (steps of 2a, 2b-1, 2b-2, 2c): the container that E1, E2 and the link assemble
// over the H0 world of every chain, plain and with rich storage, verifies.
func TestE1AssembledLegVerifiesWithTheRealVerifier(t *testing.T) {
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	verifyAssembledLeg(t, v)
}
