// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB6-F9: a gate that could not prove the member's settlement in its block says so by name (settled_unproven); it does
// not claim the transaction is not the member's settlement. Any other gate refusal keeps its own statement.
func TestTheGateNamesAnUnprovableSettlement(t *testing.T) {
	unproven := gateRefusal("421614", fmt.Errorf("RB-2: no inclusion proofs for 0xabc: %w", fmt.Errorf("%w: transaction type 0x7d has no encoder", ethproof.ErrRefused)))
	if !strings.HasPrefix(unproven.Error(), "settled_unproven:") || strings.Contains(unproven.Error(), "no observed transaction is") ||
		!errors.Is(unproven, ethproof.ErrRefused) {
		t.Fatalf("THE regression: an unprovable settlement reported as %v", unproven)
	}
	other := gateRefusal("421614", errors.New("the transaction is not bound to the member's operation"))
	if !strings.HasPrefix(other.Error(), "no observed transaction is the member's settlement") {
		t.Fatalf("another refusal: %v", other)
	}
	if none := gateRefusal("421614", nil); !strings.Contains(none.Error(), "observed no transaction") {
		t.Fatalf("no transaction: %v", none)
	}
}
