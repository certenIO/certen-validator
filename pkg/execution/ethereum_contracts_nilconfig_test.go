// Copyright 2026 Certen Protocol

package execution

import (
	"strings"
	"testing"
)

// RB7 Task 5 T5-5: a nil contract configuration used to be filled from the environment (a Sepolia chain id, an
// account contract). It is refused by name instead; the manager is only ever built from a chain's own settings.
func TestAContractManagerWithNoConfigurationIsRefusedByName(t *testing.T) {
	t.Setenv("SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "0x00000000000000000000000000000000000000f1")
	if _, err := NewEthereumContractManager(nil); err == nil || !strings.Contains(err.Error(), "configuration is missing") {
		t.Fatalf("a nil configuration was not refused by name: %v", err)
	}
}
