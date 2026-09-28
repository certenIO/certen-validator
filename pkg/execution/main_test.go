// Copyright 2026 Certen Protocol

package execution

import (
	"os"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

// Tests run as a validator whose sending keys were verified at startup - the only state in which a
// validator sends or claims anything (RB3-F64). The gate's own tests clear it (sender_gate_test.go).
func TestMain(m *testing.M) {
	sendersVerified.Store(true)
	// And they sign for the registered validator set, configured as the node requires (RB3-F21).
	testvalset.Configure()
	os.Exit(m.Run())
}
