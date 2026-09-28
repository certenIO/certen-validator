package consensus

import (
	"os"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

// Tests sign for the registered validator set, configured as the node requires (RB3-F21).
func TestMain(m *testing.M) {
	testvalset.Configure()
	os.Exit(m.Run())
}
