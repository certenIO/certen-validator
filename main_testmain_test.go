package main

import (
	"os"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

// The node starts only with its validator set configured (RB3-F21); tests - and the validator processes
// they start - run as one configured with the registered set.
func TestMain(m *testing.M) {
	// The deploy-check script test runs this test binary as the validator image's `validator finality-config-check`.
	if os.Getenv("CERTEN_TEST_RUN_FINALITY_CONFIG_CHECK") == "1" {
		os.Exit(runFinalityConfigCheck(os.Stdin, os.Stdout, os.Stderr))
	}
	testvalset.Configure()
	os.Exit(m.Run())
}
