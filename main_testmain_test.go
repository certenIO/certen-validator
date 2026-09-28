package main

import (
	"os"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

// The node starts only with its validator set configured (RB3-F21); tests - and the validator processes
// they start - run as one configured with the registered set.
func TestMain(m *testing.M) {
	testvalset.Configure()
	os.Exit(m.Run())
}
