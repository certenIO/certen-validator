// Copyright 2026 Certen Protocol

package intent

import "github.com/certen/independant-validator/pkg/envvar"

// CheckEnv reads every environment knob this package consults, so a value that does not parse stops the
// node at boot instead of refusing work later.
func CheckEnv() error {
	return envvar.Check(
		func() error { _, err := intentRewindBlocks(); return err },
		func() error { _, err := BlockWorkersFromEnv(); return err },
		func() error { _, err := defaultProofClass(); return err },
	)
}
