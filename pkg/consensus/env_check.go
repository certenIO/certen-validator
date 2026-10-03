// Copyright 2026 Certen Protocol

package consensus

import "github.com/certen/independant-validator/pkg/envvar"

// CheckEnv reads every environment knob this package consults while running, so a value that does not
// parse stops the node at boot instead of refusing work later.
func CheckEnv() error {
	return envvar.Check(
		func() error { _, err := ContractCallsAllowed(); return err },
		func() error { _, err := executionValidationEnabled(); return err },
		requireInclusionScan,
		func() error { _, err := onDemandLaneEnabled(); return err },
		func() error { _, err := blockRetentionFromEnv(); return err },
	)
}
