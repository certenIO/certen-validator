// Copyright 2026 Certen Protocol

package execution

import (
	"github.com/certen/independant-validator/pkg/envvar"
)

// CheckEnv reads every environment knob this package consults while sending transactions, so a value
// that does not parse stops the node at boot instead of refusing a settlement later. It also refuses the native-token
// prices the signed entitlement rates replaced (CERTEN_NATIVE_USD, CERTEN_NATIVE_USD_<chainId>), naming each one set.
func CheckEnv() error {
	return envvar.Check(
		func() error { _, err := gasCeilingEnforced(); return err },
		func() error { _, err := maxTxCostMicroUSD(); return err },
		checkNoConfiguredNativePrice,
	)
}
