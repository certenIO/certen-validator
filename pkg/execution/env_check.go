// Copyright 2026 Certen Protocol

package execution

import (
	"os"
	"strings"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// CheckEnv reads every environment knob this package consults while sending transactions, so a value
// that does not parse stops the node at boot instead of refusing a settlement later.
func CheckEnv() error {
	return envvar.Check(
		func() error { _, err := gasCeilingEnforced(); return err },
		func() error { _, err := maxTxCostMicroUSD(); return err },
		func() error { _, err := nativeUSDMicro(); return err },
		func() error {
			// Every catalogued chain's own native-token price, where one is set, must be a price.
			for _, id := range supportedchains.IDs() {
				if strings.TrimSpace(os.Getenv(nativeUSDEnvFor(id))) == "" {
					continue
				}
				if _, err := nativeUSDMicroFor(id); err != nil {
					return err
				}
			}
			return nil
		},
	)
}
