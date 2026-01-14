// BLS ZK Setup CLI
// Generates verification keys for the BLSZKVerifier Solidity contract

package main

import (
	"fmt"
	"os"

	bls_zkp "github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

func main() {
	if err := bls_zkp.RunSetupCLI(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
