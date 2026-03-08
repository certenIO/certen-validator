// BLS Key Info Tool - Derives public keys from private keys
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func main() {
	// Initialize BLS generators
	_, _, g1Gen, g2Gen := bls12381.Generators()
	_ = g1Gen // Not needed for public key derivation

	// Validators and their keys
	validators := []struct {
		ID      string
		Address string
		KeyPath string
	}{
		{"validator-1", "0xEAE57DBBd8A096F7dB0d4901774d0996762c614e", ""},
		{"validator-2", "0x354d53a095E0dff617805f17C12c5F86ADF65a36", ""},
		{"validator-3", "0xa68224627D38fa4b1eC60911EDD0F7eA26f1Cc73", ""},
		{"validator-4", "0x56E4187e901a7bAb9A5BdBe7487E39A0bbc6442F", "data/bls_key_validator-4.hex"},
	}

	chainID := "certen-testnet"

	fmt.Println("BLS Key Information")
	fmt.Println("===================")
	fmt.Printf("Chain ID: %s\n\n", chainID)

	for _, v := range validators {
		fmt.Printf("%s (%s)\n", v.ID, v.Address)

		var sk fr.Element

		if v.KeyPath != "" {
			// Load from file
			keyData, err := os.ReadFile(v.KeyPath)
			if err != nil {
				fmt.Printf("  Error reading key: %v\n", err)
				continue
			}
			keyBytes, err := hex.DecodeString(string(keyData))
			if err != nil {
				fmt.Printf("  Error decoding hex: %v\n", err)
				continue
			}
			sk.SetBytes(keyBytes)
			fmt.Printf("  Private Key: (loaded from %s)\n", v.KeyPath)
		} else {
			// Derive deterministically
			seed := sha256.Sum256([]byte(fmt.Sprintf("CERTEN_BLS_KEY_V1:%s:%s", v.ID, chainID)))
			seedHash := sha256.Sum256(seed[:])
			sk.SetBytes(seedHash[:])
			fmt.Printf("  Private Key: (derived from validator ID)\n")
		}

		// Derive public key: pk = sk * G2
		var pk bls12381.G2Affine
		pk.ScalarMultiplication(&g2Gen, sk.BigInt(new(big.Int)))

		// Get bytes
		pkBytes := pk.Bytes()
		pkHex := hex.EncodeToString(pkBytes[:])

		fmt.Printf("  Public Key (%d bytes): 0x%s\n\n", len(pkBytes), pkHex)
	}
}
