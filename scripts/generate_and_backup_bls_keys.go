// Generate deterministic BLS keys and create backup
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type ValidatorKey struct {
	ValidatorID   string `json:"validator_id"`
	EthAddress    string `json:"eth_address"`
	BLSPublicKey  string `json:"bls_public_key"`
	BLSPrivateKey string `json:"bls_private_key"`
	ChainID       string `json:"chain_id"`
	GeneratedAt   string `json:"generated_at"`
}

type KeyBackup struct {
	Version      string         `json:"version"`
	GeneratedAt  string         `json:"generated_at"`
	ChainID      string         `json:"chain_id"`
	DerivationFn string         `json:"derivation_function"`
	Validators   []ValidatorKey `json:"validators"`
}

var ethAddresses = map[string]string{
	"validator-1": "0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8",
	"validator-2": "0x518273099F5c4b87eEA65141931B78012dfE5c7d",
	"validator-3": "0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6",
	"validator-4": "0x6Ff54041Afef809e93ce6B570545069d2764783f",
	"validator-5": "0x9eaA84E3D31479eCC9130187DA9f962625e8C271",
	"validator-6": "0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf",
	"validator-7": "0x0D786D587aBe92f1031506fF3eF88c79a93A8962",
}

func generateKeyPair(validatorID, chainID string) (privateKeyHex, publicKeyHex string) {
	// Generate deterministic seed (matches key_manager.go)
	seed := sha256.Sum256([]byte(fmt.Sprintf("CERTEN_BLS_KEY_V1:%s:%s", validatorID, chainID)))
	
	// Hash the seed (matches GenerateKeyPairFromSeed in bls.go)
	hash := sha256.Sum256(seed[:])
	
	var sk fr.Element
	sk.SetBytes(hash[:])

	// Get G2 generator
	_, _, _, g2Gen := bls12381.Generators()

	// Compute public key: pk = sk * G2
	var publicKey bls12381.G2Affine
	publicKey.ScalarMultiplication(&g2Gen, sk.BigInt(new(big.Int)))

	// Get bytes
	skBytes := sk.Bytes()
	pkBytes := publicKey.Bytes()

	return hex.EncodeToString(skBytes[:]), hex.EncodeToString(pkBytes[:])
}

func main() {
	chainID := "certen-testnet"
	now := time.Now().UTC().Format(time.RFC3339)

	backup := KeyBackup{
		Version:      "1.0",
		GeneratedAt:  now,
		ChainID:      chainID,
		DerivationFn: "SHA256(SHA256(CERTEN_BLS_KEY_V1:{validatorID}:{chainID}))",
		Validators:   make([]ValidatorKey, 0, 7),
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("CERTEN BLS Key Generation & Backup")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Chain ID: %s\n", chainID)
	fmt.Printf("Timestamp: %s\n", now)
	fmt.Println()

	for i := 1; i <= 7; i++ {
		validatorID := fmt.Sprintf("validator-%d", i)
		ethAddr := ethAddresses[validatorID]

		privateKey, publicKey := generateKeyPair(validatorID, chainID)

		backup.Validators = append(backup.Validators, ValidatorKey{
			ValidatorID:   validatorID,
			EthAddress:    ethAddr,
			BLSPublicKey:  publicKey,
			BLSPrivateKey: privateKey,
			ChainID:       chainID,
			GeneratedAt:   now,
		})

		fmt.Printf("%s:\n", validatorID)
		fmt.Printf("  ETH Address: %s\n", ethAddr)
		fmt.Printf("  BLS PubKey:  0x%s...%s\n", publicKey[:16], publicKey[len(publicKey)-16:])
		fmt.Println()
	}

	// Save backup
	backupFile := fmt.Sprintf("bls_keys_backup_%s.json", time.Now().Format("20060102_150405"))
	data, _ := json.MarshalIndent(backup, "", "  ")
	os.WriteFile(backupFile, data, 0600)
	fmt.Printf("Backup saved to: %s\n", backupFile)

	// Also output for easy copy-paste in registration script
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("For registration script (copy these):")
	fmt.Println(strings.Repeat("=", 70))
	for _, v := range backup.Validators {
		fmt.Printf("  { name: '%s', address: '%s', blsKey: '0x%s' },\n", 
			v.ValidatorID, v.EthAddress, v.BLSPublicKey)
	}
}
