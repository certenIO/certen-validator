// Command bls-key-info prints a validator's BLS public key: from a key file, or as the validator
// derives it from its secret when it has no key file (BLS_KEY_SEED, else ETH_PRIVATE_KEY, read from the
// environment). It never prints or writes a private key.
//
//	bls-key-info -key /app/data/bls_key_validator-1.hex    public key in a key file
//	bls-key-info -derive validator-1                        public key derived from this environment's secret
//
// See docs/runbooks/bls-key-rotation.md.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

func main() {
	var (
		keyPath = flag.String("key", "", "key file whose public key to print")
		derive  = flag.String("derive", "", "validator ID whose secret-derived public key to print")
	)
	flag.Parse()

	switch {
	case *derive != "":
		raw, name := os.Getenv("BLS_KEY_SEED"), "BLS_KEY_SEED"
		if strings.TrimSpace(raw) == "" {
			raw, name = os.Getenv("ETH_PRIVATE_KEY"), "ETH_PRIVATE_KEY"
		}
		secret, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(raw), "0x"))
		if err != nil || len(secret) == 0 {
			fatal("no usable secret in BLS_KEY_SEED or ETH_PRIVATE_KEY")
		}
		_, pk, err := bls.DeriveValidatorBLSKey(*derive, secret)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Printf("%s (from %s) public key 0x%s\n", *derive, name, pk.Hex())
	case *keyPath != "":
		km := bls.NewKeyManager(*keyPath)
		if err := km.LoadKey(); err != nil {
			fatal("loading %s: %v", *keyPath, err)
		}
		fmt.Printf("public key 0x%s\n", km.GetPublicKey().Hex())
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", a...)
	os.Exit(1)
}
