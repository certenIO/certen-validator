// Command bls-key-info prints a validator BLS key file's public key, or generates a new random key
// file.
//
// A key is never derived from a validator ID: those inputs are public, and a key anyone can compute is
// no key. See docs/runbooks/bls-key-rotation.md.
//
//	bls-key-info -key data/bls_key_validator-1.hex        print the public key
//	bls-key-info -generate data/bls_key_validator-1.hex   write a new random key (never overwrites)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

func main() {
	var (
		keyPath = flag.String("key", "", "key file whose public key to print")
		genPath = flag.String("generate", "", "write a new random key to this path (must not exist)")
	)
	flag.Parse()

	switch {
	case *genPath != "":
		if _, err := os.Stat(*genPath); err == nil {
			fatal("%s already exists; refusing to overwrite a key", *genPath)
		} else if !os.IsNotExist(err) {
			fatal("stat %s: %v", *genPath, err)
		}
		km := bls.NewKeyManager(*genPath)
		if err := km.GenerateNewKey(); err != nil {
			fatal("generating key: %v", err)
		}
		fmt.Printf("wrote %s\npublic key 0x%s\n", *genPath, km.GetPublicKey().Hex())
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
