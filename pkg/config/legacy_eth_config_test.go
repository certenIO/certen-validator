// Copyright 2026 Certen Protocol

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// RB7 Task 5 T5-5: ETH_CHAIN_ID and the <CHAIN>_ACCOUNTFACTORY[_V6]_ADDRESS names are single-Ethereum-era settings that
// nothing may read. Settlement takes its account generation from CERTEN_ACCOUNT_LEAF_VERSIONS and its chain id from the
// chain's own RPC. A name left in a deployed .env is harmless exactly because no code reads it.
func TestNoCodeReadsTheRetiredChainIDAndAccountFactorySettings(t *testing.T) {
	root := filepath.Join("..", "..")
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "accumulate-lite-client-2", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, name := range []string{`"ETH_CHAIN_ID"`, "_ACCOUNTFACTORY_", "FactoryEnvPrefix", "ACCOUNT_ABSTRACTION_ADDRESS"} {
			if strings.Contains(string(b), name) {
				hits = append(hits, path+" reads "+name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("retired settings are still read:\n%s", strings.Join(hits, "\n"))
	}
}

// An account factory in the environment binds nothing: the chain row has no field for it.
func TestAChainRowCarriesNoAccountFactory(t *testing.T) {
	clearChainEnv(t)
	t.Setenv("SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "0x00000000000000000000000000000000000000f1")
	t.Setenv("ETHEREUM_SEPOLIA_RPC_URL", "http://sepolia.invalid")
	if loadEVMChainsFromEnv()[11155111] == nil {
		t.Fatal("Sepolia did not load")
	}
	if _, ok := reflect.TypeOf(EVMChainConfig{}).FieldByName("AccountFactory"); ok {
		t.Fatal("EVMChainConfig carries an AccountFactory again")
	}
}
