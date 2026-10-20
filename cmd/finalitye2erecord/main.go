// Copyright 2026 Certen Protocol

// Command finalitye2erecord records the Settlement (the L6 evidence: one transaction and its receipt proven into the block's
// roots) of the leg block of each PUBLISHED finality vector's valid case, so that the vector's recorded evidence can be appended
// through the real database path and judged by proofverify (RB11-E2E-POS, cmd/proofverify/finality_e2e_pos_test.go).
//
// The published vector sets carry only the leg's block header, never a Settlement: the evidence is about the block, the Settlement
// is the proof that a transaction of that block is in it. The blocks are real, so the Settlement is read from two independent
// public providers that must agree (ethrpc.AgreeingReader), every transaction and receipt is checked against the header's roots
// (ethproof.ReadBlock) and the proof is verified (ethproof.Settlement.Verify) before it is written. The block hash is the leg hash
// of the vector: a block that is not that block is refused.
//
//	finalitye2erecord -out cmd/proofverify/testdata/finality_e2e_pos1
//
// The command is read-only against public RPCs. The output is a JSON file per leg plus provenance; it is test data, not a golden:
// no hashed input of the finality chain or of any proof depends on it.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Leg names a published vector's valid case by the leg block it is about.
type Leg struct {
	Name      string   `json:"name"`
	Set       string   `json:"set"`
	Chain     int64    `json:"chain"`
	BlockHash string   `json:"block_hash"`
	Providers []string `json:"providers"`
}

var (
	baseProviders    = []string{"https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"}
	arbProviders     = []string{"https://sepolia-rollup.arbitrum.io/rpc", "https://arbitrum-sepolia-rpc.publicnode.com"}
	sepoliaProviders = []string{"https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.gateway.tenderly.co", "https://sepolia.drpc.org"}
)

// Legs are the leg blocks of the valid cases the end-to-end test carries (hashes read from the sets' own leg files).
var Legs = []Leg{
	{"base_posted_a", "finality_base_posted1", 84532, "0x42265a911a2f2c804017657f91cd128924748c79cc886ae18165393d334e9521", baseProviders},
	{"base_posted_b", "finality_base_posted1", 84532, "0xcef2de9d296abff195052596d0b63dcb54781fdd55ebd7b7f21ac877605bfdf6", baseProviders},
	{"base_final_47604755", "finality_base_final1", 84532, "0x56817ce00b7884d6ef67c55cd1072ad163b67a3a84f96d9278224d5fe47a03ba", baseProviders},
	{"base_final_47898494", "finality_base_final1", 84532, "0xa317d54fd2fd6b301fa08f3d70bcd6b581813289e032b4419eb7ba5c4da0357a", baseProviders},
	{"arb_posted", "finality_arb_posted1", 421614, "0x83d81943ea8f2f51d14bb50594d8d0ae12cd576e8891816e26a9c17fdca0c9f4", arbProviders},
	{"arb_final_real", "finality_arb_final1", 421614, "0xcc692c498ec4714e59a7d6bcefe91c4bc4a58ff22cb80a69aee73e9b7d42345c", arbProviders},
	{"eth_gloas_latest", "finality_eth_sepolia1", 11155111, "0x861d49e2a2bda54652b36dde771fdf9615b116a553aafd38c95fa5bfd54ddfe9", sepoliaProviders},
	{"eth_gloas_period", "finality_eth_sepolia1", 11155111, "0x38d2ed7bb6ce87c6222d2487815b069dd685cd73327df985467f674a299e3e65", sepoliaProviders},
	{"eth_legacy", "finality_eth_sepolia1", 11155111, "0x7290e175358ac8fbc09c6056e51258b376b53f466d307ec0ba8edb8949c2e4bc", sepoliaProviders},
}

// File is one recorded Settlement with where it came from.
type File struct {
	Name       string               `json:"name"`
	Set        string               `json:"set"`
	Chain      int64                `json:"chain"`
	Captured   string               `json:"captured_utc"`
	Providers  []string             `json:"providers"`
	TxIndex    uint64               `json:"tx_index"`
	TxCount    int                  `json:"tx_count"`
	Settlement *ethproof.Settlement `json:"settlement"`
}

func main() {
	out := flag.String("out", "", "output directory")
	only := flag.String("only", "", "record only this leg name")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	failed := 0
	for _, l := range Legs {
		if *only != "" && *only != l.Name {
			continue
		}
		f, err := record(l)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", l.Name, err)
			failed++
			continue
		}
		raw, err := json.MarshalIndent(f, "", " ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(*out, l.Name+".json"), raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s: block %s, %d transactions, settlement tx index %d, %d bytes\n", l.Name, l.BlockHash, f.TxCount, f.TxIndex, len(raw))
	}
	if failed > 0 {
		os.Exit(1)
	}
	if err := writeManifest(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// writeManifest writes MANIFEST.json: the SHA-256 of every recorded file in the directory, keys sorted by encoding/json.
func writeManifest(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	m := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "MANIFEST.json" || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		m[e.Name()] = hex.EncodeToString(sum[:])
	}
	raw, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "MANIFEST.json"), append(raw, '\n'), 0o644)
}

func record(l Leg) (*File, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r, err := ethrpc.NewAgreeingReader(ctx, l.Chain, l.Providers, 30*time.Second)
	if err != nil {
		return nil, err
	}
	b, err := ethproof.ReadBlock(ctx, r, common.HexToHash(l.BlockHash))
	if err != nil {
		return nil, err
	}
	if len(b.Txs) == 0 {
		return nil, fmt.Errorf("block %s holds no transaction to settle", l.BlockHash)
	}
	// the last transaction of the block: a user transaction (the first of an OP-stack block is the L1-info deposit)
	idx := uint64(len(b.Txs) - 1)
	s, err := b.Prove(crypto.Keccak256Hash(b.Txs[idx]), idx)
	if err != nil {
		return nil, err
	}
	return &File{Name: l.Name, Set: l.Set, Chain: l.Chain, Captured: time.Now().UTC().Format(time.RFC3339), Providers: l.Providers,
		TxIndex: idx, TxCount: len(b.Txs), Settlement: s}, nil
}
