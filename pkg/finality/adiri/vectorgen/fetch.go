// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// fetchLive reads the public data the live vectors and the pins derive from into cache: tn_genesis, the current epoch, every
// sealed epoch record, the 291 headers 0..290 of the genesis link and the headers of the leg blocks. Everything is
// self-authenticating (records are verified end to end by the verifier; headers re-hash to the node's hash).
func fetchLive(rpc, cache string, legBlocks []uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	p := &adiri.Prover{Endpoints: []string{rpc}}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	gen, err := p.RawCall(ctx, "tn_genesis")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cache, "tn_genesis.json"), gen, 0o644); err != nil {
		return err
	}
	curRaw, err := p.RawCall(ctx, "tn_getCurrentEpoch")
	if err != nil {
		return err
	}
	var cur uint64
	if err := json.Unmarshal(curRaw, &cur); err != nil {
		return err
	}
	recs, err := p.ReadEpochRecords(ctx, 0, cur)
	if err != nil {
		return err
	}
	rj, _ := json.Marshal(recs)
	if err := os.WriteFile(filepath.Join(cache, "epoch_records.json"), rj, 0o644); err != nil {
		return err
	}
	link, err := p.ReadHeaders(ctx, 0, 290)
	if err != nil {
		return err
	}
	var all []byte
	for _, h := range link {
		all = append(all, h...)
	}
	if err := os.WriteFile(filepath.Join(cache, "genesis_link.bin"), all, 0o644); err != nil {
		return err
	}
	fmt.Printf("fetched %d epoch records (current epoch %d), %d genesis-link headers (%d B), tn_genesis %d B\n", len(recs), cur, len(link), len(all), len(gen))
	return nil
}
