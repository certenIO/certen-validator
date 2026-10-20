// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// measure prints the size of each part of the recorded evidence and the verification time (cold: includes the one-time KZG
// context initialisation; warm: the second call), for the numbers V2_SPEC_S7 section 8.1 asks of RB11-E.
func measure(rawDir string) error {
	ev, err := os.ReadFile(filepath.Join(rawDir, "evidence.bin"))
	if err != nil {
		return err
	}
	pj, err := os.ReadFile(filepath.Join(rawDir, "pins.json"))
	if err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(pj)
	if err != nil {
		return err
	}
	lj, err := os.ReadFile(filepath.Join(rawDir, "leg.json"))
	if err != nil {
		return err
	}
	var leg rawLeg
	if err := json.Unmarshal(lj, &leg); err != nil {
		return err
	}
	ref := blockRef(legFile{Chain: leg.Chain, Number: leg.Number, Hash: leg.Hash, HeaderRLP: leg.HeaderRLP})
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		return err
	}
	e, err := arbposted.Decode(c.Body, arbposted.DefaultBounds())
	if err != nil {
		return err
	}
	nodes := 0
	for _, n := range e.Nodes {
		nodes += len(n)
	}
	spine := 0
	for _, h := range e.L1Spine {
		spine += len(h)
	}
	tx := 0
	for _, t := range e.BlockTxs {
		tx += len(t)
	}
	blobs := 0
	for _, b := range e.Blobs {
		blobs += len(b.Raw) + 96
	}
	fmt.Printf("evidence total %d B: header %d, LC %d (anchor body %d, final update %d), L1 spine %d (%d headers), block txs %d (%d txs), blobs %d (%d blobs), trie nodes %d (%d nodes), rest %d\n",
		len(ev), len(ev)-len(c.Body), len(ethl1.EncodeLC(e.LC)), len(e.LC.AnchorBody.SSZ), len(e.LC.FinalUpdate.SSZ), spine, len(e.L1Spine), tx, len(e.BlockTxs), blobs, len(e.Blobs), nodes, len(e.Nodes),
		len(ev)-(len(ev)-len(c.Body))-len(ethl1.EncodeLC(e.LC))-spine-tx-blobs-nodes)
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if _, err := arbposted.New().Verify(pins, ref, ev); err != nil {
			return err
		}
		fmt.Printf("Verify #%d: %s\n", i+1, time.Since(t0))
	}
	return nil
}
