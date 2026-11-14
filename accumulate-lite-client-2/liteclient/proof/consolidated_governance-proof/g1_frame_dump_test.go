//go:build g1record

// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// DAX-1G-R2 (G-85): the consensus question "does the fix change any byte an already committed proof carries?", answered by dumping
// the PRODUCTION ProveG1's whole output for every recorded fixture and comparing the dump of the base commit with the dump of the branch:
//
//	G1_DUMP_DIR=/tmp/dump go test -tags g1record -run TestDumpG1FixtureOutputs -count=1 ./proof/consolidated_governance-proof/
//
// One file per fixture: <name>.json is json.MarshalIndent of the G1Result (the hashed shape, the vote evidence, the timing basis, the
// route status: everything the proof emits), <name>.error.txt is the error of a fixture the proof refuses. Run it twice on one tree and the
// files are identical (the proof is deterministic over a replay); run it on the base and on the branch and `diff -r` shows what changed.
func TestDumpG1FixtureOutputs(t *testing.T) {
	dir := os.Getenv("G1_DUMP_DIR")
	if dir == "" {
		t.Fatal("G1_DUMP_DIR names the directory the dump is written to; it is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, res *G1Result, err error) {
		t.Helper()
		if err != nil {
			if werr := os.WriteFile(filepath.Join(dir, name+".error.txt"), []byte(err.Error()+"\n"), 0o644); werr != nil {
				t.Fatal(werr)
			}
			return
		}
		b, merr := json.MarshalIndent(res, "", " ")
		if merr != nil {
			t.Fatal(merr)
		}
		if werr := os.WriteFile(filepath.Join(dir, name+".json"), append(b, '\n'), 0o644); werr != nil {
			t.Fatal(werr)
		}
	}
	for _, fx := range delegationFixtures {
		res, _, err := proveReplayed(t, fx, nil)
		write(fx.name, res, err)
	}
	for _, fx := range erpInitiatorFixtures {
		capture := loadErpCaptureIfPresent(t, fx)
		if capture == nil {
			continue
		}
		g1, _ := replayErpLayer(t, fx)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		res, err := g1.ProveG1(ctx, G1Request{G0Request: G0Request{Account: fx.account, TxHash: fx.txHash, Chain: "main"}, KeyPage: fx.keyPage})
		cancel()
		write(fx.name, res, err)
	}
}

// loadErpCaptureIfPresent is nil when the fixture has not been recorded in this tree (the base commit has no r6a recording until the
// overlay brings it).
func loadErpCaptureIfPresent(t *testing.T, fx erpInitiatorFixture) *recordedCapture {
	t.Helper()
	if _, err := os.Stat(filepath.Join("testdata", "g1_erp_initiator", fx.name+".json.gz")); err != nil {
		return nil
	}
	return loadErpCapture(t, fx)
}
