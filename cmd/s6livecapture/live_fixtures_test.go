// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// fixtureDir holds the live S6 worlds recorded at inclusion from public providers (RB10-B3).
var fixtureDir = filepath.Join("..", "..", "pkg", "ethproof", "testdata", "s6live1")

func liveWorlds(t *testing.T) []string {
	t.Helper()
	ws, err := filepath.Glob(filepath.Join(fixtureDir, "*.world.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) == 0 {
		t.Fatalf("no recorded live world in %s", fixtureDir)
	}
	return ws
}

// Every recorded live world, judged offline by ethproof's capture and verifier over the providers' recorded answers,
// gives exactly the verdict recorded beside it, with the settlement's inclusion proof verified.
func TestS6LiveWorldsReverifyOffline(t *testing.T) {
	for _, path := range liveWorlds(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			w, err := ReadWorldGz(path)
			if err != nil {
				t.Fatal(err)
			}
			got, ev, err := Judge(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(strings.TrimSuffix(path, ".world.json.gz") + ".verdict.json")
			if err != nil {
				t.Fatal(err)
			}
			var want Verdict
			if err := json.Unmarshal(b, &want); err != nil {
				t.Fatal(err)
			}
			got.Live = want.Live
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			if string(gj) != string(wj) {
				t.Fatalf("offline verdict differs from the recorded one\n got: %s\nwant: %s", gj, wj)
			}
			if got.Settlement != "verified" {
				t.Fatalf("the settlement's inclusion proof does not verify: %s", got.Settlement)
			}
			switch got.State {
			case ethproof.ReplayProven:
				if ev.Proof == nil || got.Before == "" || got.ProvenAt < got.BlockNumber || len(got.ServedAfter) == 0 {
					t.Fatalf("proven without its proof, provenance or before-state: %+v", got)
				}
				if got.Before == "s6_before_unavailable" && (got.BeforeUnavailable == nil || got.BeforeUnavailable.Reason == "") {
					t.Fatalf("before-state neither proven nor disclosed: %+v", got)
				}
			case ethproof.ReplayUnproven, ethproof.ReplayEventMissing, ethproof.ReplayRefuted:
				if got.Reason == "" || got.BlockNumber == 0 {
					t.Fatalf("a named state without its reason or block: %+v", got)
				}
			default:
				t.Fatalf("verdict %q is neither proven nor a named state", got.State)
			}
		})
	}
}

// A provider answer altered after capture is caught: the recorded world with every storage proof's nodes of the
// consumed slot dropped no longer proves the guard, whatever the provider claimed the value was.
func TestS6LiveWorldTamperedProofIsNotProven(t *testing.T) {
	for _, path := range liveWorlds(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			w, err := ReadWorldGz(path)
			if err != nil {
				t.Fatal(err)
			}
			tampered := 0
			for i, x := range w.Exchanges {
				if x.Method != "eth_getProof" || len(x.Result) == 0 || string(x.Result) == "null" {
					continue
				}
				var ans map[string]json.RawMessage
				if json.Unmarshal(x.Result, &ans) != nil {
					continue
				}
				var sps []map[string]json.RawMessage
				if json.Unmarshal(ans["storageProof"], &sps) != nil || len(sps) == 0 {
					continue
				}
				for _, sp := range sps {
					sp["proof"] = json.RawMessage("[]")
				}
				ans["storageProof"], _ = json.Marshal(sps)
				w.Exchanges[i].Result, _ = json.Marshal(ans)
				tampered++
			}
			if tampered == 0 {
				t.Fatalf("the world holds no eth_getProof answer to tamper with")
			}
			got, _, err := Judge(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			if got.State == ethproof.ReplayProven {
				t.Fatalf("a world with emptied storage proofs is still judged proven: %+v", got)
			}
		})
	}
}
