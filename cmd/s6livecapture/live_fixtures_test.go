// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"fmt"
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
			// RB10-F15: the offline verdict must state what the live capture established, not only what an earlier
			// offline judge wrote beside it.
			name := strings.TrimSuffix(filepath.Base(path), ".world.json.gz")
			off := offlineSummary(got)
			if d, known := liveSummaryDiffers[name]; known {
				if want.Live != d.live || off != d.offline {
					t.Fatalf("the pinned live/offline difference (%s) no longer holds\n live: %q (pinned %q)\n offline: %q (pinned %q)",
						d.why, want.Live, d.live, off, d.offline)
				}
				if len(got.ServedBefore) == 0 {
					t.Fatalf("offline before proven, but no recorded provider answer of the parent's state verifies: %+v", got)
				}
			} else if off != want.Live {
				t.Fatalf("the offline verdict disagrees with the live capture\n offline: %q\n    live: %q", off, want.Live)
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

// offlineSummary states an offline verdict in the live capture's summary form (main.go summarize).
func offlineSummary(v *Verdict) string {
	if v.State == ethproof.ReplayProven {
		return fmt.Sprintf("proven at block %d, %s", v.ProvenAt, map[bool]string{true: "before proven", false: "s6_before_unavailable"}[v.Before == "proven"])
	}
	return fmt.Sprintf("%s{%s}: %s", v.State, v.Reason, v.Detail)
}

// liveSummaryDiffers lists the recorded worlds whose offline verdict differs from their live one, each with exactly the
// difference and its cause; every other world must agree word for word.
var liveSummaryDiffers = map[string]struct{ live, offline, why string }{
	// Captured by the RB10-B3 capture, which asked the parent's state once (RB10-F7). The live ask of block 0x12e03cc8 got
	// null from both hosts (exchanges 3080, 3081, 3085); the world's later ask of the same block (exchange 3088,
	// sepolia-rollup.arbitrum.io) was served, and the fixed capture, which asks again, proves the before-state from it.
	"arbitrum-sepolia-b46171b58f49": {
		live:    "proven at block 316686023, s6_before_unavailable",
		offline: "proven at block 316686023, before proven",
		why:     "RB10-F7: the live capture asked the parent's state once",
	},
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
