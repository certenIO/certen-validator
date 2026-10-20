// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

func liveEvidenceFiles(t *testing.T) []string {
	t.Helper()
	fs, err := filepath.Glob(filepath.Join(fixtureDir, "*.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatalf("no evidence file in %s", fixtureDir)
	}
	return fs
}

// worldSettlement is the settlement the recorded world proves: its transaction and receipt built from the recorded block
// and verified against the agreed header, as the judge builds it.
func worldSettlement(t *testing.T, w *World) *ethproof.Settlement {
	t.Helper()
	ctx := context.Background()
	tr := ReplayTransports(w)
	src, err := newSource(ctx, w.ChainID, w.Providers, func(host string) http.RoundTripper { return tr[host] })
	if err != nil {
		t.Fatal(err)
	}
	tx := common.HexToHash(w.TxHash)
	rc, err := src.TransactionReceipt(ctx, tx)
	if err != nil {
		t.Fatalf("the recorded world has no agreed receipt: %v", err)
	}
	s, err := ethproof.Build(ctx, src, rc.BlockHash, tx, uint64(rc.TransactionIndex))
	if err != nil {
		t.Fatalf("the settlement does not build from the recorded world: %v", err)
	}
	return s
}

// V-R10B2 D4: every evidence file of the live fixtures is a published fixture and says what the code accepts: it decodes by
// the S6 format's strict decoder and verifies against the settlement its own world proves, to the verdict recorded beside it.
func TestEveryLiveEvidenceFileDecodesAndVerifiesAgainstItsWorld(t *testing.T) {
	for _, path := range liveEvidenceFiles(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".evidence.json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ev, err := ethproof.DecodeReplayGuardEvidence(raw)
			if err != nil {
				t.Fatalf("the evidence file does not decode: %v", err)
			}
			w, err := ReadWorldGz(filepath.Join(fixtureDir, name+".world.json.gz"))
			if err != nil {
				t.Fatal(err)
			}
			chk, err := ev.Verify(worldSettlement(t, w))
			if err != nil {
				t.Fatalf("the evidence file does not verify against its world's settlement: %v", err)
			}
			vb, err := os.ReadFile(filepath.Join(fixtureDir, name+".verdict.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want Verdict
			if err := json.Unmarshal(vb, &want); err != nil {
				t.Fatal(err)
			}
			if chk.State != want.State || chk.Reason != want.Reason {
				t.Fatalf("the evidence file establishes %s{%s}, the verdict beside it is %s{%s}", chk.State, chk.Reason, want.State, want.Reason)
			}
			// What the file holds is what the fixed judge writes for the world: re-judging it gives the same evidence.
			_, again, err := Judge(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(again)
			b, _ := json.Marshal(ev)
			if string(a) != string(b) {
				t.Fatalf("the evidence file is not what the judge writes for its world today")
			}
		})
	}
}

// The files that no longer decode are kept, never deleted, under *.evidence.pre-b4.json, and SUPERSEDED.md names each.
func TestTheSupersededLiveEvidenceFilesAreKeptAndListed(t *testing.T) {
	old, err := filepath.Glob(filepath.Join(fixtureDir, "*.evidence.pre-b4.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 3 {
		t.Fatalf("want the three old-encoding evidence files kept as *.evidence.pre-b4.json, found %d: %v", len(old), old)
	}
	list, err := os.ReadFile(filepath.Join(fixtureDir, "SUPERSEDED.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range old {
		base := filepath.Base(path)
		if !strings.Contains(string(list), "`"+base+"`") {
			t.Fatalf("%s is not listed in SUPERSEDED.md", base)
		}
		if _, err := os.Stat(strings.Replace(path, ".evidence.pre-b4.json", ".evidence.json", 1)); err != nil {
			t.Fatalf("%s has no fresh evidence beside it: %v", base, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ethproof.DecodeReplayGuardEvidence(raw)
		var re *ethproof.ReplayError
		if !errors.As(err, &re) || re.Reason != ethproof.ReasonUnknownField {
			t.Fatalf("%s is listed as the pre-B4 encoding but decodes as: %v", base, err)
		}
	}
}
