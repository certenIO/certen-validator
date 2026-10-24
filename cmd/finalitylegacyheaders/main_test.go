// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

type fixture struct {
	name  string
	chain uint64
}

var fixtures = []fixture{{"base_sepolia_47368146", 84532}, {"sepolia_11792612", 11155111}, {"arbitrum_sepolia_315455204", 421614}}

// inputFile writes the JSON lines the host extraction produces: the production legacy component of each real settled leg.
func inputFile(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	for i, f := range fixtures {
		s := finalitytest.Settlement(t, f.name)
		comp := finalitytest.ProductionLegacyExecutionProof(t, s)
		raw, _ := json.Marshal(map[string]any{"proof_id": fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1), "bundle_id": fmt.Sprintf("b%d", i+1), "comp5": comp})
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "legacy.jsonl")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func provider(t *testing.T, name string) string {
	t.Helper()
	srv := httptest.NewServer(&ethprooftest.Provider{F: ethprooftest.Load(t, name)})
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestOfflineRunReconstructsEveryLegAndPrintsNoProviderURL(t *testing.T) {
	in := inputFile(t)
	args := []string{"-in", in, "-gap", "1ms", "-store", filepath.Join(t.TempDir(), "hdr")}
	var urls []string
	for _, f := range fixtures {
		u := provider(t, f.name)
		urls = append(urls, u)
		args = append(args, "-rpc", fmt.Sprintf("%d=%s", f.chain, u))
	}
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"SUMMARY legs=3 level1_derived=3", "chain 84532: reconstructed 1, unserved 0, invalid 0, pending 0",
		"chain 11155111: reconstructed 1", "chain 421614: reconstructed 1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	for _, u := range urls {
		if strings.Contains(out.String()+errb.String(), u) || strings.Contains(out.String()+errb.String(), strings.TrimPrefix(u, "http://")) {
			t.Fatalf("a provider URL was printed:\n%s", out.String())
		}
	}
	// a second run over the kept headers asks no provider for them: pointing every chain at a dead address still reconstructs all legs
	args2 := []string{"-in", in, "-gap", "1ms", "-store", args[5]}
	for _, f := range fixtures {
		args2 = append(args2, "-rpc", fmt.Sprintf("%d=http://127.0.0.1:1", f.chain))
	}
	out.Reset()
	if code := run(args2, &out, &errb); code != 0 || !strings.Contains(out.String(), "fetched=false") || strings.Contains(out.String(), "fetched=true") {
		t.Fatalf("a kept header was fetched again (exit %d):\n%s", code, out.String())
	}
}

func TestOfflineRunCountsWhatItCannotReconstructByName(t *testing.T) {
	in := inputFile(t)
	pruner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":4444,"message":"pruned history unavailable"}}`))
	}))
	defer pruner.Close()
	args := []string{"-in", in, "-gap", "1ms", "-rpc", "84532=" + pruner.URL, "-rpc", "11155111=" + provider(t, "sepolia_11792612"), "-rpc", "421614=" + provider(t, "arbitrum_sepolia_315455204")}
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out.String())
	}
	for _, want := range []string{"chain 84532: reconstructed 0, unserved 1", "not reconstructed: 1 x unserved (no provider served the block)", "SUMMARY legs=3 level1_derived=2"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestOfflineRunUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"-in", "x"}, {"-rpc", "banana"}, {"-in", filepath.Join(t.TempDir(), "missing"), "-rpc", "84532=http://x"}} {
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("args %v: exit %d, want 2", args, code)
		}
	}
}
