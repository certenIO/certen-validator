// Copyright 2026 Certen Protocol
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// EPS-MUTKILL-6: the positive CLI flows against the real outcome fixture: --contract-identity adds the S8 line and its exit code to the
// S7 verdict of the same run, and the network is cut exactly when --offline holds.

func TestCLIContractIdentityAddsItsLineAndExitToTheS7VerdictOfARealDocument(t *testing.T) {
	fx := fixturePath(84532)
	leg, err := settlementFromOutcomeFile(fx)
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	carried := block
	carried.HeaderRLP = nil
	raw, err := json.Marshal(map[string]any{"finality": finality.NewSection(carried, nil)})
	if err != nil {
		t.Fatal(err)
	}
	doc := writeDoc(t, raw)

	plain, perr, pcode := runCLI(t, "--finality-file", doc, "--outcome-file", fx)
	if strings.Contains(plain, "contract identity:") || strings.Contains(perr, "contract identity") {
		t.Errorf("without --contract-identity the run judged the member: %q %q", plain, perr)
	}
	if pcode == exitFailed || pcode == exitUsage {
		t.Fatalf("the S7 judgement of the fixture document exits %d: %q %q", pcode, plain, perr)
	}
	out, errw, code := runCLI(t, "--finality-file", doc, "--outcome-file", fx, "--contract-identity")
	if !strings.HasPrefix(out, plain) || !strings.HasSuffix(out, "contract identity: UNPROVEN: all\n") || code != exitCIUnproven || strings.Contains(errw, "contract identity") {
		t.Errorf("--contract-identity on a document with no member: exit %d (S7 alone exits %d)\n  stdout %q\n  stderr %q", code, pcode, out, errw)
	}
}

func TestCLIOutcomeFileCutsTheNetworkExactlyWhenOffline(t *testing.T) {
	fx := fixturePath(84532)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no such method"}}`)
	}))
	defer srv.Close()

	out, errw, code := runCLI(t, "--outcome-file", fx)
	if code != exitVerified || !strings.Contains(out, "  OUTCOME verified OFFLINE (") || strings.Contains(errw, "BLOCKED") || hits.Load() != 0 {
		t.Errorf("offline: exit %d, hits %d\n  stdout %q\n  stderr %q", code, hits.Load(), out, errw)
	}
	out, errw, code = runCLI(t, "--outcome-file", fx, "--online-rpc", srv.URL, "--offline=false")
	if hits.Load() == 0 || strings.Contains(out+errw, "BLOCKED") || code != exitFailed || !strings.Contains(out, "FAILED (outcome online)  "+fx+"\n") {
		t.Errorf("online allowed: exit %d, hits %d\n  stdout %q\n  stderr %q", code, hits.Load(), out, errw)
	}
}
