// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// hostilePage is a provider's 10 MB error page, echoing the URL it was asked (and so the key in it).
func hostilePage() string {
	return "<html><body>invalid key for https://eth-sepolia.g.alchemy.com/v2/" + leakKey + " " + strings.Repeat("<p>error page</p>", 10<<20/len("<p>error page</p>")+1)
}

// RB10-B13: a recorded world whose provider answered 10 MB of error page: the verdict, the evidence and the world written
// from it hold bounded text, the host is named and no key is.
func TestB13_ATenMegabyteProviderPageIsBoundedInTheVerdictTheEvidenceAndTheWorld(t *testing.T) {
	prov := keyedProviders()[:1]
	tx := common.Hash{0x01}
	w := &World{Format: WorldFormat, ChainID: 1, Chain: "x", Providers: prov, TxHash: tx.Hex(), StartedUTC: "2026-10-19T00:00:00Z"}
	page := hostilePage()
	for _, m := range []string{"eth_getTransactionReceipt", "eth_getTransactionByHash", "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getProof"} {
		w.Exchanges = append(w.Exchanges, Exchange{Host: prov[0].Host, Method: m, Params: json.RawMessage(`["` + tx.Hex() + `"]`), HTTPStatus: 502, Body: page})
	}
	v, ev, err := Judge(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	vb, _ := json.Marshal(v)
	eb, _ := json.MarshalIndent(ev, "", "  ")
	if len(eb)+1 > ethproof.MaxReplayEvidenceBytes || len(vb) > 64<<10 {
		t.Fatalf("the evidence file is %d bytes and the verdict %d", len(eb)+1, len(vb))
	}
	if strings.Contains(string(vb)+string(eb), leakKey) || !strings.Contains(string(vb)+string(eb), "eth-sepolia.g.alchemy.com") {
		t.Fatalf("a key is in, or the host is missing from, the verdict or the evidence:\n%.2000s\n%.2000s", vb, eb)
	}
	if ev == nil || ev.State == nil || len(ev.State.Detail) > ethproof.MaxReplayTextBytes || len(v.Detail) > ethproof.MaxReplayTextBytes || len(v.Settlement) > ethproof.MaxReplayTextBytes {
		t.Fatalf("a text is longer than %d bytes: %+v", ethproof.MaxReplayTextBytes, v)
	}
	// The world written from the recorded answers.
	sw := w.scrubbed()
	for _, x := range sw.Exchanges {
		if len(x.Body) > ethproof.MaxReplayTextBytes || strings.Contains(x.Body, leakKey) {
			t.Fatalf("the stored body is %d bytes", len(x.Body))
		}
	}
	x := scrubExchange(Exchange{Host: prov[0].Host, Method: "m", Transport: `Post "` + page + `"`, RPCError: json.RawMessage(`{"code":-1,"message":` + mustJSON(page) + `}`)})
	if len(x.Transport) > ethproof.MaxReplayTextBytes || len(x.RPCError) > 2*ethproof.MaxReplayTextBytes || strings.Contains(string(x.RPCError)+x.Transport, leakKey) {
		t.Fatalf("the stored transport error is %d bytes and the RPC error %d", len(x.Transport), len(x.RPCError))
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// The proof file is indented, which is longer than the compact form: evidence that is within the bound compact and over it
// as the file the verifier reads is the named state saying so, and the verdict is judged on that.
func TestB13_EvidenceWhoseFileWouldBeRefusedIsTheNamedStateSayingSo(t *testing.T) {
	tx := common.Hash{0x07}
	blk := common.Hash{0x08}
	big := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven,
		Reason: ethproof.ReasonStateUnavailable, ChainID: 1, TxHash: tx, BlockNumber: 9, BlockHash: blk, Providers: make([]ethproof.ReplayProviderFailure, 100000)}}
	compact, _ := json.Marshal(big)
	indented, _ := json.MarshalIndent(big, "", "  ")
	if len(compact) > ethproof.MaxReplayEvidenceBytes || len(indented)+1 <= ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the test evidence is %d bytes compact and %d indented", len(compact), len(indented))
	}
	if got := ethproof.BoundReplayEvidence(big, 1, tx); got != big {
		t.Fatal("the compact guard must keep it: this is the case only the file guard catches")
	}
	got := boundForFile(big, 1, tx)
	if got == big || got.State == nil || got.State.Reason != ethproof.ReasonStateUnavailable || got.State.BlockNumber != 9 || got.State.BlockHash != blk || got.State.TxHash != tx ||
		!strings.Contains(got.State.Detail, "the evidence file would be") || !strings.Contains(got.State.Detail, "more than the 4194304 the format allows") {
		t.Fatalf("not the named state: %+v", got)
	}
	b, _ := json.MarshalIndent(got, "", "  ")
	if _, err := ethproof.DecodeReplayGuardEvidence(b); err != nil {
		t.Fatalf("the replacement is refused by the verifier's reader: %v", err)
	}
	small := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, TxHash: tx}}
	if boundForFile(small, 1, tx) != small || boundForFile(nil, 1, tx) != nil {
		t.Fatal("evidence within the bound, or none, was changed")
	}
}
