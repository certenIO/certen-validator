//go:build g1record

// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Records the live Kermit exchanges of the erp-initiator fixtures (testdata/g1_erp_initiator/*.json.gz), the way
// g1_record_fixtures_test.go records the delegation ones:
//
//	go test -tags g1record -run TestRecordG1ErpInitiatorFixtures -count=1 -timeout 30m .
//
// Read-only queries of a public testnet. Every exchange is stored as the exact bytes the endpoint answered; a transport
// failure fails the recording instead of being written down. The untagged replay test (g1_erp_initiator_test.go) pins
// what the recordings must show (DAX-1G, DAX-G3).
func TestRecordG1ErpInitiatorFixtures(t *testing.T) {
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = "https://kermit.accumulatenetwork.io/v3"
	}
	for _, fx := range erpInitiatorFixtures {
		t.Run(fx.name, func(t *testing.T) {
			real := NewRPCClient(RPCConfig{Endpoint: ep, Timeout: 60 * time.Second, Backend: "http", UseHTTP: true})
			rc := &recordingClient{inner: real, cap: &recordedCapture{
				Description: fx.description, Endpoint: ep, CapturedAt: time.Now().UTC().Format(time.RFC3339),
				Account: fx.account, TxHash: fx.txHash, KeyPage: fx.keyPage}}
			am, err := NewArtifactManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			g1 := NewG1Layer(rc, am, "")
			if _, err := g1.ProveG1(ctx, G1Request{
				G0Request: G0Request{Account: fx.account, TxHash: fx.txHash, Chain: "main"}, KeyPage: fx.keyPage}); err != nil {
				t.Fatalf("G1 over the live %s must succeed before it is recorded: %v", fx.name, err)
			}
			if rc.err != nil {
				t.Fatalf("a request failed while recording: %v", rc.err)
			}
			out := filepath.Join("testdata", "g1_erp_initiator", fx.name+".json.gz")
			if err := writeCapture(out, rc.cap); err != nil {
				t.Fatal(err)
			}
			st, _ := os.Stat(out)
			t.Logf("%s: %d exchanges, %d bytes", out, len(rc.cap.Exchanges), st.Size())
		})
	}
}

// TestWriteG1ErpInitiatorVoteEvidenceGolden writes the vote evidence the production builder emits for each fixture, from the REPLAY of the
// recorded exchanges (no network), as testdata/g1_erp_initiator/<name>.vote_evidence.json.
func TestWriteG1ErpInitiatorVoteEvidenceGolden(t *testing.T) {
	for _, fx := range erpInitiatorFixtures {
		res, _ := proveErpReplayed(t, fx)
		if err := os.WriteFile(erpVoteEvidenceGoldenPath(fx), marshalVoteEvidence(t, res), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
