//go:build g1record

// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Records the live Kermit exchanges of the erp-initiator fixtures (testdata/g1_erp_initiator/*.json.gz), the way
// g1_record_fixtures_test.go records the delegation ones. ONE fixture is recorded per run, the one named by G1_RECORD_FIXTURE (the
// frozen g7 capture is never rewritten by accident):
//
//	G1_RECORD_FIXTURE=erp_initiator_r6a go test -tags g1record -run TestRecordG1ErpInitiatorFixtures -count=1 -timeout 30m .
//
// Read-only queries of a public testnet. Every exchange is stored as the exact bytes the endpoint answered; a transport
// failure fails the recording instead of being written down. The untagged replay test (g1_erp_initiator_test.go) pins
// what the recordings must show (DAX-1G, DAX-G3; DAX-1G-R2, G-85).
func TestRecordG1ErpInitiatorFixtures(t *testing.T) {
	want := os.Getenv("G1_RECORD_FIXTURE")
	if want == "" {
		t.Fatal("G1_RECORD_FIXTURE names the fixture to record; it is not set")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = "https://kermit.accumulatenetwork.io/v3"
	}
	found := false
	for _, fx := range erpInitiatorFixtures {
		if fx.name != want {
			continue
		}
		found = true
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
	if !found {
		t.Fatalf("G1_RECORD_FIXTURE=%q is not a fixture", want)
	}
}

// TestRecordKermitNetworkStatus stores the network-status answer (the routing table the partition of an account is read from) beside
// the erp fixtures: testdata/g1_erp_initiator/network_status_kermit.json, the exact bytes of the answer. The routing table of a network
// does not change (a table with main-chain height 1 never has), and the replay tests read the partitions of the principal and of the
// declared page from it, as the production proof reads them from the live endpoint (G1Layer.networkInfo).
func TestRecordKermitNetworkStatus(t *testing.T) {
	if os.Getenv("G1_RECORD_NETWORK_STATUS") == "" {
		t.Fatal("G1_RECORD_NETWORK_STATUS is not set")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = "https://kermit.accumulatenetwork.io/v3"
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "network-status", "params": map[string]any{}})
	req, err := http.NewRequest(http.MethodPost, ep, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("network-status answered %d", res.StatusCode)
	}
	var probe struct {
		Result struct {
			Routing json.RawMessage `json:"routing"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || len(probe.Result.Routing) == 0 {
		t.Fatalf("the answer carries no routing table: %v", err)
	}
	out := filepath.Join("testdata", "g1_erp_initiator", "network_status_kermit.json")
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %d bytes", out, len(raw))
	fmt.Println(out)
}

// TestWriteG1ErpInitiatorVoteEvidenceGolden writes the vote evidence the production builder emits for the fixture named by
// G1_RECORD_FIXTURE, from the REPLAY of the recorded exchanges (no network), as testdata/g1_erp_initiator/<name>.vote_evidence.json.
func TestWriteG1ErpInitiatorVoteEvidenceGolden(t *testing.T) {
	want := os.Getenv("G1_RECORD_FIXTURE")
	if want == "" {
		t.Fatal("G1_RECORD_FIXTURE names the fixture whose golden is written; it is not set")
	}
	found := false
	for _, fx := range erpInitiatorFixtures {
		if fx.name != want {
			continue
		}
		found = true
		res, _ := proveErpReplayed(t, fx)
		if err := os.WriteFile(erpVoteEvidenceGoldenPath(fx), marshalVoteEvidence(t, res), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("G1_RECORD_FIXTURE=%q is not a fixture", want)
	}
}
