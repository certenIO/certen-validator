//go:build g1record

// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Records the live Kermit exchanges of the delegation fixtures (testdata/g1_delegation/*.json.gz).
//
//	go test -tags g1record -run TestRecordG1DelegationFixtures -count=1 -timeout 30m .
//
// It is a build mode of its own (it reads Kermit and rewrites testdata); the untagged replay tests
// (g1_delegation_replay_test.go) pin what the recordings must show. Every exchange is stored as the exact bytes the
// endpoint answered; a transport failure fails the recording instead of being written down.

type recordingClient struct {
	inner RPCClientInterface
	mu    sync.Mutex
	cap   *recordedCapture
	err   error
}

func (r *recordingClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	raw, err := r.inner.QueryRaw(ctx, scope, query)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.err = err
		return nil, err
	}
	q, merr := json.Marshal(query)
	if merr != nil {
		r.err = merr
		return nil, merr
	}
	r.cap.Exchanges = append(r.cap.Exchanges, recordedExchange{
		Scope: (URLUtils{}).NormalizeScope(scope), Query: q, Response: string(raw)})
	return raw, nil
}

func (r *recordingClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	raw, err := r.QueryRaw(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Non-JSON response: %v", err)}
	}
	return out, nil
}

func (r *recordingClient) GetEndpoint() string { return r.inner.GetEndpoint() }

func writeCapture(path string, c *recordedCapture) error {
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(c); err != nil {
		return err
	}
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(plain.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, gz.Bytes(), 0o644)
}

func TestRecordG1DelegationFixtures(t *testing.T) {
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = "https://kermit.accumulatenetwork.io/v3"
	}
	for _, fx := range delegationFixtures {
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
			out := filepath.Join("testdata", "g1_delegation", fx.name+".json.gz")
			if err := writeCapture(out, rc.cap); err != nil {
				t.Fatal(err)
			}
			st, _ := os.Stat(out)
			t.Logf("%s: %d exchanges, %d bytes", out, len(rc.cap.Exchanges), st.Size())
		})
	}
}
