// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

// RB3 sweep: the batch queue on disk is restored whole or the node does not start, and nothing is queued
// or sent that the disk does not hold. Every path here used to drop what it could not read or write.

func savedQueue(t *testing.T) (string, []map[string]interface{}) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mempool.json")
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64})
	if err := m.SetStore(st, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(member("alpha", 6259279, 11155111)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc []map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return path, doc
}

func restore(t *testing.T, path string) error {
	t.Helper()
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64}).SetStore(st, nil)
}

func TestAQueueThatCannotBeRestoredWholeStopsTheNode(t *testing.T) {
	path, doc := savedQueue(t)
	if err := restore(t, path); err != nil {
		t.Fatalf("a well-formed queue was refused: %v", err)
	}
	for name, mutate := range map[string]func(m map[string]interface{}){
		"leg value not an integer": func(m map[string]interface{}) {
			m["legs"].([]interface{})[0].(map[string]interface{})["value"] = "1e18"
		},
		"unknown lane":              func(m map[string]interface{}) { m["lane"] = "express" },
		"no commit height":          func(m map[string]interface{}) { delete(m, "commitHeight"); delete(m, "commit_height") },
		"attestation not decodable": func(m map[string]interface{}) { m["attestation"] = "not an object" },
	} {
		cp, _ := json.Marshal(doc)
		var d []map[string]interface{}
		_ = json.Unmarshal(cp, &d)
		mutate(d[0])
		raw, _ := json.Marshal(d)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := restore(t, path); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restore(t, path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("a corrupt queue file was not refused by name: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the refused file was not left in place for the operator")
	}
}

func TestNothingIsQueuedOrSentThatTheDiskDoesNotHold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mempool.json")
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64})
	if err := m.SetStore(st, nil); err != nil {
		t.Fatal(err)
	}
	// The snapshot cannot be written: its path is a directory.
	_ = os.Remove(path)
	if err := os.MkdirAll(filepath.Join(path, "blocker"), 0o755); err != nil {
		t.Fatal(err)
	}
	err = m.Add(member("alpha", 6259279, 11155111))
	if !errors.Is(err, consensus.ErrBatchUnavailable) {
		t.Fatalf("an unpersisted member: %v; want a retryable refusal (ErrBatchUnavailable)", err)
	}
	if n := m.PendingCount(); n != 0 {
		t.Fatalf("%d member(s) left queued that the disk does not hold", n)
	}
	if m.Durable() == nil {
		t.Fatal("the queue reports durable while its snapshot cannot be written")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := m.Durable(); err != nil {
		t.Fatalf("the snapshot is writable again and still not durable: %v", err)
	}
}
