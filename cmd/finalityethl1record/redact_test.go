// Copyright 2026 Certen Protocol

package main

import (
	"strings"
	"testing"
)

// TestRecorderRoutesProviderTextThroughRedaction: an error that carries a provider URL with a key, or a body that does, reaches
// stderr and storage only after pkg/ethrpc redaction (RB11-C1B, V-C1A note).
func TestRecorderRoutesProviderTextThroughRedaction(t *testing.T) {
	const key = "SECRETKEYSECRETKEY1234567890"
	err := redactedErr("batch at %d: Post \"https://rpc.example.org/v2/%s\": status 429: %s", 7, key, "retry at https://other.example.org/?apikey="+key)
	if strings.Contains(err.Error(), key) {
		t.Fatalf("the error text still carries the provider key: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "batch at 7") {
		t.Fatalf("the redacted error lost its non-secret text: %s", err.Error())
	}
}
