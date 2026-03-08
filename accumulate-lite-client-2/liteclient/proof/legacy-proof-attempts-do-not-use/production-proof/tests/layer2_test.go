// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package tests

import (
	"context"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
)

// TestLayer2Verification tests Layer 2: BPT Root → Block Hash verification
func TestLayer2Verification(t *testing.T) {
	// Create verifier
	verifier := core.NewCryptographicVerifier()

	// Test with a known account
	accountURL, err := url.Parse("acc://dn.acme")
	if err != nil {
		t.Fatalf("Invalid URL: %v", err)
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run verification
	result, err := verifier.VerifyAccount(ctx, accountURL)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// Check Layer 2 specifically
	layer2 := result.Layers["layer2"]
	if !layer2.Verified {
		t.Errorf("Layer 2 verification failed: %s", layer2.Error)
	}

	// Check details
	if layer2.Details != nil {
		if height, ok := layer2.Details["blockHeight"].(int64); ok {
			t.Logf("Block Height: %d", height)
		}
		if hash, ok := layer2.Details["blockHash"].(string); ok && hash != "" {
			t.Logf("Block Hash: %s", hash)
		}
		if trust, ok := layer2.Details["trustRequired"].(string); ok && trust != "" {
			t.Logf("Trust Required: %s", trust)
		}
	}
}
