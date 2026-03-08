// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package tests

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
)

// TestCompleteVerification tests both Layer 1 and Layer 2 verification
func TestCompleteVerification(t *testing.T) {
	verifier := core.NewCryptographicVerifier()

	// Test with DN account (always exists on devnet)
	accountURL := protocol.DnUrl()

	verified, err := verifier.VerifyAccountSimple(accountURL)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !verified {
		t.Fatal("Complete verification should have succeeded")
	}
}
