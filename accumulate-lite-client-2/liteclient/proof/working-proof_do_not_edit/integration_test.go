//go:build integration

// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// These tests previously connected to CometBFT on both the DN and a BVN,
// queried /status and /commit, and compared app_hash to the layer beneath.
// That binding stored nothing, verified no signature, and could not run
// offline. L4 replaced it, so these tests now exercise the full L1-L4 build
// and the offline verification path instead - strictly more coverage, and no
// consensus-engine dependency.

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

// Test_ChainedProof_EndToEnd builds a complete L1-L4 proof and verifies it.
//
//	go test -tags=integration -run Test_ChainedProof_EndToEnd -v ./...
//
// Override the target with CERTEN_V3 / CERTEN_ACCOUNT / CERTEN_TXHASH.
func Test_ChainedProof_EndToEnd(t *testing.T) {
	v3URL := getenv("CERTEN_V3", defaultV3Endpoint)
	account := getenv("CERTEN_ACCOUNT", "acc://carp-buyer-62431.acme/data")
	txhash := getenv("CERTEN_TXHASH", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0")
	bvn := getenv("CERTEN_BVN", "")
	if bvn == "" {
		bvn = calculateBVNFromKermitRouting(account)
	}

	ctx := context.Background()
	t.Logf("v3=%s account=%s bvn=%s", v3URL, account, bvn)

	builder := NewProofBuilder(jsonrpc.NewClient(v3URL), true)
	builder.WithArtifacts = true

	proof, err := builder.BuildProof(ctx, ProofInput{Account: account, TxHash: txhash, BVN: bvn})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	t.Logf("L1: txChainIndex=%d bvnMinorBlockIndex=%d", proof.Layer1.TxChainIndex, proof.Layer1.BVNMinorBlockIndex)
	t.Logf("L2: dnMinorBlockIndex=%d", proof.Layer2.DNMinorBlockIndex)
	t.Logf("L3: dnConsensusHeight=%d", proof.Layer3.DNConsensusHeight)
	t.Logf("L4-BVN: partition=%s sigs=%d threshold=%d",
		proof.Layer4BVN.Partition, len(proof.Layer4BVN.Signatures), proof.Layer4BVN.Threshold)
	t.Logf("L4-DN:  partition=%s sigs=%d threshold=%d",
		proof.Layer4DN.Partition, len(proof.Layer4DN.Signatures), proof.Layer4DN.Threshold)

	// BuildProof verifies internally; verify again from the serialised form,
	// which is what a third party actually receives.
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var round ChainedProof
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if err := NewProofVerifier(true).Verify(ctx, &round); err != nil {
		t.Fatalf("verify round-tripped proof: %v", err)
	}
	t.Logf("proof verified offline from %d bytes of JSON", len(raw))

	if len(proof.Artifacts) == 0 {
		t.Fatal("expected audit artifacts")
	}
	for name := range proof.Artifacts {
		t.Logf("artifact: %s (%d bytes)", name, len(proof.Artifacts[name]))
	}
}

// Test_ChainedProof_RejectsMissingL4 pins that a proof stripped of its L4 legs
// is rejected. Before L4 existed, such an object was the normal output.
func Test_ChainedProof_RejectsMissingL4(t *testing.T) {
	v3URL := getenv("CERTEN_V3", defaultV3Endpoint)
	account := getenv("CERTEN_ACCOUNT", "acc://carp-buyer-62431.acme/data")
	txhash := getenv("CERTEN_TXHASH", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0")
	bvn := calculateBVNFromKermitRouting(account)
	ctx := context.Background()

	proof, err := builderProof(ctx, v3URL, account, txhash, bvn)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	pv := NewProofVerifier(false)

	for _, tc := range []struct {
		name  string
		strip func(p *ChainedProof)
	}{
		{"no L4 at all", func(p *ChainedProof) { p.Layer4BVN, p.Layer4DN = nil, nil }},
		{"no BVN leg", func(p *ChainedProof) { p.Layer4BVN = nil }},
		{"no DN leg", func(p *ChainedProof) { p.Layer4DN = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := *proof
			tc.strip(&clone)
			if err := pv.Verify(ctx, &clone); err == nil {
				t.Fatal("CRITICAL DEFECT: proof verified without L4 evidence")
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

func builderProof(ctx context.Context, v3URL, account, txhash, bvn string) (*ChainedProof, error) {
	b := NewProofBuilder(jsonrpc.NewClient(v3URL), false)
	return b.BuildProof(ctx, ProofInput{Account: account, TxHash: txhash, BVN: bvn})
}

// calculateBVNFromKermitRouting determines which BVN an account is on using
// Kermit's routing table:
//   - first bit = 0    -> BVN1
//   - first 2 bits = 10 -> BVN2
//   - first 2 bits = 11 -> BVN3
func calculateBVNFromKermitRouting(accountURL string) string {
	if !strings.HasPrefix(accountURL, "acc://") {
		return "bvn1"
	}
	urlPart := strings.TrimPrefix(accountURL, "acc://")
	identity := strings.Split(urlPart, "/")[0]

	h := sha256.Sum256([]byte(strings.ToLower(identity)))
	var routingNum uint64
	for i := 0; i < 8; i++ {
		routingNum = (routingNum << 8) | uint64(h[i])
	}

	if (routingNum >> 63) == 0 {
		return "bvn1"
	}
	if (routingNum>>62)&0x3 == 2 {
		return "bvn2"
	}
	return "bvn3"
}
