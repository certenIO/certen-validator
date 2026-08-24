// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// ProofBuilder orchestrates L1-L4 construction.
//
// L4 formerly consisted of two live CometBFT `/commit` assertions that stored
// nothing and verified no signature. They have been replaced by stored,
// signature-verifying Layer4 legs built from Accumulate's own threshold-signed
// partition anchors, so the builder no longer needs a consensus-engine client
// of any kind.
type ProofBuilder struct {
	V3            *jsonrpc.Client
	Debug         bool
	WithArtifacts bool
}

func NewProofBuilder(v3c *jsonrpc.Client, debug bool) *ProofBuilder {
	return &ProofBuilder{V3: v3c, Debug: debug}
}

// BuildProof is the canonical implementation of spec section 6 (normative).
//
// L1-L3 are unchanged. L4 is built for both legs and is REQUIRED: a proof
// without both legs is not proof-grade, and BuildProof fails rather than
// returning a partial object that a caller might mistake for a complete one.
func (pb *ProofBuilder) BuildProof(ctx context.Context, in ProofInput) (*ChainedProof, error) {
	if pb.V3 == nil {
		return nil, fmt.Errorf("proof builder: missing v3 client")
	}
	if in.BVN == "" {
		return nil, fmt.Errorf("proof builder: input.BVN required (e.g. bvn1)")
	}
	if _, err := MustHex32Lower(in.TxHash, "input.txHash"); err != nil {
		return nil, err
	}

	var artifacts map[string][]byte
	if pb.WithArtifacts {
		artifacts = make(map[string][]byte)
	}

	l1b := &Layer1Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}
	l2b := &Layer2Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}
	l3b := &Layer3Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}
	l4b := &Layer4Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}

	// 1) L1
	l1, err := l1b.Build(ctx, in.Account, in.TxHash)
	if err != nil {
		return nil, err
	}

	// 2) L2
	l2, err := l2b.Build(ctx, in.BVN, l1)
	if err != nil {
		return nil, err
	}

	// 3) L3
	l3, err := l3b.Build(ctx, l2)
	if err != nil {
		return nil, err
	}

	// 4) L4-BVN: the BVN's stateTreeAnchor, signed by that BVN's validators.
	l4bvn, err := l4b.BuildBVNLeg(ctx, in.BVN, l1, l2)
	if err != nil {
		return nil, fmt.Errorf("proof builder: L4 BVN leg: %w", err)
	}

	// 5) L4-DN: the DN's stateTreeAnchor, signed by Directory validators.
	l4dn, err := l4b.BuildDNLeg(ctx, in.BVN, l2, l3)
	if err != nil {
		return nil, fmt.Errorf("proof builder: L4 DN leg: %w", err)
	}

	out := &ChainedProof{
		Input:     in,
		Layer1:    l1,
		Layer2:    l2,
		Layer3:    l3,
		Layer4BVN: l4bvn,
		Layer4DN:  l4dn,
	}
	if pb.WithArtifacts {
		out.Artifacts = artifacts
	}

	// The builder must never emit an object the verifier would reject.
	if err := NewProofVerifier(pb.Debug).Verify(ctx, out); err != nil {
		return nil, fmt.Errorf("proof builder: built proof does not verify: %w", err)
	}
	return out, nil
}
