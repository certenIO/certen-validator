// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

// SignerLeg names one signer account and the partition it routes to.
type SignerLeg struct {
	Account   string
	Partition string
}

// BuildMultiPartitionProof builds a proof carrying a leg per distinct signer
// partition.
//
// Governance can span partitions - a delegated signer may live on a different
// BVN than the principal - and each distinct signer partition needs its own L1,
// L2 and L4-BVN. L3 and L4-DN stay single, because there is one Directory.
//
// "Distinct signer partition" and not "distinct signer": two accounts on one
// partition share that partition's anchor and quorum, so a second leg for them
// would be the same evidence written twice. And only COUNTED signers belong
// here - a signature that did not contribute to the threshold needs no
// inclusion proof, and proving it inflates the proof without adding evidence.
func (pb *ProofBuilder) BuildMultiPartitionProof(ctx context.Context, in ProofInput, signers []SignerLeg) (*ChainedProof, error) {
	base, err := pb.BuildProof(ctx, in)
	if err != nil {
		return nil, err
	}

	principal := base.principalPartition()
	seen := map[string]bool{strings.ToLower(principal): true}

	// Sorted, so the legs are built - and stored - in canonical order rather
	// than in whatever order resolution happened to enumerate the signers.
	// Partition discovery order is not stable, and unordered legs make two
	// validators reading identical chain data produce different bytes.
	ordered := append([]SignerLeg{}, signers...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return strings.ToLower(ordered[i].Partition) < strings.ToLower(ordered[j].Partition)
	})

	var artifacts map[string][]byte
	if pb.WithArtifacts {
		artifacts = base.Artifacts
	}
	l1b := &Layer1Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}
	l2b := &Layer2Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}
	l4b := &Layer4Builder{Client: pb.V3, Debug: pb.Debug, Artifacts: artifacts}

	for _, s := range ordered {
		key := strings.ToLower(s.Partition)
		if s.Partition == "" {
			return nil, fmt.Errorf("proof builder: signer %s has no partition; a leg whose "+
				"partition is unknown cannot be checked against the quorum that signed it", s.Account)
		}
		if seen[key] {
			continue // this partition's evidence is already in the proof
		}
		seen[key] = true

		l1, err := l1b.Build(ctx, s.Account, in.TxHash)
		if err != nil {
			return nil, fmt.Errorf("proof builder: L1 for signer %s on %s: %w", s.Account, s.Partition, err)
		}
		l2, err := l2b.Build(ctx, s.Partition, l1)
		if err != nil {
			return nil, fmt.Errorf("proof builder: L2 for %s: %w", s.Partition, err)
		}
		l4, err := l4b.BuildBVNLeg(ctx, s.Partition, l1, l2)
		if err != nil {
			return nil, fmt.Errorf("proof builder: L4 for %s: %w", s.Partition, err)
		}

		if err := base.AddLeg(PartitionLeg{
			Partition: s.Partition,
			Account:   s.Account,
			Layer1:    l1,
			Layer2:    l2,
			Layer4BVN: l4,
		}); err != nil {
			return nil, fmt.Errorf("proof builder: %w", err)
		}
	}

	// As with the single-partition path: never emit an object the verifier
	// would reject.
	if err := NewProofVerifier(pb.Debug).Verify(ctx, base); err != nil {
		return nil, fmt.Errorf("proof builder: built multi-partition proof does not verify: %w", err)
	}
	return base, nil
}
