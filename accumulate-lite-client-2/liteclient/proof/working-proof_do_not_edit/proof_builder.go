// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/cometbft/cometbft/rpc/client/http"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// ProofBuilder orchestrates L1-L3 construction + proof-grade consensus binding checks.
type ProofBuilder struct {
	V3          *jsonrpc.Client
	CometDN     *http.HTTP
	CometBVN    *http.HTTP
	Debug       bool
	WithArtifacts bool
}

func NewProofBuilder(v3c *jsonrpc.Client, cometDN *http.HTTP, cometBVN *http.HTTP, debug bool) *ProofBuilder {
	return &ProofBuilder{
		V3:       v3c,
		CometDN:  cometDN,
		CometBVN: cometBVN,
		Debug:    debug,
	}
}

// BuildProof is the canonical implementation of spec section 6 (normative).
func (pb *ProofBuilder) BuildProof(ctx context.Context, in ProofInput) (*ChainedProof, error) {
	if pb.V3 == nil {
		return nil, fmt.Errorf("proof builder: missing v3 client")
	}
	if pb.CometDN == nil {
		return nil, fmt.Errorf("proof builder: missing DN comet client (proof-grade requires DN binding)")
	}
	if pb.CometBVN == nil {
		return nil, fmt.Errorf("proof builder: missing BVN comet client (proof-grade requires BVN binding)")
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

	// 3) Bind BVN consensus (L2.2): height = BVN_MBI + 1, app_hash == BVN stateTreeAnchor
	if err := bindConsensusAppHash(ctx, pb.CometBVN, l1.BVNMinorBlockIndex+1, l2.BVNStateTreeAnchor, "BVN"); err != nil {
		return nil, err
	}

	// 4) L3
	l3, err := l3b.Build(ctx, l2)
	if err != nil {
		return nil, err
	}

	// 5) Bind DN consensus (L3.1): height = DN_MBI + 1 (DN_MBI from L2), app_hash == DN stateTreeAnchor
	if err := bindConsensusAppHash(ctx, pb.CometDN, l2.DNMinorBlockIndex+1, l3.DNStateTreeAnchor, "DN"); err != nil {
		return nil, err
	}

	out := &ChainedProof{
		Input:  in,
		Layer1: l1,
		Layer2: l2,
		Layer3: l3,
	}
	if pb.WithArtifacts {
		out.Artifacts = artifacts
	}
	return out, nil
}

func bindConsensusAppHash(ctx context.Context, comet *http.HTTP, height uint64, expectStateTreeAnchorHex string, label string) error {
	if comet == nil {
		return fmt.Errorf("%s consensus bind: missing comet client", label)
	}

	// Comet client uses int64 pointers for height
	h := int64(height)
	commit, err := comet.Commit(ctx, &h)
	if err != nil {
		return fmt.Errorf("%s consensus bind: /commit failed for height=%d: %w", label, height, err)
	}

	appHash := commit.SignedHeader.Header.AppHash
	if len(appHash) == 0 {
		return fmt.Errorf("%s consensus bind: empty app_hash at height=%d", label, height)
	}

	expectStateTreeAnchorHex, err = MustHex32Lower(expectStateTreeAnchorHex, label+" expected stateTreeAnchor")
	if err != nil {
		return err
	}
	expectBytes, _ := hex.DecodeString(expectStateTreeAnchorHex)

	// appHash is types.HexBytes under the hood (alias of []byte)
	if !bytes.Equal(appHash, expectBytes) {
		return fmt.Errorf("%s consensus bind FAILED: height=%d app_hash=%x expect=%x",
			label, height, []byte(appHash), expectBytes)
	}
	return nil
}