// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
)

// consensusProofCommitmentKey is where consensus hands the proof cycle the L1-L3 proof its
// ValidatorBlock was built on.
const consensusProofCommitmentKey = "liteClientProof"

// matchesConsensusProof requires the chained proof a cycle stores to be the proof consensus signed over
// (RB3-F87). The commitment carried that proof "so persistProofArtifact can store it", and nothing ever
// read it: the cycle regenerates the proof and stored whatever came back. The proof is a function of the
// chain (TestLiveChainedProofIsReproducible), so the two must agree on every commitment that fixes its
// path - the transaction leaf, the BVN root-chain anchor, the DN state-tree anchor, the DN consensus
// height and the partition. compared is false when consensus built the block without a proof.
func matchesConsensusProof(commitment map[string]interface{}, stored *chained_proof.ChainedProof) (compared bool, err error) {
	raw, _ := commitment[consensusProofCommitmentKey].(string)
	if raw == "" {
		return false, nil
	}
	var signed proof.LiteClientProofData
	if err := json.Unmarshal([]byte(raw), &signed); err != nil || signed.CompleteProof == nil {
		return true, fmt.Errorf("the proof consensus signed over does not decode: %v", err)
	}
	if stored == nil {
		return true, fmt.Errorf("no chained proof to compare with the one consensus signed over")
	}
	got := proof.ChainedProofToCompleteProof(stored)
	want := signed.CompleteProof
	switch {
	case !bytes.Equal(got.AccountHash, want.AccountHash):
		return true, fmt.Errorf("transaction leaf %x differs from the one consensus signed over (%x)", got.AccountHash, want.AccountHash)
	case !bytes.Equal(got.BPTRoot, want.BPTRoot):
		return true, fmt.Errorf("BVN root-chain anchor %x differs from the one consensus signed over (%x)", got.BPTRoot, want.BPTRoot)
	case !bytes.Equal(got.BlockHash, want.BlockHash):
		return true, fmt.Errorf("DN state-tree anchor %x differs from the one consensus signed over (%x)", got.BlockHash, want.BlockHash)
	case got.BlockHeight != want.BlockHeight:
		return true, fmt.Errorf("DN consensus height %d differs from the one consensus signed over (%d)", got.BlockHeight, want.BlockHeight)
	case !strings.EqualFold(got.Partition, want.Partition):
		return true, fmt.Errorf("partition %q differs from the one consensus signed over (%q)", got.Partition, want.Partition)
	}
	return true, nil
}
