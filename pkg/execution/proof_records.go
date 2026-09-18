// Copyright 2025 Certen Protocol
//
// Proof records written alongside a proof cycle: the validator set a cycle's attestations were counted
// against, and whether those attestations agree on what they signed. Shared by the unified and the
// legacy orchestrator so both record the same facts the same way.

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// unifiedAttestationSet is the validator set the unified orchestrator counts a quorum against: this
// validator and every configured attestation peer, one weight each (RB-SEC-1: TotalWeight is the whole
// set, not the responders). Members are sorted by identifier so every validator derives the same set.
func unifiedAttestationSet(selfID string, peers []string, thresholdWeight func(int64) int64, blockNumber uint64) *ValidatorSetSnapshot {
	members := append([]string{selfID}, peers...)
	sort.Strings(members)
	snapshot := &ValidatorSetSnapshot{
		BlockNumber: blockNumber,
		CreatedAt:   time.Now().UTC(),
		Validators:  make([]ValidatorEntry, len(members)),
		TotalWeight: big.NewInt(int64(len(members))),
	}
	for i, member := range members {
		snapshot.Validators[i] = ValidatorEntry{ValidatorID: member, Weight: big.NewInt(1), Index: uint32(i)}
	}
	snapshot.ThresholdWeight = big.NewInt(thresholdWeight(int64(len(members))))
	snapshot.ValidatorRoot = snapshot.ComputeValidatorRoot()
	snapshot.SnapshotID = snapshot.ComputeSnapshotID()
	return snapshot
}

// persistValidatorSetSnapshot stores a snapshot and returns its row id. The snapshot id doubles as the
// row's snapshot hash, so the same set at the same block is stored once.
func persistValidatorSetSnapshot(ctx context.Context, repo *database.ProofArtifactRepository, snapshot *ValidatorSetSnapshot, chainID, chainName string) (*uuid.UUID, error) {
	if repo == nil || snapshot == nil {
		return nil, fmt.Errorf("validator set snapshot needs a repository and a snapshot")
	}
	if snapshot.TotalWeight == nil || snapshot.ThresholdWeight == nil || !snapshot.TotalWeight.IsInt64() || !snapshot.ThresholdWeight.IsInt64() {
		return nil, fmt.Errorf("validator set snapshot weights must fit in 64 bits")
	}
	validatorsJSON, err := json.Marshal(snapshot.Validators)
	if err != nil {
		return nil, fmt.Errorf("encode validator set: %w", err)
	}
	if chainName == "" {
		chainName = chainID
	}
	record, err := repo.SaveValidatorSetSnapshot(ctx, &database.NewValidatorSetSnapshot{
		BlockNumber:     int64(snapshot.BlockNumber),
		ValidatorsJSON:  validatorsJSON,
		ValidatorRoot:   snapshot.ValidatorRoot[:],
		ValidatorCount:  len(snapshot.Validators),
		TotalWeight:     snapshot.TotalWeight.Int64(),
		ThresholdWeight: snapshot.ThresholdWeight.Int64(),
		SnapshotHash:    snapshot.SnapshotID[:],
		ChainID:         chainID,
		ChainName:       chainName,
	})
	if err != nil {
		return nil, err
	}
	return &record.SnapshotID, nil
}

// attestationMessagesAgree reports whether every attestation signed the same message. An aggregate over
// attestations to different messages proves nothing about any one of them.
func attestationMessagesAgree(hashes [][]byte) bool {
	for i := 1; i < len(hashes); i++ {
		if !bytes.Equal(hashes[i], hashes[0]) {
			return false
		}
	}
	return true
}

// persistResultHashChainLink records where a cycle's primary result landed in its observer's result hash
// chain: the sequence number, the link to the previous result, the anchor proof it binds, and the chained
// result hash the write-back bundle carries. The primary result is the cycle's first observation, whose
// row is the first chain-execution id; if the ids and observations do not line up one-to-one the primary
// row cannot be identified, and nothing is written rather than a guess.
func persistResultHashChainLink(ctx context.Context, repo *database.UnifiedRepository, execIDs []uuid.UUID, observations int, linked *ExternalChainResult) error {
	if repo == nil || linked == nil {
		return nil
	}
	if len(execIDs) == 0 || len(execIDs) != observations {
		return fmt.Errorf("cannot identify the primary chain-execution row: %d ids for %d observations", len(execIDs), observations)
	}
	return repo.UpdateChainExecutionHashChain(ctx, execIDs[0], int64(linked.SequenceNumber),
		linked.PreviousResultHash[:], linked.AnchorProofHash[:], linked.ResultHash[:])
}

// seedResultHashChains continues each of this validator's persisted result hash chains, so a restart does
// not begin them again at sequence 0 (which would fork every chain it had written).
func seedResultHashChains(ctx context.Context, repo *database.UnifiedRepository, validatorID string, chains map[string]*ResultHashChain) (int, error) {
	if repo == nil {
		return 0, nil
	}
	heads, err := repo.GetChainHashChainHeads(ctx, validatorID)
	if err != nil {
		return 0, err
	}
	for _, head := range heads {
		key := head.ChainID
		if key == "" {
			key = "default"
		}
		chain := &ResultHashChain{ChainID: key, LatestSequence: uint64(head.SequenceNumber) + 1}
		copy(chain.LatestHash[:], head.ChainResultHash)
		copy(chain.AnchorProofHash[:], head.AnchorProofHash)
		chains[key] = chain
	}
	return len(heads), nil
}
