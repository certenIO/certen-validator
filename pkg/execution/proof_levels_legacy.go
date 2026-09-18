// Copyright 2025 Certen Protocol
//
// The four proof levels and the Certen anchor proof for the legacy ProofCycleOrchestrator, the fallback
// path when the unified orchestrator is off or fails to start. The facts recorded are the same as on the
// unified path (proof_levels.go); only their sources differ.

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// votingPowerOf is a validator's weight in the set this collector counts, or 0 when it is not a member.
func (c *AttestationCollector) votingPowerOf(validatorID string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.validatorSet == nil {
		return 0
	}
	for _, v := range c.validatorSet.Validators {
		if v.ID == validatorID && v.VotingPower != nil && v.VotingPower.IsInt64() {
			return v.VotingPower.Int64()
		}
	}
	return 0
}

// persistValidatorSetSnapshot records the set the collector counts attestations against and returns its
// row id, writing each distinct snapshot once.
func (o *ProofCycleOrchestrator) persistValidatorSetSnapshot(ctx context.Context) *uuid.UUID {
	if o.repos == nil || o.repos.ProofArtifacts == nil || o.collector == nil {
		return nil
	}
	snapshot := o.collector.GetSnapshot()
	if snapshot == nil {
		return nil
	}
	o.snapshotRowsMu.Lock()
	defer o.snapshotRowsMu.Unlock()
	if id, ok := o.snapshotRows[snapshot.SnapshotID]; ok {
		return &id
	}
	chainID := strconv.FormatInt(o.config.ChainID, 10)
	id, err := persistValidatorSetSnapshot(ctx, o.repos.ProofArtifacts, snapshot, chainID, getNetworkName(chainID))
	if err != nil {
		o.logger.Printf("⚠️ [PHASE-8] Failed to persist validator set snapshot: %v", err)
		return nil
	}
	if o.snapshotRows == nil {
		o.snapshotRows = map[[32]byte]uuid.UUID{}
	}
	o.snapshotRows[snapshot.SnapshotID] = *id
	return id
}

// legacyCycleID is the key the legacy orchestrator tracks a cycle under.
func legacyCycleID(cycle *ProofCycleCompletion) string {
	if cycle.CreateTxHash != ([32]byte{}) {
		return cycle.IntentID + ":" + cycle.CreateTxHash.Hex()
	}
	if cycle.ExecutionResult != nil {
		return cycle.IntentID + ":" + cycle.ExecutionResult.TxHash.Hex()
	}
	return cycle.IntentID
}

// recordLegacyProofLevels records the four levels of a completed legacy cycle, the Certen proof, and closes
// the cycle. It runs after write-back is confirmed, so the cycle hash the legacy orchestrator computed
// over everything is final.
func (o *ProofCycleOrchestrator) recordLegacyProofLevels(
	ctx context.Context,
	artifact *database.ProofArtifact,
	cycle *ProofCycleCompletion,
	chainedProof *ChainedProofResult,
	govLevel database.GovernanceLevel,
	govJSON json.RawMessage,
	govVerified bool,
) {
	if o.repos == nil || o.repos.ProofArtifacts == nil || artifact == nil {
		return
	}
	repo := o.repos.ProofArtifacts
	cycleID := legacyCycleID(cycle)
	completion, err := repo.SaveProofCycleCompletion(ctx, &database.NewProofCycleCompletion{ProofID: artifact.ProofID, CycleID: cycleID})
	if err != nil {
		o.logger.Printf("⚠️ [PROOF-LEVELS] proof %s: could not create its level record: %v", artifact.ProofID, err)
		return
	}

	// Level 1: the chained proof.
	var chainedJSON json.RawMessage
	if chainedProof != nil {
		if encoded, err := json.Marshal(ChainedProofFromResult(chainedProof)); err == nil {
			chainedJSON = encoded
			sum := sha256.Sum256(encoded)
			logLevelError(artifact.ProofID, 1, repo.UpdateProofCycleLevel1(ctx, completion.CompletionID, artifact.ProofID, sum[:]))
		}
	}

	// Level 2: the highest governance level written, committed by its hash.
	var govCommitment []byte
	if len(govJSON) > 0 {
		sum := sha256.Sum256(govJSON)
		govCommitment = sum[:]
		logLevelError(artifact.ProofID, 2, repo.UpdateProofCycleLevel2(ctx, completion.CompletionID, artifact.ProofID, govCommitment))
	}

	// Level 3: the createAnchor transaction published the root; the canonical batch row says which root
	// and where this intent's leaf sits under it.
	chainID := o.config.ChainID
	var anchor *Layer5
	var anchorBatch *database.Layer5Binding
	if cycle.CreateResult != nil && cycle.CreateTxHash != ([32]byte{}) && cycle.CreateResult.BlockNumber != nil {
		binding, err := repo.GetLayer5Binding(ctx, cycle.IntentID, cycle.IntentTxHash)
		if err == nil {
			anchorBatch = binding
		}
		obs := &chain.ObservationResult{
			TxHash:         cycle.CreateTxHash.Hex(),
			BlockNumber:    cycle.CreateResult.BlockNumber.Uint64(),
			BlockHash:      cycle.CreateResult.BlockHash.Hex(),
			ChainName:      getNetworkName(strconv.FormatInt(chainID, 10)),
			ChainIDNumeric: chainID,
		}
		anchor, err = BuildLayer5(anchorBatch, obs, nil, nil, chainID)
		if err != nil {
			o.logger.Printf("⚠️ [PROOF-LEVELS] proof %s: anchor binding refused: %v", artifact.ProofID, err)
			anchor = nil
		}
	}
	var anchoredRoot []byte
	if anchor != nil {
		if root, err := hex.DecodeString(anchor.BatchRoot); err == nil && len(root) == 32 {
			anchoredRoot = root
			logLevelError(artifact.ProofID, 3, repo.UpdateProofCycleLevel3(ctx, completion.CompletionID, artifact.ProofID, root))
		}
	}

	// Level 4: the governance execution result, the one whose commitment the write-back carries.
	executed := cycle.GovernanceResult
	if executed == nil {
		executed = cycle.ExecutionResult
	}
	var level4Hash []byte
	if executed != nil {
		resultID, err := repo.GetExternalChainResultIDByResultHash(ctx, executed.ResultHash[:])
		if err == nil && resultID != nil {
			level4Hash = executed.ResultHash[:]
			logLevelError(artifact.ProofID, 4, repo.UpdateProofCycleLevel4(ctx, completion.CompletionID, *resultID, level4Hash))
		}
	}

	// The four-component Certen proof.
	if anchor != nil && anchoredRoot != nil {
		pc := certenProofContext{
			ValidatorID: o.validatorID,
			CycleID:     cycleID,
			SnapshotID:  o.persistValidatorSetSnapshot(ctx),
			ObservedTx:  cycle.CreateTxHash.Hex(),
		}
		if cycle.Attestation != nil {
			pc.ThresholdMet = cycle.Attestation.ThresholdMet
			pc.AttestationCount = cycle.Attestation.ValidatorCount
		}
		if cycle.CreateResult != nil {
			pc.ObservedConfirmations = cycle.CreateResult.ConfirmationBlocks
			pc.ObservedBlockHash = cycle.CreateResult.BlockHash.Hex()
		}
		if o.verifier != nil {
			pc.Sign = func(proofHash []byte) []byte {
				var message [32]byte
				copy(message[:], proofHash)
				return o.verifier.signBLS(message)
			}
			pc.SignatureScheme = "bls12-381"
		}
		storeCertenAnchorProof(ctx, o.repos, pc, proofLevelInputs{
			Artifact:      artifact,
			IntentID:      cycle.IntentID,
			AccumTxHash:   cycle.IntentTxHash,
			AccountURL:    artifact.AccountURL,
			ChainedProof:  chainedJSON,
			GovCommitment: govCommitment,
			GovLevel:      govLevel,
			GovProof:      govJSON,
			GovValid:      govVerified,
		}, anchor, anchorBatch, anchoredRoot)
	}

	// Completion: the quorum bound level 4 when it attested this result hash with one message.
	record, err := repo.GetProofCycleCompletionByID(ctx, completion.CompletionID)
	if err != nil || record == nil {
		o.logger.Printf("⚠️ [PROOF-LEVELS] proof %s: level record unreadable: %v", artifact.ProofID, err)
		return
	}
	var missing []string
	for level, done := range []bool{record.Level1Complete, record.Level2Complete, record.Level3Complete, record.Level4Complete} {
		if !done {
			missing = append(missing, "L"+strconv.Itoa(level+1))
		}
	}
	if len(missing) > 0 {
		o.logger.Printf("⚠️ [PROOF-LEVELS] cycle %s proof %s wrote back without %s; its cycle stays incomplete",
			cycleID, artifact.ProofID, strings.Join(missing, ","))
		return
	}
	bindings := cycle.Attestation != nil && cycle.Attestation.ThresholdMet && cycle.Attestation.MessageConsistencyVerified &&
		level4Hash != nil && string(cycle.Attestation.ResultHash[:]) == string(level4Hash)
	cycleHash := cycle.CycleHash[:]
	if cycle.CycleHash == ([32]byte{}) {
		cycleHash = proofCycleHash(record, writeBackHash(cycle))
	}
	if err := repo.CompleteProofCycle(ctx, completion.CompletionID, bindings, cycleHash); err != nil {
		o.logger.Printf("⚠️ [PROOF-LEVELS] cycle %s proof %s: completion not recorded: %v", cycleID, artifact.ProofID, err)
		return
	}
	o.logger.Printf("✅ [PROOF-LEVELS] cycle %s proof %s: all four levels complete (bindings_valid=%v) at %s",
		cycleID, artifact.ProofID, bindings, time.Now().UTC().Format(time.RFC3339))
}

func writeBackHash(cycle *ProofCycleCompletion) string {
	if cycle.WriteBackTx == nil || cycle.WriteBackTx.TxHash == ([32]byte{}) {
		return ""
	}
	return hex.EncodeToString(cycle.WriteBackTx.TxHash[:])
}
