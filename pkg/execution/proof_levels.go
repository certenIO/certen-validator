// Copyright 2025 Certen Protocol
//
// The four proof levels of a proof cycle, recorded as they are established, and the four-component
// Certen anchor proof built from them.
//
//	Level 1  the chained Accumulate proof (L1-L3)       hash: sha256 of the chained proof
//	Level 2  governance                                  hash: the governance commitment
//	Level 3  the anchor: where the root was published    hash: the anchored root
//	Level 4  the external execution result               hash: the observed result hash
//
// A level is recorded only when its evidence exists. A cycle is completed only when all four are, and
// its cycle hash binds the four level hashes and the write-back transaction together.

package execution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// proofLevelInputs is what one proof artifact contributes to its levels. The unified on-demand path and
// the per-transaction batch path fill it from different sources; recordProofLevels treats them alike.
type proofLevelInputs struct {
	Artifact      *database.ProofArtifact
	IntentID      string
	AccumTxHash   string
	AccountURL    string
	TransactionID int64

	// Transaction inclusion
	MerkleRoot []byte
	LeafHash   []byte
	LeafIndex  int
	MerklePath []database.MerklePathNode

	// Level 1: the chained proof, canonical JSON
	ChainedProof     json.RawMessage
	AccumBlockHeight int64
	AccumBVN         string

	// Level 2: the governance commitment and the governance proof it commits to
	GovCommitment []byte
	GovLevel      database.GovernanceLevel
	GovProof      json.RawMessage
	GovValid      bool
}

// recordProofLevels creates the proof's level-tracking row, records every level whose evidence exists,
// and builds the Certen anchor proof when the anchor is known. Failures are logged and never fail the
// cycle: the proof artifact already exists, and a missing level reads as incomplete, which is true.
func (o *UnifiedOrchestrator) recordProofLevels(ctx context.Context, cycle *activeCycle, in proofLevelInputs, anchor *Layer5, anchorBatch *database.Layer5Binding) {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil || in.Artifact == nil {
		return
	}
	repo := o.config.Repos.ProofArtifacts
	proofID := in.Artifact.ProofID
	completion, err := repo.SaveProofCycleCompletion(ctx, &database.NewProofCycleCompletion{ProofID: proofID, CycleID: cycle.CycleID})
	if err != nil {
		logfPrintf("⚠️ [PROOF-LEVELS] proof %s: could not create its level record: %v", proofID, err)
		return
	}
	cycle.Completions = append(cycle.Completions, completion.CompletionID)

	if len(in.ChainedProof) > 0 && string(in.ChainedProof) != "null" {
		sum := sha256.Sum256(in.ChainedProof)
		logLevelError(proofID, 1, repo.UpdateProofCycleLevel1(ctx, completion.CompletionID, proofID, sum[:]))
	}
	if len(in.GovCommitment) > 0 && !bytes.Equal(in.GovCommitment, make([]byte, len(in.GovCommitment))) {
		logLevelError(proofID, 2, repo.UpdateProofCycleLevel2(ctx, completion.CompletionID, proofID, in.GovCommitment))
	}
	var anchoredRoot []byte
	if anchor != nil {
		if root, err := hex.DecodeString(anchor.BatchRoot); err == nil && len(root) == 32 {
			anchoredRoot = root
			logLevelError(proofID, 3, repo.UpdateProofCycleLevel3(ctx, completion.CompletionID, proofID, root))
		}
	}
	result := cycle.Result
	if len(result.ObservationResults) > 0 && len(result.ChainExecutionIDs) == len(result.ObservationResults) {
		obs := result.ObservationResults[0]
		if obs.IsFinalized {
			logLevelError(proofID, 4, repo.UpdateProofCycleLevel4(ctx, completion.CompletionID, result.ChainExecutionIDs[0], obs.ResultHash[:]))
		}
	}

	if anchor == nil || anchoredRoot == nil {
		logfPrintf("ℹ️ [CERTEN-PROOF] proof %s: no anchor binding, so no four-component proof; level 3 stays open", proofID)
		return
	}
	o.recordCertenAnchorProof(ctx, cycle, in, anchor, anchorBatch, anchoredRoot)
}

func logLevelError(proofID uuid.UUID, level int, err error) {
	if err != nil {
		logfPrintf("⚠️ [PROOF-LEVELS] proof %s: level %d not recorded: %v", proofID, level, err)
	}
}

// certenProofContext is what the orchestrator running the cycle knows about it that the proof records.
type certenProofContext struct {
	ValidatorID      string
	CycleID          string
	ThresholdMet     bool
	AttestationCount int
	SnapshotID       *uuid.UUID

	// The transaction the cycle observed, which is the anchor only when the hashes match.
	ObservedTx            string
	ObservedConfirmations int
	ObservedBlockHash     string

	// Sign signs the proof hash with the validator's key; SignatureScheme names the key.
	Sign            func(proofHash []byte) []byte
	SignatureScheme string
}

// recordCertenAnchorProof stores the four-component proof for a unified cycle, signed with the validator's
// Ed25519 key.
func (o *UnifiedOrchestrator) recordCertenAnchorProof(ctx context.Context, cycle *activeCycle, in proofLevelInputs, anchor *Layer5, anchorBatch *database.Layer5Binding, anchoredRoot []byte) {
	result := cycle.Result
	pc := certenProofContext{
		ValidatorID:      o.config.ValidatorID,
		CycleID:          cycle.CycleID,
		ThresholdMet:     result.ThresholdMet,
		AttestationCount: len(result.Attestations),
		SnapshotID:       cycle.SnapshotID,
	}
	if len(result.ObservationResults) > 0 {
		obs := result.ObservationResults[0]
		pc.ObservedTx, pc.ObservedConfirmations, pc.ObservedBlockHash = obs.TxHash, obs.Confirmations, obs.BlockHash
	}
	if key := o.config.Ed25519Key; len(key) == ed25519.PrivateKeySize {
		pc.Sign = func(proofHash []byte) []byte { return ed25519.Sign(ed25519.PrivateKey(key), proofHash) }
		pc.SignatureScheme = "ed25519"
	}
	storeCertenAnchorProof(ctx, o.config.Repos, pc, in, anchor, anchorBatch, anchoredRoot)
}

// storeCertenAnchorProof stores the whitepaper's four-component proof for one artifact: inclusion in the
// anchored root, the anchor reference (the transaction that published the root, never the settlement),
// the chained state proof and the authority proof. It is signed with the validator's key and marked
// verified only when the quorum was met, the stored hash covers the stored proof, and the anchor binding
// verifies offline.
func storeCertenAnchorProof(ctx context.Context, repos *database.Repositories, pc certenProofContext, in proofLevelInputs, anchor *Layer5, anchorBatch *database.Layer5Binding, anchoredRoot []byte) {
	if repos == nil || repos.Proofs == nil {
		logfPrintf("⚠️ [CERTEN-PROOF] proof %s: no proof repository configured", in.Artifact.ProofID)
		return
	}
	proofs := repos.Proofs
	var batchID uuid.UUID
	anchorChain := anchor.Network
	if anchorBatch != nil {
		batchID = anchorBatch.BatchID
		// The canonical row names the chain; the observation's name is empty when its strategy set none.
		if anchorBatch.TargetChain != "" {
			anchorChain = anchorBatch.TargetChain
		}
	}
	leaf, path, leafIndex := in.LeafHash, in.MerklePath, in.LeafIndex
	if decoded, err := hex.DecodeString(anchor.LeafHash); err == nil && len(decoded) == 32 {
		// The anchor binding's leaf and path are the ones that verify against the anchored root.
		leaf, leafIndex = decoded, int(anchor.LeafIndex)
		path = make([]database.MerklePathNode, 0, len(anchor.Path))
		for _, step := range anchor.Path {
			path = append(path, database.MerklePathNode{Hash: step.Hash, Position: step.Position})
		}
	}
	accountURL := in.AccountURL
	if accountURL == "" {
		accountURL = in.Artifact.AccountURL
	}
	stored, err := proofs.CreateProof(ctx, &database.NewCertenAnchorProof{
		ProofArtifactID:   in.Artifact.ProofID,
		BatchID:           batchID,
		TransactionID:     in.TransactionID,
		AccumTxHash:       in.AccumTxHash,
		AccountURL:        accountURL,
		MerkleRoot:        anchoredRoot,
		MerkleInclusion:   path,
		LeafHash:          leaf,
		LeafIndex:         leafIndex,
		AnchorChain:       database.TargetChain(anchorChain),
		AnchorTxHash:      anchor.AnchorTx,
		AnchorBlockNumber: int64(anchor.BlockNumber),
		AnchorBlockHash:   anchor.BlockHash,
		AccumStateProof:   in.ChainedProof,
		AccumBlockHeight:  in.AccumBlockHeight,
		AccumBVN:          in.AccumBVN,
		GovProof:          in.GovProof,
		GovLevel:          in.GovLevel,
		GovValid:          in.GovValid,
		ValidatorID:       pc.ValidatorID,
	})
	if err != nil {
		logfPrintf("⚠️ [CERTEN-PROOF] proof %s: four-component proof not stored: %v", in.Artifact.ProofID, err)
		return
	}

	// Confirmations come from an observation of the anchor transaction itself: the layer's, when the
	// anchor was read back, or the cycle's, when the anchor is the transaction the cycle observed.
	confirmations, blockHash := anchor.Confirmations, anchor.BlockHash
	if confirmations == 0 && pc.ObservedTx != "" && strings.EqualFold(pc.ObservedTx, anchor.AnchorTx) {
		confirmations, blockHash = pc.ObservedConfirmations, pc.ObservedBlockHash
	}
	if confirmations > 0 {
		if err := proofs.UpdateAnchorConfirmations(ctx, stored.ProofID, confirmations, blockHash); err != nil {
			logfPrintf("⚠️ [CERTEN-PROOF] proof %s: confirmations not recorded: %v", in.Artifact.ProofID, err)
		}
	}

	if pc.Sign != nil {
		if signature := pc.Sign(stored.ProofHash); len(signature) > 0 {
			if err := proofs.UpdateValidatorSignature(ctx, stored.ProofID, signature); err != nil {
				logfPrintf("⚠️ [CERTEN-PROOF] proof %s: validator signature not recorded: %v", in.Artifact.ProofID, err)
			}
		}
	}

	anchorErr := anchor.VerifyOffline()
	hashOK := stored.VerifyProofHash()
	verified := pc.ThresholdMet && hashOK && anchorErr == nil
	details := map[string]interface{}{
		"threshold_met":           pc.ThresholdMet,
		"attestation_count":       pc.AttestationCount,
		"proof_hash_verified":     hashOK,
		"anchor_offline_verified": anchorErr == nil,
		"verified_by":             pc.ValidatorID,
		"cycle_id":                pc.CycleID,
	}
	if pc.SignatureScheme != "" {
		details["signature_scheme"] = pc.SignatureScheme
	}
	if anchorErr != nil {
		details["anchor_error"] = anchorErr.Error()
	}
	if pc.SnapshotID != nil {
		details["validator_set_snapshot_id"] = pc.SnapshotID.String()
	}
	detailsJSON, _ := json.Marshal(details)
	if err := proofs.UpdateVerification(ctx, stored.ProofID, verified, detailsJSON); err != nil {
		logfPrintf("⚠️ [CERTEN-PROOF] proof %s: verification not recorded: %v", in.Artifact.ProofID, err)
	}
	logfPrintf("📜 [CERTEN-PROOF] proof %s: four-component proof %s stored (verified=%v, anchor tx %s)",
		in.Artifact.ProofID, stored.ProofID, verified, anchor.AnchorTx)
}

// levelsBoundByAttestations reports whether the quorum signed the cross-level binding: every attestation
// carries a message naming this cycle's level-4 result and level-3 root, and they all signed the same
// message. A quorum over a different result or root binds nothing.
func levelsBoundByAttestations(result *UnifiedProofCycleResult, merkleRoot [32]byte) bool {
	if result == nil || !result.ThresholdMet || len(result.Attestations) == 0 || len(result.ObservationResults) == 0 {
		return false
	}
	resultHash := result.ObservationResults[0].ResultHash
	hashes := make([][]byte, 0, len(result.Attestations))
	for _, att := range result.Attestations {
		if att == nil || att.Message == nil {
			return false
		}
		if att.Message.ResultHash != resultHash || att.Message.MerkleRoot != merkleRoot {
			return false
		}
		hashes = append(hashes, att.MessageHash[:])
	}
	return attestationMessagesAgree(hashes)
}

// proofCycleHash binds the four level hashes and the write-back transaction.
func proofCycleHash(record *database.ProofCycleCompletionRecord, writeBackTx string) []byte {
	h := sha256.New()
	h.Write([]byte("CERTEN_PROOF_CYCLE_V1"))
	for _, part := range [][]byte{record.Level1Hash, record.Level2Hash, record.Level3Hash, record.Level4Hash} {
		h.Write(part)
	}
	h.Write([]byte(writeBackTx))
	return h.Sum(nil)
}

// completeProofCycles closes the level records of a cycle once its write-back is done. A record missing a
// level is not completed; it is reported with the levels it lacks and stays in the incomplete list.
func (o *UnifiedOrchestrator) completeProofCycles(ctx context.Context, cycleID string, completions []uuid.UUID, result *UnifiedProofCycleResult, merkleRoot [32]byte, writeBackTx string) {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil {
		return
	}
	repo := o.config.Repos.ProofArtifacts
	bindings := levelsBoundByAttestations(result, merkleRoot)
	for _, completionID := range completions {
		record, err := repo.GetProofCycleCompletionByID(ctx, completionID)
		if err != nil || record == nil {
			logfPrintf("⚠️ [PROOF-LEVELS] cycle %s: level record %s unreadable: %v", cycleID, completionID, err)
			continue
		}
		var missing []string
		for level, done := range []bool{record.Level1Complete, record.Level2Complete, record.Level3Complete, record.Level4Complete} {
			if !done {
				missing = append(missing, fmt.Sprintf("L%d", level+1))
			}
		}
		if len(missing) > 0 {
			logfPrintf("⚠️ [PROOF-LEVELS] cycle %s proof %s wrote back without %s; its cycle stays incomplete",
				cycleID, record.ProofID, strings.Join(missing, ","))
			continue
		}
		if err := repo.CompleteProofCycle(ctx, completionID, bindings, proofCycleHash(record, writeBackTx)); err != nil {
			logfPrintf("⚠️ [PROOF-LEVELS] cycle %s proof %s: completion not recorded: %v", cycleID, record.ProofID, err)
			continue
		}
		logfPrintf("✅ [PROOF-LEVELS] cycle %s proof %s: all four levels complete (bindings_valid=%v)", cycleID, record.ProofID, bindings)
	}
}

// deferredCompletion is a multi-leg chain group's cycle, whose write-back happens later in the aggregator.
type deferredCompletion struct {
	cycleID     string
	completions []uuid.UUID
	result      *UnifiedProofCycleResult
	merkleRoot  [32]byte
	deferredAt  time.Time
}

// deferredCompletions holds multi-leg cycles until the aggregator's unified write-back lands.
type deferredCompletions struct {
	mu       sync.Mutex
	byIntent map[string][]deferredCompletion
}

// deferredCompletionTTL bounds how long a chain group waits for its unified write-back before its level
// records are left incomplete; it is the aggregator's own timeout with a margin.
const deferredCompletionTTL = 2 * time.Hour

func (d *deferredCompletions) add(intentID string, entry deferredCompletion) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byIntent == nil {
		d.byIntent = map[string][]deferredCompletion{}
	}
	for id, entries := range d.byIntent {
		kept := entries[:0]
		for _, e := range entries {
			if time.Since(e.deferredAt) < deferredCompletionTTL {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(d.byIntent, id)
		} else {
			d.byIntent[id] = kept
		}
	}
	d.byIntent[intentID] = append(d.byIntent[intentID], entry)
}

func (d *deferredCompletions) take(intentID string) []deferredCompletion {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := d.byIntent[intentID]
	delete(d.byIntent, intentID)
	return entries
}
