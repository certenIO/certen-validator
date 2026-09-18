// Copyright 2025 Certen Protocol
//
// The restored Level 4 proof records, Certen anchor proofs and proof requests, exercised against the
// shared schema. Every repository function is called here, including the ones whose SQL is assembled at
// run time and so cannot be checked by the static prepare gate.

package database

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func requireTestDB(t *testing.T) {
	t.Helper()
	if testDB == nil {
		t.Skip("Test database not configured")
	}
}

// newTestArtifact creates a proof artifact to hang records off, removed when the test ends.
func newTestArtifact(t *testing.T, ctx context.Context) *ProofArtifact {
	t.Helper()
	artifact, err := NewProofArtifactRepository(testDB).CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  "records_tx_" + uuid.NewString(),
		AccountURL:   "acc://records.acme/tokens",
		ProofClass:   ProofClassOnDemand,
		ValidatorID:  "records-validator",
		ArtifactJSON: json.RawMessage(`{"records":true}`),
	})
	if err != nil {
		t.Fatalf("create proof artifact: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
	})
	return artifact
}

func hash32(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

func newTestSnapshot(t *testing.T, ctx context.Context, repo *ProofArtifactRepository, label string) *ValidatorSetSnapshotRecord {
	t.Helper()
	snapshot, err := repo.SaveValidatorSetSnapshot(ctx, &NewValidatorSetSnapshot{
		BlockNumber:     100,
		ValidatorsJSON:  json.RawMessage(`[{"validator_id":"v1","weight":1,"index":0},{"validator_id":"v2","weight":1,"index":1},{"validator_id":"v3","weight":1,"index":2}]`),
		ValidatorRoot:   hash32("root-" + label),
		ValidatorCount:  3,
		TotalWeight:     3,
		ThresholdWeight: 3,
		SnapshotHash:    hash32("snapshot-" + label),
		ChainID:         "84532",
		ChainName:       "base-sepolia",
	})
	if err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM validator_set_snapshots WHERE snapshot_id = $1`, snapshot.SnapshotID)
	})
	return snapshot
}

func newTestResult(proofID uuid.UUID, label string, sequence int64, previous []byte, anchorProof []byte, snapshot *uuid.UUID) *NewExternalChainResult {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &NewExternalChainResult{
		ProofID:             proofID,
		BundleID:            hash32("bundle-" + label),
		OperationID:         hash32("operation-" + label),
		ChainType:           "ethereum",
		ChainID:             "84532",
		ChainName:           "base-sepolia",
		BlockNumber:         1000 + sequence,
		BlockHash:           hash32("block-" + label),
		BlockTimestamp:      now,
		TransactionHash:     hash32("tx-" + label),
		TxFromAddress:       hash32("from")[:20],
		StateRoot:           hash32("state-" + label),
		TransactionsRoot:    hash32("txroot-" + label),
		ReceiptsRoot:        hash32("receipts-" + label),
		ExecutionStatus:     1,
		GasUsed:             21000,
		ReturnData:          []byte{0x01},
		StorageProofJSON:    json.RawMessage(`{"slots":[]}`),
		StorageProofHash:    hash32("storage-" + label),
		SequenceNumber:      sequence,
		PreviousResultHash:  previous,
		ResultHash:          hash32("result-" + label),
		AnchorProofHash:     anchorProof,
		ArtifactJSON:        json.RawMessage(`{"result":"` + label + `"}`),
		SnapshotID:          snapshot,
		IsFinalized:         true,
		ObserverValidatorID: "v1",
		ObservedAt:          now,
	}
}

func TestExternalChainResultHashChain(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	artifact := newTestArtifact(t, ctx)
	snapshot := newTestSnapshot(t, ctx, repo, "results-"+uuid.NewString())
	anchor := hash32("anchor-" + artifact.ProofID.String())

	first, err := repo.SaveExternalChainResult(ctx, newTestResult(artifact.ProofID, "a-"+artifact.ProofID.String(), 0, make([]byte, 32), anchor, &snapshot.SnapshotID))
	if err != nil {
		t.Fatalf("save first result: %v", err)
	}
	second, err := repo.SaveExternalChainResult(ctx, newTestResult(artifact.ProofID, "b-"+artifact.ProofID.String(), 1, first.ResultHash, anchor, &snapshot.SnapshotID))
	if err != nil {
		t.Fatalf("save second result: %v", err)
	}
	if first.ChainName != "base-sepolia" || first.ChainID != "84532" || first.SequenceNumber == nil || *first.SequenceNumber != 0 {
		t.Fatalf("first result read back as %+v", first)
	}
	if first.ProofID == nil || *first.ProofID != artifact.ProofID || first.SnapshotID == nil || *first.SnapshotID != snapshot.SnapshotID {
		t.Fatalf("first result lost its proof or snapshot: %+v", first)
	}

	got, err := repo.GetExternalChainResultByID(ctx, second.ResultID)
	if err != nil || got == nil || string(got.PreviousResultHash) != string(first.ResultHash) {
		t.Fatalf("GetExternalChainResultByID = %+v, %v", got, err)
	}
	byProof, err := repo.GetExternalChainResultsByProof(ctx, artifact.ProofID)
	if err != nil || len(byProof) != 2 || byProof[0].ResultID != first.ResultID || byProof[1].ResultID != second.ResultID {
		t.Fatalf("GetExternalChainResultsByProof = %d results, %v", len(byProof), err)
	}
	latest, err := repo.GetLatestExternalChainResult(ctx, artifact.ProofID)
	if err != nil || latest == nil || latest.ResultID != second.ResultID {
		t.Fatalf("GetLatestExternalChainResult = %+v, %v", latest, err)
	}
	valid, err := repo.VerifyExternalChainResultHashChain(ctx, artifact.ProofID)
	if err != nil || !valid {
		t.Fatalf("an intact chain did not verify: %v %v", valid, err)
	}

	// Break the link: the second result no longer points at the first.
	if err := repo.UpdateExternalChainResultHashChain(ctx, second.ResultID, 1, hash32("not-the-first"), anchor); err != nil {
		t.Fatalf("UpdateExternalChainResultHashChain: %v", err)
	}
	if valid, err := repo.VerifyExternalChainResultHashChain(ctx, artifact.ProofID); err != nil || valid {
		t.Fatalf("a broken link verified: %v %v", valid, err)
	}
	// Restore the link but skip a sequence number.
	if err := repo.UpdateExternalChainResultHashChain(ctx, second.ResultID, 2, first.ResultHash, anchor); err != nil {
		t.Fatalf("UpdateExternalChainResultHashChain: %v", err)
	}
	if valid, err := repo.VerifyExternalChainResultHashChain(ctx, artifact.ProofID); err != nil || valid {
		t.Fatalf("a sequence gap verified: %v %v", valid, err)
	}
	// Right link and sequence, different anchor proof.
	if err := repo.UpdateExternalChainResultHashChain(ctx, second.ResultID, 1, first.ResultHash, hash32("another anchor")); err != nil {
		t.Fatalf("UpdateExternalChainResultHashChain: %v", err)
	}
	if valid, err := repo.VerifyExternalChainResultHashChain(ctx, artifact.ProofID); err != nil || valid {
		t.Fatalf("results binding different anchor proofs verified: %v %v", valid, err)
	}

	if err := repo.MarkExternalChainResultVerified(ctx, first.ResultID, true); err != nil {
		t.Fatalf("MarkExternalChainResultVerified: %v", err)
	}
	if got, _ := repo.GetExternalChainResultByID(ctx, first.ResultID); got == nil || !got.Verified || got.VerifiedAt == nil {
		t.Fatalf("verification not recorded: %+v", got)
	}
	if _, err := repo.GetUnfinalizedExternalChainResults(ctx, 10); err != nil {
		t.Fatalf("GetUnfinalizedExternalChainResults: %v", err)
	}
	if _, err := repo.SaveExternalChainResult(ctx, &NewExternalChainResult{ChainID: "base"}); err == nil {
		t.Fatal("a non-numeric chain id was accepted")
	}
	if missing, err := repo.GetExternalChainResultByID(ctx, uuid.New()); err != nil || missing != nil {
		t.Fatalf("missing result = %+v, %v", missing, err)
	}
}

func TestValidatorSetSnapshotIsStoredOncePerSet(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	label := "dedupe-" + uuid.NewString()
	first := newTestSnapshot(t, ctx, repo, label)
	again := newTestSnapshot(t, ctx, repo, label)
	if first.SnapshotID != again.SnapshotID {
		t.Fatalf("the same set was stored twice: %s and %s", first.SnapshotID, again.SnapshotID)
	}
	byID, err := repo.GetValidatorSetSnapshotByID(ctx, first.SnapshotID)
	if err != nil || byID == nil || byID.ThresholdWeight != 3 || byID.ValidatorCount != 3 {
		t.Fatalf("GetValidatorSetSnapshotByID = %+v, %v", byID, err)
	}
	byHash, err := repo.GetValidatorSetSnapshotByHash(ctx, first.SnapshotHash)
	if err != nil || byHash == nil || byHash.SnapshotID != first.SnapshotID {
		t.Fatalf("GetValidatorSetSnapshotByHash = %+v, %v", byHash, err)
	}
	latest, err := repo.GetLatestValidatorSetSnapshot(ctx, "84532")
	if err != nil || latest == nil {
		t.Fatalf("GetLatestValidatorSetSnapshot = %+v, %v", latest, err)
	}
	if _, err := repo.SaveValidatorSetSnapshot(ctx, &NewValidatorSetSnapshot{
		ValidatorsJSON: json.RawMessage(`[]`), ValidatorRoot: hash32("r"), ValidatorCount: 1,
		TotalWeight: 1, ThresholdWeight: 2, SnapshotHash: hash32("impossible-" + label), ChainID: "1", ChainName: "x",
	}); err == nil {
		t.Fatal("a threshold above the total weight was accepted")
	}
}

func TestBLSAttestationsAndTheirAggregate(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	artifact := newTestArtifact(t, ctx)
	snapshot := newTestSnapshot(t, ctx, repo, "bls-"+uuid.NewString())
	result, err := repo.SaveExternalChainResult(ctx, newTestResult(artifact.ProofID, "bls-"+artifact.ProofID.String(), 0, make([]byte, 32), hash32("anchor"), &snapshot.SnapshotID))
	if err != nil {
		t.Fatalf("save result: %v", err)
	}
	message := hash32("message-" + artifact.ProofID.String())
	var ids []uuid.UUID
	for i, validator := range []string{"v1", "v2"} {
		att, err := repo.SaveBLSAttestation(ctx, &NewBLSAttestation{
			ResultID: result.ResultID, SnapshotID: &snapshot.SnapshotID,
			ResultHash: result.ResultHash, BundleID: result.BundleID,
			ValidatorID: validator, ValidatorAddress: hash32(validator)[:20], ValidatorIndex: i,
			PublicKey: hash32("pk-" + validator), MessageHash: message, Signature: hash32("sig-" + validator)[:32],
			Weight: 1, SubgroupValid: true, AttestedBlockNumber: 1000, ConfirmationsAtAttest: 12,
			AttestedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("save attestation %s: %v", validator, err)
		}
		if att.SnapshotID == nil || *att.SnapshotID != snapshot.SnapshotID || att.Weight != 1 || !att.SubgroupValid {
			t.Fatalf("attestation read back as %+v", att)
		}
		ids = append(ids, att.AttestationID)
	}
	got, err := repo.GetBLSAttestationByID(ctx, ids[0])
	if err != nil || got == nil || got.ValidatorID != "v1" || got.SignatureValid {
		t.Fatalf("GetBLSAttestationByID = %+v, %v", got, err)
	}
	if err := repo.UpdateBLSAttestationVerified(ctx, ids[0], true); err != nil {
		t.Fatalf("UpdateBLSAttestationVerified: %v", err)
	}
	if got, _ := repo.GetBLSAttestationByID(ctx, ids[0]); got == nil || !got.SignatureValid || got.VerifiedAt == nil {
		t.Fatalf("verification not recorded: %+v", got)
	}
	byResult, err := repo.GetBLSAttestationsByResult(ctx, result.ResultID)
	if err != nil || len(byResult) != 2 {
		t.Fatalf("GetBLSAttestationsByResult = %d, %v", len(byResult), err)
	}
	if consistent, err := repo.VerifyBLSAttestationMessageConsistency(ctx, result.ResultID); err != nil || !consistent {
		t.Fatalf("matching messages reported inconsistent: %v %v", consistent, err)
	}

	aggregate, err := repo.SaveAggregatedAttestation(ctx, &NewAggregatedAttestation{
		ResultID: result.ResultID, SnapshotID: &snapshot.SnapshotID,
		ResultHash: result.ResultHash, BundleID: result.BundleID, AttestedBlockNumber: 1000,
		MessageHash: message, AggregatedSignature: hash32("agg-sig"), AggregatedPublicKey: hash32("agg-pk"),
		ValidatorBitfield: []byte{0x03}, ValidatorAddresses: [][]byte{hash32("v1")[:20], hash32("v2")[:20]},
		ValidatorIndices: []int32{0, 1}, AttestationIDs: ids, ParticipantIDs: json.RawMessage(`["v1","v2"]`),
		ParticipantCount: 2, TotalWeight: 3, AchievedWeight: 2, ThresholdNumerator: 2, ThresholdDenominator: 3,
		ThresholdMet: false, MessageConsistencyValid: true,
		FirstAttestationAt: time.Now().UTC(), LastAttestationAt: time.Now().UTC(), AggregationHash: hash32("aggregation"),
	})
	if err != nil {
		t.Fatalf("SaveAggregatedAttestation: %v", err)
	}
	if aggregate.Source != "result" || aggregate.ResultID == nil || *aggregate.ResultID != result.ResultID ||
		aggregate.TotalWeight != 3 || aggregate.AchievedWeight != 2 || aggregate.ThresholdWeight != 3 ||
		!aggregate.MessageConsistencyValid || aggregate.SnapshotID == nil {
		t.Fatalf("aggregate read back as %+v", aggregate)
	}
	byResultAgg, err := repo.GetAggregatedAttestationByResult(ctx, result.ResultID)
	if err != nil || byResultAgg == nil || byResultAgg.AggregationID != aggregate.AggregationID {
		t.Fatalf("GetAggregatedAttestationByResult = %+v, %v", byResultAgg, err)
	}
	if err := repo.UpdateAggregatedAttestationVerified(ctx, aggregate.AggregationID, true); err != nil {
		t.Fatalf("UpdateAggregatedAttestationVerified (result): %v", err)
	}
	if got, _ := repo.GetAggregatedAttestationByID(ctx, aggregate.AggregationID); got == nil || !got.AggregationValid {
		t.Fatalf("result aggregate verification not recorded: %+v", got)
	}

	// A third attestation to a different message breaks consistency.
	if _, err := repo.SaveBLSAttestation(ctx, &NewBLSAttestation{
		ResultID: result.ResultID, ResultHash: result.ResultHash, BundleID: result.BundleID,
		ValidatorID: "v3", ValidatorAddress: hash32("v3")[:20], ValidatorIndex: 2,
		PublicKey: hash32("pk-v3"), MessageHash: hash32("a different message"), Signature: hash32("sig-v3"),
		AttestedBlockNumber: 1000, AttestedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save third attestation: %v", err)
	}
	if consistent, err := repo.VerifyBLSAttestationMessageConsistency(ctx, result.ResultID); err != nil || consistent {
		t.Fatalf("different messages reported consistent: %v %v", consistent, err)
	}

	// A cycle-level aggregate written by the unified orchestrator is readable through the same API.
	cycleID := "cycle-" + uuid.NewString()
	cycleAggID, err := NewUnifiedRepository(testDB).CreateAggregatedAttestation(ctx, &NewUnifiedAggregatedAttestation{
		CycleID: cycleID, Scheme: AttestationScheme("bls12-381"), MessageHash: message,
		AggregatedSignature: hash32("cycle-sig"), AggregatedPublicKey: hash32("cycle-pk"),
		ParticipantIDs: []string{"v1", "v2"}, ParticipantCount: 2, TotalWeight: 3, AchievedWeight: 2,
		ThresholdWeight: 3, ThresholdMet: false, ThresholdNumerator: 2, ThresholdDenominator: 3,
		AggregatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create cycle aggregate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM aggregated_attestations WHERE aggregation_id = $1`, cycleAggID)
	})
	cycleAgg, err := repo.GetAggregatedAttestationByID(ctx, cycleAggID)
	if err != nil || cycleAgg == nil || cycleAgg.Source != "cycle" || cycleAgg.CycleID == nil || *cycleAgg.CycleID != cycleID {
		t.Fatalf("cycle aggregate by id = %+v, %v", cycleAgg, err)
	}
	byCycle, err := repo.GetAggregatedAttestationByCycle(ctx, cycleID)
	if err != nil || byCycle == nil || byCycle.AggregationID != cycleAggID {
		t.Fatalf("GetAggregatedAttestationByCycle = %+v, %v", byCycle, err)
	}
	if err := repo.UpdateAggregatedAttestationVerified(ctx, cycleAggID, true); err != nil {
		t.Fatalf("UpdateAggregatedAttestationVerified (cycle): %v", err)
	}
	if err := repo.UpdateAggregatedAttestationVerified(ctx, uuid.New(), true); err == nil {
		t.Fatal("verifying a missing aggregate succeeded")
	}
}

func TestProofCycleCompletionTracksAllFourLevels(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	artifact := newTestArtifact(t, ctx)
	cycleID := "cycle-" + uuid.NewString()

	completion, err := repo.SaveProofCycleCompletion(ctx, &NewProofCycleCompletion{ProofID: artifact.ProofID, CycleID: cycleID})
	if err != nil {
		t.Fatalf("SaveProofCycleCompletion: %v", err)
	}
	again, err := repo.SaveProofCycleCompletion(ctx, &NewProofCycleCompletion{ProofID: artifact.ProofID})
	if err != nil || again.CompletionID != completion.CompletionID || again.CycleID == nil || *again.CycleID != cycleID {
		t.Fatalf("a second save made a new record or lost the cycle: %+v, %v", again, err)
	}
	if completion.Level1ProofID != nil || completion.Level1Complete {
		t.Fatalf("a new record claims level 1: %+v", completion)
	}

	if err := repo.UpdateProofCycleLevel1(ctx, completion.CompletionID, artifact.ProofID, hash32("l1")); err != nil {
		t.Fatalf("level 1: %v", err)
	}
	if err := repo.UpdateProofCycleLevel2(ctx, completion.CompletionID, artifact.ProofID, hash32("l2")); err != nil {
		t.Fatalf("level 2: %v", err)
	}
	if err := repo.CompleteProofCycle(ctx, completion.CompletionID, true, hash32("cycle")); err == nil {
		t.Fatal("a cycle missing levels 3 and 4 was completed")
	}
	incomplete, err := repo.GetIncompleteProofCycles(ctx, 1000)
	if err != nil || !containsCompletion(incomplete, completion.CompletionID) {
		t.Fatalf("an incomplete cycle is not listed as incomplete: %v", err)
	}
	three := true
	if err := repo.ApplyProofCycleCompletionUpdate(ctx, &ProofCycleCompletionUpdate{
		CompletionID: completion.CompletionID, Level3Complete: &three, Level3ProofID: &artifact.ProofID, Level3Hash: hash32("l3"),
	}); err != nil {
		t.Fatalf("ApplyProofCycleCompletionUpdate: %v", err)
	}
	resultID := uuid.New()
	if err := repo.UpdateProofCycleLevel4(ctx, completion.CompletionID, resultID, hash32("l4")); err != nil {
		t.Fatalf("level 4: %v", err)
	}
	if err := repo.UpdateProofCycleLevel4(ctx, completion.CompletionID, resultID, nil); err == nil {
		t.Fatal("a level was recorded without its hash")
	}
	if err := repo.CompleteProofCycle(ctx, completion.CompletionID, true, nil); err == nil {
		t.Fatal("a cycle was completed without its cycle hash")
	}
	if err := repo.CompleteProofCycle(ctx, completion.CompletionID, true, hash32("cycle")); err != nil {
		t.Fatalf("CompleteProofCycle: %v", err)
	}

	for name, get := range map[string]func() (*ProofCycleCompletionRecord, error){
		"by id": func() (*ProofCycleCompletionRecord, error) {
			return repo.GetProofCycleCompletionByID(ctx, completion.CompletionID)
		},
		"by proof": func() (*ProofCycleCompletionRecord, error) {
			return repo.GetProofCycleCompletionByProof(ctx, artifact.ProofID)
		},
		"by cycle": func() (*ProofCycleCompletionRecord, error) { return repo.GetProofCycleCompletionByCycle(ctx, cycleID) },
	} {
		got, err := get()
		if err != nil || got == nil {
			t.Fatalf("%s: %+v, %v", name, got, err)
		}
		if !got.AllLevelsComplete || !got.BindingsValid || got.CompletedAt == nil ||
			got.Level4ResultID == nil || *got.Level4ResultID != resultID ||
			got.Level3ProofID == nil || string(got.Level3Hash) != string(hash32("l3")) || got.Level1At == nil {
			t.Fatalf("%s read back as %+v", name, got)
		}
	}
	incomplete, err = repo.GetIncompleteProofCycles(ctx, 1000)
	if err != nil || containsCompletion(incomplete, completion.CompletionID) {
		t.Fatalf("a completed cycle is still listed as incomplete: %v", err)
	}
	if missing, err := repo.GetProofCycleCompletionByProof(ctx, uuid.New()); err != nil || missing != nil {
		t.Fatalf("missing completion = %+v, %v", missing, err)
	}
}

func containsCompletion(list []ProofCycleCompletionRecord, id uuid.UUID) bool {
	for _, c := range list {
		if c.CompletionID == id {
			return true
		}
	}
	return false
}

func TestCertenAnchorProofRoundTrip(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	client := NewClientFromDB(testDB)
	proofs := NewProofRepository(client)
	artifact := newTestArtifact(t, ctx)
	batchID := uuid.New()
	if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_batches (id) VALUES ($1)`, batchID); err != nil {
		t.Fatalf("create batch: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM certen_anchor_proofs WHERE proof_artifact_id = $1`, artifact.ProofID)
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_records WHERE batch_id = $1`, batchID)
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	anchorTx := "0x" + uuid.NewString()
	input := &NewCertenAnchorProof{
		ProofArtifactID: artifact.ProofID, BatchID: batchID, TransactionID: 7,
		AccumTxHash: artifact.AccumTxHash, AccountURL: artifact.AccountURL,
		MerkleRoot: hash32("root"), LeafHash: hash32("leaf"), LeafIndex: 2,
		MerkleInclusion: []MerklePathNode{{Hash: "0xabc", Position: "right"}},
		AnchorChain:     TargetChain("base-sepolia"), AnchorTxHash: anchorTx, AnchorBlockNumber: 42,
		AccumStateProof: json.RawMessage(`{"layers":3}`), AccumBlockHeight: 99, AccumBVN: "bvn1",
		GovProof: json.RawMessage(`{"level":"G1"}`), GovLevel: GovLevelG1, GovValid: true, ValidatorID: "v1",
	}
	proof, err := proofs.CreateProof(ctx, input)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	if !proof.VerifyProofHash() || len(proof.FullProof) == 0 || len(proof.AnchorRef) == 0 {
		t.Fatalf("proof hash does not cover the stored proof: %+v", proof)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(proof.FullProof, &document); err != nil {
		t.Fatalf("full proof is not JSON: %v", err)
	}
	for _, component := range []string{"transaction_inclusion", "anchor_reference", "state_proof", "authority_proof"} {
		if len(document[component]) == 0 || string(document[component]) == "null" {
			t.Fatalf("full proof lacks %s: %s", component, proof.FullProof)
		}
	}
	again, err := proofs.CreateProof(ctx, input)
	if err != nil || again.ProofID != proof.ProofID || string(again.ProofHash) != string(proof.ProofHash) {
		t.Fatalf("creating the same artifact's proof again changed it: %+v, %v", again, err)
	}

	for name, get := range map[string]func() (*CertenAnchorProof, error){
		"GetProof":              func() (*CertenAnchorProof, error) { return proofs.GetProof(ctx, proof.ProofID) },
		"GetProofByArtifactID":  func() (*CertenAnchorProof, error) { return proofs.GetProofByArtifactID(ctx, artifact.ProofID) },
		"GetProofByAccumTxHash": func() (*CertenAnchorProof, error) { return proofs.GetProofByAccumTxHash(ctx, artifact.AccumTxHash) },
	} {
		got, err := get()
		if err != nil || got.ProofID != proof.ProofID || !got.VerifyProofHash() {
			t.Fatalf("%s = %+v, %v", name, got, err)
		}
	}
	for name, list := range map[string]func() ([]*CertenAnchorProof, error){
		"GetProofsByBatchID":      func() ([]*CertenAnchorProof, error) { return proofs.GetProofsByBatchID(ctx, batchID) },
		"GetProofsByAnchorTxHash": func() ([]*CertenAnchorProof, error) { return proofs.GetProofsByAnchorTxHash(ctx, anchorTx) },
		"GetProofsByAccountURL": func() ([]*CertenAnchorProof, error) {
			return proofs.GetProofsByAccountURL(ctx, artifact.AccountURL, 1000)
		},
		"GetUnverifiedProofs": func() ([]*CertenAnchorProof, error) { return proofs.GetUnverifiedProofs(ctx, 100000) },
		"GetRecentProofs":     func() ([]*CertenAnchorProof, error) { return proofs.GetRecentProofs(ctx, 100000) },
	} {
		got, err := list()
		if err != nil || !containsProof(got, proof.ProofID) {
			t.Fatalf("%s did not return the proof: %v", name, err)
		}
	}

	if err := proofs.UpdateAnchorConfirmations(ctx, proof.ProofID, 6, "0xblock"); err != nil {
		t.Fatalf("UpdateAnchorConfirmations: %v", err)
	}
	if err := proofs.UpdateAnchorConfirmations(ctx, proof.ProofID, 3, "0xblock"); err != nil {
		t.Fatalf("UpdateAnchorConfirmations (fewer): %v", err)
	}
	if err := proofs.UpdateAnchorConfirmations(ctx, proof.ProofID, 12, "0xotherblock"); !errors.Is(err, ErrAnchorBlockMismatch) {
		t.Fatalf("a different anchor block was accepted: %v", err)
	}
	if err := proofs.UpdateValidatorSignature(ctx, proof.ProofID, hash32("sig")); err != nil {
		t.Fatalf("UpdateValidatorSignature: %v", err)
	}
	anchorID := uuid.New()
	if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_records (anchor_id, batch_id, target_chain, anchor_tx_hash, anchor_block_number) VALUES ($1, $2, 'ethereum', $3, 42)`, anchorID, batchID, anchorTx); err != nil {
		t.Fatalf("create anchor record: %v", err)
	}
	if err := proofs.UpdateAnchorID(ctx, proof.ProofID, anchorID); err != nil {
		t.Fatalf("UpdateAnchorID: %v", err)
	}
	if err := proofs.UpdateBatchID(ctx, proof.ProofID, batchID); err != nil {
		t.Fatalf("UpdateBatchID: %v", err)
	}
	if got, err := proofs.GetProofsByAnchorID(ctx, anchorID); err != nil || !containsProof(got, proof.ProofID) {
		t.Fatalf("GetProofsByAnchorID: %v", err)
	}
	if err := proofs.UpdateVerification(ctx, proof.ProofID, true, json.RawMessage(`{"checked":"all"}`)); err != nil {
		t.Fatalf("UpdateVerification: %v", err)
	}
	got, err := proofs.GetProof(ctx, proof.ProofID)
	if err != nil || !got.Verified || !got.VerificationTime.Valid || got.AnchorConfirms != 6 ||
		got.AnchorBlockHash.String != "0xblock" || len(got.ValidatorSig) == 0 || !got.AnchorID.Valid || !got.VerifyProofHash() {
		t.Fatalf("updates read back as %+v, %v", got, err)
	}
	if verified, err := proofs.GetVerifiedProofs(ctx, GovLevelG1, 100000); err != nil || !containsProof(verified, proof.ProofID) {
		t.Fatalf("GetVerifiedProofs(G1): %v", err)
	}
	if verified, err := proofs.GetVerifiedProofs(ctx, "", 100000); err != nil || !containsProof(verified, proof.ProofID) {
		t.Fatalf("GetVerifiedProofs(any): %v", err)
	}
	total, err := proofs.CountProofs(ctx)
	if err != nil || total < 1 {
		t.Fatalf("CountProofs = %d, %v", total, err)
	}
	verifiedCount, err := proofs.CountVerifiedProofs(ctx)
	if err != nil || verifiedCount < 1 || verifiedCount > total {
		t.Fatalf("CountVerifiedProofs = %d of %d, %v", verifiedCount, total, err)
	}
	if _, err := proofs.GetProof(ctx, uuid.New()); !errors.Is(err, ErrProofNotFound) {
		t.Fatalf("missing proof error = %v", err)
	}
	if err := proofs.UpdateVerification(ctx, uuid.New(), true, nil); !errors.Is(err, ErrProofNotFound) {
		t.Fatalf("updating a missing proof = %v", err)
	}
	if _, err := proofs.CreateProof(ctx, &NewCertenAnchorProof{AccumTxHash: "x", AccountURL: "acc://x"}); err == nil {
		t.Fatal("a proof without merkle root or anchor was created")
	}
}

func containsProof(list []*CertenAnchorProof, id uuid.UUID) bool {
	for _, p := range list {
		if p.ProofID == id {
			return true
		}
	}
	return false
}

func TestProofRequestLifecycle(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	requests := NewRequestRepository(NewClientFromDB(testDB))
	artifact := newTestArtifact(t, ctx)
	requester := "requester-" + uuid.NewString()
	var created []uuid.UUID
	t.Cleanup(func() {
		for _, id := range created {
			_, _ = testDB.ExecContext(context.Background(), `DELETE FROM proof_requests WHERE request_id = $1`, id)
		}
	})
	newRequest := func(class RequestType, priority RequestPriority) *ProofRequest {
		t.Helper()
		request, err := requests.CreateRequest(ctx, &NewProofRequest{
			AccumTxHash: artifact.AccumTxHash, AccountURL: artifact.AccountURL, RequestType: class,
			GovernanceLevel: GovLevelG1, Priority: priority, RequesterID: requester, CallbackURL: "https://example.invalid/cb",
		})
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		created = append(created, request.RequestID)
		return request
	}
	low := newRequest(RequestTypeOnCadence, PriorityLow)
	urgent := newRequest(RequestTypeOnDemand, PriorityUrgent)
	defaulted := newRequest(RequestTypeOnDemand, "")
	if defaulted.Priority != PriorityHigh || urgent.Status != RequestStatusPending || !urgent.CallbackURL.Valid || !urgent.GovernanceLevel.Valid {
		t.Fatalf("requests created as %+v / %+v", defaulted, urgent)
	}

	pending, err := requests.GetPendingRequests(ctx, 100000)
	if err != nil {
		t.Fatalf("GetPendingRequests: %v", err)
	}
	if indexOfRequest(pending, urgent.RequestID) > indexOfRequest(pending, low.RequestID) {
		t.Fatal("an urgent request is queued behind a low-priority one")
	}
	if onDemand, err := requests.GetPendingOnDemandRequests(ctx, 100000); err != nil || indexOfRequest(onDemand, urgent.RequestID) < 0 || indexOfRequest(onDemand, low.RequestID) >= 0 {
		t.Fatalf("GetPendingOnDemandRequests: %v", err)
	}
	if onCadence, err := requests.GetPendingOnCadenceRequests(ctx, 100000); err != nil || indexOfRequest(onCadence, low.RequestID) < 0 {
		t.Fatalf("GetPendingOnCadenceRequests: %v", err)
	}
	if count, err := requests.CountPendingByType(ctx, RequestTypeOnDemand); err != nil || count < 2 {
		t.Fatalf("CountPendingByType = %d, %v", count, err)
	}

	if err := requests.MarkProcessing(ctx, urgent.RequestID); err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	if err := requests.MarkProcessing(ctx, urgent.RequestID); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("a request was claimed twice: %v", err)
	}
	if processing, err := requests.GetProcessingRequests(ctx, 100000); err != nil || indexOfRequest(processing, urgent.RequestID) < 0 {
		t.Fatalf("GetProcessingRequests: %v", err)
	}
	batchID := uuid.New()
	if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_batches (id) VALUES ($1)`, batchID); err != nil {
		t.Fatalf("create batch: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	if err := requests.MarkBatched(ctx, urgent.RequestID, batchID); err != nil {
		t.Fatalf("MarkBatched: %v", err)
	}
	if byBatch, err := requests.GetRequestsByBatch(ctx, batchID); err != nil || len(byBatch) != 1 || byBatch[0].Status != RequestStatusBatched {
		t.Fatalf("GetRequestsByBatch: %+v, %v", byBatch, err)
	}
	if err := requests.MarkCompleted(ctx, urgent.RequestID, artifact.ProofID); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	done, err := requests.GetRequest(ctx, urgent.RequestID)
	if err != nil || done.Status != RequestStatusCompleted || done.ProofID.UUID != artifact.ProofID || !done.CompletedAt.Valid || !done.ProcessedAt.Valid {
		t.Fatalf("completed request read back as %+v, %v", done, err)
	}
	if err := requests.MarkFailed(ctx, urgent.RequestID, "too late"); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("a completed request was failed: %v", err)
	}

	if err := requests.MarkFailed(ctx, low.RequestID, "no proof yet"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if retry, err := requests.GetFailedRequestsForRetry(ctx, 3, 100000); err != nil || indexOfRequest(retry, low.RequestID) < 0 {
		t.Fatalf("GetFailedRequestsForRetry: %v", err)
	}
	if err := requests.ResetToRetry(ctx, low.RequestID); err != nil {
		t.Fatalf("ResetToRetry: %v", err)
	}
	retried, err := requests.GetRequest(ctx, low.RequestID)
	if err != nil || retried.Status != RequestStatusPending || retried.RetryCount != 1 || retried.ErrorMessage.Valid {
		t.Fatalf("retried request read back as %+v, %v", retried, err)
	}
	if err := requests.UpdateRequestStatus(ctx, defaulted.RequestID, RequestStatusCancelled, "withdrawn"); err != nil {
		t.Fatalf("UpdateRequestStatus: %v", err)
	}
	if err := requests.UpdateRequestStatus(ctx, defaulted.RequestID, RequestStatusCancelled, ""); err != nil {
		t.Fatalf("UpdateRequestStatus without message: %v", err)
	}
	if byTx, err := requests.GetRequestByAccumTxHash(ctx, artifact.AccumTxHash); err != nil || byTx == nil {
		t.Fatalf("GetRequestByAccumTxHash: %v", err)
	}
	if mine, err := requests.GetRequestsByRequester(ctx, requester, 10); err != nil || len(mine) != 3 {
		t.Fatalf("GetRequestsByRequester = %d, %v", len(mine), err)
	}
	if recent, err := requests.GetRecentRequests(ctx, 100000); err != nil || indexOfRequest(recent, low.RequestID) < 0 {
		t.Fatalf("GetRecentRequests: %v", err)
	}
	for _, count := range []func() (int64, error){
		func() (int64, error) { return requests.CountPendingRequests(ctx) },
		func() (int64, error) { return requests.CountByStatus(ctx, RequestStatusCompleted) },
	} {
		if n, err := count(); err != nil || n < 1 {
			t.Fatalf("request count = %d, %v", n, err)
		}
	}
	if _, err := requests.GetRequest(ctx, uuid.New()); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("missing request error = %v", err)
	}
	if _, err := requests.CreateRequest(ctx, &NewProofRequest{RequestType: RequestTypeOnDemand}); err == nil {
		t.Fatal("a request with no target was created")
	}
}

func indexOfRequest(list []*ProofRequest, id uuid.UUID) int {
	for i, r := range list {
		if r.RequestID == id {
			return i
		}
	}
	return -1
}

// A member written by the canonical anchor path has no chained or governance proof yet; the readers must
// still return it, with its intent.
func TestBatchTransactionsWithoutProofsAreReadable(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	batchID := uuid.New()
	if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_batches (id) VALUES ($1)`, batchID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	accumTx, intentID := "bare-"+uuid.NewString(), "intent-"+uuid.NewString()
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, chained_proof_valid, governance_valid)
		VALUES ($1, $2, 'acc://bare.acme', 0, $3, NULL, NULL)`, batchID, accumTx, intentID); err != nil {
		t.Fatal(err)
	}
	batches := NewBatchRepository(NewClientFromDB(testDB))
	byHash, err := batches.GetTransactionByAccumHash(ctx, accumTx)
	if err != nil || byHash.IntentID.String != intentID || byHash.ChainedProof != nil || byHash.GovValid {
		t.Fatalf("GetTransactionByAccumHash = %+v, %v", byHash, err)
	}
	inBatch, err := batches.GetTransactionsInBatch(ctx, batchID)
	if err != nil || len(inBatch) != 1 || inBatch[0].IntentID.String != intentID {
		t.Fatalf("GetTransactionsInBatch = %+v, %v", inBatch, err)
	}
	byID, err := batches.GetTransaction(ctx, byHash.ID)
	if err != nil || byID.AccumTxHash != accumTx {
		t.Fatalf("GetTransaction = %+v, %v", byID, err)
	}
}
