 PostgreSQL Data Population Gap Analysis & Fix Plan

 Executive Summary

 Question: Does the proof service still use PostgreSQL tables, and are all fields being populated?

 Answer:
 1. YES - The proof service reads from 14+ PostgreSQL tables via repository pattern
 2. NO - There are significant gaps in field population across multiple tables

 The Firestore sync service we just added handles real-time UI updates, but the underlying PostgreSQL data that the Proof Service API reads is incomplete.

 ---
 1. PROOF SERVICE PostgreSQL USAGE CONFIRMED

 The proofs_service reads from these PostgreSQL tables:
 ┌─────────────────────────────┬─────────────────────────┬────────────────┐
 │            Table            │       Repository        │     Status     │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ proof_artifacts             │ ProofArtifactRepository │ Primary - USED │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ chained_proof_layers        │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ governance_proof_levels     │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ anchor_batches              │ BatchRepository         │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ batch_transactions          │ BatchRepository         │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ anchor_records              │ AnchorRepository        │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ validator_attestations      │ AttestationRepository   │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ batch_attestations          │ ConsensusRepository     │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ consensus_entries           │ ConsensusRepository     │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ external_chain_results      │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ bls_result_attestations     │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ aggregated_bls_attestations │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ proof_bundles               │ ProofArtifactRepository │ USED           │
 ├─────────────────────────────┼─────────────────────────┼────────────────┤
 │ custody_chain_events        │ ProofArtifactRepository │ USED           │
 └─────────────────────────────┴─────────────────────────┴────────────────┘
 ---
 2. CRITICAL DATA POPULATION GAPS

 Gap 1: anchor_batches Phase 5 Fields NOT POPULATED

 Schema defines these fields (lines 46-54 of 001_initial_schema.sql):
 bpt_root        BYTEA,               -- NOT POPULATED
 governance_root BYTEA,               -- NOT POPULATED
 proof_data_included BOOLEAN,         -- NOT POPULATED
 attestation_count INTEGER,           -- NOT POPULATED
 aggregated_signature BYTEA,          -- NOT POPULATED
 aggregated_public_key BYTEA,         -- NOT POPULATED
 quorum_reached  BOOLEAN,             -- NOT POPULATED
 consensus_completed_at TIMESTAMPTZ   -- NOT POPULATED

 Root Cause: repository_batch.go:CloseBatch() (line 160) only updates:
 - merkle_root, status, batch_end_time, accumulate_block_height/hash

 Impact: Consensus state not visible in UI, can't verify quorum was reached.

 ---
 Gap 2: Signature Validation Fields Often NULL

 Tables affected:
 - validator_attestations.signature_valid → Often NULL
 - validator_attestations.verified_at → Often NULL
 - batch_attestations.signature_valid → Often NULL
 - bls_result_attestations.signature_valid → Often NULL

 Root Cause: Signatures are verified for consensus decisions but verification results aren't persisted back to the database.

 Impact: Can't audit which signatures were validated.

 ---
 Gap 3: proof_artifacts Missing Intent Tracking

 Current schema has no:
 - user_id column
 - intent_id column

 Root Cause: Schema was designed before Firestore integration.

 Impact: Cannot link PostgreSQL proofs back to Firestore intents for the UI.

 ---
 Gap 4: Proofs Stuck at Level 1-2

 proof_artifacts.status progression:
 - Most proofs stay at pending or batched
 - Few reach anchored, attested, verified

 Related: proof_cycle_completions (if it existed):
 - level1_complete → Sometimes populated
 - level2_complete → Rarely populated
 - level3_complete → Almost never
 - level4_complete → Almost never

 Root Cause: No orchestrator updates proof status after each phase completion.

 ---
 Gap 5: external_chain_results.is_finalized Stuck at FALSE

 Current behavior:
 - Records created with is_finalized = FALSE
 - finalized_at stays NULL

 Root Cause: Confirmation tracking doesn't trigger finalization updates.

 ---
 Gap 6: aggregated_bls_attestations.finalized_at NULL

 Current behavior:
 - Aggregations created but never marked finalized
 - aggregate_verified often NULL

 Root Cause: BLS verification runs but doesn't persist results.

 ---
 Gap 7: anchor_records.total_cost_usd Often NULL

 Current behavior:
 - Gas costs recorded in wei
 - USD conversion calculated asynchronously
 - Often fails or never runs

 ---
 3. IMPLEMENTATION PLAN

 Phase 1: Add UpdateBatchPhase5 Method (HIGH PRIORITY)

 File: pkg/database/repository_batch.go

 Add new method after line 225:
 // UpdateBatchPhase5 updates consensus/Phase 5 fields
 func (r *BatchRepository) UpdateBatchPhase5(ctx context.Context, batchID uuid.UUID, update *BatchPhase5Update) error {
     query := `
         UPDATE anchor_batches
         SET bpt_root = COALESCE($2, bpt_root),
             governance_root = COALESCE($3, governance_root),
             proof_data_included = $4,
             attestation_count = $5,
             aggregated_signature = COALESCE($6, aggregated_signature),
             aggregated_public_key = COALESCE($7, aggregated_public_key),
             quorum_reached = $8,
             consensus_completed_at = $9,
             updated_at = NOW()
         WHERE id = $1`

     _, err := r.client.ExecContext(ctx, query,
         batchID, update.BPTRoot, update.GovernanceRoot,
         update.ProofDataIncluded, update.AttestationCount,
         update.AggregatedSignature, update.AggregatedPublicKey,
         update.QuorumReached, update.ConsensusCompletedAt)
     return err
 }

 Call from: pkg/batch/consensus_coordinator.go after quorum is reached

 ---
 Phase 2: Add Signature Verification Persistence (MEDIUM PRIORITY)

 File: pkg/database/repository_attestation.go

 Add method:
 func (r *AttestationRepository) MarkVerified(ctx context.Context, attestationID uuid.UUID, valid bool) error {
     query := `UPDATE validator_attestations SET signature_valid = $2, verified_at = NOW() WHERE attestation_id = $1`
     _, err := r.client.ExecContext(ctx, query, attestationID, valid)
     return err
 }

 File: pkg/database/repository_consensus.go

 Add method:
 func (r *ConsensusRepository) MarkBatchAttestationVerified(ctx context.Context, attestationID uuid.UUID, valid bool) error {
     query := `UPDATE batch_attestations SET signature_valid = $2, verified_at = NOW() WHERE attestation_id = $1`
     _, err := r.client.ExecContext(ctx, query, attestationID, valid)
     return err
 }

 Call from: Wherever BLS/Ed25519 verification happens

 ---
 Phase 3: Add Intent Tracking to proof_artifacts (MEDIUM PRIORITY)

 New migration file: pkg/database/migrations/002_add_intent_tracking.sql

 -- Add intent tracking columns to proof_artifacts
 ALTER TABLE proof_artifacts ADD COLUMN user_id VARCHAR(256);
 ALTER TABLE proof_artifacts ADD COLUMN intent_id VARCHAR(256);

 CREATE INDEX idx_proof_artifacts_user ON proof_artifacts(user_id) WHERE user_id IS NOT NULL;
 CREATE INDEX idx_proof_artifacts_intent ON proof_artifacts(intent_id) WHERE intent_id IS NOT NULL;

 -- Add to batch_transactions too
 ALTER TABLE batch_transactions ADD COLUMN user_id VARCHAR(256);
 ALTER TABLE batch_transactions ADD COLUMN intent_id VARCHAR(256);

 INSERT INTO schema_migrations (version, description)
 VALUES ('002_add_intent_tracking', 'Add user_id and intent_id for Firestore linking');

 Update: pkg/database/proof_artifact_repository.go:CreateProofArtifact() to accept and store user_id/intent_id

 ---
 Phase 4: Add Proof Status Updates (MEDIUM PRIORITY)

 File: pkg/database/proof_artifact_repository.go

 Add methods:
 func (r *ProofArtifactRepository) UpdateProofStatus(ctx context.Context, proofID uuid.UUID, status ProofStatus) error
 func (r *ProofArtifactRepository) MarkProofAnchored(ctx context.Context, proofID uuid.UUID, anchorID uuid.UUID, anchorTxHash string, blockNum int64) error
 func (r *ProofArtifactRepository) MarkProofAttested(ctx context.Context, proofID uuid.UUID, attestationCount int) error
 func (r *ProofArtifactRepository) MarkProofVerified(ctx context.Context, proofID uuid.UUID) error

 Call from: Each phase of the proof cycle

 ---
 Phase 5: Add Finalization Updates (LOWER PRIORITY)

 File: pkg/database/proof_artifact_repository.go

 func (r *ProofArtifactRepository) MarkExternalChainResultFinalized(ctx context.Context, resultID uuid.UUID) error {
     query := `UPDATE external_chain_results SET is_finalized = TRUE, finalized_at = NOW() WHERE result_id = $1`
     _, err := r.db.ExecContext(ctx, query, resultID)
     return err
 }

 func (r *ProofArtifactRepository) MarkBLSAggregationFinalized(ctx context.Context, aggregationID uuid.UUID) error {
     query := `UPDATE aggregated_bls_attestations SET finalized_at = NOW() WHERE aggregation_id = $1`
     _, err := r.db.ExecContext(ctx, query, aggregationID)
     return err
 }

 ---
 4. FILES TO MODIFY
 ┌─────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────┐
 │                        File                         │                                          Changes                                          │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/repository_batch.go                    │ Add UpdateBatchPhase5() method                                                            │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/repository_attestation.go              │ Add MarkVerified() method                                                                 │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/repository_consensus.go                │ Add MarkBatchAttestationVerified(), UpdateConsensusAggregates()                           │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/proof_artifact_repository.go           │ Add status update methods, finalization methods, user_id/intent_id in CreateProofArtifact │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/types.go                               │ Add BatchPhase5Update struct                                                              │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/database/migrations/002_add_intent_tracking.sql │ NEW - schema changes                                                                      │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/batch/consensus_coordinator.go                  │ Call UpdateBatchPhase5() after quorum                                                     │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/batch/processor.go                              │ Call status update methods at each phase                                                  │
 ├─────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
 │ pkg/batch/collector.go                              │ Pass user_id/intent_id when adding transactions                                           │
 └─────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────┘
 ---
 5. VERIFICATION

 After implementation, verify with SQL:

 -- Check Phase 5 fields are populated
 SELECT id, quorum_reached, attestation_count, consensus_completed_at
 FROM anchor_batches WHERE status = 'confirmed' LIMIT 5;

 -- Check signature validation
 SELECT attestation_id, signature_valid, verified_at
 FROM validator_attestations WHERE signature_valid IS NOT NULL LIMIT 5;

 -- Check intent tracking
 SELECT proof_id, user_id, intent_id
 FROM proof_artifacts WHERE user_id IS NOT NULL LIMIT 5;

 -- Check proof status progression
 SELECT status, COUNT(*) FROM proof_artifacts GROUP BY status;

 -- Check finalization
 SELECT result_id, is_finalized, finalized_at
 FROM external_chain_results WHERE is_finalized = TRUE LIMIT 5;

 ---
 6. PRIORITY ORDER

 1. HIGH: Gap 1 (Phase 5 fields) - Critical for consensus visibility
 2. HIGH: Gap 3 (Intent tracking) - Critical for Firestore linking
 3. MEDIUM: Gap 2 (Signature validation) - Important for auditing
 4. MEDIUM: Gap 4 (Proof status) - Important for lifecycle tracking
 5. LOWER: Gap 5-7 (Finalization, costs) - Nice to have

 ---
 7. SUMMARY

 The proof service does use PostgreSQL and reads from all the expected tables. However, the validator is not fully populating all fields:

 - Phase 5 consensus fields never written
 - Signature validation results not persisted
 - No intent/user tracking for Firestore linking
 - Proof status not updated through lifecycle
 - Finalization flags not set

 These gaps need to be fixed by adding the missing repository methods and calling them from the appropriate places in the proof cycle.