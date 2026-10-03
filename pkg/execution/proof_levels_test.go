package execution

// The proof records the orchestrators write, driven against the shared schema: the validator set a cycle
// counts, the four proof levels, the Certen anchor proof, completion, and the result hash chain.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/strategy"
)

func levelHash(label string) [32]byte { return sha256.Sum256([]byte(label)) }

func levelBytes(label string) []byte {
	h := levelHash(label)
	return h[:]
}

// canonicalSingleLeafAnchor writes the canonical anchor row for an intent that settled alone: a one-member
// tree whose root is its leaf, published by anchorTx - a V8.2 anchor whose batch operation id commits the member's
// operation (the leaf's value here) and its governance, as the batch path records them (RB4-F66, RB5).
func canonicalSingleLeafAnchor(t *testing.T, db *sql.DB, intentID, accumTx string, leaf [32]byte, anchorTx string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	batchID := uuid.New()
	operation := "0x" + hex.EncodeToString(leaf[:])
	rec := &database.AnchorQuorumRecord{ChainID: 84532, Root: leaf[:], BatchOperationID: testBatchOperationID(operation)}
	asV8_2Anchor(t, rec, 1, 7_000_000)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, chain_id, bundle_id, anchor_create_tx, anchor_tx_hash, anchor_block_num, verify_block, quorum_reached,
			batch_operation_id, batch_operation_id_version, message_hash, anchor_version, batch_leaf_count, accumulate_block_height,
			certen_validator_set_root, accumulate_set_root, accumulate_incarnation)
		VALUES ($1, 'on_demand', 'confirmed', $2, 'evm-84532', 84532, $3, $4, $4, 4231, 4242, TRUE,
			$5, 'v2', $6, $7, $8, $9, $10, $11, $12)`,
		batchID, leaf[:], rec.BundleID, anchorTx,
		rec.BatchOperationID, rec.MessageHash, rec.AnchorVersion, rec.BatchLeafCount, rec.AccumulateBlockHeight,
		rec.CertenSetRoot, rec.AccumulateSetRoot, rec.AccumulateIncarnation); err != nil {
		t.Fatalf("canonical anchor row: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash, intent_id, merkle_path,
			operation_id, governance_commitment)
		VALUES ($1, $2, 'acc://levels.acme/tokens', 0, $3, $4, '[]', $5, $6)`, batchID, accumTx, leaf[:], intentID,
		operation, "0x"+hex.EncodeToString(testGov[:])); err != nil {
		t.Fatalf("canonical member row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	return batchID
}

type levelFixture struct {
	db         *sql.DB
	repos      *database.Repositories
	orch       *UnifiedOrchestrator
	publicKey  ed25519.PublicKey
	cycle      *activeCycle
	artifact   *database.ProofArtifact
	inputs     proofLevelInputs
	batchID    uuid.UUID
	anchorTx   string
	root       [32]byte
	govRoot    [32]byte
	chainedRaw json.RawMessage
	execID     uuid.UUID
}

func newLevelFixture(t *testing.T) *levelFixture {
	t.Helper()
	ctx := context.Background()
	db := openMigratedTestDB(t, "proof levels")
	repos := database.NewRepositories(database.NewClientFromDB(db))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &levelFixture{db: db, repos: repos, publicKey: publicKey}
	f.orch = &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{
		ValidatorID: "levels-validator", Repos: repos, UnifiedRepo: repos.Unified,
		Ed25519Key: privateKey,
	}}

	intentID := "levels-intent-" + uuid.NewString()
	accumTx := hex.EncodeToString(levelBytes("accum-" + intentID))
	f.root = levelHash("leaf-" + intentID) // a one-member tree: the root is the leaf
	f.anchorTx = "0x" + hex.EncodeToString(levelBytes("anchor-create-"+intentID))
	f.batchID = canonicalSingleLeafAnchor(t, db, intentID, accumTx, f.root, f.anchorTx)
	f.govRoot = levelHash("gov-root-" + intentID)

	f.artifact, err = repos.ProofArtifacts.CreateProofArtifact(ctx, &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: accumTx, AccountURL: "acc://levels.acme/tokens",
		ProofClass: database.ProofClassOnDemand, ValidatorID: "levels-validator",
		ArtifactJSON: json.RawMessage(`{"levels":true}`), IntentID: &intentID,
	})
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, f.artifact.ProofID)
	})

	settlementTx := "0x" + hex.EncodeToString(levelBytes("settlement-"+intentID))
	resultHash := levelHash("result-" + intentID)
	blockNumber := int64(5000)
	f.execID, err = repos.Unified.CreateChainExecutionResult(ctx, &database.NewChainExecutionResult{
		CycleID: "cycle-" + intentID, ChainPlatform: database.ChainPlatformEVM, ChainID: "84532",
		TxHash: settlementTx, BlockNumber: &blockNumber, BlockHash: "0xblock", Status: database.ExecutionStatus(1),
		IsFinalized: true, ResultHash: resultHash[:], ObserverValidatorID: "levels-validator",
	})
	if err != nil {
		t.Fatalf("chain execution row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM chain_execution_results WHERE result_id = $1`, f.execID)
	})

	// What the cycle's validators sign besides the result: the intent's operation commitment (RB3-F106).
	message := &attestation.AttestationMessage{IntentID: intentID, ResultHash: resultHash, OperationCommitment: f.root}
	messageHash := levelHash("signed-message-" + intentID)
	f.cycle = &activeCycle{
		CycleID: "cycle-" + intentID,
		Request: &UnifiedProofCycleRequest{IntentID: intentID, AccumulateTxHash: accumTx, OperationCommitment: f.root, GovernanceRoot: f.govRoot},
		Result: &UnifiedProofCycleResult{
			ChainID: "84532", ThresholdMet: true,
			ObservationResults: []*chain.ObservationResult{{
				TxHash: settlementTx, BlockNumber: uint64(blockNumber), BlockHash: "0xblock", ChainName: "base-sepolia",
				ChainIDNumeric: 84532, IsFinalized: true, Confirmations: 12, ResultHash: resultHash,
			}},
			ChainExecutionIDs: []uuid.UUID{f.execID},
			Attestations: []*attestation.Attestation{
				{ValidatorID: "levels-validator", Message: message, MessageHash: messageHash},
				{ValidatorID: "peer-2", Message: message, MessageHash: messageHash},
			},
		},
	}
	f.chainedRaw = json.RawMessage(`{"layer1":"bvn","layer2":"dn","layer3":"consensus"}`)
	f.inputs = proofLevelInputs{
		Artifact: f.artifact, IntentID: intentID, AccumTxHash: accumTx, AccountURL: "acc://levels.acme/tokens",
		MerkleRoot: f.root[:], LeafHash: f.root[:], ChainedProof: f.chainedRaw,
		GovCommitment: f.govRoot[:], GovLevel: database.GovLevelG1, GovProof: json.RawMessage(`{"level":"G1"}`), GovValid: true,
	}
	return f
}

func (f *levelFixture) record(t *testing.T) {
	t.Helper()
	anchor, batch := f.orch.resolveAnchorBinding(context.Background(), f.artifact.ProofID, f.placement(t), f.cycle.Result)
	if anchor == nil || batch == nil {
		t.Fatal("the canonical single-leaf anchor did not resolve")
	}
	f.orch.recordProofLevels(context.Background(), f.cycle, f.inputs, anchor, batch)
}

func TestUnifiedProofLevelsRecordAllFourAndComplete(t *testing.T) {
	f := newLevelFixture(t)
	ctx := context.Background()
	f.record(t)
	if len(f.cycle.Completions) != 1 {
		t.Fatalf("cycle has %d level records, want 1", len(f.cycle.Completions))
	}
	record, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
	if err != nil || record == nil {
		t.Fatalf("level record: %+v, %v", record, err)
	}
	chainedSum := sha256.Sum256(f.chainedRaw)
	resultHash := f.cycle.Result.ObservationResults[0].ResultHash
	for name, check := range map[string]bool{
		"level 1 is the chained proof hash": record.Level1Complete && string(record.Level1Hash) == string(chainedSum[:]),
		"level 2 is the governance root":    record.Level2Complete && string(record.Level2Hash) == string(f.govRoot[:]),
		"level 3 is the anchored root":      record.Level3Complete && string(record.Level3Hash) == string(f.root[:]),
		"level 4 is the observed result":    record.Level4Complete && string(record.Level4Hash) == string(resultHash[:]),
		"level 4 points at its row":         record.Level4ResultID != nil && *record.Level4ResultID == f.execID,
		"not complete before write-back":    !record.AllLevelsComplete,
		"the cycle id is recorded":          record.CycleID != nil && *record.CycleID == f.cycle.CycleID,
	} {
		if !check {
			t.Errorf("%s: %+v", name, record)
		}
	}

	certen, err := f.repos.Proofs.GetProofByArtifactID(ctx, f.artifact.ProofID)
	if err != nil {
		t.Fatalf("certen proof: %v", err)
	}
	if certen.AnchorTxHash != f.anchorTx {
		t.Errorf("the Certen proof names %s as its anchor, not the anchor-create transaction %s", certen.AnchorTxHash, f.anchorTx)
	}
	if !certen.BatchID.Valid || certen.BatchID.UUID != f.batchID {
		t.Errorf("the Certen proof is not linked to the canonical batch: %+v", certen.BatchID)
	}
	if !certen.Verified || !certen.VerifyProofHash() || string(certen.MerkleRoot) != string(f.root[:]) {
		t.Errorf("the Certen proof is not verified against its root: %+v", certen)
	}
	if !ed25519.Verify(f.publicKey, certen.ProofHash, certen.ValidatorSig) {
		t.Error("the validator signature does not verify over the proof hash")
	}

	f.orch.completeProofCycles(ctx, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root, "writeback-tx")
	done, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
	if err != nil || done == nil || !done.AllLevelsComplete || !done.BindingsValid || done.CompletedAt == nil {
		t.Fatalf("cycle not completed with valid bindings: %+v, %v", done, err)
	}
	if string(done.CycleHash) != string(proofCycleHash(record, "writeback-tx")) {
		t.Error("the cycle hash does not bind the four levels and the write-back")
	}
}

// anchorChain observes one anchor transaction; the cycle uses no other strategy method here.
type anchorChain struct {
	chain.ChainExecutionStrategy
	obs   *chain.ObservationResult
	calls int
}

func (c *anchorChain) ObserveTransaction(_ context.Context, txHash string) (*chain.ObservationResult, error) {
	c.calls++
	if !strings.EqualFold(txHash, c.obs.TxHash) {
		return nil, fmt.Errorf("transaction %s not found", txHash)
	}
	return c.obs, nil
}

// layer5Of writes the proof's layer-5 row as the cycle does and reads it back.
func layer5Of(t *testing.T, f *levelFixture) Layer5 {
	t.Helper()
	l5, binding := f.orch.resolveAnchorBinding(context.Background(), f.artifact.ProofID, f.placement(t), f.cycle.Result)
	if err := WriteLayer5Row(context.Background(), f.repos.ProofArtifacts, f.artifact.ProofID, l5, binding, t.Logf); err != nil {
		t.Fatalf("write layer 5: %v", err)
	}
	layers, err := f.repos.ProofArtifacts.GetChainedProofLayers(context.Background(), f.artifact.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	for _, layer := range layers {
		if layer.LayerName == Layer5RowName {
			var l5 Layer5
			if err := json.Unmarshal(layer.LayerJSON, &l5); err != nil {
				t.Fatal(err)
			}
			return l5
		}
	}
	t.Fatal("no layer-5 row")
	return Layer5{}
}

// The settlement observation says nothing about the anchor: the proof states the anchor transaction's own
// block (the create receipt's, not the verify transaction's), the chain named on the canonical row, and no
// depth it did not observe. Production's observation carries no chain name.
func TestTheCertenProofStatesTheAnchorsOwnBlockAndChain(t *testing.T) {
	f := newLevelFixture(t)
	f.cycle.Result.ObservationResults[0].ChainName = ""
	f.record(t)
	certen, err := f.repos.Proofs.GetProofByArtifactID(context.Background(), f.artifact.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if certen.AnchorBlockNumber != 4231 || certen.AnchorChain != "evm-84532" {
		t.Fatalf("anchor %s @ %d on %q, want block 4231 (not the verify block 4242 or the settlement 5000) on evm-84532",
			certen.AnchorTxHash, certen.AnchorBlockNumber, certen.AnchorChain)
	}
	if certen.AnchorConfirms != 0 || certen.AnchorBlockHash.Valid {
		t.Fatalf("the settlement's depth or block hash was stated for the anchor: %d %v", certen.AnchorConfirms, certen.AnchorBlockHash)
	}
	if l5 := layer5Of(t, f); l5.AnchorTx != f.anchorTx || l5.BlockNumber != 4231 || l5.BlockHash != "" {
		t.Fatalf("layer 5 states %s @ %d (%s)", l5.AnchorTx, l5.BlockNumber, l5.BlockHash)
	}
}

// With an observer for the anchor's chain, the anchor transaction is read back: the chain's block wins over
// a recorded one that disagrees, and its block hash and depth are recorded. One read per anchor per cycle.
// The canonical row names its chain as the batch path writes it ("evm-84532") and the registry keys the
// observer by chain id, as InitializeRegistry does; the lookup used to miss, and every proof was recorded
// without its anchor's block hash or depth (RB3-F44).
func TestTheAnchorIsReadBackForItsBlockHashAndDepth(t *testing.T) {
	f := newLevelFixture(t)
	observer := &anchorChain{obs: &chain.ObservationResult{
		TxHash: f.anchorTx, BlockNumber: 4230, BlockHash: "0xanchorblock", Confirmations: 812, IsFinalized: true,
		BlockTimestamp: time.Unix(1_790_000_000, 0).UTC(),
	}}
	registry := strategy.NewRegistry()
	if err := registry.RegisterChainStrategy("84532", &chain.ChainConfig{}, observer); err != nil {
		t.Fatal(err)
	}
	f.orch.config.Registry = registry
	f.record(t)

	certen, err := f.repos.Proofs.GetProofByArtifactID(context.Background(), f.artifact.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	if certen.AnchorBlockNumber != 4230 || certen.AnchorBlockHash.String != "0xanchorblock" || certen.AnchorConfirms != 812 {
		t.Fatalf("anchor recorded @ %d (%v), depth %d; want the chain's 4230, its hash and 812",
			certen.AnchorBlockNumber, certen.AnchorBlockHash, certen.AnchorConfirms)
	}
	if l5 := layer5Of(t, f); l5.BlockNumber != 4230 || l5.BlockHash != "0xanchorblock" {
		t.Fatalf("layer 5 states block %d (%s)", l5.BlockNumber, l5.BlockHash)
	}
	again, _ := f.orch.resolveAnchorBinding(context.Background(), f.artifact.ProofID, f.placement(t), f.cycle.Result)
	// The anchor block's time, as read back, is what the proof bundle states as its anchor's anchored_at (RB5-F18).
	if again == nil || !again.BlockTime.Equal(time.Unix(1_790_000_000, 0)) {
		t.Fatalf("the anchor's read-back block time is not carried: %+v", again)
	}
	if observer.calls != 1 {
		t.Fatalf("the anchor was read %d times in one cycle", observer.calls)
	}
}

func TestUnifiedProofCycleWithAMissingLevelIsNotCompleted(t *testing.T) {
	f := newLevelFixture(t)
	f.inputs.ChainedProof = nil // the chained proof could not be generated
	f.record(t)
	f.orch.completeProofCycles(context.Background(), f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root, "writeback-tx")
	record, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(context.Background(), f.artifact.ProofID)
	if err != nil || record == nil {
		t.Fatalf("level record: %v", err)
	}
	if record.Level1Complete || record.AllLevelsComplete {
		t.Fatalf("a cycle without a chained proof was completed: %+v", record)
	}
}

func TestUnifiedProofCycleBindingsNeedTheQuorumToSignThisResultAndOperationCommitment(t *testing.T) {
	f := newLevelFixture(t)
	f.record(t)
	other := *f.cycle.Result.Attestations[1].Message
	other.OperationCommitment = levelHash("a different operation commitment")
	f.cycle.Result.Attestations[1].Message = &other
	f.orch.completeProofCycles(context.Background(), f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, f.root, "writeback-tx")
	record, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(context.Background(), f.artifact.ProofID)
	if err != nil || record == nil || !record.AllLevelsComplete {
		t.Fatalf("level record: %+v, %v", record, err)
	}
	if record.BindingsValid {
		t.Fatal("bindings were accepted though one attestation signed a different root")
	}
}

// RB5-F18 (survey §5 item 10): bindings_valid said the quorum signed "this cycle's level-4 result and level-3 root",
// but the quorum's message names the operation, not the root, and nothing tied the root to that operation: a quorum
// over another operation, whose level 3 commits a different one, was bound. Level 3 must now commit the operation the
// quorum signed - proven from layer 5 - or the record is not bound.
func TestUnifiedProofCycleBindingsNeedLevel3ToCommitTheSignedOperation(t *testing.T) {
	ctx := context.Background()
	complete := func(t *testing.T, f *levelFixture, signed [32]byte) *database.ProofCycleCompletionRecord {
		t.Helper()
		f.orch.completeProofCycles(ctx, f.cycle.CycleID, f.cycle.Completions, f.cycle.Result, signed, "writeback-tx")
		record, err := f.repos.ProofArtifacts.GetProofCycleCompletionByProof(ctx, f.artifact.ProofID)
		if err != nil || record == nil || !record.AllLevelsComplete {
			t.Fatalf("level record: %+v, %v", record, err)
		}
		return record
	}

	t.Run("the quorum signed another operation than level 3 commits", func(t *testing.T) {
		f := newLevelFixture(t)
		other := levelHash("an operation that is not in the anchored batch")
		f.cycle.Request.OperationCommitment = other
		message := *f.cycle.Result.Attestations[0].Message
		message.OperationCommitment = other
		for _, att := range f.cycle.Result.Attestations {
			att.Message = &message
		}
		f.record(t)
		if complete(t, f, other).BindingsValid {
			t.Fatal("bindings were accepted though the level-3 root commits another operation than the quorum signed")
		}
	})

	t.Run("level 3 states no members of its batch", func(t *testing.T) {
		f := newLevelFixture(t)
		if _, err := f.db.ExecContext(ctx, `UPDATE anchor_batches SET batch_operation_id_version = NULL WHERE id = $1`, f.batchID); err != nil {
			t.Fatal(err)
		}
		f.record(t)
		if complete(t, f, f.root).BindingsValid {
			t.Fatal("bindings were accepted though no operation is proven under the level-3 root")
		}
	})

	t.Run("level 3 commits the signed operation", func(t *testing.T) {
		f := newLevelFixture(t)
		f.record(t)
		if !complete(t, f, f.root).BindingsValid {
			t.Fatal("a level-3 root that commits the signed operation was not bound")
		}
	})
}

func TestLevelsBoundByAttestations(t *testing.T) {
	root, result := levelHash("root"), levelHash("result")
	message := &attestation.AttestationMessage{ResultHash: result, OperationCommitment: root}
	make := func(threshold bool, atts ...*attestation.Attestation) *UnifiedProofCycleResult {
		return &UnifiedProofCycleResult{ThresholdMet: threshold, Attestations: atts,
			ObservationResults: []*chain.ObservationResult{{ResultHash: result}}}
	}
	signed := func(m *attestation.AttestationMessage, hash string) *attestation.Attestation {
		return &attestation.Attestation{Message: m, MessageHash: levelHash(hash)}
	}
	cases := map[string]struct {
		result *UnifiedProofCycleResult
		want   bool
	}{
		"quorum over this result and root": {make(true, signed(message, "m"), signed(message, "m")), true},
		"below threshold":                  {make(false, signed(message, "m")), false},
		"no attestations":                  {make(true), false},
		"a different result":               {make(true, signed(&attestation.AttestationMessage{ResultHash: levelHash("x"), OperationCommitment: root}, "m")), false},
		"a different operation commitment": {make(true, signed(&attestation.AttestationMessage{ResultHash: result, OperationCommitment: levelHash("x")}, "m")), false},
		"no message":                       {make(true, &attestation.Attestation{}), false},
		"different signed messages":        {make(true, signed(message, "m"), signed(message, "n")), false},
	}
	for name, tc := range cases {
		if got := levelsBoundByAttestations(tc.result, root); got != tc.want {
			t.Errorf("%s: bound = %v, want %v", name, got, tc.want)
		}
	}
}

func TestRegistryAttestationSetIsTheSameOnEveryValidator(t *testing.T) {
	threshold := attestation.DefaultThresholdConfig().CalculateThresholdWeight
	_, reg := rb3Validators(t, 3)
	a, err := registryAttestationSet(reg, threshold, 99)
	if err != nil {
		t.Fatal(err)
	}
	// The set is the registry's, so every validator - whoever it is - derives the same snapshot.
	b, err := registryAttestationSet(reg, threshold, 99)
	if err != nil {
		t.Fatal(err)
	}
	if a.SnapshotID != b.SnapshotID || a.ValidatorRoot != b.ValidatorRoot {
		t.Fatal("two validators of one set derived different snapshots")
	}
	if a.TotalWeight.Int64() != 3 || a.ThresholdWeight.Int64() != threshold(3) {
		t.Fatalf("weights %s/%s", a.ThresholdWeight, a.TotalWeight)
	}
	for _, v := range a.Validators {
		if len(v.PublicKey) == 0 || v.Weight.Int64() != 1 {
			t.Fatalf("member %s recorded without its registered key or power", v.ValidatorID)
		}
	}
	smaller := map[string]consensus.ValidatorRegistryEntry{}
	for k, v := range reg {
		smaller[k] = v
		break
	}
	c, err := registryAttestationSet(smaller, threshold, 99)
	if err != nil {
		t.Fatal(err)
	}
	if c.SnapshotID == a.SnapshotID {
		t.Fatal("a smaller set produced the same snapshot")
	}

	db := openMigratedTestDB(t, "validator set snapshots")
	repo := database.NewProofArtifactRepository(db)
	first, err := persistValidatorSetSnapshot(context.Background(), repo, a, "84532", "base-sepolia")
	if err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM validator_set_snapshots WHERE snapshot_id = $1`, *first)
	})
	second, err := persistValidatorSetSnapshot(context.Background(), repo, b, "84532", "base-sepolia")
	if err != nil || *second != *first {
		t.Fatalf("the same set was stored twice: %v %v", second, err)
	}
	stored, err := repo.GetValidatorSetSnapshotByID(context.Background(), *first)
	if err != nil || stored == nil || stored.ValidatorCount != 3 || string(stored.SnapshotHash) != string(a.SnapshotID[:]) {
		t.Fatalf("stored snapshot = %+v, %v", stored, err)
	}
}

func TestResultHashChainIsPersistedVerifiedAndContinuedAfterRestart(t *testing.T) {
	db := openMigratedTestDB(t, "result hash chain")
	ctx := context.Background()
	unified := database.NewUnifiedRepository(db)
	validator := "hash-chain-" + uuid.NewString()
	// Each result binds its own member's anchored root (RB3-F106); these three share one.
	anchorProof := levelHash("anchor-proof-" + validator)
	chainState := NewResultHashChain("84532")

	var ids []uuid.UUID
	var linked []*ExternalChainResult
	for i := 0; i < 3; i++ {
		id, err := unified.CreateChainExecutionResult(ctx, &database.NewChainExecutionResult{
			CycleID: validator, ChainPlatform: database.ChainPlatformEVM, ChainID: "84532",
			TxHash: "0x" + hex.EncodeToString(levelBytes(validator+string(rune('a'+i)))), Status: database.ExecutionStatus(1),
			IsFinalized: true, ObserverValidatorID: validator,
		})
		if err != nil {
			t.Fatalf("chain execution row %d: %v", i, err)
		}
		ids = append(ids, id)
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM chain_execution_results WHERE result_id = $1`, id)
		})
		ext := &ExternalChainResult{Chain: "base-sepolia", ChainID: 84532, TxHash: common.BytesToHash(levelBytes(validator + string(rune('a'+i)))),
			BlockNumber: big.NewInt(int64(100 + i)), Status: 1, FinalizedAt: time.Unix(int64(1700000000+i), 0).UTC()}
		if err := chainState.AddResult(ext, anchorProof); err != nil {
			t.Fatal(err)
		}
		if err := persistResultHashChainLink(ctx, unified, []uuid.UUID{id}, 1, ext); err != nil {
			t.Fatalf("persist link %d: %v", i, err)
		}
		linked = append(linked, ext)
	}
	if n, err := unified.VerifyChainExecutionHashChain(ctx, validator, "84532"); err != nil || n != 3 {
		t.Fatalf("persisted chain verified %d links, %v", n, err)
	}

	restarted := map[string]*ResultHashChain{}
	if n, err := seedResultHashChains(ctx, unified, validator, restarted); err != nil || n != 1 {
		t.Fatalf("seeded %d chains, %v", n, err)
	}
	continued := restarted["84532"]
	if continued == nil || continued.LatestSequence != 3 || continued.LatestHash != linked[2].ResultHash {
		t.Fatalf("a restarted validator would not continue the chain: %+v", continued)
	}

	if err := persistResultHashChainLink(ctx, unified, []uuid.UUID{ids[0]}, 2, linked[0]); err == nil {
		t.Fatal("a link was written though the primary row could not be identified")
	}
	if err := unified.UpdateChainExecutionHashChain(ctx, ids[2], 2, levelBytes("not the previous link"), anchorProof[:], linked[2].ResultHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := unified.VerifyChainExecutionHashChain(ctx, validator, "84532"); !errors.Is(err, database.ErrHashChainBroken) {
		t.Fatalf("a broken link verified: %v", err)
	}
}

type testLogger struct{ t *testing.T }

func (l testLogger) Printf(format string, v ...interface{}) { l.t.Logf(format, v...) }

// placement is the fixture member's canonical batch row, as the bundle writer looks it up.
func (f *levelFixture) placement(t *testing.T) *database.Layer5Binding {
	t.Helper()
	p, err := f.orch.batchPlacement(context.Background(), f.inputs.IntentID, f.inputs.AccumTxHash, 84532)
	if err != nil {
		t.Fatalf("placement: %v", err)
	}
	return p
}
