package database

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// RB5 D4, migration 00020: a recorded batch outcome is stored once, with every leaf and the evidence an offline
// verifier needs; a second write must state the same record, and a contradiction is refused, never resolved.

func outcomeRepoForTest(t *testing.T) *BatchOutcomeRepository {
	t.Helper()
	if testDB == nil {
		t.Fatal("CERTEN_TEST_DB is required: this test runs against PostgreSQL (a skipped gate is not a green gate)")
	}
	return NewBatchOutcomeRepository(NewClientFromDB(testDB))
}

func word(b byte) string { return "0x" + strings.Repeat(fmt.Sprintf("%02x", b), 32) }

var zeroWord = "0x" + strings.Repeat("0", 64)

func outcomeRecordForTest(bundle string, source string) *BatchOutcomeRecord {
	rec := &BatchOutcomeRecord{
		ChainID: 84532, BundleID: bundle, Registry: "0xd479841a17770d89dae94b5b41c95d2117414c21", OutcomeRoot: word(0x0a),
		MessageHash: word(0x0b), CertenValidatorSetRoot: word(0x0c), AccumulateSetRoot: word(0x0d), AccumulateIncarnation: word(0x0e),
		LeafCount: 2, RecordTx: word(0x0f), RecordBlock: 4242, Recorder: "0x1111111111111111111111111111111111111111",
		Signers:      []string{"0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222"},
		SignerPowers: []*big.Int{big.NewInt(100), big.NewInt(100)}, SignedVotingPower: big.NewInt(200),
		TotalVotingPower: big.NewInt(300), QuorumProof: []byte{1, 2, 3}, EvidenceSource: source,
		Leaves: []BatchOutcomeLeafRow{
			{LeafIndex: 0, BatchLeaf: word(1), OperationID: word(2), Status: 1, Tx: word(3), BlockNumber: 100, BlockHash: word(4),
				ReceiptsRoot: word(5), EffectsHash: word(6), LeafHash: word(7)},
			{LeafIndex: 1, BatchLeaf: word(8), OperationID: word(9), Status: 3, Tx: zeroWord, BlockNumber: 200, BlockHash: word(0x10),
				ReceiptsRoot: word(0x11), EffectsHash: zeroWord, LeafHash: word(0x12)},
		},
	}
	if source == BatchOutcomeEvidenceRecorder {
		rec.AggregateSignature, rec.AggregatePublicKey = "0xabcd", "0xef01"
	}
	return rec
}

func TestABatchOutcomeIsStoredOnceWithEveryLeaf(t *testing.T) {
	repo := outcomeRepoForTest(t)
	ctx := context.Background()
	bundle := bundleHex(900)
	rec := outcomeRecordForTest(bundle, BatchOutcomeEvidenceRecorder)
	if err := repo.RecordBatchOutcome(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := repo.BatchOutcome(ctx, 84532, bundle)
	if err != nil || got == nil {
		t.Fatalf("(%v, %v)", got, err)
	}
	if why := sameBatchOutcome(got, rec); why != "" || got.AggregateSignature != "0xabcd" || len(got.Leaves) != 2 {
		t.Fatalf("read back differs: %s", why)
	}
	// The same record again is the same record.
	if err := repo.RecordBatchOutcome(ctx, outcomeRecordForTest(bundle, BatchOutcomeEvidenceRecorder)); err != nil {
		t.Fatalf("an identical write was refused: %v", err)
	}
	// Another root, or another leaf, for the same anchor is a contradiction.
	other := outcomeRecordForTest(bundle, BatchOutcomeEvidenceRecorder)
	other.OutcomeRoot = word(0x99)
	if err := repo.RecordBatchOutcome(ctx, other); !errors.Is(err, ErrBatchOutcomeContradiction) {
		t.Fatalf("a different root: %v", err)
	}
	other = outcomeRecordForTest(bundle, BatchOutcomeEvidenceRecorder)
	other.Leaves[1].Status = 4
	if err := repo.RecordBatchOutcome(ctx, other); !errors.Is(err, ErrBatchOutcomeContradiction) {
		t.Fatalf("a different leaf: %v", err)
	}
	if none, err := repo.BatchOutcome(ctx, 84532, bundleHex(901)); none != nil || err != nil {
		t.Fatalf("an unrecorded anchor: (%v, %v)", none, err)
	}
}

func TestARecorderCompletesARecordRebuiltFromTheChain(t *testing.T) {
	repo := outcomeRepoForTest(t)
	ctx := context.Background()
	bundle := bundleHex(902)
	if err := repo.RecordBatchOutcome(ctx, outcomeRecordForTest(bundle, BatchOutcomeEvidenceChain)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.BatchOutcome(ctx, 84532, bundle); got.AggregateSignature != "" || got.EvidenceSource != BatchOutcomeEvidenceChain {
		t.Fatalf("a chain row carries an aggregate: %+v", got)
	}
	if err := repo.RecordBatchOutcome(ctx, outcomeRecordForTest(bundle, BatchOutcomeEvidenceRecorder)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.BatchOutcome(ctx, 84532, bundle); got.AggregateSignature != "0xabcd" || got.EvidenceSource != BatchOutcomeEvidenceRecorder {
		t.Fatalf("the recorder did not complete the row: %+v", got)
	}
}

func TestTheSchemaRefusesAnOutcomeLeafThatContradictsItsStatus(t *testing.T) {
	repo := outcomeRepoForTest(t)
	ctx := context.Background()
	for i, mutate := range []func(*BatchOutcomeRecord){
		func(r *BatchOutcomeRecord) { r.Leaves[1].EffectsHash = word(0x55) }, // not settled, with effects
		func(r *BatchOutcomeRecord) { r.Leaves[0].Tx = zeroWord },            // executed, naming no transaction
		func(r *BatchOutcomeRecord) { r.Leaves[0].Status = 5 },
		func(r *BatchOutcomeRecord) { r.OutcomeRoot = zeroWord },
		func(r *BatchOutcomeRecord) { r.AggregateSignature = "" }, // a recorder row without its aggregate
		func(r *BatchOutcomeRecord) { r.TotalVotingPower = big.NewInt(1) },
	} {
		rec := outcomeRecordForTest(bundleHex(910+i), BatchOutcomeEvidenceRecorder)
		mutate(rec)
		if err := repo.RecordBatchOutcome(ctx, rec); err == nil {
			t.Errorf("case %d: the schema stored a contradicting record", i)
		}
		if got, err := repo.BatchOutcome(ctx, 84532, rec.BundleID); got != nil || err != nil {
			t.Errorf("case %d: a refused record left a row: (%v, %v)", i, got, err)
		}
	}
	// Leaves that do not number the leaf count are refused before the database.
	rec := outcomeRecordForTest(bundleHex(920), BatchOutcomeEvidenceRecorder)
	rec.Leaves = rec.Leaves[:1]
	if err := repo.RecordBatchOutcome(ctx, rec); err == nil {
		t.Error("a record missing a leaf was stored")
	}
}

func TestAttestedAnchorsWithoutAnOutcomeAreListedAsHints(t *testing.T) {
	repo := outcomeRepoForTest(t)
	ctx := context.Background()
	pending, recorded := bundleHex(930), bundleHex(931)
	for _, b := range []string{pending, recorded} {
		if _, err := testDB.ExecContext(ctx, `
			INSERT INTO anchor_batches (chain_id, bundle_id, verify_tx, anchor_version, accumulate_set_root, accumulate_incarnation)
			VALUES (7777, $1, $2, 'v8_2', $3, $3)`, b, word(0x21), word(0x22)); err != nil {
			t.Fatal(err)
		}
	}
	rec := outcomeRecordForTest(recorded, BatchOutcomeEvidenceRecorder)
	rec.ChainID = 7777
	if err := repo.RecordBatchOutcome(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := repo.AttestedAnchorsWithoutOutcome(ctx, 7777, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, b := range got {
		seen[b] = true
	}
	if !seen[pending] || seen[recorded] {
		t.Fatalf("hints %v", got)
	}
}
