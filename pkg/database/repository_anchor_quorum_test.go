package database

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for canonical anchor rows, against CERTEN_TEST_DB (see TestMain in
// proof_artifact_repository_test.go). They pin the properties that make the row trustworthy:
//
//   - one row per (chain_id, bundle_id), whichever of the seven validators gets there first;
//   - evidence is never overwritten, and a disagreement is reported rather than resolved;
//   - the L5 binding query sees canonical rows ONLY, so the shadow row that produced the false
//     "root d2d24ab3… is in tx 0x9e4ff6ab…" claim can never be selected again.

func anchorRepoForTest(t *testing.T) *BatchRepository {
	t.Helper()
	if testDB == nil {
		t.Skip("Test database not configured")
	}
	client := NewClientFromDB(testDB)
	var migErr error
	migrateConsensusOnce.Do(func() { migErr = applyMigrationFilesDirectly(client) })
	if migErr != nil {
		t.Fatalf("migrations: %v", migErr)
	}
	return NewBatchRepository(client)
}

// bundleHex makes a distinct bundle id per test RUN as well as per case: the test database persists
// between runs, and a canonical row is deliberately write-once — a fixed id would make the second run
// measure the first run's row instead of this one's.
var bundleRunNonce = uuid.New()

func bundleHex(n int) string {
	nonce := strings.ReplaceAll(bundleRunNonce.String(), "-", "") // 32 hex chars
	return fmt.Sprintf("0x%s%s%08x", nonce, nonce[:24], n)        // 32 + 24 + 8 = 64
}

func anchorRecordForTest(chainID int64, bundle string, rootByte byte) *AnchorQuorumRecord {
	root := make([]byte, 32)
	for i := range root {
		root[i] = rootByte
	}
	leaf := make([]byte, 32)
	leaf[0] = 0x11
	return &AnchorQuorumRecord{
		ChainID:            chainID,
		BundleID:           bundle,
		Root:               root,
		BatchOperationID:   bundleHex(999),
		MessageHash:        bundleHex(888),
		AnchorCreateTx:     "0x51a1c0de" + strings.Repeat("00", 28), // a real hash is 0x + 64 hex chars
		VerifyTx:           "0xbeef" + strings.Repeat("11", 30),
		VerifyBlock:        45943100,
		VerifiedAt:         time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		AggregateSignature: []byte{0xab, 0xcd},
		AggregatePubKey:    []byte{0x12, 0x34},
		Signers: []AnchorQuorumSigner{
			{Address: "0xaaa", VotingPower: big.NewInt(100)},
			{Address: "0xbbb", VotingPower: big.NewInt(100)},
		},
		SignedVotingPower: big.NewInt(200),
		TotalVotingPower:  big.NewInt(700),
		Lane:              "on_demand",
		EvidenceSource:    "live",
		TargetChain:       "base-sepolia",
		Members: []AnchorQuorumMemberRecord{{
			IntentID:    "f6cea77e-0000-0000-0000-000000000001",
			AccumTxHash: "member-" + bundle,
			ADIURL:      "acc://fictional-payer.acme",
			OperationID: bundleHex(777),
			Leaf:        leaf,
			LeafIndex:   0,
			Branch:      []MerklePathNode{{Hash: strings.Repeat("22", 32), Position: "right"}},
		}},
	}
}

func TestRecordAnchorQuorumWritesOnceWithItsEvidence(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	rec := anchorRecordForTest(84532, bundleHex(1001), 0xaa)

	written, err := repo.RecordAnchorQuorum(ctx, rec)
	if err != nil || !written {
		t.Fatalf("first write: written=%v err=%v", written, err)
	}

	row, err := repo.GetAnchorQuorum(ctx, rec.ChainID, rec.BundleID)
	if err != nil || row == nil {
		t.Fatalf("canonical row not found: %v", err)
	}
	if !row.QuorumReached {
		t.Fatal("quorum_reached is false on a row written from a proven quorum")
	}
	if row.AttestationCount != 2 || row.SignedVotingPower != "200" || row.TotalVotingPower != "700" {
		t.Fatalf("evidence not stored: count=%d signed=%s total=%s",
			row.AttestationCount, row.SignedVotingPower, row.TotalVotingPower)
	}
	if row.AnchorCreateTx != rec.AnchorCreateTx || row.VerifyTx != rec.VerifyTx || row.VerifyBlock != rec.VerifyBlock {
		t.Fatalf("chain coordinates not stored: %+v", row)
	}
	if !row.VerifiedAt.Equal(rec.VerifiedAt) {
		t.Fatalf("consensus_completed_at = %v, want the on-chain verification time %v", row.VerifiedAt, rec.VerifiedAt)
	}
	if row.EvidenceSource != "live" || row.Lane != "on_demand" || row.MemberCount != 1 {
		t.Fatalf("row shape: %+v", row)
	}

	// A second validator proving the same anchor adds nothing and reports it did not write.
	again, err := repo.RecordAnchorQuorum(ctx, anchorRecordForTest(84532, rec.BundleID, 0xaa))
	if err != nil || again {
		t.Fatalf("second write: written=%v err=%v (want false, nil)", again, err)
	}

	var members, attestations int
	if err := testDB.QueryRow(
		`SELECT COUNT(*) FROM batch_transactions WHERE batch_id = $1`, row.BatchID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if err := testDB.QueryRow(
		`SELECT COUNT(*) FROM batch_attestations WHERE batch_id = $1`, row.BatchID).Scan(&attestations); err != nil {
		t.Fatal(err)
	}
	if members != 1 || attestations != 2 {
		t.Fatalf("members=%d attestations=%d, want 1 and 2 (no duplication on the second write)", members, attestations)
	}
}

// Seven validators prove every anchor. Exactly one row, one member set and one attestation set may result.
func TestRecordAnchorQuorumIsSafeUnderSevenConcurrentValidators(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	bundle := bundleHex(2002)

	var wg sync.WaitGroup
	results := make(chan struct {
		written bool
		err     error
	}, 7)
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.RecordAnchorQuorum(ctx, anchorRecordForTest(84532, bundle, 0xbb))
			results <- struct {
				written bool
				err     error
			}{w, err}
		}()
	}
	wg.Wait()
	close(results)

	writes := 0
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent write failed: %v", r.err)
		}
		if r.written {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("writes = %d, want exactly 1", writes)
	}

	var rows int
	if err := testDB.QueryRow(
		`SELECT COUNT(*) FROM anchor_batches WHERE chain_id = $1 AND bundle_id = $2`, 84532, bundle).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("anchor rows = %d, want 1", rows)
	}
}

// A different aggregate for the same anchor is a disagreement about what the chain executed. It must be
// reported and must not touch the stored row.
func TestRecordAnchorQuorumRefusesToOverwriteDifferentEvidence(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	bundle := bundleHex(3003)

	first := anchorRecordForTest(84532, bundle, 0xcc)
	if _, err := repo.RecordAnchorQuorum(ctx, first); err != nil {
		t.Fatal(err)
	}

	rival := anchorRecordForTest(84532, bundle, 0xdd) // different root
	rival.AggregateSignature = []byte{0xff, 0xee}
	_, err := repo.RecordAnchorQuorum(ctx, rival)

	var conflict *AnchorQuorumConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want an AnchorQuorumConflict", err)
	}
	if conflict.BundleID != bundle {
		t.Fatalf("conflict names the wrong anchor: %+v", conflict)
	}

	row, err := repo.GetAnchorQuorum(ctx, 84532, bundle)
	if err != nil || row == nil {
		t.Fatalf("row missing after a conflict: %v", err)
	}
	if hex.EncodeToString(row.Root) != hex.EncodeToString(first.Root) {
		t.Fatalf("stored row was changed by the conflicting write: %x", row.Root)
	}
}

func TestRecordAnchorQuorumRejectsIncompleteEvidence(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	if _, err := repo.RecordAnchorQuorum(ctx, nil); err == nil {
		t.Fatal("nil record accepted")
	}
	noBundle := anchorRecordForTest(84532, "", 0x01)
	if _, err := repo.RecordAnchorQuorum(ctx, noBundle); err == nil {
		t.Fatal("record without a bundle id accepted")
	}
	noRoot := anchorRecordForTest(84532, bundleHex(4004), 0x01)
	noRoot.Root = nil
	if _, err := repo.RecordAnchorQuorum(ctx, noRoot); err == nil {
		t.Fatal("record without a root accepted")
	}
	badSource := anchorRecordForTest(84532, bundleHex(4005), 0x01)
	badSource.EvidenceSource = "assumed"
	if _, err := repo.RecordAnchorQuorum(ctx, badSource); err == nil {
		t.Fatal("record with an unrecognised evidence source accepted")
	}
}

// THE REGRESSION. A shadow row must never be selected for an L5 binding, even when it is the newest row
// for that transaction — that rule is what published "root d2d24ab3… is in tx 0x9e4ff6ab…".
func TestLayer5BindingIgnoresShadowRowsAndUsesTheAnchorCreateTx(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	accumTx := "l5-binding-" + bundleRunNonce.String()
	bundle := bundleHex(5005)

	// A canonical row with its member (written first).
	rec := anchorRecordForTest(84532, bundle, 0x2f)
	rec.Members[0].AccumTxHash = accumTx
	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// A NEWER shadow row for the same transaction: a random UUID, a root nobody published, no bundle id.
	shadowBatch := uuid.New()
	shadowRoot, _ := hex.DecodeString("d2d24ab3bc0e2f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2")
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, transaction_count,
		                            anchor_tx_hash, evidence_source, created_at)
		 VALUES ($1, 'on_demand', 'pending', $2, 'base-sepolia', 1, $3, 'legacy_shadow', NOW() + interval '1 hour')`,
		shadowBatch, shadowRoot, "0x9e4ff6ab"+strings.Repeat("00", 28)); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash, created_at)
		 VALUES ($1, $2, 'acc://fictional-payer.acme', 0, $3, NOW() + interval '1 hour')`,
		shadowBatch, accumTx, shadowRoot); err != nil {
		t.Fatal(err)
	}

	artifacts := NewProofArtifactRepository(testDB)
	binding, err := artifacts.GetLayer5Binding(ctx, "", accumTx)
	if err != nil {
		t.Fatalf("binding lookup failed: %v", err)
	}
	if hex.EncodeToString(binding.BatchRoot) == hex.EncodeToString(shadowRoot) {
		t.Fatal("REGRESSION: the shadow root was selected for an L5 binding")
	}
	if hex.EncodeToString(binding.BatchRoot) != hex.EncodeToString(rec.Root) {
		t.Fatalf("binding root = %x, want the published root %x", binding.BatchRoot, rec.Root)
	}
	if binding.AnchorTxHash != rec.AnchorCreateTx {
		t.Fatalf("binding anchor tx = %s, want the anchor-create tx %s", binding.AnchorTxHash, rec.AnchorCreateTx)
	}
}

// A transaction that exists ONLY in shadow rows has no canonical binding: the honest answer is "none",
// not a path to a root nobody published.
func TestLayer5BindingReportsNoneWhenOnlyShadowRowsExist(t *testing.T) {
	anchorRepoForTest(t)
	ctx := context.Background()
	accumTx := "shadow-only-" + bundleRunNonce.String()

	shadowBatch := uuid.New()
	shadowRoot, _ := hex.DecodeString("d2d24ab3bc0e2f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2")
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, transaction_count, evidence_source)
		 VALUES ($1, 'on_demand', 'pending', $2, 'base-sepolia', 1, 'legacy_shadow')`,
		shadowBatch, shadowRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash)
		 VALUES ($1, $2, 'acc://fictional-payer.acme', 0, $3)`,
		shadowBatch, accumTx, shadowRoot); err != nil {
		t.Fatal(err)
	}

	artifacts := NewProofArtifactRepository(testDB)
	_, err := artifacts.GetLayer5Binding(ctx, "", accumTx)
	if !errors.Is(err, ErrNoBatchBinding) {
		t.Fatalf("err = %v, want ErrNoBatchBinding", err)
	}
}

func TestAnchorQuorumUsesSharedSchema(t *testing.T) {
	_ = anchorRepoForTest(t)
}

// REGRESSION — the live failure of 2026-09-16, intent 7758cbed.
//
// The batch path never sees an intent's Accumulate transaction hash: a member arrives as
// (intent id, ADI, operation id, legs). So a CANONICAL member row has no accumulate_tx_hash, and a
// binding keyed on that column finds only the retired shadow rows — which the canonical filter then
// discards, leaving no binding at all. Layer 5 fell back to the settlement observation and published the
// settlement transaction, while a correct canonical row (root matching the on-chain anchor) sat unused.
//
// The fixture is the live shape exactly: a canonical row reachable only by intent_id, and shadow rows
// carrying the Accumulate transaction hash.
func TestLayer5BindingFindsTheCanonicalRowByIntentWhenTheAccumHashIsOnlyOnShadowRows(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	artifacts := NewProofArtifactRepository(testDB)

	intentID := "intent-" + uuid.NewString()
	accumTx := strings.Repeat("ab", 32) // the WriteData hash, known ONLY to the shadow path
	anchorCreateTx := "0x51a1c0de" + strings.Repeat("00", 28)

	rec := anchorRecordForTest(84532, bundleHex(7758), 0xda)
	rec.AnchorCreateTx = anchorCreateTx
	// Exactly as the live writer produces it: a member with an intent id and NO Accumulate tx hash.
	rec.Members = []AnchorQuorumMemberRecord{{
		IntentID:    intentID,
		AccumTxHash: "",
		ADIURL:      "acc://fictional-payer.acme",
		Leaf:        rec.Root,
		LeafIndex:   0,
	}}
	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// Seven shadow rows for the same intent, each carrying the real Accumulate hash and a root that was
	// never published — the live picture.
	shadowRoot, _ := hex.DecodeString("c3da22722f0972af4e6571520d58d22ee6ecf57a3321df5a5c19067f41244fc7")
	for i := 0; i < 7; i++ {
		sb := uuid.New()
		if _, err := testDB.ExecContext(ctx,
			`INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, transaction_count, created_at)
			 VALUES ($1, 'on_demand', 'pending', $2, 'base-sepolia', 1, NOW() + interval '1 hour')`,
			sb, shadowRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := testDB.ExecContext(ctx,
			`INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash, intent_id, created_at)
			 VALUES ($1, $2, 'acc://fictional-payer.acme', 0, $3, $4, NOW() + interval '1 hour')`,
			sb, accumTx, shadowRoot, intentID); err != nil {
			t.Fatal(err)
		}
	}

	// The live call: the orchestrator knows both, and the intent id is what reaches the canonical row.
	binding, err := artifacts.GetLayer5Binding(ctx, intentID, accumTx)
	if err != nil {
		t.Fatalf("no binding found for an intent that HAS a canonical anchor: %v", err)
	}
	if hex.EncodeToString(binding.BatchRoot) == hex.EncodeToString(shadowRoot) {
		t.Fatal("REGRESSION: a shadow root was bound")
	}
	if hex.EncodeToString(binding.BatchRoot) != hex.EncodeToString(rec.Root) {
		t.Fatalf("binding root = %x, want the published root %x", binding.BatchRoot, rec.Root)
	}
	if binding.AnchorTxHash != anchorCreateTx {
		t.Fatalf("binding anchor tx = %q, want the anchor-create tx — an empty one sends layer 5 back to "+
			"the settlement observation", binding.AnchorTxHash)
	}
}

// An intent with no canonical anchor at all must still report "none", not borrow a shadow row.
func TestLayer5BindingRefusesWhenOnlyShadowRowsExistForTheIntent(t *testing.T) {
	_ = anchorRepoForTest(t)
	ctx := context.Background()
	artifacts := NewProofArtifactRepository(testDB)

	intentID := "intent-" + uuid.NewString()
	accumTx := strings.Repeat("cd", 32)
	shadowRoot, _ := hex.DecodeString("d2d24ab3bc0e2f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2")
	sb := uuid.New()
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO anchor_batches (id, batch_type, status, merkle_root, target_chain, transaction_count, created_at)
		 VALUES ($1, 'on_demand', 'pending', $2, 'base-sepolia', 1, NOW())`, sb, shadowRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx,
		`INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, transaction_hash, intent_id, created_at)
		 VALUES ($1, $2, 'acc://fictional-payer.acme', 0, $3, $4, NOW())`,
		sb, accumTx, shadowRoot, intentID); err != nil {
		t.Fatal(err)
	}

	if _, err := artifacts.GetLayer5Binding(ctx, intentID, accumTx); !errors.Is(err, ErrNoBatchBinding) {
		t.Fatalf("expected ErrNoBatchBinding, got %v", err)
	}
}

// REGRESSION — a backfilled row must not inherit a lane it never observed.
//
// anchor_batches.batch_type is NOT NULL and DEFAULTS to 'on_cadence'. A row reconstructed from the chain
// has no lane: neither the calldata nor the anchor's stored state records how this fleet scheduled the
// batch, and a one-member batch is not evidence of the on-demand lane because a period can close with
// one member. Letting the default apply would stamp 'on_cadence' on every backfilled row — a fact nobody
// established, in a column that reads as evidence.
//
// Caught by the first -write attempt against production, which failed the valid_batch_type constraint
// rather than writing anything.
func TestBackfilledRowRecordsAnUnknownLaneRatherThanInheritingOne(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	rec := anchorRecordForTest(84532, bundleHex(2101), 0xb1)
	rec.EvidenceSource = "chain_backfill"
	rec.Lane = "" // the chain does not say
	rec.Members = nil

	written, err := repo.RecordAnchorQuorum(ctx, rec)
	if err != nil {
		t.Fatalf("a backfilled row with no lane could not be written: %v", err)
	}
	if !written {
		t.Fatal("no row written")
	}

	var batchType string
	var lane *string
	if err := testDB.QueryRowContext(ctx,
		`SELECT batch_type, lane FROM anchor_batches WHERE chain_id=$1 AND bundle_id=$2`,
		rec.ChainID, rec.BundleID).Scan(&batchType, &lane); err != nil {
		t.Fatal(err)
	}
	if batchType != "unknown" {
		t.Fatalf("batch_type = %q, want \"unknown\" — anything else asserts a lane the chain never recorded",
			batchType)
	}
	if lane != nil {
		t.Fatalf("lane = %q, want NULL; NULL already means \"not recorded\"", *lane)
	}
}

// A live row still records the lane it actually ran, in both columns.
func TestLiveRowKeepsItsRealLane(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	rec := anchorRecordForTest(84532, bundleHex(2102), 0xb2)
	rec.EvidenceSource = "live"
	rec.Lane = "on_demand"

	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatal(err)
	}
	var batchType string
	var lane *string
	if err := testDB.QueryRowContext(ctx,
		`SELECT batch_type, lane FROM anchor_batches WHERE chain_id=$1 AND bundle_id=$2`,
		rec.ChainID, rec.BundleID).Scan(&batchType, &lane); err != nil {
		t.Fatal(err)
	}
	if batchType != "on_demand" || lane == nil || *lane != "on_demand" {
		t.Fatalf("batch_type=%q lane=%v, want both on_demand", batchType, lane)
	}
}

// REGRESSION — the canonical member row must carry what the shadow row it replaces carried.
//
// §3 of the hardening runbook retires the shadow pipeline. That is only safe once the canonical row is
// at least as rich, because proofs_service reads these columns for the Transaction Center. Live on
// 2026-09-18 the canonical row held the operation id in accumulate_tx_hash and nothing else, so retiring
// the shadow writer would have emptied the console for every new intent.
func TestCanonicalMemberRowCarriesTheAccumulateTransactionAndLeg(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	const accumTx = "3e595d2c526dfacb5e332cd11f4f0306d2648cf1291bed63a9bcfd6ef44a7a12"
	rec := anchorRecordForTest(84532, bundleHex(3101), 0xc1)
	rec.Members = []AnchorQuorumMemberRecord{{
		IntentID:    "intent-canonical-rich",
		AccumTxHash: accumTx,
		ADIURL:      "acc://spk-cust-tcl1.acme",
		OperationID: "0x" + strings.Repeat("01", 32),
		Leaf:        rec.Root,
		LeafIndex:   0,
		FromChain:   "accumulate",
		ToChain:     "base-sepolia",
		FromAddress: "0x9cc158f77DAdF9a605E141262338c89588825f6c",
		ToAddress:   "0x12dD00C619C1Ac3F58eC68ed44ec1023fE33B9Ff",
		Amount:      "0",
		TokenSymbol: "ETH",
		UserID:      "acc://spk-cust-tcl1.acme",
	}}

	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatalf("RecordAnchorQuorum: %v", err)
	}

	var gotAccum, fromChain, toChain, fromAddr, toAddr, amount, token, userID string
	if err := testDB.QueryRowContext(ctx, `
		SELECT bt.accumulate_tx_hash, bt.from_chain, bt.to_chain, bt.from_address, bt.to_address,
		       bt.amount, bt.token_symbol, COALESCE(bt.user_id,'')
		  FROM batch_transactions bt JOIN anchor_batches ab ON ab.id = bt.batch_id
		 WHERE ab.bundle_id = $1`, rec.BundleID).
		Scan(&gotAccum, &fromChain, &toChain, &fromAddr, &toAddr, &amount, &token, &userID); err != nil {
		t.Fatalf("reading the member row: %v", err)
	}

	if gotAccum != accumTx {
		t.Fatalf("accumulate_tx_hash = %q, want the Accumulate transaction %q", gotAccum, accumTx)
	}
	if fromChain != "accumulate" || toChain != "base-sepolia" {
		t.Fatalf("chains = %s -> %s", fromChain, toChain)
	}
	if fromAddr == "" || toAddr == "" || token != "ETH" || amount != "0" || userID == "" {
		t.Fatalf("leg not recorded: from=%q to=%q amount=%q token=%q user=%q",
			fromAddr, toAddr, amount, token, userID)
	}
}

// A member with no provenance (restored from an older mempool blob) must still be writable, with empty
// columns rather than a failed insert. Empty is honest; refusing to record the anchor is not.
func TestCanonicalMemberRowAcceptsMissingProvenance(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	rec := anchorRecordForTest(84532, bundleHex(3102), 0xc2)
	rec.Members = []AnchorQuorumMemberRecord{{
		IntentID: "intent-bare", ADIURL: "acc://bare.acme", Leaf: rec.Root, LeafIndex: 0,
	}}
	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatalf("a member with no provenance could not be written: %v", err)
	}
	var n int
	if err := testDB.QueryRowContext(ctx,
		`SELECT count(*) FROM batch_transactions bt JOIN anchor_batches ab ON ab.id=bt.batch_id
		  WHERE ab.bundle_id=$1`, rec.BundleID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("member rows = %d, want 1", n)
	}
}

// REGRESSION — the database must refuse a status word where a transaction hash belongs.
//
// createBatchAnchor returns "already-exists" when another validator created the anchor first. On
// 2026-09-18 that sentinel was stored in anchor_create_tx and copied into layer 5, which published
// `anchorTx: "already-exists"` — a root claimed to appear in something that is not a transaction.
//
// The orchestrator no longer produces it (IsTransactionHash). This asserts the second lock: migration
// 00003's CHECK, which stops EVERY writer, including one written by someone who never read that code.
func TestAnchorCreateTxMustBeATransactionHash(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	rec := anchorRecordForTest(84532, bundleHex(4101), 0xd1)
	rec.AnchorCreateTx = "already-exists"
	rec.Members = nil

	if _, err := repo.RecordAnchorQuorum(ctx, rec); err == nil {
		t.Fatal("a sentinel was accepted into anchor_create_tx; the column is read as evidence and " +
			"travels into layer 5 as anchorTx")
	} else if !strings.Contains(err.Error(), "anchor_create_tx_is_a_transaction") {
		t.Fatalf("refused, but not by the constraint that should catch it: %v", err)
	}
}

// NULL remains valid: a validator that did not create the anchor does not know which transaction did,
// and empty is how that is said. Refusing it would lose real quorum evidence over a display field.
func TestAnchorCreateTxAcceptsUnknown(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	rec := anchorRecordForTest(84532, bundleHex(4102), 0xd2)
	rec.AnchorCreateTx = ""
	rec.Members = nil

	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatalf("an anchor whose creating transaction is unknown could not be recorded: %v", err)
	}
	var got *string
	if err := testDB.QueryRowContext(ctx,
		`SELECT anchor_create_tx FROM anchor_batches WHERE bundle_id=$1`, rec.BundleID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("anchor_create_tx = %q, want NULL", *got)
	}
}

// And a real hash is stored unchanged.
func TestAnchorCreateTxAcceptsARealHash(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()

	const real = "0xbafab491071b28f21956c82317abe2a531bb41ad89880153901991f15fb3da58"
	rec := anchorRecordForTest(84532, bundleHex(4103), 0xd3)
	rec.AnchorCreateTx = real
	rec.Members = nil

	if _, err := repo.RecordAnchorQuorum(ctx, rec); err != nil {
		t.Fatalf("a real anchor-create transaction was refused: %v", err)
	}
	var got string
	if err := testDB.QueryRowContext(ctx,
		`SELECT anchor_create_tx FROM anchor_batches WHERE bundle_id=$1`, rec.BundleID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("anchor_create_tx = %q, want %q", got, real)
	}
}
