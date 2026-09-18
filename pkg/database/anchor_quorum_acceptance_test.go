// Copyright 2026 Certen Protocol
//
// The acceptance gate must DETECT. Each test plants exactly the condition a check exists for and requires
// that check to fail — then removes it and requires a pass. A gate that cannot fail proves nothing.

package database

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// acceptanceBundleSeq keeps every fixture on its own anchor. (chain_id, bundle_id) is unique and rows are
// write-once, so two tests sharing a bundle id would have the second measure the first one's row.
var acceptanceBundleSeq atomic.Int64

// acceptanceFixture writes one healthy canonical anchor with n distinct signers and returns its key.
func acceptanceFixture(t *testing.T, signers int) (chainID int64, bundleID string, root []byte, batchID uuid.UUID) {
	t.Helper()
	_ = anchorRepoForTest(t) // schema up; skips when no database is configured
	ctx := context.Background()

	chainID = 84532
	bundleID = bundleHex(7100 + int(acceptanceBundleSeq.Add(1)))
	root = make([]byte, 32)
	for i := range root {
		root[i] = 0xa7
	}
	batchID = uuid.New()
	verifyTx := "0x" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("0", 32)
	createTx := "0x" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("1", 32)

	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, anchor_create_tx, verify_tx, verify_block,
		                            quorum_reached, attestation_count,
		                            signed_voting_power, total_voting_power,
		                            evidence_source, lane, created_at, updated_at)
		VALUES ($1,'on_demand','confirmed',$2,1,1,$3,$4,$5,$6,123,
		        TRUE,$7,700,700,'live','on_demand',NOW(),NOW())`,
		batchID, root, chainID, bundleID, createTx, verifyTx, signers); err != nil {
		t.Fatalf("planting anchor: %v", err)
	}
	for i := 0; i < signers; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		if _, err := testDB.ExecContext(ctx, `
			INSERT INTO batch_attestations (batch_id, validator_id, evm_address, voting_power, merkle_root,
			                                bls_public_key, tx_count, block_height, attestation_time, signature_valid)
			VALUES ($1,$2,$2,100,$3,$4,1,123,NOW(),TRUE)`, batchID, addr, root, []byte{0xab, 0xcd}); err != nil {
			t.Fatalf("planting attestation %d: %v", i, err)
		}
	}
	return chainID, bundleID, root, batchID
}

// healthyOpts describes a fleet where everything the gate needs was actually inspected.
func healthyOpts(verifyTx string, root []byte, signers int) AnchorQuorumAcceptanceOptions {
	return AnchorQuorumAcceptanceOptions{
		ExpectedSigners:    signers,
		QuarantinedEntries: 0,
		OnChain: &AnchorQuorumOnChain{
			VerifyTx:      verifyTx,
			Root:          root,
			ProofExecuted: true,
		},
	}
}

func verifyTxOf(t *testing.T, chainID int64, bundleID string) string {
	t.Helper()
	var tx string
	if err := testDB.QueryRowContext(context.Background(),
		`SELECT COALESCE(verify_tx,'') FROM anchor_batches WHERE chain_id=$1 AND bundle_id=$2`,
		chainID, bundleID).Scan(&tx); err != nil {
		t.Fatal(err)
	}
	return tx
}

func checkByID(t *testing.T, res *AnchorQuorumAcceptance, id string) AnchorQuorumCheck {
	t.Helper()
	for _, c := range res.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("the gate did not evaluate %s at all; checks were %+v", id, res.Checks)
	return AnchorQuorumCheck{}
}

// A healthy anchor passes every check that is about the anchor itself.
func TestAcceptanceGatePassesAHealthyAnchor(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"E1", "E2", "E3", "E4", "E5", "E6", "E7"} {
		if c := checkByID(t, res, id); !c.Passed {
			t.Errorf("%s (%s) failed on a healthy anchor: %s", c.ID, c.Name, c.Detail)
		}
	}
}

// E1: an anchor that was never recorded must fail, and must not report the rest as clean.
func TestAcceptanceGateFailsWhenNoCanonicalRowExists(t *testing.T) {
	_ = anchorRepoForTest(t)
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, 84532, bundleHex(7999),
		healthyOpts("0xdead", []byte{1}, 7))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"E1", "E2", "E3", "E4", "E5", "E6"} {
		if c := checkByID(t, res, id); c.Passed {
			t.Errorf("%s passed for an anchor with no canonical row: %s", id, c.Detail)
		}
	}
	if res.Passed() {
		t.Fatal("the gate passed an anchor that does not exist")
	}
}

// E2: the quorum must be complete. A row at 600/700 has not met the quorum it claims.
func TestAcceptanceGateFailsWhenSignedPowerIsNotTheTotal(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	if _, err := testDB.ExecContext(context.Background(),
		`UPDATE anchor_batches SET signed_voting_power = 600 WHERE chain_id=$1 AND bundle_id=$2`,
		chainID, bundleID); err != nil {
		t.Fatal(err)
	}
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7))
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E2"); c.Passed {
		t.Fatalf("E2 passed with signed power below the total: %s", c.Detail)
	}
}

// E3 is the check that binds the row to reality. A stored verify_tx that is not the transaction the chain
// says proved this anchor is the d2d24ab3 defect in its general form.
func TestAcceptanceGateFailsWhenTheChainNamesADifferentTransaction(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	opts := healthyOpts("0x"+strings.Repeat("9e", 32), root, 7) // the chain proved it in a DIFFERENT tx
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E3"); c.Passed {
		t.Fatalf("E3 passed while the row and the chain name different transactions: %s", c.Detail)
	}
}

func TestAcceptanceGateFailsWhenTheChainRootDisagrees(t *testing.T) {
	chainID, bundleID, _, _ := acceptanceFixture(t, 7)
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xd2 // the shadow root shape
	}
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		healthyOpts(verifyTxOf(t, chainID, bundleID), other, 7))
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E3"); c.Passed {
		t.Fatalf("E3 passed while the stored root is not the root on chain: %s", c.Detail)
	}
}

func TestAcceptanceGateFailsWhenProofWasNotExecuted(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	opts := healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7)
	opts.OnChain.ProofExecuted = false
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E3"); c.Passed {
		t.Fatalf("E3 passed for an anchor the chain never executed: %s", c.Detail)
	}
}

// A gate that silently skips the chain would report a clean sheet for an anchor nobody verified.
func TestAcceptanceGateRefusesToPassE3WithoutConsultingTheChain(t *testing.T) {
	chainID, bundleID, _, _ := acceptanceFixture(t, 7)
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		AnchorQuorumAcceptanceOptions{ExpectedSigners: 7, QuarantinedEntries: 0}) // OnChain nil
	if err != nil {
		t.Fatal(err)
	}
	c := checkByID(t, res, "E3")
	if c.Passed {
		t.Fatal("E3 passed without the chain being read")
	}
	if !strings.Contains(c.Detail, "not consulted") {
		t.Fatalf("E3 does not say why it could not pass: %s", c.Detail)
	}
	if res.Passed() {
		t.Fatal("the overall gate passed with an unevaluated check")
	}
}

// E4: seven rows naming one address is one signature claimed seven times — the shape a forged quorum takes.
func TestAcceptanceGateFailsWhenSignersAreNotDistinct(t *testing.T) {
	chainID, bundleID, root, batchID := acceptanceFixture(t, 3)
	// validator_id is unique per batch, so a duplicate ADDRESS is planted under a distinct validator id.
	if _, err := testDB.ExecContext(context.Background(), `
		INSERT INTO batch_attestations (batch_id, validator_id, evm_address, voting_power, merkle_root,
		                                bls_public_key, tx_count, block_height, attestation_time, signature_valid)
		VALUES ($1,'duplicate-validator',$2,100,$3,$4,1,123,NOW(),TRUE)`,
		batchID, fmt.Sprintf("0x%040x", 1), root, []byte{0xab, 0xcd}); err != nil {
		t.Fatal(err)
	}
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		healthyOpts(verifyTxOf(t, chainID, bundleID), root, 0)) // any count, but they must be distinct
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E4"); c.Passed {
		t.Fatalf("E4 passed with a repeated signer address: %s", c.Detail)
	}
}

// E5 must report what proofs_service will actually show, not what the writer intended.
func TestAcceptanceGateFailsE5WhenQuorumIsNotReached(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	if _, err := testDB.ExecContext(context.Background(),
		`UPDATE anchor_batches SET quorum_reached = FALSE WHERE chain_id=$1 AND bundle_id=$2`,
		chainID, bundleID); err != nil {
		t.Fatal(err)
	}
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID,
		healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7))
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E5"); c.Passed {
		t.Fatalf("E5 passed while the row reports no quorum: %s", c.Detail)
	}
}

// E7: a conflict is durable evidence that two nodes disagree, and the gate must not pass over it.
func TestAcceptanceGateFailsWhenEvidenceIsQuarantined(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	opts := healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7)
	opts.QuarantinedEntries = 2
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E7"); c.Passed {
		t.Fatalf("E7 passed with conflicting evidence in quarantine: %s", c.Detail)
	}
}

func TestAcceptanceGateRefusesToPassE7WithoutInspectingTheOutbox(t *testing.T) {
	chainID, bundleID, root, _ := acceptanceFixture(t, 7)
	opts := healthyOpts(verifyTxOf(t, chainID, bundleID), root, 7)
	opts.QuarantinedEntries = -1 // not inspected
	res, err := RunAnchorQuorumAcceptance(context.Background(), testDB, chainID, bundleID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c := checkByID(t, res, "E7"); c.Passed {
		t.Fatalf("E7 passed without the outbox being looked at: %s", c.Detail)
	}
}

// ─── §4.D, the whole-table gate ─────────────────────────────────────────────────────────────────────

// D4 is the one that must never be waved through: a shadow row asserting a quorum republishes the
// original defect, because its root was never on any chain.
func TestBackfillGateFailsWhenAShadowRowClaimsAQuorum(t *testing.T) {
	_ = anchorRepoForTest(t)
	ctx := context.Background()

	clean, err := RunAnchorQuorumBackfillGate(ctx, testDB)
	if err != nil {
		t.Fatal(err)
	}
	if clean.ShadowRowsClaimingQuorum != 0 {
		t.Fatalf("the table already holds %d shadow rows claiming quorum", clean.ShadowRowsClaimingQuorum)
	}

	shadowRoot, _ := hex.DecodeString("d2d24ab3bc0e2f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2")
	shadow := uuid.New()
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            quorum_reached, evidence_source, created_at, updated_at)
		VALUES ($1,'on_demand','pending',$2,1,1,TRUE,'legacy_shadow',NOW(),NOW())`,
		shadow, shadowRoot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id=$1`, shadow)
	})

	dirty, err := RunAnchorQuorumBackfillGate(ctx, testDB)
	if err != nil {
		t.Fatal(err)
	}
	if dirty.ShadowRowsClaimingQuorum != 1 {
		t.Fatalf("D4 counted %d shadow rows claiming quorum, want 1", dirty.ShadowRowsClaimingQuorum)
	}
	// The same defect stated without trusting the label: quorum on a row with no bundle id.
	if dirty.CanonicalRowsWithoutBundle != 1 {
		t.Fatalf("a quorum on a row with no bundle id was not counted (got %d)", dirty.CanonicalRowsWithoutBundle)
	}
	if dirty.Passed() {
		t.Fatal("the backfill gate passed a table containing a shadow row that claims a quorum")
	}
}

func TestBackfillGateCountsBackfilledRows(t *testing.T) {
	_ = anchorRepoForTest(t)
	ctx := context.Background()

	before, err := RunAnchorQuorumBackfillGate(ctx, testDB)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.New()
	root := make([]byte, 32)
	root[0] = 0xbf
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, quorum_reached, evidence_source, created_at, updated_at)
		VALUES ($1,'unknown','confirmed',$2,1,1,84532,$3,TRUE,'chain_backfill',NOW(),NOW())`,
		id, root, bundleHex(7777)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id=$1`, id)
	})

	after, err := RunAnchorQuorumBackfillGate(ctx, testDB)
	if err != nil {
		t.Fatal(err)
	}
	if after.BackfilledRows != before.BackfilledRows+1 {
		t.Fatalf("D3 counted %d backfilled rows, want %d", after.BackfilledRows, before.BackfilledRows+1)
	}
	if !after.Passed() {
		t.Fatalf("a correctly backfilled row failed the gate: %+v", after)
	}
}

func TestAcceptanceGateNeedsAnAnchorToCheck(t *testing.T) {
	_ = anchorRepoForTest(t)
	if _, err := RunAnchorQuorumAcceptance(context.Background(), testDB, 0, "", AnchorQuorumAcceptanceOptions{}); err == nil {
		t.Fatal("the gate ran without being told which anchor to check")
	}
	if _, err := RunAnchorQuorumAcceptance(context.Background(), nil, 84532, "0xab",
		AnchorQuorumAcceptanceOptions{}); err == nil {
		t.Fatal("the gate ran without a database")
	}
}
