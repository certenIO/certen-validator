// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/finality"
)

// seedComposable stores a production-shaped leg with the rows ComposeContractIdentity reads (result, QC, account URL) and returns its
// composed LegContext.
func seedComposable(t *testing.T) (string, ci.LegContext) {
	t.Helper()
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	seedBatchFacts(t, pid)
	if _, err := testDB.Exec(`UPDATE proof_artifacts SET account_url = 'acc://certen-demo.acme/book/1' WHERE proof_id = $1::uuid`, pid); err != nil {
		t.Fatal(err)
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	src := NewContractIdentitySource(NewClientFromDB(testDB), NewFinalityAddendaRepository(NewClientFromDB(testDB)), pins)
	lc, err := src.ComposeContractIdentity(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	return pid, lc
}

// WP-S8-5 end to end on PostgreSQL: the production Appender (the REAL verifier, the repository sink) judges the container with the context
// COMPOSED FROM THE STORED ROWS. A context the real Verify refuses (here: a value the store does not hold, named context_incomplete) appends
// nothing; a complete context lets the container in as seq 1, and the same container again is a no-op.
func TestRepositoryAppenderRunsTheRealVerifyOnTheComposedContext(t *testing.T) {
	ctx := context.Background()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	repo := NewContractIdentityRepository(NewClientFromDB(testDB))
	if _, err := repo.Appender("00000000-0000-0000-0000-000000000000", nil); err == nil {
		t.Fatal("a nil manifest is a construction error")
	}
	pid, lc := seedComposable(t)
	ap, err := repo.Appender(pid, m)
	if err != nil {
		t.Fatal(err)
	}
	blk := ci.BlockRef{Number: lc.S7.Block.Number, Hash: lc.S7.Block.Hash}
	stated := func(reason string) *ci.Stated {
		return &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: blk.Number, JudgedHash: blk.Hash}
	}
	parts := capture.Parts{Chain: lc.Chain, Leg: blk,
		Settle: &capture.SettleResult{Chain: lc.Chain, Block: blk, Stated: stated("capture_not_attempted_in_window")},
		Attest: &capture.AttestPart{Stated: stated("attest_block_state_unavailable")}}

	// (a) the context as the store composes it, with the batch root the store may not hold zeroed: the real Verify decides, Append obeys.
	broken := lc
	broken.Batch.BatchRoot = [32]byte{}
	var refused *capture.RefusedError
	if _, err := ap.Append(ctx, broken, parts); !errors.As(err, &refused) || refused.Report.Headline.Kind != ci.HeadlineRefused {
		t.Fatalf("an incomplete context must be refused by the real Verify and not appended, got %v", err)
	}
	if _, ok, err := repo.Latest(ctx, pid); err != nil || ok {
		t.Fatalf("a refused container must leave no row: %v %v", ok, err)
	}

	// (b) a complete context: accepted and stored once
	complete := lc
	if complete.Batch.BatchRoot == ([32]byte{}) {
		complete.Batch.BatchRoot[0] = 0x01 // the production-shaped test bundle carries no 1_merkle_inclusion; the value is not judged by a Stated container
	}
	res, err := ap.Append(ctx, complete, parts)
	if err != nil {
		var r *capture.RefusedError
		if errors.As(err, &r) {
			t.Fatalf("the real Verify refused the Stated container under the composed context: %+v", r.Report.Headline.First)
		}
		t.Fatal(err)
	}
	row, ok, err := repo.Latest(ctx, pid)
	if err != nil || !ok || row.Seq != 1 || !bytes.Equal(row.Evidence, res.Container) || row.Digest != res.Digest {
		t.Fatalf("the accepted container is stored as seq 1: %+v %v %v", row, ok, err)
	}
	if _, err := ap.Append(ctx, complete, parts); err != nil {
		t.Fatalf("the same container again is a no-op: %v", err)
	}
	if row2, _, _ := repo.Latest(ctx, pid); row2.Seq != 1 {
		t.Fatalf("an identical container must not add a row, seq %d", row2.Seq)
	}
}

// The exported bound equals the codec's container bound and the octet_length check of migration 00031 (4194304).
func TestMaxContractIdentityBytesEqualsTheContainerLimitAndTheMigration(t *testing.T) {
	if ci.MaxContractIdentityBytes != ci.DefaultLimits().MaxContainerBytes || ci.MaxContractIdentityBytes != 4194304 {
		t.Fatalf("MaxContractIdentityBytes %d, MaxContainerBytes %d", ci.MaxContractIdentityBytes, ci.DefaultLimits().MaxContainerBytes)
	}
	if capture.MaxItemBytes() != ci.MaxContractIdentityBytes {
		t.Fatalf("capture item bound %d", capture.MaxItemBytes())
	}
}

// seedBatchFacts stores what the live store holds for a settled proof that has its batch facts: an anchor_batches row (operation id, accumulate
// set root, incarnation) linked by proof_artifacts.batch_id, and the intent_quorum_certificates row of that operation id carrying the registry
// sample. The operation id of the live anchor_batches rows is 0x + 64 hex.
func seedBatchFacts(t *testing.T, proofID string) {
	t.Helper()
	opID := make([]byte, 32)
	_, _ = rand.Read(opID)
	opHex := "0x" + hex.EncodeToString(opID)
	var batch string
	if err := testDB.QueryRow(`INSERT INTO anchor_batches (merkle_root, batch_operation_id, accumulate_set_root, accumulate_incarnation, certen_validator_set_root)
		VALUES ($1, $2, $3, $4, $5) RETURNING id::text`, bytes.Repeat([]byte{3}, 32), opHex, "0x"+strings.Repeat("ab", 32), "0x"+strings.Repeat("cd", 32), "0x"+strings.Repeat("ef", 32)).Scan(&batch); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`UPDATE proof_artifacts SET batch_id = $2::uuid WHERE proof_id = $1::uuid`, proofID, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`INSERT INTO intent_quorum_certificates (operation_id, message, registry_version, certen_chain_id, certificate, registry, message_inputs, certified_height)
		VALUES ($1, $2, 1, 'certen-testnet', '{}', $3::jsonb, '{}'::jsonb, 1)`, opHex, "0x"+strings.Repeat("11", 32), string(fixtureBytes(t, "qc_registry.sample.json"))); err != nil {
		t.Fatal(err)
	}
}

// A settled proof without an anchor_batches row (the rows written before stage 3: 192 of the 575 live settled proofs have no batch_id) composes
// with ZERO batch facts and no registry: nothing is defaulted, and the verifier names what is missing (context_incomplete).
func TestComposeWithoutABatchRowLeavesTheBatchFactsZeroAndNamed(t *testing.T) {
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := NewContractIdentitySource(NewClientFromDB(testDB), NewFinalityAddendaRepository(NewClientFromDB(testDB)), pins).ComposeContractIdentity(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	if lc.Batch.OperationID != ([32]byte{}) || lc.Batch.AccSetRoot != ([32]byte{}) || lc.Batch.Incarnation != ([32]byte{}) || lc.Registry9 != nil {
		t.Fatalf("no batch row: %+v", lc.Batch)
	}
	var se *ci.StateError
	if err := lc.ValidateContext(); !errors.As(err, &se) || se.Code != ci.CodeContextIncomplete {
		t.Fatalf("the verifier must name the missing facts: %v", err)
	}
}

// storeLegContext stores a production-shaped leg WITHOUT batch facts and composes its context.
func storeLegContext(t *testing.T) (string, ci.LegContext) {
	t.Helper()
	pid, _ := storeLeg(t, "base_sepolia_47368146")
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := NewContractIdentitySource(NewClientFromDB(testDB), NewFinalityAddendaRepository(NewClientFromDB(testDB)), pins).ComposeContractIdentity(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	return pid, lc
}
