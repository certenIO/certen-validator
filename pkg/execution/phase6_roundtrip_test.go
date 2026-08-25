// Copyright 2026 Certen Protocol
//
// Phase 6 Gate 5 — THE GATE THIS PHASE EXISTS FOR.
//
// A governance proof is written to PostgreSQL through the production write
// path, read back through ChainedProofFromStorage, and verified by the
// UNMODIFIED offline verifier with the network cut. Then every mutation in
// runbook §5.3 is applied to the STORED BYTES and must be rejected.
//
// # WHY BOTH HALVES ARE REQUIRED
//
// Storing evidence and checking evidence are different claims. A test that
// only asserts fields are present proves the first and says nothing about the
// second — and a verifier that is not actually running will pass such a test
// on any input at all. So the mutations are not optional colour: they are what
// distinguishes "we ran the verifier" from "we returned nil".
//
// WHY THIS TEST LIVES IN pkg/execution AND NOT pkg/proof
//
// The runbook puts the Gate 5 command in ./pkg/proof/. It cannot be there:
// this test drives the real WRITE path (BuildLayer4Rows, WithCanonicalL1..L3,
// which are in pkg/execution) and the real READ path
// (proof.ChainedProofFromStorage, in pkg/proof), and pkg/execution imports
// pkg/proof. A test in pkg/proof that imported pkg/execution would be an
// import cycle, so it would have to re-implement the write path — and a
// round-trip through a reimplementation of the writer proves nothing about the
// writer. The gate command is therefore:
//
//	go test ./pkg/execution/ -run 'TestP6_StoredProofVerifiesOffline|TestP6_StoredProofRejects' -count=1 -v
//
// It needs a PostgreSQL carrying the live schema, addressed by CERTEN_TEST_DB.
// Without it the test SKIPS rather than passing vacuously — a skipped Gate 5
// is not a green Gate 5.
package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// =============================================================================
// Harness
// =============================================================================

// p6DeadDialer refuses every outbound connection, so any network access during
// verification is a loud failure rather than something that quietly succeeds on
// a developer's machine. Same device offline_verify_test.go uses.
type p6DeadDialer struct{ t *testing.T }

func (d p6DeadDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.t.Error("CRITICAL DEFECT: verification from storage attempted a network connection")
	return nil, fmt.Errorf("network disabled for this test")
}

func p6CutTheNetwork(t *testing.T) {
	t.Helper()
	origTransport, origClient := http.DefaultTransport, http.DefaultClient
	dead := &http.Transport{
		DialContext:           p6DeadDialer{t}.DialContext,
		ResponseHeaderTimeout: time.Millisecond,
	}
	http.DefaultTransport = dead
	http.DefaultClient = &http.Client{Transport: dead}
	t.Cleanup(func() {
		http.DefaultTransport = origTransport
		http.DefaultClient = origClient
	})
}

func p6OpenDB(t *testing.T) *sql.DB {
	t.Helper()
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Skip("CERTEN_TEST_DB not set — Gate 5 needs a PostgreSQL with the live schema. " +
			"A skipped Gate 5 is not a green Gate 5.")
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// p6LoadFixture reads one of the real stored proofs. Their signatures are
// genuine ed25519 signatures over genuine Accumulate anchors — the offline
// verifier already rejects 34 targeted mutations against them — so a
// round-trip through storage is exercising real cryptography, not a stub.
func p6LoadFixture(t *testing.T, name string) *chained_proof.ChainedProof {
	t.Helper()
	path := filepath.Join("..", "..", "accumulate-lite-client-2", "liteclient", "proof",
		"working-proof_do_not_edit", "testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(raw, cp); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if cp.Layer4BVN == nil || cp.Layer4DN == nil {
		t.Fatalf("fixture %s carries no L4 legs", name)
	}
	return cp
}

// p6Store writes a proof through the PRODUCTION write path and returns its id.
//
// It uses the same repository call and the same row builders the orchestrators
// use. Nothing here re-implements the writer: if BuildLayer4Rows or
// WithCanonicalL1 regress, this test fails, which is the point of driving the
// real path rather than a convenient one.
func p6Store(ctx context.Context, t *testing.T, db *sql.DB, cp *chained_proof.ChainedProof) uuid.UUID {
	t.Helper()
	repo := database.NewProofArtifactRepository(db)
	proofID := uuid.New()
	// Unique per run so repeated runs never collide on the tx hash the blob
	// join uses.
	txHash := fmt.Sprintf("%s-%s", cp.Input.TxHash[:32], proofID.String()[:8])

	_, err := db.ExecContext(ctx, `
		INSERT INTO proof_artifacts (proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			proof_class, validator_id, status, artifact_json, artifact_hash, verification_status)
		VALUES ($1, 'chained', '3.0', $2, $3, 'on_demand', 'validator-test', 'pending',
			'{}'::jsonb, '\x00'::bytea, 'verified')`,
		proofID, txHash, cp.Input.Account)
	if err != nil {
		t.Fatalf("insert proof_artifacts: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM chained_proof_layers WHERE proof_id = $1`, proofID)
		// Children before parents: anchor_batches is looked up THROUGH
		// batch_transactions, so deleting the transaction first would orphan
		// the batch rather than remove it.
		db.Exec(`DELETE FROM anchor_batches WHERE id IN (
			SELECT batch_id FROM batch_transactions WHERE accumulate_tx_hash = $1)`, txHash)
		db.Exec(`DELETE FROM batch_transactions WHERE accumulate_tx_hash = $1`, txHash)
		db.Exec(`DELETE FROM proof_artifacts WHERE proof_id = $1`, proofID)
	})

	// L1-L3 rows, carrying both the description and the authoritative layer.
	for _, spec := range []struct {
		num  int
		name string
		desc map[string]interface{}
	}{
		{1, "L1 - Transaction to BVN", map[string]interface{}{"layer": "L1", "description": "Transaction to BVN"}},
		{2, "L2 - BVN to DN", map[string]interface{}{"layer": "L2", "description": "BVN to DN"}},
		{3, "L3 - DN to Consensus", map[string]interface{}{"layer": "L3", "description": "DN to Consensus"}},
	} {
		descJSON, _ := json.Marshal(spec.desc)
		layerJSON := json.RawMessage(descJSON)
		switch spec.num {
		case 1:
			layerJSON = WithCanonicalL1(layerJSON, cp)
		case 2:
			layerJSON = WithCanonicalL2(layerJSON, cp)
		case 3:
			layerJSON = WithCanonicalL3(layerJSON, cp)
		}
		if _, err := repo.CreateChainedProofLayer(ctx, &database.NewChainedProofLayer{
			ProofID:     proofID,
			LayerNumber: spec.num,
			LayerName:   spec.name,
			LayerJSON:   layerJSON,
		}); err != nil {
			t.Fatalf("write layer %d: %v", spec.num, err)
		}
	}

	// L4 rows, through the shared helper both orchestrators call.
	if err := WriteLayer4Rows(ctx, repo, proofID, cp, t.Logf); err != nil {
		t.Fatalf("write layer-4 rows: %v", err)
	}

	// The travelling blob, built the way discovery.go builds it.
	complete := certenproof.ChainedProofToCompleteProof(cp)
	adapter := certenproof.NewCertenProofAdapter(complete, &certenproof.ProofRequest{
		ProofType:       "chained_l1_l2_l3",
		TransactionHash: cp.Input.TxHash,
		AccountURL:      cp.Input.Account,
	}, "validator-test")
	blob, err := json.Marshal(adapter.ToCertenProof().LiteClientProof)
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}
	// batch_transactions.batch_id is a real foreign key, so the blob needs a
	// batch to hang off. Creating one keeps this fixture on the same schema
	// production enforces rather than a relaxed copy of it.
	batchID := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, tx_count, transaction_count, target_chain)
		VALUES ($1, 'on_demand', 'pending', 1, 1, 'base-sepolia')`, batchID); err != nil {
		t.Fatalf("insert anchor_batches: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, chained_proof)
		VALUES ($1, $2, $3, 0, $4)`,
		batchID, txHash, cp.Input.Account, blob); err != nil {
		t.Fatalf("insert batch_transactions: %v", err)
	}

	return proofID
}

// =============================================================================
// Gate 5 — a proof read back from PostgreSQL verifies offline.
// =============================================================================

func TestP6_StoredProofVerifiesOffline(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	for _, fixture := range []string{"proof_bvn1.json", "proof_bvn3.json"} {
		t.Run(fixture, func(t *testing.T) {
			cp := p6LoadFixture(t, fixture)
			proofID := p6Store(ctx, t, db, cp)

			store := certenproof.NewPostgresProofStorage(db)
			got, err := certenproof.VerifyStoredProof(ctx, store, proofID)
			if err != nil {
				t.Fatalf("GATE 5 FAILED: a proof written today does not verify when read back "+
					"from PostgreSQL with the network disabled: %v", err)
			}

			// The reassembly must be the proof that was stored, not a proof
			// that merely happens to verify.
			if got.Layer1.Leaf != cp.Layer1.Leaf {
				t.Errorf("reassembled a different proof: leaf %s != %s", got.Layer1.Leaf, cp.Layer1.Leaf)
			}
			if got.Layer4BVN.Partition != cp.Layer4BVN.Partition || got.Layer4DN.Partition != cp.Layer4DN.Partition {
				t.Errorf("reassembled the wrong legs: %s/%s != %s/%s",
					got.Layer4BVN.Partition, got.Layer4DN.Partition,
					cp.Layer4BVN.Partition, cp.Layer4DN.Partition)
			}
			t.Logf("verified from storage, network disabled: L1..L3 receipts recomputed; "+
				"L4-%s %d sigs / threshold %d; L4-%s %d sigs / threshold %d",
				got.Layer4BVN.Partition, len(got.Layer4BVN.Signatures), got.Layer4BVN.Threshold,
				got.Layer4DN.Partition, len(got.Layer4DN.Signatures), got.Layer4DN.Threshold)
		})
	}
}

// TestP6_SummaryOnlyProofIsNotReportedVerified covers the other half of
// honesty: a proof stored the OLD way must come back as ErrSummaryOnly, not as
// a proof that fails verification and certainly not as one that passes.
//
// "Not verifiable from storage" and "verified" are different facts, and a
// reader that cannot tell them apart will eventually report the first as the
// second.
func TestP6_SummaryOnlyProofIsNotReportedVerified(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	cp := p6LoadFixture(t, "proof_bvn1.json")
	proofID := p6Store(ctx, t, db, cp)

	// Reduce the record to its pre-Phase-6 state: layer-4 rows gone, and the
	// blob's L4 evidence stripped, leaving only the conclusions.
	if _, err := db.ExecContext(ctx, `DELETE FROM chained_proof_layers WHERE proof_id = $1 AND layer_number = 4`, proofID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE batch_transactions SET chained_proof =
			chained_proof #- '{complete_proof,layer4Bvn}' #- '{complete_proof,layer4Dn}'
		WHERE accumulate_tx_hash = (SELECT accum_tx_hash FROM proof_artifacts WHERE proof_id = $1)`, proofID); err != nil {
		t.Fatal(err)
	}

	store := certenproof.NewPostgresProofStorage(db)
	_, err := certenproof.ChainedProofFromStorage(ctx, store, proofID)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: a proof with no stored L4 evidence was reassembled as if complete")
	}
	if !strings.Contains(err.Error(), certenproof.ErrSummaryOnly.Error()) {
		t.Fatalf("expected ErrSummaryOnly, got a different failure: %v", err)
	}
	t.Logf("summary-only proof correctly refused: %v", err)
}

// =============================================================================
// Gate 5, second half — every mutation of the STORED bytes is rejected.
// =============================================================================

// p6Mutation edits the stored evidence in place. Each returns a description of
// what it broke.
type p6Mutation struct {
	name string
	// apply mutates the DN leg (or whatever it chooses) as stored, in BOTH the
	// row and the blob, so the mutation is genuinely "what is in the database"
	// rather than a copy the reader ignores.
	apply func(t *testing.T, ctx context.Context, db *sql.DB, proofID uuid.UUID, cp *chained_proof.ChainedProof)
}

// p6RewriteDNLeg replaces the stored DN leg everywhere it lives.
func p6RewriteDNLeg(t *testing.T, ctx context.Context, db *sql.DB, proofID uuid.UUID, leg *chained_proof.Layer4) {
	t.Helper()
	raw, err := json.Marshal(leg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE chained_proof_layers SET layer_json = $2 WHERE proof_id = $1 AND layer_number = 4 AND layer_name = $3`,
		proofID, raw, Layer4DNRowName); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE batch_transactions
		SET chained_proof = jsonb_set(chained_proof, '{complete_proof,layer4Dn}', $2::jsonb)
		WHERE accumulate_tx_hash = (SELECT accum_tx_hash FROM proof_artifacts WHERE proof_id = $1)`,
		proofID, string(raw)); err != nil {
		t.Fatal(err)
	}
}

// p6FlipHexByte flips the low bit of the first nibble, producing a different
// but still well-formed hex string.
func p6FlipHexByte(s string) string {
	if s == "" {
		return s
	}
	const digits = "0123456789abcdef"
	i := strings.IndexByte(digits, s[0])
	if i < 0 {
		return s
	}
	return string(digits[(i+1)%16]) + s[1:]
}

func TestP6_StoredProofRejectsTampering(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	// The graft source: a DIFFERENT proof's DN leg. Its signatures are
	// perfectly valid — they just attest to another anchor, which is exactly
	// what makes it the right negative test.
	other := p6LoadFixture(t, "proof_bvn3.json")

	mutations := []p6Mutation{
		{"flip one byte of a stored signature", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			leg := *cp.Layer4DN
			leg.Signatures = append([]chained_proof.AnchorSignature(nil), leg.Signatures...)
			leg.Signatures[0].Signature = p6FlipHexByte(leg.Signatures[0].Signature)
			p6RewriteDNLeg(t, ctx, db, id, &leg)
		}},
		{"drop a signature below threshold", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			leg := *cp.Layer4DN
			// Threshold is 2 of 3 on the DN leg; one signature cannot meet it.
			leg.Signatures = append([]chained_proof.AnchorSignature(nil), leg.Signatures[:1]...)
			p6RewriteDNLeg(t, ctx, db, id, &leg)
		}},
		{"substitute a validator not in the set", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			leg := *cp.Layer4DN
			leg.Signatures = append([]chained_proof.AnchorSignature(nil), leg.Signatures...)
			leg.Signatures[0].PublicKey = p6FlipHexByte(leg.Signatures[0].PublicKey)
			p6RewriteDNLeg(t, ctx, db, id, &leg)
		}},
		{"alter stored stateTreeAnchor", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			leg := *cp.Layer4DN
			leg.StateTreeAnchor = p6FlipHexByte(leg.StateTreeAnchor)
			p6RewriteDNLeg(t, ctx, db, id, &leg)
		}},
		{"alter stored sequencedMessage", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			leg := *cp.Layer4DN
			leg.SequencedMessage = p6FlipHexByte(leg.SequencedMessage)
			p6RewriteDNLeg(t, ctx, db, id, &leg)
		}},
		{"graft another proof's stored DN leg", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			p6RewriteDNLeg(t, ctx, db, id, other.Layer4DN)
		}},
		{"alter a stored L1 receipt entry", func(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, cp *chained_proof.ChainedProof) {
			l1 := cp.Layer1
			l1.Receipt.Entries = append([]chained_proof.ReceiptStep(nil), l1.Receipt.Entries...)
			l1.Receipt.Entries[0].Hash = p6FlipHexByte(l1.Receipt.Entries[0].Hash)
			raw, err := json.Marshal(l1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `
				UPDATE chained_proof_layers SET layer_json = jsonb_set(layer_json, '{layer1}', $2::jsonb)
				WHERE proof_id = $1 AND layer_number = 1`, id, string(raw)); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			cp := p6LoadFixture(t, "proof_bvn1.json")
			proofID := p6Store(ctx, t, db, cp)
			store := certenproof.NewPostgresProofStorage(db)

			// The untampered record must verify first. Without this, a
			// mutation "rejected" for an unrelated reason would look like a
			// pass and the gate would be worthless.
			if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err != nil {
				t.Fatalf("baseline stored proof does not verify, so this mutation proves nothing: %v", err)
			}

			m.apply(t, ctx, db, proofID, cp)

			if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err == nil {
				t.Fatalf("CRITICAL DEFECT: tampering %q was ACCEPTED from storage. "+
					"The evidence is being stored and not checked.", m.name)
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

// TestP6_BlobIsPreferredOverRows pins the precedence ChainedProofFromStorage
// documents, by making the two sources DISAGREE and checking which one wins.
//
// This matters because it decides where an auditor looks. If the rows silently
// won, the travelling artifact could be tampered with and a verification run
// against the database would still pass — reporting the blob as sound when it
// is not.
func TestP6_BlobIsPreferredOverRows(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	cp := p6LoadFixture(t, "proof_bvn1.json")
	proofID := p6Store(ctx, t, db, cp)
	store := certenproof.NewPostgresProofStorage(db)

	if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err != nil {
		t.Fatalf("baseline does not verify: %v", err)
	}

	// Corrupt ONLY the blob's DN leg; leave the row intact.
	bad := *cp.Layer4DN
	bad.StateTreeAnchor = p6FlipHexByte(bad.StateTreeAnchor)
	raw, err := json.Marshal(&bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE batch_transactions
		SET chained_proof = jsonb_set(chained_proof, '{complete_proof,layer4Dn}', $2::jsonb)
		WHERE accumulate_tx_hash = (SELECT accum_tx_hash FROM proof_artifacts WHERE proof_id = $1)`,
		proofID, string(raw)); err != nil {
		t.Fatal(err)
	}

	if _, err := certenproof.VerifyStoredProof(ctx, store, proofID); err == nil {
		t.Fatal("CRITICAL DEFECT: a tampered travelling blob was masked by the intact layer row. " +
			"A verification run would report the blob as sound when it is not.")
	} else {
		t.Logf("blob precedence confirmed — tampering the blob alone is caught: %v", err)
	}
}

// TestP6_FiveLayerRowsPerProof is Gate 3 / P6.3.
//
// Five rows, not three: 1, 2, 3, and one layer-4 row per SIGNING PARTITION.
// The two layer-4 rows must carry different partitions — if both legs came
// from the same signing set, one leg is redundant and the BVN->DN hop is
// unwitnessed, which is a proof of something other than what it claims.
func TestP6_FiveLayerRowsPerProof(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()

	cp := p6LoadFixture(t, "proof_bvn1.json")
	proofID := p6Store(ctx, t, db, cp)

	rows, err := db.QueryContext(ctx, `
		SELECT layer_number, layer_name, bvn_partition, signature_count, threshold, length(signed_hash)
		FROM chained_proof_layers WHERE proof_id = $1 ORDER BY layer_number, layer_name`, proofID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type row struct {
		num       int
		name      string
		partition *string
		sigCount  *int
		threshold *int
		shLen     *int
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.num, &r.name, &r.partition, &r.sigCount, &r.threshold, &r.shLen); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 5 {
		t.Fatalf("GATE 3 FAILED: expected 5 layer rows (1,2,3,4-BVN,4-DN), got %d: %+v", len(got), got)
	}

	for i, want := range []int{1, 2, 3, 4, 4} {
		if got[i].num != want {
			t.Fatalf("row %d is layer %d, expected %d", i, got[i].num, want)
		}
	}

	// The state layers carry no quorum, and must not pretend to.
	for i := 0; i < 3; i++ {
		if got[i].sigCount != nil || got[i].threshold != nil || got[i].shLen != nil {
			t.Errorf("layer %d has quorum projections set; only layer 4 has a quorum", got[i].num)
		}
	}

	// The two quorum legs.
	bvn, dn := got[3], got[4]
	if bvn.name != Layer4BVNRowName || dn.name != Layer4DNRowName {
		t.Fatalf("layer-4 rows are named %q / %q, expected %q / %q",
			bvn.name, dn.name, Layer4BVNRowName, Layer4DNRowName)
	}
	if bvn.partition == nil || dn.partition == nil {
		t.Fatal("a layer-4 row with no partition cannot say whose quorum signed it")
	}
	if *bvn.partition == *dn.partition {
		t.Fatalf("both layer-4 rows are partition %q; the BVN->DN hop is not witnessed", *bvn.partition)
	}
	if *dn.partition != "Directory" {
		t.Errorf("DN leg partition is %q, expected Directory", *dn.partition)
	}
	for _, r := range []row{bvn, dn} {
		if r.sigCount == nil || *r.sigCount == 0 {
			t.Errorf("%s: signature_count is not set", r.name)
		}
		if r.threshold == nil || *r.threshold == 0 {
			t.Errorf("%s: threshold is not set — a zero threshold no signature set can fail", r.name)
		}
		if r.shLen == nil || *r.shLen != 32 {
			t.Errorf("%s: signed_hash is not 32 bytes", r.name)
		}
	}

	t.Logf("5 rows: 1, 2, 3, 4-%s (%d sigs / threshold %d), 4-%s (%d sigs / threshold %d)",
		*bvn.partition, *bvn.sigCount, *bvn.threshold,
		*dn.partition, *dn.sigCount, *dn.threshold)
}

// TestP6_NilLegWritesNoRow pins rule 8: a nil leg is a broken pipeline, not a
// row to write.
//
// The failure mode this forbids is the quiet one — writing the BVN row,
// failing on the DN row, and leaving a record that looks like evidence and can
// never verify. Half a proof is not half as good; it is unverifiable, which is
// the state this phase exists to end.
func TestP6_NilLegWritesNoRow(t *testing.T) {
	cp := p6LoadFixture(t, "proof_bvn1.json")

	for _, tc := range []struct {
		name string
		mut  func(c *chained_proof.ChainedProof)
	}{
		{"BVN leg nil", func(c *chained_proof.ChainedProof) { c.Layer4BVN = nil }},
		{"DN leg nil", func(c *chained_proof.ChainedProof) { c.Layer4DN = nil }},
		{"both legs nil", func(c *chained_proof.ChainedProof) { c.Layer4BVN, c.Layer4DN = nil, nil }},
		{"both legs same partition", func(c *chained_proof.ChainedProof) { c.Layer4BVN = c.Layer4DN }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *cp
			tc.mut(&c)
			rows, err := BuildLayer4Rows(uuid.New(), &c)
			if err == nil {
				t.Fatalf("CRITICAL DEFECT: %s produced %d rows instead of an error", tc.name, len(rows))
			}
			if rows != nil {
				t.Fatalf("CRITICAL DEFECT: %s returned rows alongside an error — a caller that ignores "+
					"the error would write a half record", tc.name)
			}
			t.Logf("refused: %v", err)
		})
	}

	if _, err := BuildLayer4Rows(uuid.New(), nil); err == nil {
		t.Fatal("a nil chained proof must not produce layer-4 rows")
	}
}
