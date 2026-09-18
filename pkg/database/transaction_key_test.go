// Copyright 2025 Certen Protocol

package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestTransactionHashKey(t *testing.T) {
	hash := strings.Repeat("0e", 32)
	for input, want := range map[string]string{
		"acc://" + hash + "@spk-cust-tcl1.acme/data": hash,
		"acc://" + strings.ToUpper(hash) + "@x.acme": hash,
		hash:                        hash,
		strings.ToUpper(hash):       hash,
		"  " + hash + "\n":          hash,
		"acc://" + hash:             "acc://" + hash, // no principal: not a transaction ID
		"acc://" + hash[:62] + "@x": "acc://" + hash[:62] + "@x",
		"acc://not-a-hash@x.acme":   "acc://not-a-hash@x.acme",
		"0x" + hash:                 "0x" + hash,
		"records_tx_Mixed-Case":     "records_tx_Mixed-Case",
		"":                          "",
	} {
		if got := TransactionHashKey(input); got != want {
			t.Errorf("TransactionHashKey(%q) = %q, want %q", input, got, want)
		}
	}
}

// Every lookup of an Accumulate transaction finds what is stored under its bare hash when it is named by
// its transaction ID, in any case and with any principal, and still finds nothing for another transaction.
func TestTransactionLookupsAcceptTheTransactionID(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	client := NewClientFromDB(testDB)
	artifacts := NewProofArtifactRepository(testDB)

	hash := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	other := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	forms := map[string]string{
		"bare":                        hash,
		"bare upper-case":             strings.ToUpper(hash),
		"transaction ID":              "acc://" + hash + "@txkey.acme/data",
		"upper-case, other principal": "acc://" + strings.ToUpper(hash) + "@someone-else.acme",
	}
	missing := "acc://" + other + "@txkey.acme/data"

	artifact, err := artifacts.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType: ProofTypeCertenAnchor, AccumTxHash: hash, AccountURL: "acc://txkey.acme/data",
		ProofClass: ProofClassOnDemand, ValidatorID: "txkey", ArtifactJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}
	batchID, intentID := uuid.New(), "intent-"+uuid.NewString()
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = testDB.ExecContext(bg, `DELETE FROM proof_requests WHERE accum_tx_hash LIKE '%' || $1 || '%'`, hash)
		_, _ = testDB.ExecContext(bg, `DELETE FROM proof_requests WHERE accum_tx_hash LIKE '%' || $1 || '%'`, other)
		_, _ = testDB.ExecContext(bg, `DELETE FROM intent_lifecycle WHERE intent_id = $1`, intentID)
		_, _ = testDB.ExecContext(bg, `DELETE FROM certen_anchor_proofs WHERE proof_artifact_id = $1`, artifact.ProofID)
		_, _ = testDB.ExecContext(bg, `DELETE FROM proof_bundles WHERE proof_id = $1`, artifact.ProofID)
		_, _ = testDB.ExecContext(bg, `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
		_, _ = testDB.ExecContext(bg, `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})

	bundle, err := artifacts.CreateProofBundle(ctx, &NewProofBundle{
		ProofID: artifact.ProofID, BundleFormat: "json", BundleVersion: "1.0", BundleData: []byte(`{}`),
		BundleHash: hash32("bundle-" + hash), BundleSizeBytes: 2,
	})
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_batches (id) VALUES ($1)`, batchID); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id)
		VALUES ($1, $2, 'acc://txkey.acme/data', 0, $3)`, batchID, hash, intentID); err != nil {
		t.Fatal(err)
	}
	lifecycle := NewIntentLifecycleRepository(client)
	if err := lifecycle.UpsertOnDiscovery(ctx, intentID, hash, 1, "", "on_demand", "base-sepolia"); err != nil {
		t.Fatalf("create lifecycle: %v", err)
	}
	proofs := NewProofRepository(client)
	certen, err := proofs.CreateProof(ctx, &NewCertenAnchorProof{
		ProofArtifactID: artifact.ProofID, AccumTxHash: hash, AccountURL: artifact.AccountURL,
		MerkleRoot: hash32("root-" + hash), AnchorChain: TargetChain("base-sepolia"), AnchorTxHash: "0x" + other,
		AnchorBlockNumber: 1,
	})
	if err != nil {
		t.Fatalf("create certen proof: %v", err)
	}
	requests := NewRequestRepository(client)
	// Stored as clients send it: the transaction ID.
	request, err := requests.CreateRequest(ctx, &NewProofRequest{
		AccumTxHash: "acc://" + hash + "@txkey.acme/data", RequestType: RequestTypeOnDemand,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	batches := NewBatchRepository(client)

	for name, value := range forms {
		if got, err := artifacts.GetProofByTxHash(ctx, value); err != nil || got == nil || got.ProofID != artifact.ProofID {
			t.Errorf("%s: GetProofByTxHash = %+v, %v", name, got, err)
		}
		if got, err := artifacts.GetProofBundleByTxHash(ctx, value); err != nil || got == nil || got.BundleID != bundle.BundleID {
			t.Errorf("%s: GetProofBundleByTxHash = %+v, %v", name, got, err)
		}
		v := value
		if got, err := artifacts.QueryProofs(ctx, &ProofArtifactFilter{AccumTxHash: &v}); err != nil || len(got) != 1 || got[0].ProofID != artifact.ProofID {
			t.Errorf("%s: QueryProofs by transaction = %+v, %v", name, got, err)
		}
		if got, err := batches.GetTransactionByAccumHash(ctx, value); err != nil || got.IntentID.String != intentID {
			t.Errorf("%s: GetTransactionByAccumHash = %+v, %v", name, got, err)
		}
		if got, err := lifecycle.GetByTxHash(ctx, value); err != nil || got == nil || got.IntentID != intentID {
			t.Errorf("%s: IntentLifecycle.GetByTxHash = %+v, %v", name, got, err)
		}
		if got, err := proofs.GetProofByAccumTxHash(ctx, value); err != nil || got == nil || got.ProofID != certen.ProofID {
			t.Errorf("%s: GetProofByAccumTxHash = %+v, %v", name, got, err)
		}
		if got, err := requests.GetRequestByAccumTxHash(ctx, value); err != nil || got == nil || got.RequestID != request.RequestID {
			t.Errorf("%s: GetRequestByAccumTxHash = %+v, %v", name, got, err)
		}
	}

	// Another transaction finds none of it.
	if got, err := artifacts.GetProofByTxHash(ctx, missing); err == nil && got != nil {
		t.Errorf("GetProofByTxHash found %s for another transaction", got.ProofID)
	}
	if got, err := batches.GetTransactionByAccumHash(ctx, missing); err == nil && got != nil {
		t.Errorf("GetTransactionByAccumHash found %d for another transaction", got.ID)
	}
	if got, err := proofs.GetProofByAccumTxHash(ctx, missing); err == nil && got != nil {
		t.Errorf("GetProofByAccumTxHash found %s for another transaction", got.ProofID)
	}
	if got, err := requests.GetRequestByAccumTxHash(ctx, missing); err == nil && got != nil {
		t.Errorf("GetRequestByAccumTxHash found %s for another transaction", got.RequestID)
	}

	// A request stored under the bare hash is found by its transaction ID too.
	bare, err := requests.CreateRequest(ctx, &NewProofRequest{AccumTxHash: other, RequestType: RequestTypeOnDemand})
	if err != nil {
		t.Fatalf("create bare request: %v", err)
	}
	if got, err := requests.GetRequestByAccumTxHash(ctx, missing); err != nil || got == nil || got.RequestID != bare.RequestID {
		t.Errorf("a request stored under the bare hash was not found by its transaction ID: %+v, %v", got, err)
	}
}
