// Copyright 2026 Certen Protocol

package finalitytest

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// The database shape production writes for a settled leg (pkg/execution generateAndPersistBundle), which the leg source
// (pkg/database FinalityAddendaRepository) reads:
//
//   - proof_artifacts.artifact_json is the cycle SUMMARY only: chain_id, cycle_id, threshold_met, chain_platform,
//     write_back_state, execution_outcome, attestation_scheme, write_back_success, execution_tx_hashes. It never carries
//     proof_components. The row's settlement_tx_hash and settlement_block_number columns are set once the leg settled.
//   - the full bundle is a proof_bundles row (bundle_format certen_v1): bundle_data is the GZIP of the bundle JSON, whose
//     proof_components member holds component 5, the execution proof, beside the other components.
//
// Tests seed exactly this shape. An earlier seeding put proof_components inside artifact_json, which production never
// writes, so the source read a column production could not satisfy and every test passed.

// ProductionSummary is the artifact_json of a settled leg of the given chain: the summary, with no proof_components.
func ProductionSummary(chain uint64) []byte {
	raw, err := json.Marshal(map[string]any{
		"chain_id":            strconv.FormatUint(chain, 10),
		"cycle_id":            "cycle-" + strconv.FormatUint(chain, 10),
		"threshold_met":       true,
		"chain_platform":      "evm",
		"write_back_state":    "confirmed",
		"execution_outcome":   "success",
		"attestation_scheme":  "bls12-381",
		"write_back_success":  true,
		"execution_tx_hashes": []string{},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

// ProductionExecutionProof is component 5 as production stores it (pkg/proof ExecutionProof): the settlement's own fields
// plus the chain id, the block number, the status, both roots, the raw receipt, the decoded logs and who verified it.
func ProductionExecutionProof(t testing.TB, s finality.Settlement) map[string]any {
	t.Helper()
	raw, err := json.Marshal(s.Included)
	if err != nil {
		t.Fatal(err)
	}
	exec := map[string]any{}
	if err := json.Unmarshal(raw, &exec); err != nil {
		t.Fatal(err)
	}
	header, _, err := s.Included.Verify()
	if err != nil {
		t.Fatalf("the settlement does not verify: %v", err)
	}
	receipt, ok := exec["receipt_inclusion_proof"].(map[string]any)
	if !ok {
		t.Fatal("the settlement carries no receipt proof")
	}
	exec["chain_id"] = strconv.FormatUint(s.Chain, 10)
	exec["block_number"] = header.Number.Uint64()
	exec["status"] = 1
	exec["transactions_root"] = header.TxHash.Hex()
	exec["receipts_root"] = header.ReceiptHash.Hex()
	exec["raw_receipt"] = receipt["leaf_value"]
	exec["logs"] = []any{}
	exec["verified_by"] = "validator-test"
	exec["verified_at"] = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	return exec
}

// ProductionBundleJSON is the JSON document a certen_v1 bundle holds (pkg/proof CertenProofBundle): the same top-level members, with
// bundle_integrity.custody_chain_hash set to the proof id as the writer sets it (lower-case hex, no dashes),
// the components keyed as production keys them. A nil exec leaves component 5 out, as a bundle without a receipt proof does.
func ProductionBundleJSON(proofID string, exec map[string]any) []byte {
	components := map[string]any{
		"1_merkle_inclusion": map[string]any{"leaf_hash": "00"},
		"2_anchor_reference": map[string]any{"anchor_tx": "0x00"},
		"3_chained_proof":    map[string]any{"layers": []any{}},
		"4_governance_proof": map[string]any{"level": "G0"},
	}
	if exec != nil {
		components["5_execution_proof"] = exec
	}
	raw, err := json.Marshal(map[string]any{
		"$schema":   "https://certen.io/schemas/proof-bundle/v1.0",
		"bundle_id": "bundle-test",
		"bundle_integrity": map[string]any{"artifact_hash": "sha256:00", "bundle_signature": "", "signer_id": "validator-test",
			"custody_chain_hash": strings.ReplaceAll(strings.ToLower(proofID), "-", "")},
		"bundle_version":         "1.0",
		"generated_at":           time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"proof_components":       components,
		"transaction_reference":  map[string]any{"accum_tx_hash": "00", "account_url": "acc://finality-test.acme/tokens"},
		"validator_attestations": []any{},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

// Gzip compresses a bundle document as production stores it in proof_bundles.bundle_data.
func Gzip(doc []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(doc); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// StoreProductionArtifact inserts a proof_artifacts row in the production shape (summary artifact_json, settlement columns
// set when settlementBlock is non-zero) and returns its proof id. It writes with plain SQL so any package's tests can use it.
func StoreProductionArtifact(t testing.TB, db *sql.DB, chain uint64, settlementTx string, settlementBlock uint64) string {
	t.Helper()
	summary := ProductionSummary(chain)
	hash := sha256.Sum256(summary)
	var tx any
	var block any
	if settlementBlock != 0 {
		tx, block = settlementTx, int64(settlementBlock)
	}
	var id string
	err := db.QueryRow(`INSERT INTO proof_artifacts (proof_type, accum_tx_hash, account_url, proof_class, validator_id,
			artifact_json, artifact_hash, chain_platform, target_chain, settlement_tx_hash, settlement_block_number)
		VALUES ('certen_anchor', 'prod_' || substr(md5(random()::text), 1, 12), 'acc://finality-test.acme/tokens', 'on_cadence', 'test-validator-1',
			$1::jsonb, $2, 'evm', $3, $4, $5) RETURNING proof_id::text`,
		string(summary), hash[:], strconv.FormatUint(chain, 10), tx, block).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// StoreBundleRow inserts a proof_bundles row (certen_v1) holding data, which is the gzip of a bundle document in production.
func StoreBundleRow(t testing.TB, db *sql.DB, proofID string, data []byte) {
	t.Helper()
	hash := sha256.Sum256(data)
	if _, err := db.Exec(`INSERT INTO proof_bundles (proof_id, bundle_format, bundle_version, bundle_data, bundle_hash, bundle_size_bytes)
		VALUES ($1::uuid, 'certen_v1', '1.0', $2, $3, $4)`, proofID, data, hash[:], len(data)); err != nil {
		t.Fatal(err)
	}
}

// StoreProductionLeg stores the leg of a settlement exactly as production does and returns its proof id: a summary-only
// proof_artifacts row with its settlement columns, and the gzip bundle (execution proof included) in proof_bundles.
func StoreProductionLeg(t testing.TB, db *sql.DB, s finality.Settlement) string {
	t.Helper()
	exec := ProductionExecutionProof(t, s)
	id := StoreProductionArtifact(t, db, s.Chain, exec["tx_hash"].(string), exec["block_number"].(uint64))
	StoreBundleRow(t, db, id, Gzip(ProductionBundleJSON(id, exec)))
	return id
}
