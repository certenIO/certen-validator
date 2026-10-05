package main

import (
	"compress/gzip"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	schema "github.com/certen/independant-validator/db"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const kermitPin = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

func gunzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The shadow's exit check: a stored v2 proof that verifies and agrees with v1's replay exits 0; one page that differs
// from v1's replay exits 1, named.
func TestShadowExitCheck(t *testing.T) {
	dsn := os.Getenv("CERTEN_TEST_DB")
	if dsn == "" {
		t.Fatal("CERTEN_TEST_DB is required: this test runs against PostgreSQL (a skipped gate is not a green gate)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(t.Context(), "proofv2report-test"); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DELETE FROM proof_v2_shadow`, `DELETE FROM proof_v2_spine`, `DELETE FROM governance_proof_levels WHERE level_name = 'proofv2report-test'`,
		`DELETE FROM proof_artifacts WHERE validator_id = 'proofv2report-test'`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	// The spine and a live Kermit proof with three pages (pkg/proof/v2 testdata).
	ar, err := proofv2.UnmarshalArchive(gunzip(t, "../../pkg/proof/v2/testdata/archive.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range ar.Majors {
		b, _ := m.MarshalBinary()
		if _, err := db.Exec(`INSERT INTO proof_v2_spine (major_index, record) VALUES ($1, $2)`, i+1, b); err != nil {
			t.Fatal(err)
		}
	}
	evRaw := gunzip(t, "../../pkg/proof/v2/testdata/evidence_3cfb04cf.json.gz")
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(evRaw, ev); err != nil {
		t.Fatal(err)
	}
	const intent = "proofv2report-test-intent"
	if _, err := db.Exec(`INSERT INTO proof_v2_shadow (intent_id, accum_tx_hash, account_url, evidence, verdict) VALUES ($1, $2, $3, $4, 'verified')`,
		intent, ev.TxHash, ev.Account, evRaw); err != nil {
		t.Fatal(err)
	}

	// v1's replay of each key page, as G1 stores it: authoritySnapshot.stateExec.
	var snaps []map[string]any
	for _, p := range ev.Pages {
		raw, _ := hex.DecodeString(p.State)
		acct, err := protocol.UnmarshalAccount(raw)
		if err != nil {
			t.Fatal(err)
		}
		kp, ok := acct.(*protocol.KeyPage)
		if !ok {
			continue
		}
		var keys []string
		for _, k := range kp.Keys {
			keys = append(keys, hex.EncodeToString(k.PublicKeyHash))
		}
		snaps = append(snaps, map[string]any{"page": kp.Url.String(), "stateExec": map[string]any{"version": kp.Version, "threshold": kp.AcceptThreshold, "keys": keys}})
	}
	if len(snaps) != 2 {
		t.Fatalf("fixture has %d key pages, want 2", len(snaps))
	}
	levelJSON, _ := json.Marshal(map[string]any{"authorizations": []any{map[string]any{"authoritySnapshot": snaps[0]}, map[string]any{"authoritySnapshot": snaps[1]}}})
	var proofID string
	if err := db.QueryRow(`INSERT INTO proof_artifacts (proof_type, accum_tx_hash, account_url, proof_class, validator_id, artifact_json, artifact_hash, intent_id)
		VALUES ('governance', $1, $2, 'on_demand', 'proofv2report-test', '{}', '\x00', $3) RETURNING proof_id`, ev.TxHash, ev.Account, intent).Scan(&proofID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO governance_proof_levels (proof_id, gov_level, level_name, level_json) VALUES ($1, 'G1', 'proofv2report-test', $2)`, proofID, levelJSON); err != nil {
		t.Fatal(err)
	}

	inc := "../../pkg/proof/testdata/incarnation/kermit.json"
	if code, err := run(dsn, inc, kermitPin, ""); err != nil || code != 0 {
		t.Fatalf("agreeing shadow: exit %d, %v", code, err)
	}

	// v1 replayed a different threshold for one page: a disagreement, and the exit check fails.
	snaps[0]["stateExec"].(map[string]any)["threshold"] = 99
	levelJSON, _ = json.Marshal(map[string]any{"authorizations": []any{map[string]any{"authoritySnapshot": snaps[0]}, map[string]any{"authoritySnapshot": snaps[1]}}})
	if _, err := db.Exec(`UPDATE governance_proof_levels SET level_json = $1 WHERE level_name = 'proofv2report-test'`, levelJSON); err != nil {
		t.Fatal(err)
	}
	if code, err := run(dsn, inc, kermitPin, ""); err != nil || code != 1 {
		t.Fatalf("disagreeing shadow: exit %d, %v (want 1)", code, err)
	}

	// A failed build fails the exit check too.
	if _, err := db.Exec(`UPDATE governance_proof_levels SET level_json = '{}' WHERE level_name = 'proofv2report-test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO proof_v2_shadow (intent_id, accum_tx_hash, account_url, verdict, error) VALUES ('proofv2report-test-failed', 'ff', 'acc://x', 'failed', 'g1_historical_unavailable')`); err != nil {
		t.Fatal(err)
	}
	if code, err := run(dsn, inc, kermitPin, ""); err != nil || code != 1 {
		t.Fatalf("a failed build: exit %d, %v (want 1)", code, err)
	}
}
