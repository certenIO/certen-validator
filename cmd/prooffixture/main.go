// Command prooffixture writes one stored proof out as a test fixture: the L1-L4 chained proof reassembled from storage
// and verified, the stored G0-G2 results, and the G1 level's vote record and its evidence, the record evaluated again
// from that evidence before anything is written. It reads only through the storage readers cmd/proofverify uses, so
// the fixture is exactly what a verifier of the stored proof sees.
//
// Run it against a session forced read-only (options=-c default_transaction_read_only=on); it writes nothing to the
// database.
//
//	prooffixture --db "$CERTEN_DB" --proof-prefix e1e34338 --out fixture.json
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// Fixture is the file this command writes.
type Fixture struct {
	ProofID      uuid.UUID                   `json:"proof_id"`
	ChainedProof *chained_proof.ChainedProof `json:"chained_proof"`
	// G0, G1, G2 are the stored results exactly as stored.
	G0 json.RawMessage `json:"g0"`
	G1 json.RawMessage `json:"g1"`
	G2 json.RawMessage `json:"g2"`
	// Authorization and VoteEvidence are the G1 level's vote record and its evidence.
	Authorization json.RawMessage `json:"authorization"`
	VoteEvidence  json.RawMessage `json:"vote_evidence"`
}

func main() {
	dsn := flag.String("db", os.Getenv("CERTEN_DB"), "PostgreSQL DSN (a read-only session)")
	prefix := flag.String("proof-prefix", "", "a proof id, or a prefix of exactly one")
	out := flag.String("out", "", "file to write")
	flag.Parse()
	if *dsn == "" || *prefix == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: prooffixture --db <dsn> --proof-prefix <id or prefix> --out <file>")
		os.Exit(2)
	}
	if err := run(*dsn, *prefix, *out); err != nil {
		fmt.Fprintln(os.Stderr, "prooffixture:", err)
		os.Exit(1)
	}
}

func run(dsn, prefix, out string) error {
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var readOnly string
	if err := db.QueryRowContext(ctx, `SHOW default_transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		return fmt.Errorf("the session is not read-only (default_transaction_read_only=%q, %v)", readOnly, err)
	}
	rows, err := db.QueryContext(ctx, `SELECT proof_id FROM proof_artifacts WHERE proof_id::text LIKE $1 || '%' LIMIT 2`, prefix)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 1 {
		return fmt.Errorf("%q names %d proofs, not one", prefix, len(ids))
	}
	f := Fixture{ProofID: ids[0]}

	store := certenproof.NewPostgresProofStorage(db)
	if f.ChainedProof, err = certenproof.VerifyStoredProof(ctx, store, f.ProofID); err != nil {
		return fmt.Errorf("L1-L4: %w", err)
	}
	levels, err := certenproof.GovernanceLevelsFromStorage(ctx, store, f.ProofID)
	if err != nil {
		return err
	}
	for _, l := range levels {
		switch l.Level {
		case "G0":
			f.G0 = l.Result
		case "G1":
			f.G1 = l.Result
			f.Authorization = l.Flags[execution.GovLevelAuthorizationKey]
			f.VoteEvidence = l.Flags[execution.GovLevelVoteEvidenceKey]
		case "G2":
			f.G2 = l.Result
		}
	}
	if len(f.G0) == 0 || len(f.G1) == 0 || len(f.G2) == 0 || len(f.Authorization) == 0 || len(f.VoteEvidence) == 0 {
		return fmt.Errorf("the proof does not store all of G0, G1, G2, the vote record and its evidence")
	}
	var g0 certenproof.G0Result
	if err := json.Unmarshal(f.G0, &g0); err != nil {
		return fmt.Errorf("G0: %w", err)
	}
	var rec certenproof.AuthorizationRecord
	if err := json.Unmarshal(f.Authorization, &rec); err != nil {
		return fmt.Errorf("the vote record: %w", err)
	}
	ev, err := certenproof.DecodeVoteEvidence(f.VoteEvidence)
	if err != nil {
		return err
	}
	if err := certenproof.VerifyVoteEvidence(ctx, &g0, ev, &rec); err != nil {
		return fmt.Errorf("the vote record does not evaluate again from its evidence: %w", err)
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("proof %s: L1-L4 verified, vote record evaluated again from its evidence; %d bytes to %s\n", f.ProofID, len(b), out)
	return nil
}
