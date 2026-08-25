// Copyright 2026 Certen Protocol
//
// Stage 2 Gates 2c and 2d — THE GATES THIS STAGE EXISTS FOR.
//
// A governance level is written to PostgreSQL through the SHARED construction
// helper every writer calls, read back through GovernanceLevelsFromStorage, and
// its receipt is recomputed FROM level_json ALONE with the network cut. Then
// every mutation in runbook §2d is applied to the STORED BYTES and must be
// rejected.
//
// # WHY BOTH HALVES ARE REQUIRED
//
// Storing evidence and checking evidence are different claims. A test that only
// asserts fields are present proves the first and says nothing about the second
// — and a verifier that is not actually running will pass such a test on any
// input at all. That is not hypothetical here: before the merkle path was
// captured, "receipt binding" compared a start and an anchor that came from the
// same response, which is self-consistency, not proof. The mutations are what
// distinguishes "we ran the recomputation" from "we returned nil".
//
// # THE FIXTURE IS A REAL ACCUMULATE RECEIPT
//
// layer1.receipt from the working-proof testdata: a genuine 12-step merkle path
// that genuinely recomputes to its own anchor. The offline verifier already
// rejects 34 targeted mutations against these fixtures, so this exercises real
// cryptography rather than a synthetic tree built with the same rule it is
// checked by.
//
//	go test ./pkg/execution/ -run 'TestS2_' -count=1 -v
//
// It needs a PostgreSQL carrying the live schema plus migration 015, addressed
// by CERTEN_TEST_DB. Without it the test SKIPS rather than passing vacuously — a
// skipped gate is not a green gate.
package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
)

// =============================================================================
// Harness
// =============================================================================

// s2Evidence lifts a real receipt out of a working-proof fixture and labels it
// as a governance receipt for one level.
//
// Using layer1.receipt rather than inventing a tree matters: a synthetic path
// built with sha256(left||right) and then checked with sha256(left||right)
// proves the two agree with each other, not that either is right.
func s2Evidence(t *testing.T, fixture, level string) *certenproof.GovReceiptEvidence {
	t.Helper()
	cp := p6LoadFixture(t, fixture)
	r := cp.Layer1.Receipt
	if len(r.Entries) == 0 {
		t.Fatalf("fixture %s layer1.receipt has no merkle path; this gate would be vacuous", fixture)
	}
	return &certenproof.GovReceiptEvidence{
		Level:      level,
		Start:      r.Start,
		Anchor:     r.Anchor,
		LocalBlock: int64(r.LocalBlock),
		Entries:    r.Entries,
	}
}

// s2Flags is the verdict-flag object the writers have always produced. Kept in
// the fixture so the additive rule is exercised: every one of these keys must
// survive into the stored row.
func s2Flags() map[string]interface{} {
	return map[string]interface{}{
		"inclusion_verified": true,
		"finality_achieved":  true,
		"confirmations":      12,
		"threshold_m":        1,
		"threshold_n":        1,
		"authority_url":      "acc://certen-demo.acme/book",
	}
}

// s2StoreProof creates the parent proof_artifacts row the FK requires.
func s2StoreProof(ctx context.Context, t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	proofID := uuid.New()
	txHash := "s2-" + proofID.String()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO proof_artifacts (proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			proof_class, validator_id, status, artifact_json, artifact_hash, verification_status)
		VALUES ($1, 'chained', '3.0', $2, 'acc://certen-demo.acme/data', 'on_demand', 'validator-test',
			'pending', '{}'::jsonb, '\x00'::bytea, 'verified')`, proofID, txHash); err != nil {
		t.Fatalf("insert proof_artifacts: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM governance_proof_levels WHERE proof_id = $1`, proofID)
		db.Exec(`DELETE FROM proof_artifacts WHERE proof_id = $1`, proofID)
	})
	return proofID
}

// s2WriteLevel writes one governance level through the PRODUCTION path: the
// shared BuildGovernanceLevelJSON helper and the real repository call every
// orchestrator uses. Nothing here re-implements the writer — a round trip
// through a reimplementation of the writer proves nothing about the writer.
func s2WriteLevel(ctx context.Context, t *testing.T, db *sql.DB, proofID uuid.UUID,
	level string, result json.RawMessage, ev *certenproof.GovReceiptEvidence) {
	t.Helper()

	levelJSON := BuildGovernanceLevelJSON(level, result, ev, s2Flags())

	var govLevel string
	switch level {
	case "G0":
		govLevel = "G0"
	case "G1":
		govLevel = "G1"
	case "G2":
		govLevel = "G2"
	default:
		t.Fatalf("unknown level %q", level)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO governance_proof_levels (proof_id, gov_level, level_name, level_json, verified)
		VALUES ($1, $2, $3, $4, true)`,
		proofID, govLevel, level+" - test", []byte(levelJSON)); err != nil {
		t.Fatalf("insert governance level %s: %v", level, err)
	}
}

// s2MutateStored applies a jsonb mutation to the STORED bytes and returns the
// resulting verification error, if any.
//
// The mutation goes through SQL, not through the Go object, because what must be
// rejected is a tampered ROW — someone with database access editing level_json.
// Mutating a struct in memory and re-verifying it would test a different thing.
func s2MutateStored(ctx context.Context, t *testing.T, db *sql.DB, proofID uuid.UUID, level, expr string) error {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		`UPDATE governance_proof_levels SET level_json = `+expr+
			` WHERE proof_id = $1 AND gov_level = $2`, proofID, level); err != nil {
		t.Fatalf("apply mutation: %v", err)
	}
	store := certenproof.NewPostgresProofStorage(db)
	_, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID)
	return err
}

// =============================================================================
// GATE 2c — round trip: a level written today recomputes when read back
// =============================================================================

func TestS2_StoredGovernanceLevelRecomputesOffline(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	proofID := s2StoreProof(ctx, t, db)

	// A stand-in for the canonical G-result. Its CONTENT is not what this gate
	// checks — the govRoot gate does that — but its presence must survive the
	// round trip, because a row that carries the conclusion is worth more than
	// one that carries only flags.
	result := json.RawMessage(`{"tx_hash":"8888","g0_proof_complete":true}`)

	for _, level := range []string{"G0", "G1", "G2"} {
		s2WriteLevel(ctx, t, db, proofID, level, result, s2Evidence(t, "proof_bvn1.json", level))
	}

	store := certenproof.NewPostgresProofStorage(db)
	levels, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID)
	if err != nil {
		t.Fatalf("GATE 2c FAILED: a governance level written today does not recompute when read back "+
			"from PostgreSQL with the network disabled: %v", err)
	}
	if len(levels) != 3 {
		t.Fatalf("expected 3 levels, read back %d", len(levels))
	}

	for _, l := range levels {
		if !l.HasEvidence() {
			t.Errorf("%s came back with no receipt evidence — it was written with a 12-step path", l.Level)
			continue
		}
		if !l.HasResult() {
			t.Errorf("%s came back with no result; the real G-result must survive the round trip", l.Level)
		}
		if len(l.Receipt.Entries) != 12 {
			t.Errorf("%s: merkle path came back with %d steps, expected 12", l.Level, len(l.Receipt.Entries))
		}

		// ADDITIVE: every flag the evidence report and the approval console read
		// must still be there. This is rule 9, and it is cheap to break by
		// accident — BuildGovernanceLevelJSON copies the map, and a future edit
		// that replaced instead of copied would pass every other assertion here.
		for _, k := range []string{"inclusion_verified", "finality_achieved", "confirmations",
			"threshold_m", "threshold_n", "authority_url"} {
			if _, ok := l.Flags[k]; !ok {
				t.Errorf("%s: flag %q was lost; the stored row must be ADDITIVE over what was there before", l.Level, k)
			}
		}
	}
	t.Logf("recomputed 3 governance levels from level_json alone, network disabled: %d-step real Accumulate path each",
		len(levels[0].Receipt.Entries))
}

// The other half of honesty: a level stored the OLD way — flags only — must come
// back as ErrGovernanceSummaryOnly. Not verified, and NOT failed.
//
// This is Gate 2e. The 1,106 historical levels are in exactly this state and
// their evidence cannot be reconstructed. A reader that cannot tell "never
// captured" from "checked and wrong" will eventually report one as the other.
func TestS2_HistoricalLevelReadsSummaryOnly(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	proofID := s2StoreProof(ctx, t, db)

	// Exactly what production holds for the historical rows: the verdict flags
	// and nothing else. Written through the same helper with no result and no
	// evidence, so the "absent" path is the one under test.
	s2WriteLevel(ctx, t, db, proofID, "G0", nil, nil)

	store := certenproof.NewPostgresProofStorage(db)
	levels, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: a level with no receipt evidence was reported as verified. " +
			"Nothing was checked, so nothing may be claimed.")
	}
	if !errors.Is(err, certenproof.ErrGovernanceSummaryOnly) {
		t.Fatalf("expected ErrGovernanceSummaryOnly, got a different failure: %v", err)
	}
	if len(levels) != 1 || levels[0].HasEvidence() {
		t.Fatalf("expected one evidence-free level, got %+v", levels)
	}
	// The flags must still be readable — the console depends on them, and a
	// summary-only level is still a record.
	if _, ok := levels[0].Flags["inclusion_verified"]; !ok {
		t.Error("a summary-only level lost its verdict flags")
	}
	t.Logf("historical level correctly reads summary-only, not verified and not failed: %v", err)
}

// A partially-evidenced proof — some levels checkable, some not — must report
// summary-only rather than clean. This is the shape every proof written between
// Phase 6 and Stage 2 will have if only some levels carried a path.
func TestS2_PartialEvidenceIsNotAPass(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	proofID := s2StoreProof(ctx, t, db)
	s2WriteLevel(ctx, t, db, proofID, "G0", nil, s2Evidence(t, "proof_bvn1.json", "G0"))
	s2WriteLevel(ctx, t, db, proofID, "G1", nil, nil) // no evidence

	store := certenproof.NewPostgresProofStorage(db)
	_, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID)
	if err == nil {
		t.Fatal("CRITICAL DEFECT: a proof with an unchecked level reported clean")
	}
	if !errors.Is(err, certenproof.ErrGovernanceSummaryOnly) {
		t.Fatalf("expected ErrGovernanceSummaryOnly for partial evidence, got: %v", err)
	}
	if !strings.Contains(err.Error(), "G1") {
		t.Errorf("the error must name which level lacks evidence: %v", err)
	}
}

// =============================================================================
// GATE 2d — MANDATORY. Every mutation of the stored bytes must be REJECTED.
// =============================================================================
//
// If verification passes but a mutation is NOT rejected, the recomputation is
// not running and every other assertion in this file is worthless.

func TestS2_StoredGovernanceMutationsRejected(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	// The six mutations of runbook §2d. Each is applied to level_json in SQL,
	// against a freshly written, freshly verified level.
	cases := []struct {
		name string
		// expr is the jsonb expression replacing level_json.
		expr string
		why  string
	}{
		{
			name: "flip a byte of entries[0].hash",
			expr: `jsonb_set(level_json, '{receipt,entries,0,hash}',
			         to_jsonb('0000000000000000000000000000000000000000000000000000000000000000'::text))`,
			why: "a sibling hash that was not the sibling cannot reach the anchor",
		},
		{
			name: "flip entries[0].right",
			expr: `jsonb_set(level_json, '{receipt,entries,0,right}',
			         to_jsonb(NOT COALESCE((level_json->'receipt'->'entries'->0->>'right')::boolean, false)))`,
			why: "hashing the pair in the other order yields a different node; side is not decoration",
		},
		{
			name: "drop one entry from the path",
			expr: `jsonb_set(level_json, '{receipt,entries}',
			         (level_json->'receipt'->'entries') - 0)`,
			why: "a short path lands on an intermediate node, not the anchor",
		},
		{
			name: "empty the path while start != anchor",
			expr: `jsonb_set(level_json, '{receipt,entries}', '[]'::jsonb)`,
			why: "THE VACUOUS PASS. An empty path is valid ONLY when the leaf IS the anchor; " +
				"accepting it otherwise makes every receipt verify",
		},
		{
			name: "alter the stored anchor",
			expr: `jsonb_set(level_json, '{receipt,anchor}',
			         to_jsonb('1111111111111111111111111111111111111111111111111111111111111111'::text))`,
			why: "the recomputation must reach the anchor the row itself claims",
		},
		{
			name: "alter the stored start (the leaf)",
			expr: `jsonb_set(level_json, '{receipt,start}',
			         to_jsonb('2222222222222222222222222222222222222222222222222222222222222222'::text))`,
			why: "a different leaf under the same path reaches a different root",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proofID := s2StoreProof(ctx, t, db)
			s2WriteLevel(ctx, t, db, proofID, "G0", nil, s2Evidence(t, "proof_bvn1.json", "G0"))

			// It must verify BEFORE the mutation, or the rejection afterwards
			// proves nothing.
			store := certenproof.NewPostgresProofStorage(db)
			if _, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID); err != nil {
				t.Fatalf("the unmutated level does not verify, so this mutation case is meaningless: %v", err)
			}

			err := s2MutateStored(ctx, t, db, proofID, "G0", tc.expr)
			if err == nil {
				t.Fatalf("CRITICAL DEFECT: mutation %q was ACCEPTED.\n  %s\n"+
					"The recomputation is not running; every other assertion about stored "+
					"governance evidence is worthless until this is fixed.", tc.name, tc.why)
			}
			if errors.Is(err, certenproof.ErrGovernanceSummaryOnly) {
				t.Fatalf("mutation %q was reported as SUMMARY-ONLY rather than rejected: %v\n"+
					"Tampered evidence is present evidence that does not check out — that is a "+
					"FAILURE, and reporting it as 'nothing to check' hides it.", tc.name, err)
			}
			t.Logf("rejected: %v", err)
		})
	}
}

// The sixth mutation in the runbook's table, and the one a per-field check would
// miss entirely: graft ANOTHER proof's receipt into this proof's level.
//
// Each field is individually well-formed and the grafted receipt recomputes
// perfectly — against its OWN anchor. It is rejected because the evidence is
// self-contained: start, anchor and path are stored together and checked against
// each other, so a whole valid receipt from elsewhere is still not this one.
func TestS2_GraftedReceiptFromAnotherProofIsRejected(t *testing.T) {
	db := p6OpenDB(t)
	ctx := context.Background()
	p6CutTheNetwork(t)

	mine := s2Evidence(t, "proof_bvn1.json", "G1")
	theirs := s2Evidence(t, "proof_bvn3.json", "G1")
	if mine.Anchor == theirs.Anchor {
		t.Skip("the two fixtures share an anchor; this graft would not be a graft")
	}

	proofID := s2StoreProof(ctx, t, db)
	s2WriteLevel(ctx, t, db, proofID, "G1", nil, mine)

	store := certenproof.NewPostgresProofStorage(db)
	if _, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, proofID); err != nil {
		t.Fatalf("the unmutated level does not verify: %v", err)
	}

	// Graft ONLY the path and the start, leaving this row's own anchor in place —
	// the shape an attacker would actually produce, since the anchor is what the
	// rest of the record is bound to.
	grafted, err := json.Marshal(theirs.Entries)
	if err != nil {
		t.Fatal(err)
	}
	expr := fmt.Sprintf(`jsonb_set(jsonb_set(level_json, '{receipt,entries}', %s::jsonb),
	                      '{receipt,start}', to_jsonb('%s'::text))`, quoteSQL(string(grafted)), theirs.Start)

	if err := s2MutateStored(ctx, t, db, proofID, "G1", expr); err == nil {
		t.Fatal("CRITICAL DEFECT: another proof's receipt was accepted as this proof's evidence. " +
			"Every field is well-formed and the path recomputes — against the WRONG anchor.")
	} else {
		t.Logf("grafted receipt rejected: %v", err)
	}
}

// quoteSQL renders a string as a SQL literal. Test-only: the input is a JSON
// document this test just produced, not anything a user supplied.
func quoteSQL(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// =============================================================================
// The single-leaf rule, both directions
// =============================================================================
//
// The empty path is where a vacuous pass hides, so both directions are asserted
// explicitly rather than inferred from the mutation above.
func TestS2_SingleLeafReceiptRuleBothDirections(t *testing.T) {
	const h = "3333333333333333333333333333333333333333333333333333333333333333"

	// Leaf IS the anchor: a one-leaf tree. Legitimate, and must PASS.
	ok := &certenproof.GovReceiptEvidence{Level: "G0", Start: h, Anchor: h}
	if err := ok.VerifyMerkle(); err != nil {
		t.Fatalf("a single-leaf receipt (start == anchor, empty path) must verify: %v", err)
	}

	// Empty path with a different anchor: must REJECT. If this passes, every
	// receipt in the system verifies by carrying no evidence at all.
	bad := &certenproof.GovReceiptEvidence{
		Level:  "G0",
		Start:  h,
		Anchor: "4444444444444444444444444444444444444444444444444444444444444444",
	}
	if err := bad.VerifyMerkle(); err == nil {
		t.Fatal("CRITICAL DEFECT: an empty merkle path was accepted with start != anchor. " +
			"Every receipt now verifies vacuously.")
	}

	// Absent evidence is not a short path — it is no record, and must not verify.
	var absent *certenproof.GovReceiptEvidence
	if err := absent.VerifyMerkle(); err == nil {
		t.Fatal("absent receipt evidence must not verify")
	}
	if (&certenproof.GovReceiptEvidence{Level: "G0"}).VerifyMerkle() == nil {
		t.Fatal("evidence with no start or anchor must not verify")
	}
}

// The shared helper is ADDITIVE, and that is rule 9. Asserted directly on the
// helper as well as through the round trip, because the round trip would still
// pass if a future edit dropped a key the console reads but the test does not.
func TestS2_BuildGovernanceLevelJSONIsAdditive(t *testing.T) {
	existing := s2Flags()
	ev := &certenproof.GovReceiptEvidence{
		Level: "G0", Start: "aa", Anchor: "aa",
	}
	out := BuildGovernanceLevelJSON("G0", json.RawMessage(`{"x":1}`), ev, existing)

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("helper produced invalid JSON: %v", err)
	}
	for k := range existing {
		if _, ok := obj[k]; !ok {
			t.Errorf("key %q was dropped; level_json must be additive over what was already stored", k)
		}
	}
	if _, ok := obj[GovLevelResultKey]; !ok {
		t.Error("the result key was not added")
	}
	if _, ok := obj[GovLevelReceiptKey]; !ok {
		t.Error("the receipt key was not added")
	}

	// With nothing to add, the flags must come back untouched — that is what the
	// 1,106 historical rows look like, and rewriting them is not this stage's job.
	bare := BuildGovernanceLevelJSON("G0", nil, nil, existing)
	// A FRESH map: json.Unmarshal MERGES into a non-empty one, so reusing obj
	// would carry the keys from the case above and this assertion would pass
	// whatever the helper did.
	bareObj := map[string]json.RawMessage{}
	if err := json.Unmarshal(bare, &bareObj); err != nil {
		t.Fatalf("helper produced invalid JSON with no evidence: %v", err)
	}
	obj = bareObj
	if _, ok := obj[GovLevelReceiptKey]; ok {
		t.Error("an absent receipt must NOT produce a receipt key — an empty path that is " +
			"accepted makes every receipt verify")
	}
	if _, ok := obj[GovLevelResultKey]; ok {
		t.Error("an absent result must not produce a result key")
	}
}
