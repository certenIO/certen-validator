// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/execution"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB5-F15: proofverify verifies a proof's recorded on-chain outcome OFFLINE - exit 0 verified, 1 failed, 3 a named weaker
// state - from the real evidence of the 55d23cb0 anchors (pkg/execution/testdata/outcome_evidence).

func fixturePath(chain int64) string {
	return filepath.Join("..", "..", "pkg", "execution", "testdata", "outcome_evidence", fmt.Sprintf("outcome_evidence_%d.json", chain))
}

func loadFixture(t *testing.T, chain int64) *execution.OutcomeEvidence {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(chain))
	if err != nil {
		t.Fatal(err)
	}
	ev := new(execution.OutcomeEvidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func writeEvidence(t *testing.T, ev *execution.OutcomeEvidence) string {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnOutcomeEvidenceFileVerifiesOffline(t *testing.T) {
	for _, chain := range []int64{11155111, 84532, 421614} {
		var out bytes.Buffer
		if code := reportOutcomeFile(context.Background(), &out, fixturePath(chain), ""); code != exitVerified {
			t.Fatalf("chain %d: exit %d\n%s", chain, code, out.String())
		}
		for _, want := range []string{"OUTCOME verified OFFLINE", "status 1 (executed", "Groth16", "NOT established offline",
			"NOT checked here: which proof"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("chain %d: the report does not say %q:\n%s", chain, want, out.String())
			}
		}
	}
}

func TestATamperedOutcomeEvidenceFileFails(t *testing.T) {
	for name, tamper := range map[string]func(e *execution.OutcomeEvidence){
		"leaf":    func(e *execution.OutcomeEvidence) { e.Member.Leaf.BlockNumber++ },
		"root":    func(e *execution.OutcomeEvidence) { e.Record.OutcomeRoot = "0x" + strings.Repeat("11", 32) },
		"signer":  func(e *execution.OutcomeEvidence) { e.Quorum.SignerPowers[0] = "300" },
		"proof":   func(e *execution.OutcomeEvidence) { e.Quorum.ZKProof[7] ^= 1 },
		"receipt": func(e *execution.OutcomeEvidence) { e.Member.Transaction.Receipt[3] ^= 1 },
		"header":  func(e *execution.OutcomeEvidence) { e.Record.Inclusion.Header[9] ^= 1 },
		"status":  func(e *execution.OutcomeEvidence) { e.Member.Leaf.Status = uint8(execution.OutcomeEffectsNotProven) },
	} {
		ev := loadFixture(t, 84532)
		tamper(ev)
		var out bytes.Buffer
		if code := reportOutcomeFile(context.Background(), &out, writeEvidence(t, ev), ""); code != exitFailed ||
			!strings.Contains(out.String(), "FAILED (outcome)") {
			t.Fatalf("%s: exit %d\n%s", name, code, out.String())
		}
	}
	var out bytes.Buffer
	if code := reportOutcomeFile(context.Background(), &out, filepath.Join(t.TempDir(), "absent.json"), ""); code != exitFailed {
		t.Fatalf("an absent file: exit %d", code)
	}
}

type memStore map[uuid.UUID][]certenproof.StoredLayerRow

func (m memStore) LayerRows(_ context.Context, id uuid.UUID) ([]certenproof.StoredLayerRow, error) {
	return m[id], nil
}
func (m memStore) ProofBlob(context.Context, uuid.UUID) (json.RawMessage, error) { return nil, nil }

// proofOf is a stored proof of the fixture's member: its layer 5 and, with ev, its outcome evidence.
func proofOf(t *testing.T, fixture, ev *execution.OutcomeEvidence, mutateL5 func(*execution.Layer5)) (memStore, uuid.UUID) {
	t.Helper()
	a := fixture.Anchor
	l5 := &execution.Layer5{ChainID: fixture.ChainID, Network: "fixture", AnchorTx: "0x" + strings.Repeat("ab", 32), BlockNumber: 1,
		BatchRoot: strings.TrimPrefix(a.BatchRoot, "0x"), LeafHash: strings.TrimPrefix(fixture.Member.Leaf.BatchLeaf, "0x"),
		LeafIndex: fixture.Member.Leaf.LeafIndex,
		Commitment: &execution.AnchorCommitment{Version: "v8_2", BundleID: a.BundleID, LeafCount: a.LeafCount, BatchOperationID: a.BatchOperationID,
			AccumulateBlockHeight: a.AccumulateBlockHeight, CertenSetRoot: a.CertenSetRoot, AccumulateSetRoot: a.AccumulateSetRoot,
			Incarnation: a.Incarnation}}
	if mutateL5 != nil {
		mutateL5(l5)
	}
	id := uuid.New()
	raw, _ := json.Marshal(l5)
	m := memStore{id: {{LayerNumber: 5, LayerName: execution.Layer5RowName, LayerJSON: raw}}}
	if ev != nil {
		raw, _ := json.Marshal(ev)
		m[id] = append(m[id], certenproof.StoredLayerRow{LayerNumber: execution.Layer6LayerNumber, LayerName: execution.Layer6RowName, LayerJSON: raw})
	}
	return m, id
}

func TestAStoredProofsOutcomeIsReportedByItsVerdict(t *testing.T) {
	fx := loadFixture(t, 11155111)
	for _, c := range []struct {
		name  string
		ev    *execution.OutcomeEvidence
		l5    func(*execution.Layer5)
		code  int
		label string
	}{
		{"recorded and bound", fx, nil, exitVerified, "bound to this proof"},
		{"no outcome recorded for the proof", nil, nil, exitSummaryOnly, "OUTCOME NOT RECORDED"},
		{"the outcome of another member", fx, func(l *execution.Layer5) { l.LeafHash = strings.Repeat("ab", 32) }, exitFailed, "FAILED (outcome)"},
		{"certified by another CERTEN set than the anchor's", fx, func(l *execution.Layer5) {
			l.Commitment.CertenSetRoot = "0x" + strings.Repeat("ef", 32)
		}, exitSummaryOnly, "SUMMARY-ONLY (outcome)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, id := proofOf(t, fx, c.ev, c.l5)
			var out bytes.Buffer
			if code := reportOutcome(context.Background(), &out, store, id, ""); code != c.code || !strings.Contains(out.String(), c.label) {
				t.Fatalf("exit %d, want %d naming %q:\n%s", code, c.code, c.label, out.String())
			}
		})
	}
}
