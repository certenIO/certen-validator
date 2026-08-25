// Copyright 2026 Certen Protocol
//
// GovernanceLevelsFromStorage — read the governance levels back out of
// PostgreSQL and recompute each receipt FROM THE STORED BYTES ALONE.
//
// Stage 2 writes; this reads. Storing evidence and checking evidence are
// different claims, and only this path substantiates the second one. It is the
// governance-level counterpart of ChainedProofFromStorage, and it follows the
// same two rules that file already established:
//
//	IT NEVER FILLS A GAP. A row with no "receipt" key comes back as
//	ErrGovernanceSummaryOnly and no verified claim, rather than as a level that
//	quietly verifies. A caller that got a pass back would be unable to tell
//	"checked" from "there was nothing to check".
//
//	IT NEVER RE-QUERIES ACCUMULATE. The receipt fetched today is not necessarily
//	the one the proof was built on, so a "repaired" historical level would carry
//	a merkle path for a different receipt. That is the governance-layer version
//	of reconstructing a historical validator set: a synthesized record is worse
//	than an absent one, because the absent one is honest.
package proof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrGovernanceSummaryOnly reports that a stored governance level carries the
// CONCLUSION of the governance check but not the evidence for it, so it cannot
// be recomputed offline.
//
// Every governance level written before Stage 2 is in this state, and correctly
// so: 1,106 rows measured on 2026-08-25 carry no "receipt" key at all. Their
// merkle paths were never captured and CANNOT be reconstructed. Mirrors
// ErrSummaryOnly, which says the same thing one layer down about L4.
var ErrGovernanceSummaryOnly = errors.New(
	"governance level is summary-only: no receipt merkle path was persisted, so it cannot be recomputed offline")

// ErrNoStoredGovernanceLevels reports that nothing was stored for this proof —
// distinct from ErrGovernanceSummaryOnly, which means something was stored and
// it was not enough.
var ErrNoStoredGovernanceLevels = errors.New("no governance levels stored for this proof")

// StoredGovLevelRow is one governance_proof_levels row, reduced to what
// reassembly needs.
//
// Declared here rather than taken from pkg/database so this package does not
// depend on the storage package: the same reassembly then works against a
// repository, a test double, or an exported proof bundle.
type StoredGovLevelRow struct {
	GovLevel  string
	LevelName string
	LevelJSON json.RawMessage
}

// GovernanceStorageReader is the storage this reassembly reads.
type GovernanceStorageReader interface {
	GovernanceLevelRows(ctx context.Context, proofID uuid.UUID) ([]StoredGovLevelRow, error)
}

// StoredGovernanceLevel is one governance level as it came out of storage.
type StoredGovernanceLevel struct {
	Level string // "G0" | "G1" | "G2"
	Name  string

	// Result is the raw G*Result exactly as stored — NOT decoded and
	// re-encoded. It is the govRoot preimage for this level, and a round trip
	// through the Go structs could normalise a field, which would change the
	// hash a reader recomputes from it.
	Result json.RawMessage

	// Receipt is the merkle path. Nil means summary-only: the row records what
	// was concluded and carries nothing that can be checked.
	Receipt *GovReceiptEvidence

	// Flags is every other key in level_json — inclusion_verified,
	// finality_achieved, threshold_m/n, authority_url, confirmations. Carried
	// through so a reader of this path sees exactly what the evidence report and
	// the approval console see, and so nothing that was already stored is lost
	// on the way out.
	Flags map[string]json.RawMessage
}

// HasEvidence reports whether this level carries a recomputable receipt.
func (l *StoredGovernanceLevel) HasEvidence() bool { return l != nil && l.Receipt.HasPath() }

// HasResult reports whether the real G*Result was stored.
//
// Separate from HasEvidence on purpose: a row can carry the conclusion in its
// canonical shape and still have no path to check it with, and those are
// different facts about how much that row is worth.
func (l *StoredGovernanceLevel) HasResult() bool { return l != nil && len(l.Result) > 0 }

// GovernanceLevelsFromStorage reads every stored governance level for a proof.
//
// It performs no network access and never repairs a row. Levels come back in
// whatever order storage returned them, each carrying exactly what was stored:
// the result if it was stored, the receipt if it was stored, and the flags
// either way.
func GovernanceLevelsFromStorage(ctx context.Context, store GovernanceStorageReader, proofID uuid.UUID) ([]StoredGovernanceLevel, error) {
	if store == nil {
		return nil, fmt.Errorf("governance storage reader is nil")
	}
	rows, err := store.GovernanceLevelRows(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("read governance levels for proof %s: %w", proofID, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("proof %s: %w", proofID, ErrNoStoredGovernanceLevels)
	}

	out := make([]StoredGovernanceLevel, 0, len(rows))
	for _, row := range rows {
		lvl := StoredGovernanceLevel{
			Level: row.GovLevel,
			Name:  row.LevelName,
			Flags: map[string]json.RawMessage{},
		}
		if len(row.LevelJSON) > 0 {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(row.LevelJSON, &obj); err != nil {
				// A row whose level_json will not parse is a corrupt record, not a
				// tolerable one. Continuing would produce a level silently missing
				// its evidence, and the verifier would then blame the evidence.
				return nil, fmt.Errorf("proof %s level %s: level_json does not parse: %w",
					proofID, row.GovLevel, err)
			}
			for k, v := range obj {
				switch k {
				case "result":
					lvl.Result = v
				case "receipt":
					ev := new(GovReceiptEvidence)
					if err := json.Unmarshal(v, ev); err != nil {
						return nil, fmt.Errorf("proof %s level %s: receipt evidence does not decode: %w",
							proofID, row.GovLevel, err)
					}
					// The stored evidence names its own level. Trust the ROW's level
					// when the record is silent, but never overwrite a stated one —
					// a disagreement between them is a fact worth surfacing, not
					// something to paper over.
					if ev.Level == "" {
						ev.Level = row.GovLevel
					}
					lvl.Receipt = ev
				default:
					lvl.Flags[k] = v
				}
			}
		}
		out = append(out, lvl)
	}
	return out, nil
}

// VerifyStoredGovernanceLevels reads the governance levels back and recomputes
// every receipt FROM level_json ALONE.
//
// This is the gate that matters. It performs no network access and it does not
// re-implement the merkle walk: each level's evidence is handed to
// GovReceiptEvidence.VerifyMerkle, which defers to the one ReceiptVerifier in
// the tree.
//
// Returns the levels it read even on failure, so a caller can report WHICH level
// failed and why rather than only that something did.
//
// A level with no evidence yields ErrGovernanceSummaryOnly. That is not a
// verification failure and must never be reported as one: nothing was checked
// and nothing was found wrong. Callers distinguish the two with errors.Is.
func VerifyStoredGovernanceLevels(ctx context.Context, store GovernanceStorageReader, proofID uuid.UUID) ([]StoredGovernanceLevel, error) {
	levels, err := GovernanceLevelsFromStorage(ctx, store, proofID)
	if err != nil {
		return nil, err
	}

	var summaryOnly []string
	for i := range levels {
		l := &levels[i]
		if !l.HasEvidence() {
			summaryOnly = append(summaryOnly, l.Level)
			continue
		}
		if err := l.Receipt.VerifyMerkle(); err != nil {
			return levels, fmt.Errorf("proof %s level %s failed offline recomputation from storage: %w",
				proofID, l.Level, err)
		}
	}

	if len(summaryOnly) == len(levels) {
		return levels, fmt.Errorf("proof %s: no level carries receipt evidence (%v): %w",
			proofID, summaryOnly, ErrGovernanceSummaryOnly)
	}
	if len(summaryOnly) > 0 {
		// Partial evidence is a real state and is reported as one. It is NOT a
		// failure — the levels that could be checked were checked and passed —
		// and it is NOT a clean pass either.
		return levels, fmt.Errorf("proof %s: level(s) %v carry no receipt evidence: %w",
			proofID, summaryOnly, ErrGovernanceSummaryOnly)
	}
	return levels, nil
}

// =============================================================================
// The PostgreSQL-backed reader
// =============================================================================

// GovernanceLevelRows returns every governance level stored for the proof.
//
// A deliberately minimal query rather than the repository's full row scanner:
// this path must be able to read HISTORICAL rows in order to report them
// summary-only (that is the whole point of Gate 2e), and the wide scanner fails
// on rows with NULL projection columns. Reading three columns it can always read
// beats reading twenty it sometimes cannot.
func (s *PostgresProofStorage) GovernanceLevelRows(ctx context.Context, proofID uuid.UUID) ([]StoredGovLevelRow, error) {
	const q = `
		SELECT gov_level, COALESCE(level_name, ''), COALESCE(level_json, '{}'::jsonb)
		FROM governance_proof_levels
		WHERE proof_id = $1
		ORDER BY gov_level`
	rows, err := s.db.QueryContext(ctx, q, proofID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []StoredGovLevelRow
	for rows.Next() {
		var r StoredGovLevelRow
		var raw []byte
		if err := rows.Scan(&r.GovLevel, &r.LevelName, &raw); err != nil {
			return nil, err
		}
		r.LevelJSON = json.RawMessage(raw)
		out = append(out, r)
	}
	return out, rows.Err()
}
