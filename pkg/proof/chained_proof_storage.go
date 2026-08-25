// Copyright 2026 Certen Protocol
//
// ChainedProofFromStorage — read a governance proof back out of PostgreSQL and
// hand it to the unmodified offline verifier.
//
// This is the function that converts "we store more" into "we can prove it".
// Everything else in Phase 6 writes; this is the only thing that reads, and it
// is the only thing that turns the stored bytes back into a claim anyone can
// check. Governance spec §4 — "a governance proof MUST be verifiable offline"
// — is met by this path or it is not met at all.
//
// # WHAT IT REFUSES TO DO
//
// It never fills a gap. If the layer-4 evidence is absent it returns
// ErrSummaryOnly and no proof, rather than a proof missing its quorum: a
// caller that got an object back would hand it to the verifier, the verifier
// would reject it, and the reason would read as "tampering" instead of "never
// stored". Those are different facts and the caller has to be able to tell
// them apart.
//
// It also never re-queries Accumulate to repair a proof. Re-querying returns
// TODAY's validator set, not the one that signed, so a "repaired" historical
// proof would carry a quorum that never existed. A synthesized quorum is worse
// than an absent one — the absent one is at least honest.
package proof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/google/uuid"
)

// ErrSummaryOnly reports that a proof's stored record carries the CONCLUSIONS
// of the L4 quorum check but not the evidence for it, so it cannot be verified
// offline.
//
// Every proof written before Phase 6 is in this state, and correctly so: the
// signatures, validator set and signed bytes were never persisted and cannot
// be reconstructed. Such proofs are marked verification_status =
// 'summary_only' rather than 'verified', so "not verifiable from storage" is
// never read as "verified".
var ErrSummaryOnly = errors.New("proof is summary-only: L4 quorum evidence was never persisted, so it cannot be verified offline")

// ErrNoStoredProof reports that nothing was stored for this proof at all —
// distinct from ErrSummaryOnly, which means something was stored and it was
// not enough.
var ErrNoStoredProof = errors.New("no chained proof rows or blob stored for this proof")

// StoredLayerRow is one chained_proof_layers row, reduced to what reassembly
// needs.
//
// Declared here rather than taken from pkg/database so this package does not
// depend on the storage package: the same reassembly then works against a
// repository, a test double, or a proof bundle read off disk.
type StoredLayerRow struct {
	LayerNumber int
	LayerName   string
	LayerJSON   json.RawMessage
}

// ProofStorageReader is the storage this reassembly reads.
//
// LayerRows returns every chained_proof_layers row for the proof. ProofBlob
// returns batch_transactions.chained_proof — the travelling artifact — or nil
// if there is none; it is optional, and an implementation with no blob to
// offer returns (nil, nil) rather than an error.
type ProofStorageReader interface {
	LayerRows(ctx context.Context, proofID uuid.UUID) ([]StoredLayerRow, error)
	ProofBlob(ctx context.Context, proofID uuid.UUID) (json.RawMessage, error)
}

// storedBlob mirrors the shape written into batch_transactions.chained_proof:
// json.Marshal(CertenProof.LiteClientProof). Only the parts reassembly needs
// are declared; every other key is ignored.
type storedBlob struct {
	CompleteProof *lcproof.CompleteProof `json:"complete_proof"`
}

// ChainedProofFromStorage reassembles a ChainedProof for proofID and returns
// it ready for ProofVerifier.Verify. It performs no network access.
//
// Sources, and why in this order:
//
//	L4  the blob first, then the rows. The blob is the artifact that TRAVELS —
//	    a verifier handed that one column should not need a second query — so
//	    it is the authoritative copy when present. The rows are the fallback
//	    and the queryable index.
//	L1-L3  the rows only. The blob carries these receipts in a lossy
//	    re-encoding (merkle.Receipt keeps start/anchor/entries and drops
//	    localBlock, chain indices and block heights), and the verifier enforces
//	    invariants over exactly those dropped scalars. The rows carry the
//	    authoritative typed layers under `layer1`/`layer2`/`layer3`.
//
// A proof whose rows predate Phase 6 has the descriptions but not the
// canonical keys, and comes back as ErrSummaryOnly.
func ChainedProofFromStorage(ctx context.Context, store ProofStorageReader, proofID uuid.UUID) (*chained_proof.ChainedProof, error) {
	if store == nil {
		return nil, fmt.Errorf("chained proof storage reader is nil")
	}

	rows, err := store.LayerRows(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("read layer rows for proof %s: %w", proofID, err)
	}

	blobRaw, err := store.ProofBlob(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("read stored blob for proof %s: %w", proofID, err)
	}
	if len(rows) == 0 && len(blobRaw) == 0 {
		return nil, fmt.Errorf("proof %s: %w", proofID, ErrNoStoredProof)
	}

	cp := &chained_proof.ChainedProof{}

	// --- L1-L3, from the rows -------------------------------------------
	var haveL1, haveL2, haveL3 bool
	for _, row := range rows {
		if len(row.LayerJSON) == 0 {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(row.LayerJSON, &obj); err != nil {
			// A row whose layer_json will not parse is a corrupt record, not a
			// tolerable one: continuing would silently produce a proof missing
			// a layer, which the verifier would then blame on the layer's
			// contents.
			return nil, fmt.Errorf("proof %s layer %d (%s): layer_json does not parse: %w",
				proofID, row.LayerNumber, row.LayerName, err)
		}

		switch row.LayerNumber {
		case 1:
			if raw, ok := obj["input"]; ok {
				if err := json.Unmarshal(raw, &cp.Input); err != nil {
					return nil, fmt.Errorf("proof %s: layer1.input does not decode: %w", proofID, err)
				}
			}
			if raw, ok := obj["layer1"]; ok {
				if err := json.Unmarshal(raw, &cp.Layer1); err != nil {
					return nil, fmt.Errorf("proof %s: layer1 does not decode: %w", proofID, err)
				}
				haveL1 = true
			}
		case 2:
			if raw, ok := obj["layer2"]; ok {
				if err := json.Unmarshal(raw, &cp.Layer2); err != nil {
					return nil, fmt.Errorf("proof %s: layer2 does not decode: %w", proofID, err)
				}
				haveL2 = true
			}
		case 3:
			if raw, ok := obj["layer3"]; ok {
				if err := json.Unmarshal(raw, &cp.Layer3); err != nil {
					return nil, fmt.Errorf("proof %s: layer3 does not decode: %w", proofID, err)
				}
				haveL3 = true
			}
		case 4:
			leg := new(chained_proof.Layer4)
			if err := json.Unmarshal(row.LayerJSON, leg); err != nil {
				return nil, fmt.Errorf("proof %s layer 4 (%s): leg does not decode: %w",
					proofID, row.LayerName, err)
			}
			// The leg's OWN partition decides which side it is, not the row
			// name. The row name is a label an operator reads; the partition
			// is what the quorum signed and what the verifier checks against.
			if leg.Partition == "Directory" {
				cp.Layer4DN = leg
			} else {
				cp.Layer4BVN = leg
			}
		}
	}

	// --- L4, preferring the blob ----------------------------------------
	if len(blobRaw) > 0 {
		var blob storedBlob
		if err := json.Unmarshal(blobRaw, &blob); err != nil {
			return nil, fmt.Errorf("proof %s: stored blob does not parse: %w", proofID, err)
		}
		if blob.CompleteProof != nil {
			if blob.CompleteProof.Layer4BVN != nil {
				cp.Layer4BVN = blob.CompleteProof.Layer4BVN
			}
			if blob.CompleteProof.Layer4DN != nil {
				cp.Layer4DN = blob.CompleteProof.Layer4DN
			}
		}
	}

	// --- what is missing, said precisely --------------------------------
	if !haveL1 || !haveL2 || !haveL3 {
		return nil, fmt.Errorf(
			"proof %s: stored rows carry no canonical layer object (layer1=%v layer2=%v layer3=%v); "+
				"the rows describe the proof but cannot rebuild it: %w",
			proofID, haveL1, haveL2, haveL3, ErrSummaryOnly)
	}
	if cp.Layer4BVN == nil || cp.Layer4DN == nil {
		return nil, fmt.Errorf(
			"proof %s: L4 quorum evidence absent from storage (bvn=%v dn=%v): %w",
			proofID, cp.Layer4BVN != nil, cp.Layer4DN != nil, ErrSummaryOnly)
	}

	return cp, nil
}

// VerifyStoredProof reads a proof back from storage and verifies it offline.
//
// It is deliberately thin: it does NOT re-implement any check, it hands the
// reassembled object to the unmodified ProofVerifier from
// working-proof_do_not_edit. Storing evidence and checking evidence are
// different claims, and only running the real verifier substantiates the
// second one.
func VerifyStoredProof(ctx context.Context, store ProofStorageReader, proofID uuid.UUID) (*chained_proof.ChainedProof, error) {
	cp, err := ChainedProofFromStorage(ctx, store, proofID)
	if err != nil {
		return nil, err
	}
	if err := chained_proof.NewProofVerifier(false).Verify(ctx, cp); err != nil {
		return nil, fmt.Errorf("proof %s failed offline verification from storage: %w", proofID, err)
	}
	return cp, nil
}

// =============================================================================
// The PostgreSQL-backed reader.
// =============================================================================

// PostgresProofStorage reads a stored proof out of the live schema:
// chained_proof_layers for the layers, batch_transactions.chained_proof for the
// travelling blob.
type PostgresProofStorage struct {
	repo *database.ProofArtifactRepository
	db   *sql.DB
}

// NewPostgresProofStorage builds a reader over an open database handle.
func NewPostgresProofStorage(db *sql.DB) *PostgresProofStorage {
	return &PostgresProofStorage{repo: database.NewProofArtifactRepository(db), db: db}
}

// LayerRows returns every stored layer for the proof, in layer order.
func (s *PostgresProofStorage) LayerRows(ctx context.Context, proofID uuid.UUID) ([]StoredLayerRow, error) {
	layers, err := s.repo.GetChainedProofLayers(ctx, proofID)
	if err != nil {
		return nil, err
	}
	out := make([]StoredLayerRow, 0, len(layers))
	for _, l := range layers {
		out = append(out, StoredLayerRow{
			LayerNumber: l.LayerNumber,
			LayerName:   l.LayerName,
			LayerJSON:   l.LayerJSON,
		})
	}
	return out, nil
}

// ProofBlob returns batch_transactions.chained_proof for the proof, or nil.
//
// The join is on accumulate_tx_hash rather than a foreign key because
// batch_transactions predates proof_artifacts and carries no proof_id. A proof
// with no batch row is not an error — it is a proof whose blob has not been
// written yet, and the layer rows are then the only source.
func (s *PostgresProofStorage) ProofBlob(ctx context.Context, proofID uuid.UUID) (json.RawMessage, error) {
	const q = `
		SELECT bt.chained_proof
		FROM proof_artifacts pa
		JOIN batch_transactions bt ON bt.accumulate_tx_hash = pa.accum_tx_hash
		WHERE pa.proof_id = $1 AND bt.chained_proof IS NOT NULL
		ORDER BY bt.created_at DESC
		LIMIT 1`
	var raw []byte
	err := s.db.QueryRowContext(ctx, q, proofID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}
