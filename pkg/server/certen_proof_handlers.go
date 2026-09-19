// Copyright 2025 Certen Protocol
//
// Certen anchor proof endpoints: the four-component proof (whitepaper 3.4.1) stored per proof artifact.
// /api/proofs/* returns proof artifacts; these return the Certen proof built from one.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// certenProofResponse is a stored Certen proof, whether its hash still covers its content, and every
// correction made to it after it was published (each keeps the proof as it was).
type certenProofResponse struct {
	*database.CertenAnchorProof
	ProofHashVerified bool                          `json:"proof_hash_verified"`
	Corrections       []database.EvidenceCorrection `json:"corrections"`
}

func (h *BatchHandlers) certenProofView(ctx context.Context, proof *database.CertenAnchorProof) (certenProofResponse, error) {
	view := certenProofResponse{CertenAnchorProof: proof, ProofHashVerified: proof.VerifyProofHash(), Corrections: []database.EvidenceCorrection{}}
	if h.repos.EvidenceRepair != nil {
		corrections, err := h.repos.EvidenceRepair.GetCorrections(ctx, database.CorrectionRecordCertenProof, proof.ProofID.String())
		if err != nil {
			return view, err
		}
		view.Corrections = corrections
	}
	return view, nil
}

func (h *BatchHandlers) certenProofRequest(w http.ResponseWriter, r *http.Request, prefix string) (string, context.Context, context.CancelFunc, bool) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", nil, nil, false
	}
	if h.repos == nil || h.repos.Proofs == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return "", nil, nil, false
	}
	key := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if key == "" || key == strings.TrimSuffix(r.URL.Path, "/") {
		writeJSONError(w, "identifier required", http.StatusBadRequest)
		return "", nil, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	return key, ctx, cancel, true
}

func (h *BatchHandlers) writeCertenProof(ctx context.Context, w http.ResponseWriter, proof *database.CertenAnchorProof, err error) {
	if errors.Is(err, database.ErrProofNotFound) {
		writeJSONError(w, "certen proof not found", http.StatusNotFound)
		return
	}
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to get certen proof: %v", err), http.StatusInternalServerError)
		return
	}
	view, err := h.certenProofView(ctx, proof)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to get certen proof corrections: %v", err), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(view)
}

// HandleGetCertenProof handles GET /api/certen-proofs/:id
func (h *BatchHandlers) HandleGetCertenProof(w http.ResponseWriter, r *http.Request) {
	key, ctx, cancel, ok := h.certenProofRequest(w, r, "/api/certen-proofs/")
	if !ok {
		return
	}
	defer cancel()
	id, err := uuid.Parse(key)
	if err != nil {
		writeJSONError(w, "invalid certen proof ID", http.StatusBadRequest)
		return
	}
	proof, err := h.repos.Proofs.GetProof(ctx, id)
	h.writeCertenProof(ctx, w, proof, err)
}

// HandleGetCertenProofByArtifact handles GET /api/certen-proofs/by-artifact/:proof_id
func (h *BatchHandlers) HandleGetCertenProofByArtifact(w http.ResponseWriter, r *http.Request) {
	key, ctx, cancel, ok := h.certenProofRequest(w, r, "/api/certen-proofs/by-artifact/")
	if !ok {
		return
	}
	defer cancel()
	id, err := uuid.Parse(key)
	if err != nil {
		writeJSONError(w, "invalid proof artifact ID", http.StatusBadRequest)
		return
	}
	proof, err := h.repos.Proofs.GetProofByArtifactID(ctx, id)
	h.writeCertenProof(ctx, w, proof, err)
}

// HandleGetCertenProofByTxHash handles GET /api/certen-proofs/by-tx/:hash
func (h *BatchHandlers) HandleGetCertenProofByTxHash(w http.ResponseWriter, r *http.Request) {
	key, ctx, cancel, ok := h.certenProofRequest(w, r, "/api/certen-proofs/by-tx/")
	if !ok {
		return
	}
	defer cancel()
	proof, err := h.repos.Proofs.GetProofByAccumTxHash(ctx, key)
	h.writeCertenProof(ctx, w, proof, err)
}

// HandleGetCertenProofsByAccount handles GET /api/certen-proofs/by-account/:url
func (h *BatchHandlers) HandleGetCertenProofsByAccount(w http.ResponseWriter, r *http.Request) {
	key, ctx, cancel, ok := h.certenProofRequest(w, r, "/api/certen-proofs/by-account/")
	if !ok {
		return
	}
	defer cancel()
	proofs, err := h.repos.Proofs.GetProofsByAccountURL(ctx, key, 100)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to get certen proofs: %v", err), http.StatusInternalServerError)
		return
	}
	responses := make([]certenProofResponse, 0, len(proofs))
	for _, proof := range proofs {
		view, err := h.certenProofView(ctx, proof)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("failed to get certen proof corrections: %v", err), http.StatusInternalServerError)
			return
		}
		responses = append(responses, view)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"account_url": key,
		"proofs":      responses,
		"count":       len(responses),
	})
}
