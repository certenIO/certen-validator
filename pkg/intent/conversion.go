// Copyright 2025 Certen Protocol
//
// Intent Conversion Functions - Build CertenIntent from 4 JSON blobs
// This module is responsible for:
//   - Extracting a few convenience fields (intent ID, org ADI)
//   - Encoding the 4 logical blobs as raw JSON ([]byte)
//
// IMPORTANT:
//   - Canonicalization (RFC 8785) and operation_id / commitment computation
//     are handled later in the consensus / proof pipeline.
//   - This file MUST NOT define a second CertenIntent type. It uses the
//     canonical alias defined via protocol package.

package intent

import (
    "encoding/json"
    "fmt"
)

// rawIntentMeta represents the structure for parsing intent metadata blob
type rawIntentMeta struct {
    Kind         string `json:"kind,omitempty"`
    Version      string `json:"version,omitempty"`
    IntentType   string `json:"intentType,omitempty"`
    Organization string `json:"organizationAdi,omitempty"`
    IntentID     string `json:"intent_id,omitempty"`
    CreatedAt    string `json:"created_at,omitempty"`
    ProofClass   string `json:"proof_class,omitempty"`    // CRITICAL for routing
}

// rawGovernance represents the structure for parsing governance blob
type rawGovernance struct {
    OrganizationAdi string `json:"organizationAdi,omitempty"`
}

// rawReplay represents the structure for parsing replay protection blob.
// NOTE: The actual expiry semantics are enforced later via ReplayData.ExpiresAt.
// Here we only decode for potential validation if needed.
type rawReplay struct {
    // Unix timestamp in SECONDS (not ms) since epoch.
    ExpiresAt int64 `json:"expires_at,omitempty"`
}

// BuildCertenIntent builds a canonical CertenIntent from the 4 JSON blobs.
//
// Inputs:
//   - txHash: Accumulate transaction hash that carried the intent
//   - intentBlob:       logical "intent" JSON map
//   - crossBlob:        logical "cross-chain" JSON map
//   - govBlob:          logical "governance" JSON map
//   - replayBlob:       logical "replay protection" JSON map
//
// Behavior:
//   - Extracts IntentID (if present) and OrganizationADI
//   - Derives AccountURL = "<OrganizationADI>/data" when possible
//   - Marshals each blob to raw JSON []byte and stores them on CertenIntent
//   - Leaves canonicalization + operation_id hashing to the consensus builder
func BuildCertenIntent(
    txHash string,
    intentBlob, crossBlob, govBlob, replayBlob map[string]interface{},
) (*CertenIntent, error) {
    // Decode metadata from intent blob
    var im rawIntentMeta
    if err := mapToStruct(intentBlob, &im); err != nil {
        return nil, fmt.Errorf("decode intent metadata: %w", err)
    }

    // Decode governance to extract org ADI if present there
    var gv rawGovernance
    if err := mapToStruct(govBlob, &gv); err != nil {
        return nil, fmt.Errorf("decode governance data: %w", err)
    }

    // Optional: decode replay protection for sanity checking (not required here)
    // We keep this in case you want to add validation hooks later.
    var _rp rawReplay
    _ = mapToStruct(replayBlob, &_rp)

    // Compute OrganizationADI using governance first, then intent
    orgADI := firstNonEmpty(gv.OrganizationAdi, im.Organization)

    // Extract ProofClass from intent blob - CRITICAL for routing
    proofClass := firstNonEmpty(im.ProofClass, extractProofClassFromBlob(intentBlob))

    // Derive principal account URL (where the writeData TX lives)
    // Convention: <orgAdi>/data
    accountURL := ""
    if orgADI != "" {
        accountURL = fmt.Sprintf("%s/data", orgADI)
    }

    // Marshal each logical blob to raw JSON bytes.
    // These are the "raw" (non-canonical) blobs; downstream code is free
    // to canonicalize them as needed when building commitments/proofs.
    intentBytes, err := json.Marshal(intentBlob)
    if err != nil {
        return nil, fmt.Errorf("marshal intent blob: %w", err)
    }

    crossBytes, err := json.Marshal(crossBlob)
    if err != nil {
        return nil, fmt.Errorf("marshal cross-chain blob: %w", err)
    }

    govBytes, err := json.Marshal(govBlob)
    if err != nil {
        return nil, fmt.Errorf("marshal governance blob: %w", err)
    }

    replayBytes, err := json.Marshal(replayBlob)
    if err != nil {
        return nil, fmt.Errorf("marshal replay blob: %w", err)
    }

    // Build the canonical CertenIntent struct (as defined in pkg/consensus/intent.go)
    ci := &CertenIntent{
        IntentID:        im.IntentID,
        TransactionHash: txHash,
        AccountURL:      accountURL,
        OrganizationADI: orgADI,
        ProofClass:      proofClass,  // CRITICAL: drives routing ("on_demand" vs "on_cadence")
        IntentData:      intentBytes,
        CrossChainData:  crossBytes,
        GovernanceData:  govBytes,
        ReplayData:      replayBytes,
    }

    return ci, nil
}

// mapToStruct converts a map[string]interface{} to a struct using JSON marshaling
func mapToStruct(m map[string]interface{}, out interface{}) error {
    if m == nil {
        // Nothing to decode; caller should handle zero-value structs.
        return nil
    }

    b, err := json.Marshal(m)
    if err != nil {
        return err
    }
    return json.Unmarshal(b, out)
}

// firstNonEmpty returns the first non-empty string
func firstNonEmpty(s1, s2 string) string {
    if s1 != "" {
        return s1
    }
    return s2
}

// extractProofClassFromBlob extracts proof_class from intent blob map
func extractProofClassFromBlob(intentBlob map[string]interface{}) string {
    if intentBlob == nil {
        return ""
    }

    // Try proof_class field (snake_case)
    if pc, ok := intentBlob["proof_class"].(string); ok {
        return pc
    }

    // Try proofClass field (camelCase)
    if pc, ok := intentBlob["proofClass"].(string); ok {
        return pc
    }

    // Legacy: infer from priority field
    if priority, ok := intentBlob["priority"].(string); ok {
        switch priority {
        case "high", "urgent":
            return "on_demand"
        case "low", "normal":
            return "on_cadence"
        }
    }

    // Default fallback
    return "on_demand"
}