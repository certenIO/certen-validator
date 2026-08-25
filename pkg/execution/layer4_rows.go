// Copyright 2026 Certen Protocol
//
// Layer-4 row construction — ONE implementation, used by both orchestrators.
//
// proof_cycle_orchestrator and unified_orchestrator each persist the chained
// proof, and each had its own hardcoded `for layer := 1; layer <= 3` copy of
// the same logic. Two copies of a thing that must agree is how L4 came to be
// missing from one path already, so the row construction lives here and both
// call it. A change made here cannot land on one path and not the other.
//
// # WHAT THESE ROWS ARE FOR
//
// The govRoot commits to a SUMMARY of L4 (partition, threshold, sorted
// signers, signedHash, the two anchors). That summary is a conclusion. It says
// a quorum signed; it does not let anyone check that a quorum signed. The
// evidence — the ed25519 signatures, the validator set, and the canonical
// signed bytes — is roughly 6 KB per proof and cannot go into the summary
// without moving every govRoot ever signed (CanonicalJSONMarshal is
// json.Marshal, so struct layout IS the wire format).
//
// So it goes BESIDE the summary, in layer_json, in the leg's own shape: the
// exact chained_proof.Layer4 encoding that working-proof_do_not_edit's offline
// verifier and its testdata fixtures already use. A stored leg and a fixture
// are the same document, and the unmodified verifier runs on both with no
// shim.
package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/google/uuid"
)

// Layer-4 row names. The BVN leg sorts before the DN leg, which is the order
// GetChainedProofLayers returns them in (ORDER BY layer_number, layer_name).
const (
	Layer4BVNRowName = "L4-BVN - Quorum Signature"
	Layer4DNRowName  = "L4-DN - Quorum Signature"
)

// layer4RowWriter is the slice of the repository these rows need. Both
// orchestrators hold a *database.ProofArtifactRepository, which satisfies it.
type layer4RowWriter interface {
	CreateChainedProofLayer(ctx context.Context, input *database.NewChainedProofLayer) (*database.ChainedProofLayer, error)
}

// ChainedProofFromResult recovers the full ChainedProof carried by a
// ChainedProofResult.
//
// ChainedProofResult flattens L1-L3 into scalars for the visualisation
// columns and keeps the whole proof in CompleteProof as an interface{}. The L4
// legs exist only there, so every caller that wants them goes through this
// function rather than repeating the type assertion.
func ChainedProofFromResult(r *ChainedProofResult) *chained_proof.ChainedProof {
	if r == nil {
		return nil
	}
	cp, _ := r.CompleteProof.(*chained_proof.ChainedProof)
	return cp
}

// BuildLayer4Rows returns the two layer-4 rows for a proof, or an error.
//
// It returns BOTH rows or NEITHER. A single stored leg is not half a proof, it
// is an unverifiable one: ProofVerifier.Verify requires both legs and treats a
// missing leg as a failure, never a pass. Returning a partial slice here would
// put a row in the database that reads like evidence and cannot be checked,
// which is the exact condition this phase exists to end.
//
// A nil leg is not "skip". If a leg is nil at persistence time the proof
// should not exist: RequireL4Committed rejects such a proof upstream, before
// it can be signed. Reaching here with one means the plumbing broke, so this
// says so loudly instead of writing a quieter, weaker record.
func BuildLayer4Rows(proofID uuid.UUID, cp *chained_proof.ChainedProof) ([]*database.NewChainedProofLayer, error) {
	if cp == nil {
		return nil, fmt.Errorf("layer4: no chained proof available; cannot persist quorum evidence")
	}
	if cp.Layer4BVN == nil || cp.Layer4DN == nil {
		return nil, fmt.Errorf(
			"layer4: leg(s) missing at persistence time (bvn=%v dn=%v) — RequireL4Committed should have "+
				"rejected this proof upstream; writing no layer-4 row rather than a half one",
			cp.Layer4BVN != nil, cp.Layer4DN != nil)
	}

	// N + 1 rows: one per signer partition, plus the Directory.
	//
	// Governance can span partitions, so a proof may carry a BVN leg for each
	// partition that signed. Writing only the principal's would leave the stored
	// proof unable to reassemble the others, and ChainedProofFromStorage would
	// then produce a proof missing a leg the summary names — a record that reads
	// as evidence and cannot be checked.
	//
	// The row NAME carries the partition for every leg past the first, because
	// (layer_number, layer_name) is how rows are ordered and read back, and two
	// rows sharing a name would be indistinguishable.
	legs := cp.Legs()
	rows := make([]*database.NewChainedProofLayer, 0, len(legs)+1)
	seen := map[string]bool{}
	for i, leg := range legs {
		if leg.Layer4BVN == nil {
			return nil, fmt.Errorf("layer4: partition %s has no signed anchor; refusing to store "+
				"a proof whose leg cannot be verified", leg.Partition)
		}
		if seen[leg.Partition] {
			return nil, fmt.Errorf("layer4: two legs claim partition %s", leg.Partition)
		}
		seen[leg.Partition] = true

		name := Layer4BVNRowName
		if i > 0 || len(legs) > 1 {
			name = fmt.Sprintf("%s (%s)", Layer4BVNRowName, leg.Partition)
		}
		row, err := buildLayer4Row(proofID, name, leg.Layer4BVN)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}

	dnRow, err := buildLayer4Row(proofID, Layer4DNRowName, cp.Layer4DN)
	if err != nil {
		return nil, err
	}

	// No BVN leg may be signed by the Directory. If one were, that hop is
	// unwitnessed — the verifier rejects it, and there is no reason to store it
	// as though it were evidence.
	if seen[cp.Layer4DN.Partition] {
		return nil, fmt.Errorf("layer4: a BVN leg is signed by %q, the same partition as the DN leg; "+
			"the BVN->DN hop is not witnessed", cp.Layer4DN.Partition)
	}

	return append(rows, dnRow), nil
}

func buildLayer4Row(proofID uuid.UUID, name string, leg *chained_proof.Layer4) (*database.NewChainedProofLayer, error) {
	// The full leg, in its own tags. This is the authoritative record: the
	// three projection columns below are for querying and are never trusted.
	legJSON, err := json.Marshal(leg)
	if err != nil {
		return nil, fmt.Errorf("layer4[%s]: marshal leg: %w", leg.Partition, err)
	}

	// signed_hash is bytea. A leg whose signedHash is not 32 bytes of hex
	// cannot verify, so it is a hard error rather than a NULL projection on an
	// otherwise plausible-looking row.
	signedHash, err := hex.DecodeString(leg.SignedHash)
	if err != nil || len(signedHash) != 32 {
		return nil, fmt.Errorf("layer4[%s]: signedHash is not 32 bytes of hex (%q)", leg.Partition, leg.SignedHash)
	}

	partition := leg.Partition
	sigCount := len(leg.Signatures)
	threshold := int(leg.Threshold)

	return &database.NewChainedProofLayer{
		ProofID:      proofID,
		LayerNumber:  4,
		LayerName:    name,
		BVNPartition: &partition,
		LayerJSON:    legJSON,

		SignatureCount: &sigCount,
		Threshold:      &threshold,
		SignedHash:     signedHash,
	}, nil
}

// WriteLayer4Rows builds and persists both layer-4 rows.
//
// logf is the caller's logger, so the loud failure lands in the same stream as
// the rest of that orchestrator's proof-persistence output.
func WriteLayer4Rows(ctx context.Context, repo layer4RowWriter, proofID uuid.UUID, cp *chained_proof.ChainedProof, logf func(string, ...interface{})) error {
	rows, err := BuildLayer4Rows(proofID, cp)
	if err != nil {
		logf("🚨 [L4-PERSIST] proof %s: %v", proofID, err)
		return err
	}
	for _, row := range rows {
		if _, err := repo.CreateChainedProofLayer(ctx, row); err != nil {
			// One row written and one failed leaves exactly the half-record
			// this function refuses to construct, so it is reported as the
			// defect it is rather than as a warning.
			logf("🚨 [L4-PERSIST] proof %s: failed to write %s — the stored proof is now incomplete "+
				"and must not be read as offline-verifiable: %v", proofID, row.LayerName, err)
			return fmt.Errorf("write layer-4 row %q: %w", row.LayerName, err)
		}
	}
	parts := make([]string, 0, len(rows))
	for _, leg := range cp.Legs() {
		if leg.Layer4BVN != nil {
			parts = append(parts, fmt.Sprintf("%s (%d sigs / threshold %d)",
				leg.Layer4BVN.Partition, len(leg.Layer4BVN.Signatures), leg.Layer4BVN.Threshold))
		}
	}
	parts = append(parts, fmt.Sprintf("%s (%d sigs / threshold %d)",
		cp.Layer4DN.Partition, len(cp.Layer4DN.Signatures), cp.Layer4DN.Threshold))
	logf("✅ [L4-PERSIST] proof %s: stored L4 quorum evidence over %d leg(s) — %s",
		proofID, len(rows), strings.Join(parts, ", "))
	return nil
}

// logfPrintf adapts fmt.Printf to the logf signature WriteLayer4Rows takes.
// unified_orchestrator logs with fmt.Printf rather than a *log.Logger, so its
// L4 output lands in the same stream as the rest of its persistence messages.
func logfPrintf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// WithCanonicalLayer returns layerJSON with the AUTHORITATIVE layer object
// added under its own key, leaving every existing key untouched.
//
// # WHY THIS IS NEEDED FOR LAYERS 1-3, WHICH ALREADY HAD ROWS
//
// The layer_json written for L1-L3 is a DESCRIPTION: bvn_partition,
// source_hash, target_hash, path_depth. Together with receipt_entries it is
// enough to redraw the proof and to recompute a merkle path, and it is NOT
// enough to rebuild the object ProofVerifier.Verify checks. That verifier
// enforces scalar invariants the description drops — bvnMinorBlockIndex ==
// receipt.localBlock, dnConsensusHeight == DN_MBI + 1, DN_FINAL_MBI >= DN_MBI
// — so a proof reassembled from the description alone fails on fields that
// were never wrong, only never stored.
//
// So the full typed layer goes in beside the description, under the same tags
// the offline verifier and the testdata fixtures use. Additive by
// construction: every existing key survives, so the web app and the bundle
// exporter keep reading exactly what they read before.
//
// On a marshal error the original is returned unchanged. A row that describes
// the proof is worth more than no row, and the absence of the canonical key is
// what ChainedProofFromStorage reports as summary-only — it will not silently
// pass off a partial reassembly as a verified one.
func WithCanonicalLayer(layerJSON json.RawMessage, key string, value interface{}) json.RawMessage {
	var obj map[string]interface{}
	if err := json.Unmarshal(layerJSON, &obj); err != nil || obj == nil {
		obj = map[string]interface{}{}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return layerJSON
	}
	obj[key] = json.RawMessage(raw)
	out, err := json.Marshal(obj)
	if err != nil {
		return layerJSON
	}
	return out
}

// CanonicalLayerKeys are the keys WithCanonicalLayer writes. They match
// chained_proof.ChainedProof's own json tags, so the stored rows and the
// testdata fixtures speak the same language.
const (
	CanonicalInputKey  = "input"
	CanonicalLayer1Key = "layer1"
	CanonicalLayer2Key = "layer2"
	CanonicalLayer3Key = "layer3"

	// CanonicalAdditionalLegsKey carries the L1/L2 of every signer partition
	// beyond the principal's. It rides on the L1 row because the layer rows are
	// keyed by layer, so there is exactly one L1 row however many partitions
	// signed. The legs' L4 evidence is NOT here - each has its own layer-4 row.
	CanonicalAdditionalLegsKey = "additionalLegs"
)

// WithCanonicalL1 / L2 / L3 add the authoritative layer object to a row's
// layer_json. Each is nil-safe: with no chained proof in hand there is nothing
// authoritative to add, and the row keeps its description rather than gaining
// a fabricated canonical key that would make it look reassemblable when it is
// not.
func WithCanonicalL1(layerJSON json.RawMessage, cp *chained_proof.ChainedProof) json.RawMessage {
	if cp == nil {
		return layerJSON
	}
	// The input travels with L1 because layer1.leaf must equal input.txHash,
	// and a verifier that cannot see the input cannot check that.
	layerJSON = WithCanonicalLayer(layerJSON, CanonicalInputKey, cp.Input)
	layerJSON = WithCanonicalLayer(layerJSON, CanonicalLayer1Key, cp.Layer1)

	// Additional signer partitions travel here too, because their L1 and L2 have
	// nowhere else to go: the layer rows are keyed by LAYER, so there is one L1
	// row and one L2 row however many partitions signed.
	//
	// Their L4 legs are stripped first. Each of those has its own layer-4 row,
	// and one leg stored twice is two things that can disagree - at which point
	// a reader has no way to say which is the evidence. Reassembly matches them
	// back by partition and FAILS CLOSED if a leg named here has no row.
	if len(cp.AdditionalLegs) > 0 {
		stripped := make([]chained_proof.PartitionLeg, 0, len(cp.AdditionalLegs))
		for _, leg := range cp.AdditionalLegs {
			leg.Layer4BVN = nil
			stripped = append(stripped, leg)
		}
		layerJSON = WithCanonicalLayer(layerJSON, CanonicalAdditionalLegsKey, stripped)
	}
	return layerJSON
}

func WithCanonicalL2(layerJSON json.RawMessage, cp *chained_proof.ChainedProof) json.RawMessage {
	if cp == nil {
		return layerJSON
	}
	return WithCanonicalLayer(layerJSON, CanonicalLayer2Key, cp.Layer2)
}

func WithCanonicalL3(layerJSON json.RawMessage, cp *chained_proof.ChainedProof) json.RawMessage {
	if cp == nil {
		return layerJSON
	}
	return WithCanonicalLayer(layerJSON, CanonicalLayer3Key, cp.Layer3)
}
