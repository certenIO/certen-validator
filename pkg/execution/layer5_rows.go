// Copyright 2026 Certen Protocol
//
// Layer-5 row construction — ONE implementation, in the same family as
// layer4_rows.go and for the same reason.
//
// certen_anchor_proofs was the L5 slot and had 0 rows — exactly the state
// chained_proof_layers layer 4 was in before Phase 6: the pieces existed,
// unjoined, and nothing assembled them. Migration 013 deliberately added NO
// CHECK on layer_number precisely so a future L5 would not be rejected by the
// table. This is that future.
//
// # WHAT AN L5 ROW IS FOR
//
// The govRoot commits to L1-L4 and G0-G2. It does NOT commit to L5, and
// structurally cannot: L5 describes the anchoring of a govRoot that must already
// exist before the anchor can be written. So L5 is storage and read-path only —
// there is no hash to move here, and no atomic fleet upgrade required.
//
// The row carries the leaf, the batch root, the path between them, and the
// external coordinates. Everything a verifier needs for the offline half is in
// layer_json; the external half is coordinates it can act on, never a claim it
// can check offline.
package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
)

// Layer5RowName is the layer_name for the external-anchor row. It sorts after
// the two L4 legs, which is the order GetChainedProofLayers returns rows in.
const Layer5RowName = "L5 - External Anchor"

// Layer5LayerNumber is 5. Named rather than inlined so the one place that
// decides it is greppable — the hardcoded `layer <= 3` upper bound in two
// orchestrators is how L4 came to be missing from a path already.
const Layer5LayerNumber = 5

// BuildLayer5 assembles the external-anchor layer from what actually settled.
//
// binding is the batch join (nil when this proof settled outside the batch
// path); obs is the observed target-chain receipt; leafHash and merkleRoot come
// from the proof cycle request.
//
// Returns nil, nil when there is not enough to make an honest L5 — no leaf, or
// no external transaction. That is not a failure: an L5 that cannot be built is
// simply absent, and absent reads as summary-only downstream. Building a
// half-populated one would put a row in the database that looks like an anchor
// binding and cannot be checked, which is the condition this whole line of work
// exists to end.
func BuildLayer5(
	binding *database.Layer5Binding,
	obs *chain.ObservationResult,
	leafHash []byte,
	merkleRoot []byte,
	chainID int64,
) (*certenproof.Layer5, error) {
	if len(leafHash) != 32 {
		return nil, nil // nothing to anchor
	}
	if obs == nil || obs.TxHash == "" || obs.BlockNumber == 0 {
		return nil, nil // no actionable external coordinates
	}

	l5 := &certenproof.Layer5{
		ChainID:     chainID,
		Network:     obs.ChainName,
		AnchorTx:    obs.TxHash,
		BlockNumber: obs.BlockNumber,
		BlockHash:   obs.BlockHash,
		LeafHash:    hex.EncodeToString(leafHash),
	}
	if l5.Network == "" {
		l5.Network = fmt.Sprintf("chain-%d", chainID)
	}

	switch {
	case binding != nil && len(binding.BatchRoot) == 32:
		// The batch path: a real tree with a real path. This is where the
		// leaf->root half stops being trivial.
		l5.BatchRoot = hex.EncodeToString(binding.BatchRoot)
		l5.LeafIndex = uint64(binding.TreeIndex)
		l5.Path = merkleStepsFromNodes(binding.MerklePath)

	case len(merkleRoot) == 32:
		// No batch row: this intent settled alone, so it is a ONE-MEMBER tree
		// whose root equals its leaf and whose path is empty. N=1 is not a
		// special case — it is the ordinary case with one member — and it is
		// only sound because VerifyOffline requires leaf == root before
		// accepting an empty path. If they differ here, the caller has handed
		// us a root this leaf is not under, and BuildLayer5 must not paper over
		// that by emitting a row that will fail later with a confusing message.
		l5.BatchRoot = hex.EncodeToString(merkleRoot)
		l5.LeafIndex = 0
		l5.Path = nil
		if l5.BatchRoot != l5.LeafHash {
			return nil, fmt.Errorf(
				"layer5: no batch path is available and leaf %s… != root %s…; this proof cannot be "+
					"shown to be under that root, and no L5 row will be written",
				l5.LeafHash[:16], l5.BatchRoot[:16])
		}

	default:
		return nil, nil // no root at all
	}

	// Never store a row that does not verify. The write path and the read path
	// must agree, and the cheapest way to guarantee that is to run the read
	// path's check before writing.
	if err := l5.VerifyOffline(); err != nil {
		return nil, fmt.Errorf("layer5: refusing to store an unverifiable anchor binding: %w", err)
	}
	return l5, nil
}

// merkleStepsFromNodes converts the stored path shape to the layer's.
//
// database.MerklePathNode.Position and certenproof.MerkleStep.Position carry the
// same meaning — the SIBLING's side — so this is a rename, not a translation.
// It is written out rather than aliased because the two types live in packages
// with different reasons to change.
func merkleStepsFromNodes(nodes []database.MerklePathNode) []certenproof.MerkleStep {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]certenproof.MerkleStep, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, certenproof.MerkleStep{Hash: n.Hash, Position: n.Position})
	}
	return out
}

// BuildLayer5Row returns the chained_proof_layers row for an external anchor.
func BuildLayer5Row(proofID uuid.UUID, l5 *certenproof.Layer5) (*database.NewChainedProofLayer, error) {
	if l5 == nil {
		return nil, fmt.Errorf("layer5: no anchor binding to persist")
	}
	layerJSON, err := json.Marshal(l5)
	if err != nil {
		return nil, fmt.Errorf("layer5: marshal: %w", err)
	}
	return &database.NewChainedProofLayer{
		ProofID:     proofID,
		LayerNumber: Layer5LayerNumber,
		LayerName:   Layer5RowName,
		LayerJSON:   layerJSON,
	}, nil
}

// WriteLayer5Row persists the external-anchor row, and populates the joins that
// were never written.
//
// Three things happen here, and only the first is the new layer:
//
//	chained_proof_layers        row 5, the assembled binding
//	proof_artifacts             batch_id + merkle_path, 0/418 before this
//	anchor_batches              anchor_tx_hash, 0/67,847 before this
//
// The last two are the actual plumbing defect and are worth more on their own
// than the row is: without them the path proving a proof is in an anchored batch
// exists in the database and cannot be joined to either end.
//
// Never fatal to the cycle. The settlement already happened on chain; failing to
// record the binding must not undo it. Every failure is logged loudly, because
// silence here is what left certen_anchor_proofs empty for 418 proofs.
func WriteLayer5Row(
	ctx context.Context,
	repo *database.ProofArtifactRepository,
	proofID uuid.UUID,
	l5 *certenproof.Layer5,
	binding *database.Layer5Binding,
	logf func(string, ...interface{}),
) error {
	if repo == nil || l5 == nil {
		return nil
	}

	row, err := BuildLayer5Row(proofID, l5)
	if err != nil {
		logf("🚨 [L5-PERSIST] proof %s: %v", proofID, err)
		return err
	}
	if _, err := repo.CreateChainedProofLayer(ctx, row); err != nil {
		logf("🚨 [L5-PERSIST] proof %s: failed to write %s — the external anchor binding is not "+
			"stored and this proof cannot be shown to be in an anchored batch: %v",
			proofID, row.LayerName, err)
		return fmt.Errorf("write layer-5 row: %w", err)
	}

	if binding != nil {
		if err := repo.BindProofToBatch(ctx, proofID, binding.BatchID, binding.TreeIndex, binding.MerklePath); err != nil {
			logf("⚠️ [L5-PERSIST] proof %s: layer-5 row written but proof_artifacts.batch_id/"+
				"merkle_path were NOT populated: %v", proofID, err)
		}
		err := repo.SetAnchorBatchTxHash(ctx, binding.BatchID, l5.AnchorTx, int64(l5.BlockNumber))
		switch {
		case err == nil:
			logf("✅ [L5-PERSIST] batch %s now records anchor tx %s at block %d",
				binding.BatchID, l5.AnchorTx, l5.BlockNumber)
		case errors.Is(err, database.ErrAnchorTxAlreadyRecorded):
			// Ordinary on a replay: the batch was anchored once and keeps its
			// first hash. Said out loud rather than swallowed, so "already
			// recorded" is never confused with "recorded by us".
			logf("ℹ️ [L5-PERSIST] batch %s already carries an anchor tx; left unchanged", binding.BatchID)
		default:
			logf("⚠️ [L5-PERSIST] proof %s: failed to record the batch's anchor tx: %v", proofID, err)
		}
	}

	logf("✅ [L5-PERSIST] proof %s: leaf %s… under batch root %s… over %d step(s), anchored in %s at block %d on %s",
		proofID, l5.LeafHash[:16], l5.BatchRoot[:16], len(l5.Path), l5.AnchorTx, l5.BlockNumber, l5.Network)
	return nil
}

// writeLayer5 assembles and persists the external-anchor layer for one proof.
//
// Lives on the orchestrator so it can reach the request, the observation results
// and the repository in one place, and so there is ONE call site rather than a
// copy per path — the same rule L4 follows, for the same reason.
//
// Never fatal. The intent already settled on chain; a missing anchor binding
// makes the stored proof summary-only for L5, which is honest, and is strictly
// better than failing a cycle that succeeded.
func (o *UnifiedOrchestrator) writeLayer5(
	ctx context.Context,
	proofID uuid.UUID,
	req *UnifiedProofCycleRequest,
	result *UnifiedProofCycleResult,
) {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil || req == nil || result == nil {
		return
	}
	if len(result.ObservationResults) == 0 {
		logfPrintf("ℹ️ [L5-PERSIST] proof %s: no observed target-chain transaction, so there are no "+
			"external coordinates to bind to; no L5 row", proofID)
		return
	}
	obs := result.ObservationResults[0]

	// The batch join. Absent is a legitimate state — an intent that settled
	// alone has no batch row — and is distinguished from a real lookup failure,
	// because treating "settled alone" as "lookup failed" would suppress L5 for
	// exactly the proofs where it is simplest to produce.
	var binding *database.Layer5Binding
	if req.AccumulateTxHash != "" {
		b, err := o.config.Repos.ProofArtifacts.GetLayer5Binding(ctx, req.AccumulateTxHash)
		switch {
		case err == nil:
			binding = b
		case errors.Is(err, database.ErrNoBatchBinding):
			logfPrintf("ℹ️ [L5-PERSIST] proof %s settled outside the batch path; treating it as a "+
				"one-member tree whose root IS its leaf", proofID)
		default:
			logfPrintf("⚠️ [L5-PERSIST] proof %s: batch binding lookup failed, falling back to the "+
				"single-leaf case: %v", proofID, err)
		}
	}

	// result.ChainID is the strategy's string id; the layer records the numeric
	// EVM chain id, which is what an auditor needs to pick the right explorer.
	// The observation carries it directly when the strategy populated it.
	chainIDNum := obs.ChainIDNumeric
	if chainIDNum == 0 {
		if n, perr := strconv.ParseInt(result.ChainID, 10, 64); perr == nil {
			chainIDNum = n
		}
	}

	merkleRoot := req.MerkleRoot[:]
	l5, err := BuildLayer5(binding, obs, req.LeafHash, merkleRoot, chainIDNum)
	if err != nil {
		logfPrintf("🚨 [L5-PERSIST] proof %s: %v", proofID, err)
		return
	}
	if l5 == nil {
		logfPrintf("ℹ️ [L5-PERSIST] proof %s: not enough to build an honest external anchor binding "+
			"(leaf=%d bytes, tx=%q, block=%d); no L5 row rather than a half one",
			proofID, len(req.LeafHash), obs.TxHash, obs.BlockNumber)
		return
	}

	if err := WriteLayer5Row(ctx, o.config.Repos.ProofArtifacts, proofID, l5, binding, logfPrintf); err != nil {
		return
	}
	logfPrintf("   L5 claim: %s", l5.ExternalClaim())
}
