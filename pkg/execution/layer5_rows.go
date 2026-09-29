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
	"strings"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
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
// binding is the member's canonical batch row (nil when there is none); obs is the observed
// target-chain receipt.
//
// Returns nil, nil when there is not enough to make an honest L5 — no canonical row, or no external
// transaction. It used to accept, with no row, the proof cycle's own leaf and root when they were
// equal: they were the operation commitment twice, so every such L5 stated a one-leaf tree of a value
// that is not the leaf and verified offline all the same (RB3-F85). That is not a failure: an L5 that cannot be built is
// simply absent, and absent reads as summary-only downstream. Building a
// half-populated one would put a row in the database that looks like an anchor
// binding and cannot be checked, which is the condition this whole line of work
// exists to end.
func BuildLayer5(
	binding *database.Layer5Binding,
	obs *chain.ObservationResult,
	chainID int64,
) (*Layer5, error) {
	if obs == nil || obs.TxHash == "" || obs.BlockNumber == 0 {
		return nil, nil // no actionable external coordinates
	}
	// The anchor transaction is where the ROOT was published: the anchor-create transaction the canonical
	// row carries, and nothing else. `obs` describes the settlement, which published no root. A row that
	// does not name its create transaction has no honest layer 5, and it is absent (summary-only) - it used
	// to fall back to the settlement's transaction and block, and published exactly that claim for three
	// anchors on 2026-09-19..21 (RB3-F134), in their layer 5 and in the Certen proofs built from it.
	if binding == nil || !IsTransactionHash(binding.AnchorTxHash) {
		return nil, nil
	}

	l5 := &Layer5{
		ChainID:  chainID,
		Network:  obs.ChainName,
		AnchorTx: binding.AnchorTxHash,
		// The anchor's block is the one recorded with it (the create receipt's), and unknown (zero) until
		// the anchor transaction itself is read. Never the verify transaction's block, and never the
		// settlement's; nor the settlement block's hash or depth.
		BlockNumber: uint64(max(binding.AnchorBlockNum, 0)),
	}
	if l5.Network == "" {
		// The strategy did not name its chain. The canonical row does, and a known chain id has a name;
		// "chain-<id>" only for a chain this build cannot name, so every record of one anchor agrees.
		l5.Network = chainName(chainID)
		if binding != nil && binding.TargetChain != "" {
			l5.Network = binding.TargetChain
		}
	}

	switch {
	case binding != nil && len(binding.BatchRoot) == 32 && len(binding.LeafHash) == 32:
		// THE BATCH PATH, AND THE ONLY ONE THAT CAN BE HONEST.
		//
		// The leaf is batch_transactions.transaction_hash — the BATCH-FORM leaf,
		// keccak256("certen:batchleaf:v1" || chainId || adiURLHash || execCommitment ||
		// operationID), the same value CertenAccountV7.computeLeaf returns and the same one
		// the tree was built over.
		//
		// It is deliberately NOT the proof cycle's LeafHash. That field carries the
		// operationCommitment, which is an INPUT to the leaf, not the leaf. Measured live on
		// 2026-08-25, intent 50376476: operationCommitment 4b0149349a37ae53… against a batch
		// root of 82d2566e777bb9b5…. Using it produced a binding that could not verify, and
		// the fail-closed guard below refused to store it — correctly, but the record was
		// then simply absent.
		l5.BatchRoot = hex.EncodeToString(binding.BatchRoot)
		l5.LeafHash = hex.EncodeToString(binding.LeafHash)
		l5.LeafIndex = uint64(binding.TreeIndex)
		path, err := merkleStepsFromNodes(binding.MerklePath)
		if err != nil {
			return nil, fmt.Errorf("layer5: the batch row's path: %w", err)
		}
		l5.Path = path

	default:
		// No canonical row: nothing to bind. Returning nil is not a failure - an absent L5 reads as
		// summary-only, which is true.
		return nil, nil
	}

	// Never store a row that would not read back. The write path and the read path must
	// agree, and the cheapest guarantee is running the reader's check before writing.
	if err := l5.VerifyOffline(); err != nil {
		return nil, fmt.Errorf("layer5: refusing to store an unverifiable anchor binding: %w", err)
	}
	return l5, nil
}

// merkleStepsFromNodes converts the stored path shape to the layer's.
//
// database.MerklePathNode.Position and MerkleStep.Position carry the
// same meaning — the SIBLING's side — so this is a rename, not a translation.
// It is written out rather than aliased because the two types live in packages
// with different reasons to change.
//
// Each sibling is stated in one form - 64 lower-case hex characters - whichever form the row stored it in: the
// canonical writer stores 0x-prefixed hashes, the rows before it bare ones, and the layer's reader takes bare hex.
// Passed through as stored, every multi-member canonical batch produced a layer 5 whose path did not decode, and
// the binding was refused as unverifiable - its members had no layer 5 at all (RB4-F72). A node that is not 32
// bytes of hex either way is an error, not a node.
func merkleStepsFromNodes(nodes []database.MerklePathNode) ([]MerkleStep, error) {
	if len(nodes) == 0 {
		return nil, nil
	}
	out := make([]MerkleStep, 0, len(nodes))
	for i, n := range nodes {
		h := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(n.Hash, "0x"), "0X"))
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			return nil, fmt.Errorf("merkle path node %d (%q) is not a 32-byte hash", i, n.Hash)
		}
		out = append(out, MerkleStep{Hash: h, Position: n.Position})
	}
	return out, nil
}

// BuildLayer5Row returns the chained_proof_layers row for an external anchor.
func BuildLayer5Row(proofID uuid.UUID, l5 *Layer5) (*database.NewChainedProofLayer, error) {
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
	l5 *Layer5,
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
			logf("🚨 [L5-PERSIST] proof %s: layer-5 row written but proof_artifacts.batch_id/"+
				"merkle_path were NOT populated: %v", proofID, err)
			return fmt.Errorf("bind proof to its batch: %w", err)
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
			logf("🚨 [L5-PERSIST] proof %s: failed to record the batch's anchor tx: %v", proofID, err)
			return fmt.Errorf("record the batch's anchor tx: %w", err)
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
// A binding that cannot be stated (no canonical row, no observed coordinates) leaves the proof
// summary-only for L5, said by name. A binding that can be stated and that the database refuses is an
// error: the bundle is not stored as if it carried the evidence (RB3-F91, the rule RB3-F73 set for the
// governance rows). The settlement itself is recorded separately, whatever happens here.
func (o *UnifiedOrchestrator) writeLayer5(
	ctx context.Context,
	proofID uuid.UUID,
	member *database.Layer5Binding,
	result *UnifiedProofCycleResult,
) (*Layer5, *database.Layer5Binding, error) {
	l5, binding := o.resolveAnchorBinding(ctx, proofID, member, result)
	if l5 == nil {
		return nil, binding, nil
	}
	if err := WriteLayer5Row(ctx, o.config.Repos.ProofArtifacts, proofID, l5, binding, logfPrintf); err != nil {
		return nil, binding, fmt.Errorf("layer 5 of proof %s: %w", proofID, err)
	}
	logfPrintf("   L5 claim: %s", l5.ExternalClaim())
	return l5, binding, nil
}

// resolveAnchorBinding works out where a proof's root was anchored: the canonical batch row covering the
// member's leaf from its canonical batch row. It returns nil when no honest binding can be built, never
// a binding to the settlement transaction. Layer 5, level 3 of the
// proof cycle and the Certen anchor proof all take their anchor from here, so they cannot disagree.
func (o *UnifiedOrchestrator) resolveAnchorBinding(
	ctx context.Context,
	proofID uuid.UUID,
	member *database.Layer5Binding,
	result *UnifiedProofCycleResult,
) (*Layer5, *database.Layer5Binding) {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil || result == nil {
		return nil, nil
	}
	if len(result.ObservationResults) == 0 {
		logfPrintf("ℹ️ [L5-PERSIST] proof %s: no observed target-chain transaction, so there are no "+
			"external coordinates to bind to; no L5 row", proofID)
		return nil, nil
	}
	obs := result.ObservationResults[0]
	binding := member
	if binding == nil {
		// Every member settles through the batch path and has a canonical row; one without it has no
		// place in any anchored tree that can be stated. It used to be written as a one-member tree of
		// the operation commitment (RB3-F85).
		logfPrintf("🚨 [L5-PERSIST] proof %s: no canonical batch row for this member - no L5 row; the proof "+
			"is summary-only for layer 5", proofID)
		return nil, nil
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

	// The anchor, when it is not the observed transaction, is read back first: the layer needs its block
	// before it can verify, and the chain's block is the one to state.
	var anchorObs *chain.ObservationResult
	if binding != nil && binding.AnchorTxHash != "" && !strings.EqualFold(binding.AnchorTxHash, obs.TxHash) {
		anchorObs = o.observeAnchor(ctx, proofID, binding.AnchorTxHash, binding, obs, result)
		if anchorObs != nil {
			if binding.AnchorBlockNum > 0 && uint64(binding.AnchorBlockNum) != anchorObs.BlockNumber {
				logfPrintf("🚨 [L5-PERSIST] proof %s: anchor %s is in block %d on chain, not block %d as recorded; "+
					"the chain's block is used", proofID, binding.AnchorTxHash, anchorObs.BlockNumber, binding.AnchorBlockNum)
			}
			binding.AnchorBlockNum = int64(anchorObs.BlockNumber)
		}
	}

	l5, err := BuildLayer5(binding, obs, chainIDNum)
	if err != nil {
		logfPrintf("🚨 [L5-PERSIST] proof %s: %v", proofID, err)
		return nil, binding
	}
	if l5 == nil {
		logfPrintf("ℹ️ [L5-PERSIST] proof %s: not enough to build an honest external anchor binding "+
			"(tx=%q, block=%d); no L5 row rather than a half one", proofID, obs.TxHash, obs.BlockNumber)
		return nil, binding
	}
	if anchorObs != nil && l5.BlockNumber == anchorObs.BlockNumber {
		l5.BlockHash, l5.Confirmations = anchorObs.BlockHash, anchorObs.Confirmations
	}
	return l5, binding
}

// anchorObservationTimeout bounds reading an anchor transaction back. The anchor was mined before the
// settlement this cycle already saw finalised, so the receipt is there; this only guards a stalled RPC.
const anchorObservationTimeout = 2 * time.Minute

// observeAnchor reads the anchor transaction's own coordinates off its chain: the block it is in, that
// block's hash and its depth. The settlement observation cannot supply them, and the canonical row has
// only the block, and not even that when another validator created the anchor. Nil when there is no
// observer for the chain or the read fails. One read per anchor per cycle.
func (o *UnifiedOrchestrator) observeAnchor(ctx context.Context, proofID uuid.UUID, anchorTx string, binding *database.Layer5Binding, obs *chain.ObservationResult, result *UnifiedProofCycleResult) *chain.ObservationResult {
	if o.config.Registry == nil {
		return nil
	}
	key := strings.ToLower(anchorTx)
	anchorObs, seen := result.anchorObservations[key]
	if !seen {
		chainName := obs.ChainName
		if binding != nil && binding.TargetChain != "" {
			chainName = binding.TargetChain
		}
		strategy, err := o.config.Registry.GetChainStrategy(chainName)
		if err != nil {
			logfPrintf("⚠️ [L5-PERSIST] proof %s: no observer for anchor chain %q, so anchor %s is recorded "+
				"without its block hash or depth: %v", proofID, chainName, anchorTx, err)
			return nil
		}
		timeout := anchorObservationTimeout
		if o.config.ObservationTimeout > 0 && o.config.ObservationTimeout < timeout {
			timeout = o.config.ObservationTimeout
		}
		observeCtx, cancel := context.WithTimeout(ctx, timeout)
		anchorObs, err = strategy.ObserveTransaction(observeCtx, anchorTx)
		cancel()
		if err != nil || anchorObs == nil || anchorObs.BlockNumber == 0 {
			logfPrintf("⚠️ [L5-PERSIST] proof %s: anchor %s could not be read back (%v); recorded without its "+
				"block hash or depth", proofID, anchorTx, err)
			anchorObs = nil
		}
		if result.anchorObservations == nil {
			result.anchorObservations = map[string]*chain.ObservationResult{}
		}
		result.anchorObservations[key] = anchorObs
	}
	return anchorObs
}

// batchPlacement is the member's place in its anchored batch: its canonical row, looked up by intent and
// chain (RB3-F85/F86), with its path checked to reach the root it names. nil, nil when the member has
// no row - its place is then stated as unknown, never as a one-leaf tree of its operation commitment.
func (o *UnifiedOrchestrator) batchPlacement(ctx context.Context, intentID, accumTxHash string, chainID int64) (*database.Layer5Binding, error) {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil {
		return nil, fmt.Errorf("no proof-artifact repository is wired to read the member's batch placement")
	}
	b, err := o.config.Repos.ProofArtifacts.GetLayer5Binding(ctx, intentID, accumTxHash, chainID)
	if errors.Is(err, database.ErrNoBatchBinding) {
		logfPrintf("🚨 [BATCH-PLACEMENT] intent %s on chain %d has no canonical batch row: its leaf, path and "+
			"root are unknown and stated as such", intentID, chainID)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the member's batch placement: %w", err)
	}
	if err := checkBatchPlacement(b); err != nil {
		return nil, fmt.Errorf("the member's canonical batch row contradicts itself: %w", err)
	}
	return b, nil
}

// checkBatchPlacement folds the row's leaf up its path (sorted-pair keccak, as the anchor verifies) and
// requires the root it names.
func checkBatchPlacement(b *database.Layer5Binding) error {
	if len(b.LeafHash) != 32 || len(b.BatchRoot) != 32 {
		return fmt.Errorf("leaf %d bytes, root %d bytes", len(b.LeafHash), len(b.BatchRoot))
	}
	var cur, rootHash [32]byte
	copy(cur[:], b.LeafHash)
	copy(rootHash[:], b.BatchRoot)
	for i, node := range b.MerklePath {
		sib, err := hex.DecodeString(strings.TrimPrefix(node.Hash, "0x"))
		if err != nil || len(sib) != 32 {
			return fmt.Errorf("path step %d is not a 32-byte hash", i)
		}
		var s [32]byte
		copy(s[:], sib)
		cur = hashPair(cur, s)
	}
	if cur != rootHash {
		return fmt.Errorf("leaf %x… does not reach root %x… by its path", b.LeafHash[:8], b.BatchRoot[:8])
	}
	return nil
}
