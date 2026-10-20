// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// A recorded outcome's evidence, attached to its members' proofs (RB5-F15)
// =============================================================================
//
// A member's proof is stored when its settlement is observed - before its anchor's outcome can be recorded, which
// waits for every member to be final. So the outcome evidence is attached afterwards, by the recorder, to every proof
// whose layer 5 places it at that leaf of that anchor, as the proof's layer-6 row. A proof with no such row is in a
// named state - its anchor's outcome is not recorded yet, or the proof predates outcome evidence - never a pass.

// OutcomeProofStore is where the member proofs are (database.ProofArtifactRepository).
type OutcomeProofStore interface {
	ProofsOfAnchorLeaf(ctx context.Context, chainID int64, bundleID, batchRoot, leafHash string) ([]uuid.UUID, error)
	AttachOutcomeLayer(ctx context.Context, proofID uuid.UUID, layerName string, layerJSON []byte,
		decide func(standing []byte) (database.OutcomeLayerDecision, string, error)) (bool, error)
}

// OutcomeEvidenceAttacher builds a final record's evidence and attaches each member's to its proofs, returning how
// many proofs gained or completed their evidence.
type OutcomeEvidenceAttacher interface {
	AttachOutcomeEvidence(ctx context.Context, c OutcomeEvidenceSource, in OutcomeEvidenceInput) (int, error)
}

// ProofOutcomeEvidence is the production attacher.
type ProofOutcomeEvidence struct {
	Proofs OutcomeProofStore
	Logf   func(string, ...interface{})
}

// AttachOutcomeEvidence: see OutcomeEvidenceAttacher.
func (p ProofOutcomeEvidence) AttachOutcomeEvidence(ctx context.Context, c OutcomeEvidenceSource, in OutcomeEvidenceInput) (int, error) {
	if p.Proofs == nil {
		return 0, fmt.Errorf("no proof store to attach outcome evidence to")
	}
	evs, err := BuildOutcomeEvidence(ctx, c, in)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, ev := range evs {
		raw, err := json.Marshal(ev)
		if err != nil {
			return written, err
		}
		ids, err := p.Proofs.ProofsOfAnchorLeaf(ctx, ev.ChainID, ev.Anchor.BundleID, ev.Anchor.BatchRoot, ev.Member.Leaf.BatchLeaf)
		if err != nil {
			return written, err
		}
		for _, id := range ids {
			var merged *OutcomeEvidence
			ok, err := p.Proofs.AttachOutcomeLayer(ctx, id, Layer6RowName, raw, func(standing []byte) (database.OutcomeLayerDecision, string, error) {
				d, reason, m, err := decideOutcomeLayerMerge(standing, ev)
				merged = m
				return d, reason, err
			})
			if err != nil {
				return written, err
			}
			if !ok && merged != nil {
				// The standing row and this evidence each hold a part the other lacks (the BLS aggregate, a proven replay
				// guard): their union is attached, superseding the standing row, so neither part is lost.
				mraw, err := json.Marshal(merged)
				if err != nil {
					return written, err
				}
				if ok, err = p.Proofs.AttachOutcomeLayer(ctx, id, Layer6RowName, mraw, func(standing []byte) (database.OutcomeLayerDecision, string, error) {
					d, reason, _, err := decideOutcomeLayerMerge(standing, merged)
					return d, reason, err
				}); err != nil {
					return written, err
				}
			}
			if ok {
				written++
				if p.Logf != nil {
					p.Logf("🧾 [OUTCOME] proof %s: outcome evidence attached (chain %d anchor %s… leaf %d, status %d)", id, ev.ChainID,
						ev.Anchor.BundleID[:18], ev.Member.Leaf.LeafIndex, ev.Member.Leaf.Status)
				}
			}
		}
		if len(ids) == 0 && p.Logf != nil {
			p.Logf("ℹ️ [OUTCOME] chain %d anchor %s… leaf %d (status %d): no stored proof places a member there; its evidence is "+
				"attached when one does", ev.ChainID, ev.Anchor.BundleID[:18], ev.Member.Leaf.LeafIndex, ev.Member.Leaf.Status)
		}
	}
	return written, nil
}

// decideOutcomeLayer compares a proof's standing outcome evidence with new evidence of it. The two must state the same
// outcome, bar two parts that depend on who built the evidence and when: the BLS aggregate only the recording validator
// holds, and the S6 replay-guard evidence, whose bytes depend on which provider still served the state (RB10-F1). Evidence
// with the aggregate supersedes evidence without it, and a better replay guard (ranked: one that does not verify, none, a
// named state, proven) supersedes a worse one; when each holds the better of one part, their union is attached (V-R10B
// D1), so a worse guard never ends up attached over a better one; anything else that differs is a contradiction.
func decideOutcomeLayer(standing []byte, ev *OutcomeEvidence) (database.OutcomeLayerDecision, string, error) {
	d, reason, _, err := decideOutcomeLayerMerge(standing, ev)
	return d, reason, err
}

// decideOutcomeLayerMerge is decideOutcomeLayer and, when the standing evidence and ev each hold a part the other lacks
// (one the BLS aggregate, the other a proven replay guard), the decision Keep with merged the union of the two to attach.
func decideOutcomeLayerMerge(standing []byte, ev *OutcomeEvidence) (database.OutcomeLayerDecision, string, *OutcomeEvidence, error) {
	var old OutcomeEvidence
	if err := json.Unmarshal(standing, &old); err != nil {
		return database.OutcomeLayerKeep, "", nil, fmt.Errorf("the standing outcome evidence does not decode: %v", err)
	}
	a, b := old, *ev
	a.Quorum.AggregateSignature, a.Quorum.AggregatePublicKey = "", ""
	b.Quorum.AggregateSignature, b.Quorum.AggregatePublicKey = "", ""
	a.Member.ReplayGuard, b.Member.ReplayGuard = nil, nil
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil || !bytes.Equal(ja, jb) {
		return database.OutcomeLayerKeep, "", nil, fmt.Errorf("the standing evidence states another outcome or other evidence of it")
	}
	if old.Quorum.AggregateSignature != "" && ev.Quorum.AggregateSignature != "" &&
		(old.Quorum.AggregateSignature != ev.Quorum.AggregateSignature || old.Quorum.AggregatePublicKey != ev.Quorum.AggregatePublicKey) {
		return database.OutcomeLayerKeep, "", nil, fmt.Errorf("the standing evidence carries another BLS aggregate")
	}
	aggUp := old.Quorum.AggregateSignature == "" && ev.Quorum.AggregateSignature != ""
	aggDown := old.Quorum.AggregateSignature != "" && ev.Quorum.AggregateSignature == ""
	oldRG, newRG := old.replayGuardStanding(), ev.replayGuardStanding()
	// V-R10B D1: the guards are ranked (a guard that does not verify refuses the whole layer, so it ranks below none);
	// whichever way the aggregate moves, the attached row keeps the better guard.
	guardUp := newRG.order() > oldRG.order()
	guardDown := newRG.order() < oldRG.order()
	switch {
	case aggUp && guardUp:
		return database.OutcomeLayerSupersede, fmt.Sprintf("completed with the BLS aggregate the recording validator holds and a better S6 replay guard (%s over the standing row's %s)", newRG, oldRG), nil, nil
	case aggUp && !guardDown:
		return database.OutcomeLayerSupersede, "completed with the BLS aggregate the recording validator holds", nil, nil
	case guardUp && !aggDown:
		return database.OutcomeLayerSupersede, fmt.Sprintf("completed with a better S6 replay guard (%s over the standing row's %s)", newRG, oldRG), nil, nil
	case aggUp && guardDown:
		m := *ev
		m.Member.ReplayGuard = old.Member.ReplayGuard
		return database.OutcomeLayerKeep, "", &m, nil
	case guardUp && aggDown:
		m := *ev
		m.Quorum.AggregateSignature, m.Quorum.AggregatePublicKey = old.Quorum.AggregateSignature, old.Quorum.AggregatePublicKey
		return database.OutcomeLayerKeep, "", &m, nil
	}
	return database.OutcomeLayerKeep, "", nil, nil
}

// OutcomeEvidenceFromStorage reads a proof's outcome evidence (its layer-6 row); ErrNoOutcomeEvidence when it has none.
func OutcomeEvidenceFromStorage(ctx context.Context, store certenproof.ProofStorageReader, proofID uuid.UUID) (*OutcomeEvidence, error) {
	if store == nil {
		return nil, fmt.Errorf("chained proof storage reader is nil")
	}
	rows, err := store.LayerRows(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("read layer rows for proof %s: %w", proofID, err)
	}
	var found *OutcomeEvidence
	for _, row := range rows {
		if row.LayerNumber != Layer6LayerNumber || len(row.LayerJSON) == 0 {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: proof %s carries two standing outcome evidence rows", ErrOutcomeEvidence, proofID)
		}
		ev := new(OutcomeEvidence)
		if err := json.Unmarshal(row.LayerJSON, ev); err != nil {
			// A corrupt row is not an absent one.
			return nil, fmt.Errorf("%w: proof %s layer 6 (%s) does not decode: %v", ErrOutcomeEvidence, proofID, row.LayerName, err)
		}
		found = ev
	}
	if found == nil {
		return nil, fmt.Errorf("proof %s: %w", proofID, ErrNoOutcomeEvidence)
	}
	return found, nil
}

// VerifyStoredOutcome reads a proof's outcome evidence, verifies it offline, and binds it to the proof's own layer 5:
// the leaf, the batch root and the anchor the outcome is of must be the ones the proof is anchored under.
//
// ErrNoOutcomeEvidence (no evidence, or no layer 5 to bind it to) and ErrOutcomeSetRotated are named weaker states;
// ErrOutcomeEvidence is a failure.
func VerifyStoredOutcome(ctx context.Context, store certenproof.ProofStorageReader, proofID uuid.UUID) (*OutcomeEvidence, *OutcomeEvidenceCheck, error) {
	ev, err := OutcomeEvidenceFromStorage(ctx, store, proofID)
	if err != nil {
		return nil, nil, err
	}
	chk, err := ev.VerifyOffline()
	if err != nil {
		return ev, nil, err
	}
	l5, err := Layer5FromStorage(ctx, store, proofID)
	if errors.Is(err, ErrNoLayer5) {
		return ev, chk, fmt.Errorf("%w: the proof carries outcome evidence and no layer 5, so nothing places it at that leaf of "+
			"that anchor", ErrNoOutcomeEvidence)
	}
	if err != nil {
		return ev, chk, err
	}
	if err := BindOutcomeToLayer5(ev, l5, chk); err != nil {
		return ev, chk, err
	}
	return ev, chk, nil
}

// BindOutcomeToLayer5 requires the outcome evidence to be of the leaf and anchor the proof's layer 5 names.
func BindOutcomeToLayer5(ev *OutcomeEvidence, l5 *Layer5, chk *OutcomeEvidenceCheck) error {
	if l5 == nil {
		return fmt.Errorf("%w: no layer 5 to bind the outcome to", ErrNoOutcomeEvidence)
	}
	eq := func(a, b string) bool {
		norm := func(s string) string { return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x")) }
		return norm(a) == norm(b)
	}
	m := ev.Member.Leaf
	switch {
	case l5.ChainID != ev.ChainID:
		return evidenceFail("the outcome is of chain %d, the proof is anchored on chain %d", ev.ChainID, l5.ChainID)
	case !eq(l5.LeafHash, m.BatchLeaf) || l5.LeafIndex != m.LeafIndex:
		return evidenceFail("the outcome is of leaf %d %s, the proof is leaf %d %s", m.LeafIndex, m.BatchLeaf, l5.LeafIndex, l5.LeafHash)
	case !eq(l5.BatchRoot, ev.Anchor.BatchRoot):
		return evidenceFail("the outcome's anchor commits batch root %s, the proof's %s", ev.Anchor.BatchRoot, l5.BatchRoot)
	case l5.Governance != nil && l5.Governance.OperationID != "" && !eq(l5.Governance.OperationID, m.OperationID):
		return evidenceFail("the outcome is of operation %s, the proof of %s", m.OperationID, l5.Governance.OperationID)
	}
	if c := l5.Commitment; c != nil {
		switch {
		case !eq(c.BundleID, ev.Anchor.BundleID) || c.LeafCount != ev.Anchor.LeafCount || !eq(c.BatchOperationID, ev.Anchor.BatchOperationID) ||
			c.AccumulateBlockHeight != ev.Anchor.AccumulateBlockHeight:
			return evidenceFail("the outcome's anchor %s (%d leaves, operation %s, height %d) is not the proof's anchor %s (%d, %s, %d)",
				ev.Anchor.BundleID, ev.Anchor.LeafCount, ev.Anchor.BatchOperationID, ev.Anchor.AccumulateBlockHeight, c.BundleID,
				c.LeafCount, c.BatchOperationID, c.AccumulateBlockHeight)
		case !eq(c.AccumulateSetRoot, ev.Anchor.AccumulateSetRoot) || !eq(c.Incarnation, ev.Anchor.Incarnation):
			return evidenceFail("the outcome's anchor commits Accumulate set %s under %s, the proof's anchor %s under %s",
				ev.Anchor.AccumulateSetRoot, ev.Anchor.Incarnation, c.AccumulateSetRoot, c.Incarnation)
		case !eq(c.CertenSetRoot, ev.Anchor.CertenSetRoot):
			return fmt.Errorf("%w: the anchor was signed by CERTEN set %s, the outcome certified by set %s", ErrOutcomeSetRotated,
				c.CertenSetRoot, ev.Anchor.CertenSetRoot)
		}
		chk.proved("bound to this proof: its layer 5 places it at leaf %d of anchor %s…, the outcome's anchor, signed by the same "+
			"CERTEN set", l5.LeafIndex, ev.Anchor.BundleID[:18])
		return nil
	}
	chk.proved("bound to this proof by leaf %d and batch root only: its layer 5 records no anchor commitment (written before it "+
		"was recorded)", l5.LeafIndex)
	return nil
}
