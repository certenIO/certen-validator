// Copyright 2026 Certen Protocol
//
// CHECKING WHO DECIDED A STORED PROOF'S TRANSACTION, AND THAT ITS ANCHOR COMMITS TO IT (RB4-F66).
//
// A proof stores, with its G1 level, the governance decision record - who decided the transaction, down to the keys
// behind every delegate - its commitment, and the vote record it was derived from; and, in its layer 5, every
// member's (operation id, governance commitment) and the batch operation id the anchor stores and the quorum signed.
// From those alone, offline:
//
//   - the vote record is evaluated again from its stored evidence - the chain-bound signatures, votes and page
//     histories - and must be reached exactly;
//   - the decision is derived again from the stored vote record and G0 result, and must be the stored decision;
//   - its commitment must be the one the batch lists for this member;
//   - the batch operation id must recompute from the members (Layer5.VerifyOffline).
//
// Online, the anchor-create transaction's calldata must carry that batch operation id and the batch root
// (VerifyLayer5Online). Together: the quorum signed, and the anchor stores, a commitment to who decided this
// transaction.
package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// ErrNoGovernanceDecision: the proof stores no governance decision - it predates RB4-F66. Who decided is not
// recorded; nothing about the proof is known to be wrong.
var ErrNoGovernanceDecision = errors.New("the proof stores no governance decision (it predates RB4-F66)")

// ErrGovernanceNotAnchored: the decision is recorded and re-derives, and the batch the proof settled in does not
// commit to it - a batch formed before governance commitments (v1), or a layer 5 without its governance.
var ErrGovernanceNotAnchored = errors.New("the governance decision is recorded and not anchored")

// GovernanceDecisionCheck is what CheckGovernanceDecision established.
type GovernanceDecisionCheck struct {
	Commitment  string // 0x-hex
	Authorities int
	// Evidence is what the vote record was evaluated again from: signatures, recorded and delegated votes, and
	// page histories replayed from genesis.
	EvidenceMessages int
	EvidencePages    int
	BatchOperationID string // 0x-hex, when anchored
	BatchVersion     string
}

// CheckGovernanceDecision re-derives the stored decision and checks it against the layer 5's batch. l5 may be nil
// (no layer 5 stored). The error is ErrNoGovernanceDecision or ErrGovernanceNotAnchored for the two named weaker
// states, anything else for evidence that does not agree with itself.
func CheckGovernanceDecision(levels []certenproof.StoredGovernanceLevel, l5 *Layer5) (*GovernanceDecisionCheck, error) {
	var g1 *certenproof.StoredGovernanceLevel
	for i := range levels {
		if levels[i].Level == "G1" {
			g1 = &levels[i]
		}
	}
	if g1 == nil {
		return nil, fmt.Errorf("%w: no G1 level is stored", ErrNoGovernanceDecision)
	}
	rawDecision, hasDecision := g1.Flags[GovLevelDecisionKey]
	if !hasDecision {
		return nil, ErrNoGovernanceDecision
	}
	var decisionHex, commitmentHex string
	if err := json.Unmarshal(rawDecision, &decisionHex); err != nil {
		return nil, fmt.Errorf("the stored governance decision is not a hex string: %w", err)
	}
	if err := json.Unmarshal(g1.Flags[GovLevelCommitmentKey], &commitmentHex); err != nil {
		return nil, fmt.Errorf("the stored governance commitment is not a hex string: %w", err)
	}
	decision, err := hex.DecodeString(decisionHex)
	if err != nil || len(decision) == 0 {
		return nil, fmt.Errorf("the stored governance decision is not hex")
	}
	var rec certenproof.AuthorizationRecord
	if err := json.Unmarshal(g1.Flags[GovLevelAuthorizationKey], &rec); err != nil {
		return nil, fmt.Errorf("the stored vote record does not decode: %w", err)
	}
	if len(g1.Result) == 0 {
		return nil, fmt.Errorf("the G1 level stores a decision without its G1 result, which names the transaction")
	}
	var g0 certenproof.G0Result
	if err := json.Unmarshal(g1.Result, &g0); err != nil {
		return nil, fmt.Errorf("the stored G1 result does not decode: %w", err)
	}
	rawEvidence, ok := g1.Flags[GovLevelVoteEvidenceKey]
	if !ok {
		return nil, fmt.Errorf("the G1 level stores a governance decision without the evidence of its vote record")
	}
	ev, err := certenproof.DecodeVoteEvidence(rawEvidence)
	if err != nil {
		return nil, err
	}
	if err := certenproof.VerifyVoteEvidence(context.Background(), &g0, ev, &rec); err != nil {
		return nil, fmt.Errorf("the stored vote record: %w", err)
	}
	again, err := certenproof.GovernanceDecisionRecord(&g0, &rec)
	if err != nil {
		return nil, fmt.Errorf("the stored vote record does not support a decision: %w", err)
	}
	if string(again) != string(decision) {
		return nil, fmt.Errorf("the stored decision is not the one its vote record and G1 result derive")
	}
	c := certenproof.GovernanceCommitment(decision)
	commitment := "0x" + hex.EncodeToString(c[:])
	if !strings.EqualFold(strings.TrimPrefix(commitmentHex, "0x"), hex.EncodeToString(c[:])) {
		return nil, fmt.Errorf("the stored commitment %s is not the decision's (%s)", commitmentHex, commitment)
	}
	out := &GovernanceDecisionCheck{Commitment: commitment, Authorities: len(rec.Authorities),
		EvidenceMessages: len(ev.Signatures) + len(ev.Votes) + len(ev.Arrivals), EvidencePages: len(ev.Pages)}

	if l5 == nil || l5.Governance == nil {
		return out, fmt.Errorf("%w: the proof's layer 5 carries no batch governance", ErrGovernanceNotAnchored)
	}
	g := l5.Governance
	out.BatchOperationID, out.BatchVersion = g.BatchOperationID, g.Version
	if err := g.Verify(); err != nil {
		return out, err
	}
	if g.Version != BatchOperationIDV2 {
		return out, fmt.Errorf("%w: the proof settled in a %s batch, whose operation id commits to no governance",
			ErrGovernanceNotAnchored, g.Version)
	}
	if !strings.EqualFold(g.GovernanceCommitment, commitment) {
		return out, fmt.Errorf("the batch lists this member's governance commitment as %s, the proof's decision "+
			"commits to %s", g.GovernanceCommitment, commitment)
	}
	return out, nil
}
