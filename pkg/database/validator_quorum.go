// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// AnchorQuorumThresholdNumerator / Denominator are the quorum rule the validators hold an anchor to:
// its aggregate must carry at least 2/3 of the validator set's voting power (signed*3 >= total*2).
// The batch quorum refuses to fold an aggregate below it, and the anchor contract verifies the same
// signature against the validator-set root that commits it.
const (
	AnchorQuorumThresholdNumerator   int64 = 2
	AnchorQuorumThresholdDenominator int64 = 3
)

// ValidatorQuorum is the independent checkers' requirement for a proof and what met it: the quorum
// that signed the anchor its member settled under, as the chain verified it (RB3-F76). It is not the
// key page's M-of-N, which is what the organisation's own signers were held to.
type ValidatorQuorum struct {
	ChainID              int64  `json:"chain_id"`
	Signers              int    `json:"signers"`
	SignedVotingPower    string `json:"signed_voting_power"`
	TotalVotingPower     string `json:"total_voting_power"`
	ThresholdNumerator   int64  `json:"threshold_numerator"`
	ThresholdDenominator int64  `json:"threshold_denominator"`
	VerifyTx             string `json:"verify_tx"`
}

// GetValidatorQuorum returns the verified quorum of the anchor batch a proof belongs to, or nil when
// the proof names no batch or its batch has no chain-verified quorum.
func (r *ProofArtifactRepository) GetValidatorQuorum(ctx context.Context, batchID *uuid.UUID) (*ValidatorQuorum, error) {
	if batchID == nil {
		return nil, nil
	}
	var q ValidatorQuorum
	var signers []json.RawMessage
	var raw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT chain_id, signers, signed_voting_power::text, total_voting_power::text, verify_tx
		FROM anchor_batches
		WHERE id = $1 AND bundle_id IS NOT NULL AND verify_tx IS NOT NULL
		  AND chain_id IS NOT NULL AND signers IS NOT NULL
		  AND signed_voting_power IS NOT NULL AND total_voting_power IS NOT NULL`, *batchID).
		Scan(&q.ChainID, &raw, &q.SignedVotingPower, &q.TotalVotingPower, &q.VerifyTx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("validator quorum of batch %s: %w", batchID, err)
	}
	if err := json.Unmarshal(raw, &signers); err != nil {
		return nil, fmt.Errorf("validator quorum of batch %s: signers: %w", batchID, err)
	}
	q.Signers = len(signers)
	q.ThresholdNumerator = AnchorQuorumThresholdNumerator
	q.ThresholdDenominator = AnchorQuorumThresholdDenominator
	return &q, nil
}
