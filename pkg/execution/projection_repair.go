// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/database"
)

// The settlement is not the anchor (RB3-F135). proof_artifacts, anchor_references and validator_attestations
// stated the member's settlement transaction in their anchor_* columns. `validator repair projections`
// classifies each proof's stated transaction from the chain and moves it where it belongs:
//
//	the proof's standing layer 5 names it          already the anchor; unchanged
//	it is a createBatchAnchor / createAnchor call   it IS an anchor; unchanged unless layer 5 names another
//	                                                (a contradiction, refused)
//	anything else, mined                            the settlement: moved to settlement_*, and the anchor
//	                                                columns state layer 5's anchor, or nothing without one
//
// Only the supported chains (Sepolia, Base Sepolia, Arbitrum Sepolia) are classified.

// projectionChains are the supported chains' ids as proof_artifacts.anchor_chain stores them.
var projectionChains = []string{"11155111", "84532", "421614"}

// anchorCreateSelectors are the calls that publish a root: createBatchAnchor (the V7/V8 batch generation) and
// the per-intent createAnchor of every generation that has one - 7 arguments in CertenAnchorV5/V6, 8 (with
// operationID) from V6_1 on. Selectors from the deployed contracts' own signatures.
var anchorCreateSelectors = [][]byte{
	createBatchAnchorMethod.ID,
	crypto.Keccak256([]byte("createAnchor(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256)"))[:4],
	crypto.Keccak256([]byte("createAnchor(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256)"))[:4],
}

func isAnchorCreateCall(input []byte) bool {
	if len(input) < 4 {
		return false
	}
	for _, sel := range anchorCreateSelectors {
		if bytes.Equal(input[:4], sel) {
			return true
		}
	}
	return false
}

// ProjectionRepairConfig configures RepairProofProjections.
type ProjectionRepairConfig struct {
	Repair      *database.EvidenceRepair
	Reader      AnchorTxReader
	ValidatorID string
	Apply       bool
	Now         func() time.Time
}

// ProjectionRepairReport says what a run found and did (or, without Apply, would do).
type ProjectionRepairReport struct {
	Proofs         int      `json:"proofs"`
	AlreadyAnchor  int      `json:"already_the_anchor"`
	Moved          int      `json:"settlements_moved"`
	AnchorsStated  int      `json:"anchors_stated_from_layer5"`
	AnchorsUnknown int      `json:"anchors_not_established"`
	Actions        []string `json:"actions"`
	Refused        []string `json:"refused"`
	Changed        []string `json:"changed_underneath"`
}

// RepairProofProjections classifies and moves every unclassified proof on the supported chains.
func RepairProofProjections(ctx context.Context, cfg ProjectionRepairConfig) (*ProjectionRepairReport, error) {
	if cfg.Repair == nil || cfg.Reader == nil || cfg.ValidatorID == "" {
		return nil, errors.New("projection repair needs the repository, a chain reader and the validator id")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	proofs, err := cfg.Repair.ListUnclassifiedProjections(ctx, projectionChains)
	if err != nil {
		return nil, err
	}
	report := &ProjectionRepairReport{Proofs: len(proofs), Actions: []string{}, Refused: []string{}, Changed: []string{}}
	for _, p := range proofs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := repairProjection(ctx, cfg, p, report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// What a proof's stated transaction is, as the chain shows it.
type statedClass int

const (
	statedRefused    statedClass = iota // not established, or contradicting layer 5
	statedAnchor                        // an anchor-create call: it is an anchor
	statedSettlement                    // a mined call that published no root: the settlement
)

// classifyStated reads a proof's stated transaction and decides what it is (see the file header).
func classifyStated(ctx context.Context, reader AnchorTxReader, chainID int64, stated, l5Anchor string) (statedClass, *AnchorTxReading, string) {
	reading, err := reader.ReadAnchorTx(ctx, chainID, stated)
	if err != nil {
		return statedRefused, nil, fmt.Sprintf("could not be read: %v", err)
	}
	if reading == nil || !reading.Found || reading.BlockNumber == 0 {
		return statedRefused, reading, "the chain does not show it mined"
	}
	if isAnchorCreateCall(reading.Input) {
		if l5Anchor != "" {
			return statedRefused, reading, fmt.Sprintf("it is an anchor-create call, but the proof's layer 5 names anchor %s", l5Anchor)
		}
		return statedAnchor, reading, ""
	}
	return statedSettlement, reading, ""
}

func repairProjection(ctx context.Context, cfg ProjectionRepairConfig, p database.ProofProjection, report *ProjectionRepairReport) error {
	label := fmt.Sprintf("proof %s (%s on chain %s)", p.ProofID, p.StatedTx, p.Chain)
	if p.L5AnchorTx != "" && sameHex(p.L5AnchorTx, p.StatedTx) {
		report.AlreadyAnchor++
		return nil
	}
	chainID, err := strconv.ParseInt(p.Chain, 10, 64)
	if err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: chain %q is not a chain id", label, p.Chain))
		return nil
	}
	class, reading, why := classifyStated(ctx, cfg.Reader, chainID, p.StatedTx, p.L5AnchorTx)
	switch class {
	case statedRefused:
		report.Refused = append(report.Refused, fmt.Sprintf("%s: %s; nothing changed", label, why))
		return nil
	case statedAnchor:
		report.AlreadyAnchor++
		return nil
	}
	// A mined call that published no root: the settlement the proof cycle observed and attested.
	move := database.SettlementMove{
		SettlementBlock: int64(reading.BlockNumber),
		AnchorTx:        p.L5AnchorTx, AnchorBlock: p.L5Block, AnchorBlockHash: p.L5BlockHash,
		Evidence: database.AnchorChainFacts{
			ChainID: chainID, TargetChain: chainName(chainID), TxHash: p.StatedTx, Succeeded: reading.Succeeded,
			BlockNumber: int64(reading.BlockNumber), BlockHash: reading.BlockHash, BlockTime: int64(reading.BlockTime),
			Head: int64(reading.Head), Sender: reading.From, Contract: reading.To,
			ReadAt: cfg.Now().UTC().Format(time.RFC3339Nano),
		},
	}
	anchorText := "none: the proof has no layer 5, so its anchor is not established"
	if p.L5AnchorTx != "" {
		anchorText = fmt.Sprintf("%s @ %d, from its layer 5", p.L5AnchorTx, p.L5Block)
	}
	move.Reason = fmt.Sprintf("%s (block %d, a call to %s, not an anchor-create call) is the member's settlement, stated in the "+
		"anchor columns (RB3-F135); moved to settlement_*. Anchor: %s.", p.StatedTx, reading.BlockNumber, reading.To, anchorText)
	action := fmt.Sprintf("%s: settlement %s @ %d moved out of the anchor columns; anchor -> %s", label, p.StatedTx, reading.BlockNumber, anchorText)
	if cfg.Apply {
		switch err := cfg.Repair.MoveSettlementOutOfAnchor(ctx, p, move, cfg.ValidatorID); {
		case errors.Is(err, database.ErrEvidenceChanged):
			report.Changed = append(report.Changed, label)
			return nil
		case err != nil:
			return err
		}
	}
	report.Moved++
	if p.L5AnchorTx != "" {
		report.AnchorsStated++
	} else {
		report.AnchorsUnknown++
	}
	report.Actions = append(report.Actions, strings.TrimSpace(action))
	return nil
}
